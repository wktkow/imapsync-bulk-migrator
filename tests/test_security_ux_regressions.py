from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest import mock

import pytest


def test_environment_rejects_unsupported_python_39() -> None:
    from components.utils import check_environment

    with mock.patch("components.utils.sys.version_info", (3, 9, 99)):
        with pytest.raises(RuntimeError, match=r"Python 3\.10\+"):
            check_environment()


def test_legacy_config_rejects_cleartext_imap(tmp_path: Path) -> None:
    from components.models import Config

    config_path = tmp_path / "legacy.json"
    config_path.write_text(
        json.dumps(
            {
                "server": {"host": "imap.example.com", "port": 143, "ssl": False, "starttls": False},
                "accounts": [{"email": "user@example.com", "password": "secret"}],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="cleartext IMAP authentication"):
        Config.from_json_file(config_path)


def test_legacy_config_allows_historical_cleartext_source_descriptor(tmp_path: Path) -> None:
    from components.models import Config

    config_path = tmp_path / "legacy-import.json"
    config_path.write_text(
        json.dumps(
            {
                "server": {"host": "target.example.com", "port": 993, "ssl": True},
                "source_server": {
                    "host": "retired-source.example.com",
                    "port": 143,
                    "ssl": False,
                    "starttls": False,
                },
                "accounts": [{"email": "user@example.com", "password": "secret"}],
            }
        ),
        encoding="utf-8",
    )

    config = Config.from_json_file(config_path)

    assert config.source_server is not None
    assert config.source_server.ssl is False
    assert config.source_server.starttls is False


def test_generic_provider_config_rejects_cleartext_imap() -> None:
    from components.models import ProviderEndpoint

    with pytest.raises(ValueError, match="cleartext IMAP authentication"):
        ProviderEndpoint.from_dict(
            {
                "provider": "imap",
                "host": "imap.example.com",
                "port": 143,
                "ssl": False,
                "starttls": False,
                "auth": {"method": "password", "password": "secret"},
            },
            context="source",
        )


def test_legacy_imap_helper_defensively_refuses_cleartext_login() -> None:
    from components.imap_ops import imap_connection
    from components.models import Account, ServerConfig

    with pytest.raises(RuntimeError, match="cleartext connection"):
        with imap_connection(
            ServerConfig(host="imap.example.com", port=143, ssl=False, starttls=False),
            Account(email="user@example.com", password="secret"),
        ):
            pytest.fail("connection helper should reject cleartext authentication")


def test_provider_imap_helper_defensively_refuses_cleartext_authentication() -> None:
    from components.models import AuthConfig, MigrationAccount, ProviderEndpoint
    from components.provider_ops import imap_connection

    endpoint = ProviderEndpoint(
        provider="imap",
        host="imap.example.com",
        port=143,
        ssl=False,
        starttls=False,
        auth=AuthConfig(method="password", password="secret"),
    )
    account = MigrationAccount(source_email="source@example.com", target_email="target@example.com")

    with pytest.raises(RuntimeError, match="cleartext connection"):
        with imap_connection(endpoint, account, role="source"):
            pytest.fail("connection helper should reject cleartext authentication")


@pytest.mark.parametrize(
    ("module_name", "argv"),
    [
        (
            "directadmin_indexer",
            [
                "--url", "https://panel.example.com:2222",
                "--username", "admin",
                "--password", "secret",
                "--imap-host", "imap.example.com",
                "--no-imap-ssl",
            ],
        ),
        (
            "cpanel_indexer",
            [
                "--url", "https://panel.example.com:2083",
                "--username", "admin",
                "--token", "secret",
                "--imap-host", "imap.example.com",
                "--no-imap-ssl",
            ],
        ),
    ],
)
def test_panel_indexers_reject_cleartext_imap_output(module_name: str, argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    module = __import__(module_name)

    assert module.main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "cleartext IMAP config" in captured.err


@pytest.mark.parametrize("module_name", ["directadmin_indexer", "cpanel_indexer"])
def test_panel_indexer_transport_selects_the_expected_default_port(module_name: str) -> None:
    module = __import__(module_name)
    auth = ["--password", "secret"] if module_name == "directadmin_indexer" else ["--token", "secret"]
    base = [
        "--url", "https://panel.example.com",
        "--username", "admin",
        *auth,
        "--imap-host", "imap.example.com",
    ]

    assert module.parse_args(base).imap_port == 993
    assert module.parse_args([*base, "--imap-starttls"]).imap_port == 143
    assert module.parse_args([*base, "--imap-starttls", "--imap-port", "1143"]).imap_port == 1143


@pytest.mark.parametrize(
    "constructor",
    [
        lambda: __import__("components.cpanel_client", fromlist=["CPanelClient"]).CPanelClient(
            "http://panel.example.com:2083", "admin", token="token"
        ),
        lambda: __import__("components.da_client", fromlist=["DirectAdminClient"]).DirectAdminClient(
            "http://panel.example.com:2222", "admin", "password"
        ),
        lambda: __import__("directadmin_indexer").DirectAdminClient(
            "http://panel.example.com:2222", "admin", "password"
        ),
    ],
)
def test_panel_clients_reject_plain_http(constructor) -> None:
    with pytest.raises(ValueError, match="https://"):
        constructor()


@pytest.mark.parametrize(
    "constructor",
    [
        lambda url: __import__("components.cpanel_client", fromlist=["CPanelClient"]).CPanelClient(
            url, "admin", token="token"
        ),
        lambda url: __import__("components.da_client", fromlist=["DirectAdminClient"]).DirectAdminClient(
            url, "admin", "password"
        ),
        lambda url: __import__("directadmin_indexer").DirectAdminClient(url, "admin", "password"),
    ],
)
@pytest.mark.parametrize(
    "url",
    [
        "https://panel.example.com:bad",
        "https://panel.example.com:99999",
        "https://panel.example.com?redirect=elsewhere",
        "https://panel.example.com#fragment",
        "https://user:secret@panel.example.com",
    ],
)
def test_panel_clients_reject_invalid_ports(constructor, url: str) -> None:
    with pytest.raises(ValueError, match="valid host and port"):
        constructor(url)


def test_panel_clients_allow_literal_loopback_http() -> None:
    from components.cpanel_client import CPanelClient
    from components.da_client import DirectAdminClient
    from directadmin_indexer import DirectAdminClient as IndexerDirectAdminClient

    clients = [
        CPanelClient("http://127.0.0.1:2082", "admin", token="token"),
        DirectAdminClient("http://127.0.0.1:2222", "admin", "password"),
        IndexerDirectAdminClient("http://[::1]:2222", "admin", "password"),
    ]

    assert [client.base_url for client in clients] == [
        "http://127.0.0.1:2082",
        "http://127.0.0.1:2222",
        "http://[::1]:2222",
    ]


@pytest.mark.parametrize(
    ("module_name", "argv"),
    [
        (
            "directadmin_indexer",
            [
                "--url", "https://panel.example.com:2222",
                "--username", "admin",
                "--password", "secret",
                "--imap-host", "",
            ],
        ),
        (
            "cpanel_indexer",
            [
                "--url", "https://panel.example.com:2083",
                "--username", "admin",
                "--token", "secret",
                "--imap-host", "",
            ],
        ),
    ],
)
def test_panel_indexers_reject_empty_imap_host_before_query(
    module_name: str,
    argv: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = __import__(module_name)
    client = mock.Mock(side_effect=AssertionError("panel query must not start"))

    with mock.patch.object(module, "CPanelClient" if module_name == "cpanel_indexer" else "DirectAdminClient", client):
        assert module.main(argv) == 2

    client.assert_not_called()
    assert "IMAP host must be non-empty" in capsys.readouterr().err


def test_cpanel_client_refuses_redirects_without_exposing_location() -> None:
    from components.cpanel_client import CPanelClient

    class Response:
        status_code = 302

        def raise_for_status(self) -> None:
            pass

    class Session:
        def get(self, _url, *, params, timeout, allow_redirects):
            assert params == {"password": "mailbox-secret"}
            assert timeout == 20
            assert allow_redirects is False
            return Response()

    client = object.__new__(CPanelClient)
    client.base_url = "https://panel.example.com:2083"
    client.session = Session()
    client.timeout_sec = 20

    with pytest.raises(RuntimeError, match=r"request failed: HTTP 302") as exc_info:
        client._call("Email", "add_pop", {"password": "mailbox-secret"})
    assert "mailbox-secret" not in str(exc_info.value)


def test_directadmin_clients_refuse_redirects() -> None:
    from components.da_client import DirectAdminClient
    from directadmin_indexer import DirectAdminClient as IndexerDirectAdminClient

    class Response:
        status_code = 307

        def raise_for_status(self) -> None:
            pass

    class Session:
        def get(self, _url, *, params, timeout, allow_redirects):
            assert timeout == 20
            assert allow_redirects is False
            return Response()

        def post(self, _url, *, data, timeout, allow_redirects):
            assert timeout == 20
            assert allow_redirects is False
            return Response()

    for client_class in (DirectAdminClient, IndexerDirectAdminClient):
        client = object.__new__(client_class)
        client.base_url = "https://panel.example.com:2222"
        client.session = Session()
        client.timeout_sec = 20
        with pytest.raises(RuntimeError, match=r"request failed: HTTP 307"):
            client._get("CMD_API_POP", {"domain": "example.com"})

    client = object.__new__(DirectAdminClient)
    client.base_url = "https://panel.example.com:2222"
    client.session = Session()
    client.timeout_sec = 20
    with pytest.raises(RuntimeError, match=r"request failed: HTTP 307"):
        client._post("CMD_API_POP", {"passwd": "mailbox-secret"})


@pytest.mark.parametrize(
    "ensure_function",
    [
        pytest.param(
            lambda config, client: __import__(
                "components.cpanel_ensure", fromlist=["ensure_accounts_exist_cpanel"]
            ).ensure_accounts_exist_cpanel(config, client),
            id="cpanel-create",
        ),
        pytest.param(
            lambda config, client: __import__(
                "components.cpanel_ensure", fromlist=["reset_accounts_cpanel"]
            ).reset_accounts_cpanel(config, client),
            id="cpanel-reset",
        ),
        pytest.param(
            lambda config, client: __import__(
                "components.da_ensure", fromlist=["ensure_accounts_exist_directadmin"]
            ).ensure_accounts_exist_directadmin(config, client),
            id="directadmin-create",
        ),
        pytest.param(
            lambda config, client: __import__(
                "components.da_ensure", fromlist=["reset_accounts_directadmin"]
            ).reset_accounts_directadmin(config, client),
            id="directadmin-reset",
        ),
    ],
)
def test_panel_mutations_reject_empty_mailbox_password_before_client_call(ensure_function) -> None:
    from components.models import Account, Config, ServerConfig

    config = Config(
        server=ServerConfig(host="imap.example.com"),
        accounts=[Account(email="user@example.com", password="")],
    )

    with pytest.raises(ValueError, match=r"non-empty accounts\[\]\.password"):
        ensure_function(config, object())


def test_panel_import_rejects_empty_password_before_reset_journal_archive(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from components.main import main

    config_path = tmp_path / "import.json"
    config_path.write_text(
        json.dumps(
            {
                "server": {"host": "imap.example.com", "ssl": True, "starttls": False},
                "accounts": [{"email": "user@example.com", "password": ""}],
            }
        ),
        encoding="utf-8",
    )
    archive = mock.Mock(side_effect=AssertionError("journal archive must not run"))
    with (
        mock.patch("components.main.check_environment"),
        mock.patch("components.main.archive_legacy_import_journal_for_reset", archive),
    ):
        rc = main(
            [
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "staged"),
                "--log-dir", str(tmp_path / "logs"),
                "--auto-provision-da",
                "--reset",
                "--reset-confirm", "YES",
                "--da-url", "https://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "panel-secret",
            ]
        )

    assert rc == 2
    archive.assert_not_called()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "non-empty accounts[].password" in captured.err


def test_panel_import_rejects_plain_http_before_audit_or_journal_archive(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from components.main import main

    config_path = tmp_path / "import.json"
    config_path.write_text(
        json.dumps(
            {
                "server": {"host": "imap.example.com", "ssl": True, "starttls": False},
                "accounts": [{"email": "user@example.com", "password": "mailbox-secret"}],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "staged" / "user@example.com").mkdir(parents=True)
    audit = mock.Mock(side_effect=AssertionError("staged audit must not run with an invalid panel URL"))
    archive = mock.Mock(side_effect=AssertionError("journal archive must not run with an invalid panel URL"))
    journal_check = mock.Mock(side_effect=AssertionError("journal must not be inspected or repaired with an invalid panel URL"))
    with (
        mock.patch("components.main.check_environment"),
        mock.patch("components.main.audit_export", audit),
        mock.patch("components.main.archive_legacy_import_journal_for_reset", archive),
        mock.patch("components.main._legacy_pending_import_journal_issues", journal_check),
    ):
        rc = main(
            [
                "--mode", "import",
                "--config", str(config_path),
                "--input-dir", str(tmp_path / "staged"),
                "--log-dir", str(tmp_path / "logs"),
                "--no-connectivity-test",
                "--auto-provision-da",
                "--reset",
                "--reset-confirm", "YES",
                "--da-url", "http://panel.example.com:2222",
                "--da-username", "admin",
                "--da-password", "panel-secret",
            ]
        )

    assert rc == 2
    audit.assert_not_called()
    archive.assert_not_called()
    journal_check.assert_not_called()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "must use https://" in captured.err


def test_console_logs_and_cli_errors_use_stderr(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from components.main import main

    rc = main(
        [
            "--mode", "preflight",
            "--no-connectivity-test",
            "--log-dir", str(tmp_path / "logs"),
        ]
    )

    assert rc == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "--no-connectivity-test cannot be used with --mode preflight" in captured.err

    # Avoid retaining a handler backed by pytest's closed capture stream.
    for handler in list(logging.getLogger().handlers):
        logging.getLogger().removeHandler(handler)
        handler.close()
