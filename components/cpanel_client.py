from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore


class CPanelClient:
    """Minimal cPanel UAPI client for mailbox provisioning."""

    def __init__(
        self,
        base_url: str,
        username: str,
        *,
        password: Optional[str] = None,
        token: Optional[str] = None,
        verify_ssl: bool = True,
        timeout_sec: int = 20,
    ) -> None:
        if requests is None:  # type: ignore
            raise RuntimeError("cPanel provisioning requires the 'requests' package. Install it via: pip install -r requirements.txt")
        if bool(password) == bool(token):
            raise ValueError("cPanel client requires exactly one of password or token")
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.session = requests.Session()  # type: ignore
        if token:
            self.session.headers.update({"Authorization": f"cpanel {username}:{token}"})
        else:
            self.session.auth = (username, password)
        self.session.verify = verify_ssl
        self.timeout_sec = timeout_sec

    def _endpoint(self, module: str, function: str) -> str:
        return f"{self.base_url}/execute/{module}/{function}"

    @staticmethod
    def _result_error_message(result: Dict[str, Any]) -> str:
        values: List[str] = []
        for key in ("errors", "messages", "warnings"):
            raw = result.get(key)
            if isinstance(raw, list):
                values.extend(str(item) for item in raw if item)
            elif raw:
                values.append(str(raw))
        return "; ".join(values) or "cPanel UAPI returned an error"

    @staticmethod
    def _looks_already_exists(message: str) -> bool:
        return bool(re.search(r"\b(already exists?|exists? already|account exists?|user exists?)\b", message, flags=re.IGNORECASE))

    @staticmethod
    def _looks_not_found(message: str) -> bool:
        return bool(re.search(r"\b(not exist|does not exist|doesn't exist|not found|no such)\b", message, flags=re.IGNORECASE))

    def _call(self, module: str, function: str, params: Optional[Dict[str, Any]] = None) -> Any:
        endpoint = self._endpoint(module, function)
        try:
            response = self.session.get(endpoint, params=dict(params or {}), timeout=self.timeout_sec)
            response.raise_for_status()
        except Exception as exc:
            raise RuntimeError(f"cPanel UAPI {module}/{function} request failed: {type(exc).__name__}") from None
        try:
            payload = response.json()
        except Exception as exc:
            raise RuntimeError("Unable to parse cPanel UAPI JSON response") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Unable to parse cPanel UAPI response")
        result = payload.get("result")
        if not isinstance(result, dict):
            raise RuntimeError("Unable to parse cPanel UAPI result")
        if int(result.get("status") or 0) != 1:
            raise RuntimeError(self._result_error_message(result))
        return result.get("data")

    @staticmethod
    def _local_part(value: str, domain: Optional[str] = None) -> str:
        value = value.strip()
        if "@" in value:
            local, value_domain = value.split("@", 1)
            if domain is not None and value_domain.lower() != domain.lower():
                return ""
            return local
        return value

    @staticmethod
    def _email_from_entry(entry: Any) -> str:
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict):
            user = entry.get("email_user") or entry.get("user")
            domain = entry.get("domain")
            if isinstance(user, str) and isinstance(domain, str) and user.strip() and domain.strip():
                return f"{user}@{domain}"
            for key in ("email", "login", "user", "address"):
                value = entry.get(key)
                if isinstance(value, str) and value.strip():
                    return value
        return ""

    def list_pop_accounts(self, domain: str) -> List[str]:
        data = self._call("Email", "list_pops", {"skip_main": 1})
        if not isinstance(data, list):
            raise RuntimeError("Unable to parse cPanel email account list response")
        locals_: List[str] = []
        seen = set()
        for entry in data:
            local = self._local_part(self._email_from_entry(entry), domain)
            if local and local not in seen:
                seen.add(local)
                locals_.append(local)
        return locals_

    def list_all_email_accounts(self) -> List[str]:
        data = self._call("Email", "list_pops", {"skip_main": 1})
        if not isinstance(data, list):
            raise RuntimeError("Unable to parse cPanel email account list response")
        emails: List[str] = []
        seen = set()
        for entry in data:
            email = self._email_from_entry(entry).strip()
            if email and "@" in email and email.lower() not in seen:
                seen.add(email.lower())
                emails.append(email)
        return emails

    def create_pop_account(self, domain: str, local_part: str, password: str, quota_mb: int = 0, *, allow_existing: bool = True) -> None:
        try:
            self._call(
                "Email",
                "add_pop",
                {
                    "email": local_part,
                    "domain": domain,
                    "password": password,
                    "quota": str(int(quota_mb) if quota_mb >= 0 else 0),
                    "skip_update_db": 1,
                },
            )
        except Exception as exc:
            if allow_existing and self._looks_already_exists(str(exc)):
                return
            raise

    def delete_pop_account(self, domain: str, local_part: str) -> None:
        try:
            self._call("Email", "delete_pop", {"email": f"{local_part}@{domain}", "domain": domain})
        except Exception as exc:
            lowered = str(exc).lower()
            if self._looks_not_found(lowered):
                return
            raise
