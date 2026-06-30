import logging
from typing import Any, Dict, List, Optional, Set

from .da_client import DirectAdminClient
from .models import Account, Config


def _accounts_by_domain(config: Config) -> Dict[str, List[Account]]:
    per_domain: Dict[str, List[Account]] = {}
    invalid: List[str] = []
    for acc in config.accounts:
        email = acc.email.strip()
        if email != acc.email or email.count("@") != 1 or any(ch.isspace() for ch in email):
            invalid.append(acc.email)
            continue
        local, domain = email.split("@", 1)
        if not local or not domain:
            invalid.append(acc.email)
            continue
        per_domain.setdefault(domain.lower(), []).append(acc)
    if invalid:
        raise ValueError("DirectAdmin provisioning requires mailbox accounts in local@domain form: " + ", ".join(invalid))
    return per_domain


def _raise_if_stopped(stop_event: Optional[Any], label: str) -> None:
    if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
        raise RuntimeError(f"{label}: stop requested before completion")


def ensure_accounts_exist_directadmin(
    config: "Config",
    client: DirectAdminClient,
    *,
    dry_run: bool = False,
    ignore_errors: bool = False,
    quota_mb: int = 0,
    stop_event: Optional[Any] = None,
) -> Set[str]:
    failed: Set[str] = set()
    per_domain = _accounts_by_domain(config)
    for domain, accounts in per_domain.items():
        _raise_if_stopped(stop_event, f"directadmin provisioning {domain}")
        try:
            existing_locals = set(client.list_pop_accounts(domain))
        except Exception as exc:
            logging.error("[da] Failed to list accounts for domain %s: %s", domain, exc)
            if dry_run or not ignore_errors:
                raise
            failed.update(acc.email for acc in accounts)
            continue
        for acc in accounts:
            local = acc.email.split("@", 1)[0]
            if local in existing_locals:
                logging.info("[da] Exists: %s", acc.email)
                continue
            if dry_run:
                logging.info("[da][dry-run] Would create mailbox: %s", acc.email)
                continue
            _raise_if_stopped(stop_event, f"directadmin provisioning {acc.email}")
            try:
                client.create_pop_account(domain, local, acc.password, quota_mb=quota_mb)
                existing_locals.add(local)
                logging.info("[da] Created mailbox: %s", acc.email)
            except Exception as exc:
                logging.error("[da] Failed to create %s: %s", acc.email, exc)
                failed.add(acc.email)
                if not ignore_errors:
                    raise
    return failed


def reset_accounts_directadmin(
    config: "Config",
    client: DirectAdminClient,
    *,
    dry_run: bool = False,
    ignore_errors: bool = False,
    quota_mb: int = 0,
    stop_event: Optional[Any] = None,
) -> Set[str]:
    """Delete then recreate each account in the config via DirectAdmin.

    Intended for use prior to import when a clean mailbox is desired.
    """
    failed: Set[str] = set()
    per_domain = _accounts_by_domain(config)

    for domain, accounts in per_domain.items():
        _raise_if_stopped(stop_event, f"directadmin reset {domain}")
        if dry_run:
            try:
                existing_locals = set(client.list_pop_accounts(domain))
            except Exception as exc:
                logging.error("[da] Failed to list accounts for domain %s: %s", domain, exc)
                raise
            logging.info("[da][dry-run] Domain %s has %d existing mailbox(es)", domain, len(existing_locals))
        for acc in accounts:
            local = acc.email.split("@", 1)[0]
            if dry_run:
                logging.info("[da][dry-run] Would reset mailbox: %s (delete+create)", acc.email)
                continue
            _raise_if_stopped(stop_event, f"directadmin reset {acc.email}")
            try:
                client.delete_pop_account(domain, local)
                client.create_pop_account(domain, local, acc.password, quota_mb=quota_mb, allow_existing=False)
                logging.info("[da] Reset mailbox: %s", acc.email)
            except Exception as exc:
                failed.add(acc.email)
                logging.error("[da] Failed to reset %s: %s", acc.email, exc)
                if not ignore_errors:
                    raise
    return failed
