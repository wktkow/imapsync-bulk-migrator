from __future__ import annotations

import logging
from typing import Dict, List, Set

from .cpanel_client import CPanelClient
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
        raise ValueError("cPanel provisioning requires mailbox accounts in local@domain form: " + ", ".join(invalid))
    return per_domain


def ensure_accounts_exist_cpanel(
    config: Config,
    client: CPanelClient,
    *,
    dry_run: bool = False,
    ignore_errors: bool = False,
    quota_mb: int = 0,
) -> None:
    for domain, accounts in _accounts_by_domain(config).items():
        try:
            existing_locals = set(client.list_pop_accounts(domain))
        except Exception as exc:
            logging.error("[cpanel] Failed to list accounts for domain %s: %s", domain, exc)
            if dry_run or not ignore_errors:
                raise
            continue
        for acc in accounts:
            local = acc.email.split("@", 1)[0]
            if local in existing_locals:
                logging.info("[cpanel] Exists: %s", acc.email)
                continue
            if dry_run:
                logging.info("[cpanel][dry-run] Would create mailbox: %s", acc.email)
                continue
            try:
                client.create_pop_account(domain, local, acc.password, quota_mb=quota_mb)
                existing_locals.add(local)
                logging.info("[cpanel] Created mailbox: %s", acc.email)
            except Exception as exc:
                logging.error("[cpanel] Failed to create %s: %s", acc.email, exc)
                if not ignore_errors:
                    raise


def reset_accounts_cpanel(
    config: Config,
    client: CPanelClient,
    *,
    dry_run: bool = False,
    ignore_errors: bool = False,
    quota_mb: int = 0,
) -> Set[str]:
    failed: Set[str] = set()
    for domain, accounts in _accounts_by_domain(config).items():
        if dry_run:
            try:
                existing_locals = set(client.list_pop_accounts(domain))
            except Exception as exc:
                logging.error("[cpanel] Failed to list accounts for domain %s: %s", domain, exc)
                raise
            logging.info("[cpanel][dry-run] Domain %s has %d existing mailbox(es)", domain, len(existing_locals))
        for acc in accounts:
            local = acc.email.split("@", 1)[0]
            if dry_run:
                logging.info("[cpanel][dry-run] Would reset mailbox: %s (delete+create)", acc.email)
                continue
            try:
                client.delete_pop_account(domain, local)
                client.create_pop_account(domain, local, acc.password, quota_mb=quota_mb, allow_existing=False)
                logging.info("[cpanel] Reset mailbox: %s", acc.email)
            except Exception as exc:
                failed.add(acc.email)
                logging.error("[cpanel] Failed to reset %s: %s", acc.email, exc)
                if not ignore_errors:
                    raise
    return failed
