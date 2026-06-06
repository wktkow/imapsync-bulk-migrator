from __future__ import annotations

import logging
from typing import Dict, List, Set

from .cpanel_client import CPanelClient
from .models import Account, Config


def _accounts_by_domain(config: Config) -> Dict[str, List[Account]]:
    per_domain: Dict[str, List[Account]] = {}
    for acc in config.accounts:
        if "@" not in acc.email:
            logging.warning("[cpanel] Skipping invalid email (no domain): %s", acc.email)
            continue
        local, domain = acc.email.split("@", 1)
        if not local or not domain:
            logging.warning("[cpanel] Skipping invalid email: %s", acc.email)
            continue
        per_domain.setdefault(domain.lower(), []).append(acc)
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
            if not ignore_errors and not dry_run:
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
