import logging
from typing import Dict, List

from .da_client import DirectAdminClient
from .models import Account, Config


def ensure_accounts_exist_directadmin(config: "Config", client: DirectAdminClient, *, dry_run: bool = False, ignore_errors: bool = False, quota_mb: int = 0) -> None:
    per_domain: Dict[str, List[Account]] = {}
    for acc in config.accounts:
        if "@" not in acc.email:
            logging.warning("[da] Skipping invalid email (no domain): %s", acc.email)
            continue
        local, domain = acc.email.split("@", 1)
        if not local or not domain:
            logging.warning("[da] Skipping invalid email: %s", acc.email)
            continue
        per_domain.setdefault(domain.lower(), []).append(acc)

    for domain, accounts in per_domain.items():
        try:
            existing_locals = set(client.list_pop_accounts(domain))
        except Exception as exc:
            logging.error("[da] Failed to list accounts for domain %s: %s", domain, exc)
            if not ignore_errors and not dry_run:
                raise
            else:
                continue
        for acc in accounts:
            local = acc.email.split("@", 1)[0]
            if local in existing_locals:
                logging.info("[da] Exists: %s", acc.email)
                continue
            if dry_run:
                logging.info("[da][dry-run] Would create mailbox: %s", acc.email)
                continue
            try:
                client.create_pop_account(domain, local, acc.password, quota_mb=quota_mb)
                existing_locals.add(local)
                logging.info("[da] Created mailbox: %s", acc.email)
            except Exception as exc:
                logging.error("[da] Failed to create %s: %s", acc.email, exc)
                if not ignore_errors:
                    raise


