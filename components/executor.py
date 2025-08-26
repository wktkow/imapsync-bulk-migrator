import concurrent.futures
import logging
import queue
from typing import List

from .models import Account


"""Simple thread-pool executor for per-account functions.

Each account is processed once by `func`. Errors are collected and either
stop the pool immediately (stop_on_error=True) or are summarized at the end.
"""


def parallel_process_accounts(
    label: str,
    func,
    accounts: List[Account],
    max_workers: int,
    stop_on_error: bool,
) -> None:
    errors: queue.Queue[str] = queue.Queue()

    def wrapped(acc: Account) -> None:
        try:
            func(acc)
        except Exception as exc:
            logging.error("[%s] %s: FAILED: %s", label, acc.email, exc)
            errors.put(f"{acc.email}: {exc}")
            if stop_on_error:
                raise

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=label) as ex:
        futures = [ex.submit(wrapped, acc) for acc in accounts]
        for fut in concurrent.futures.as_completed(futures):
            fut.result()

    if not errors.empty() and not stop_on_error:
        count = errors.qsize()
        logging.warning("[%s] Completed with errors (%d accounts). Details follow:", label, count)
        # Drain the queue for operator visibility
        while not errors.empty():
            try:
                logging.warning("[%s] %s", label, errors.get_nowait())
            except Exception:
                break


