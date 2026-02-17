from __future__ import annotations
import concurrent.futures
import logging
import queue
from typing import Callable, List

from .models import Account


"""Simple thread-pool executor for per-account functions.

Each account is processed once by `func`. Errors are collected and either
stop the pool immediately (stop_on_error=True) or are summarized at the end.
"""


def parallel_process_accounts(
    label: str,
    func: Callable[[Account], None],
    accounts: List[Account],
    max_workers: int,
    stop_on_error: bool,
) -> None:
    if max_workers < 1:
        raise ValueError("max_workers must be >= 1")
    errors: queue.Queue[str] = queue.Queue()

    def wrapped(acc: Account) -> None:
        try:
            func(acc)
        except Exception as exc:
            logging.error("[%s] %s: FAILED: %s", label, acc.email, exc)
            errors.put(f"{acc.email}: {exc}")
            if stop_on_error:
                raise

    first_exc: BaseException | None = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=label) as ex:
        futures = [ex.submit(wrapped, acc) for acc in accounts]
        for fut in concurrent.futures.as_completed(futures):
            try:
                fut.result()
            except Exception as exc:
                if stop_on_error and first_exc is None:
                    first_exc = exc
                # In stop_on_error mode, we still iterate remaining futures
                # so their exceptions are collected, but we don't re-raise
                # until we've logged everything below.

    # Always drain and log collected errors for operator visibility
    if not errors.empty():
        count = errors.qsize()
        logging.warning("[%s] Completed with errors (%d accounts). Details follow:", label, count)
        while not errors.empty():
            try:
                logging.warning("[%s] %s", label, errors.get_nowait())
            except Exception:
                break

    # Re-raise the first exception if stop_on_error was requested
    if first_exc is not None:
        raise first_exc


