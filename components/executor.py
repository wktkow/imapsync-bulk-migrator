from __future__ import annotations
import concurrent.futures
import logging
import queue
import threading
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
    error_messages: List[str] = []
    error_lock = threading.Lock()
    first_exc: BaseException | None = None

    def wrapped(acc: Account) -> None:
        nonlocal first_exc
        try:
            func(acc)
        except Exception as exc:
            logging.error("[%s] %s: FAILED: %s", label, acc.email, exc)
            message = f"{acc.email}: {exc}"
            errors.put(message)
            with error_lock:
                error_messages.append(message)
                if first_exc is None:
                    first_exc = exc
            if stop_on_error:
                raise

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=label) as ex:
        if stop_on_error:
            account_iter = iter(accounts)
            futures: dict[concurrent.futures.Future[None], Account] = {}

            def submit_next() -> None:
                try:
                    acc = next(account_iter)
                except StopIteration:
                    return
                futures[ex.submit(wrapped, acc)] = acc

            for _ in range(min(max_workers, len(accounts))):
                submit_next()

            while futures:
                done, _pending = concurrent.futures.wait(
                    futures,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                completed_successfully = 0
                should_stop = False
                for fut in done:
                    futures.pop(fut, None)
                    try:
                        fut.result()
                    except Exception as exc:
                        if first_exc is None:
                            first_exc = exc
                        should_stop = True
                    else:
                        completed_successfully += 1
                if not should_stop:
                    for _ in range(completed_successfully):
                        submit_next()
                if should_stop:
                    for pending in futures:
                        pending.cancel()
                    for fut in concurrent.futures.as_completed(list(futures)):
                        try:
                            fut.result()
                        except concurrent.futures.CancelledError:
                            pass
                        except Exception as exc:
                            if first_exc is None:
                                first_exc = exc
                    futures.clear()
        else:
            futures = [ex.submit(wrapped, acc) for acc in accounts]
            for fut in concurrent.futures.as_completed(futures):
                fut.result()

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
        if stop_on_error:
            raise first_exc
        raise RuntimeError(f"{label} failed for {len(error_messages)} account(s): " + "; ".join(error_messages))
