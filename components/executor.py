from __future__ import annotations
import concurrent.futures
import logging
import queue
import threading
from typing import Callable, List, Optional

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
    stop_event: Optional[object] = None,
) -> None:
    if max_workers < 1:
        raise ValueError("max_workers must be >= 1")
    errors: queue.Queue[str] = queue.Queue()
    error_messages: List[str] = []
    error_lock = threading.Lock()
    first_exc: BaseException | None = None

    def stop_requested() -> bool:
        is_set = getattr(stop_event, "is_set", None)
        return bool(is_set is not None and is_set())

    def stop_error() -> RuntimeError:
        return RuntimeError(f"{label}: stop requested before completion")

    def record_first_exc(exc: BaseException) -> None:
        nonlocal first_exc
        with error_lock:
            if first_exc is None:
                first_exc = exc

    def wrapped(acc: Account) -> None:
        nonlocal first_exc
        try:
            if stop_requested():
                raise stop_error()
            func(acc)
        except Exception as exc:
            logging.error("[%s] %s: FAILED: %s", label, acc.email, exc)
            message = f"{acc.email}: {exc}"
            errors.put(message)
            with error_lock:
                error_messages.append(message)
                if first_exc is None:
                    first_exc = exc
            if stop_on_error or stop_requested():
                raise

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=label) as ex:
        account_iter = iter(accounts)
        futures: dict[concurrent.futures.Future[None], Account] = {}

        def submit_next() -> bool:
            if stop_requested():
                return False
            try:
                acc = next(account_iter)
            except StopIteration:
                return False
            futures[ex.submit(wrapped, acc)] = acc
            return True

        def cancel_and_drain_pending() -> None:
            for pending in futures:
                pending.cancel()
            for fut in concurrent.futures.as_completed(list(futures)):
                try:
                    fut.result()
                except concurrent.futures.CancelledError:
                    pass
                except Exception as exc:
                    record_first_exc(exc)
            futures.clear()

        for _ in range(min(max_workers, len(accounts))):
            submit_next()

        wait_timeout = 0.2 if stop_event is not None else None
        while futures:
            if stop_requested():
                record_first_exc(stop_error())
                cancel_and_drain_pending()
                break
            done, _pending = concurrent.futures.wait(
                futures,
                timeout=wait_timeout,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                continue
            completed_successfully = 0
            should_stop = False
            for fut in done:
                futures.pop(fut, None)
                try:
                    fut.result()
                except Exception as exc:
                    record_first_exc(exc)
                    should_stop = True
                else:
                    completed_successfully += 1
            if should_stop or stop_requested():
                if stop_requested():
                    record_first_exc(stop_error())
                cancel_and_drain_pending()
                break
            for _ in range(completed_successfully):
                submit_next()

    if stop_requested():
        record_first_exc(stop_error())

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
        if stop_on_error or stop_requested():
            raise first_exc
        raise RuntimeError(f"{label} failed for {len(error_messages)} account(s): " + "; ".join(error_messages))
