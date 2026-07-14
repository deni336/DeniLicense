from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass
from urllib.parse import quote

import httpx

logger = logging.getLogger("denilicense.email")


@dataclass(frozen=True, slots=True)
class EmailJob:
    kind: str
    recipient: str
    token: str
    request_id: str


class EmailSender:
    def __init__(self, webhook_url: str, bearer: str, public_url: str) -> None:
        self._webhook_url = webhook_url
        self._bearer = bearer
        self._public_url = public_url.rstrip("/")
        self._jobs: queue.Queue[EmailJob | None] = queue.Queue(maxsize=256)
        self._threads: list[threading.Thread] = []
        self._client = httpx.Client(timeout=10, follow_redirects=False)
        if self.configured:
            for index in range(2):
                worker = threading.Thread(target=self._run, name=f"denilicense-email-{index}", daemon=True)
                worker.start()
                self._threads.append(worker)

    @property
    def configured(self) -> bool:
        return bool(self._webhook_url)

    def enqueue(self, job: EmailJob) -> bool:
        if not self.configured or job.kind not in {"verification", "password_reset"}:
            return False
        try:
            self._jobs.put_nowait(job)
        except queue.Full:
            logger.warning(
                "email delivery queue full", extra={"request_id": job.request_id, "kind": job.kind}
            )
            return False
        return True

    def _deliver(self, job: EmailJob) -> None:
        if job.kind == "verification":
            template, path = "denilicense-email-verification", "/verify-email?token="
        else:
            template, path = "denilicense-password-reset", "/reset-password?token="
        payload = {
            "template": template,
            "recipient": job.recipient,
            "actionUrl": self._public_url + path + quote(job.token, safe=""),
        }
        response = self._client.post(
            self._webhook_url,
            json=payload,
            headers={"Authorization": f"Bearer {self._bearer}", "User-Agent": "DeniLicense/1"},
        )
        response.raise_for_status()

    def _run(self) -> None:
        while True:
            job = self._jobs.get()
            try:
                if job is None:
                    return
                last_error: Exception | None = None
                for attempt in range(3):
                    try:
                        self._deliver(job)
                        last_error = None
                        break
                    except (httpx.HTTPError, ValueError) as exc:
                        last_error = exc
                        if attempt < 2:
                            time.sleep(0.5 * (2**attempt))
                if last_error is not None:
                    logger.warning(
                        "email delivery failed",
                        extra={"request_id": job.request_id, "kind": job.kind, "error": str(last_error)},
                    )
            finally:
                self._jobs.task_done()

    def close(self, timeout: float = 15) -> bool:
        if not self._threads:
            self._client.close()
            return True
        deadline = time.monotonic() + timeout
        while self._jobs.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)
        drained = self._jobs.unfinished_tasks == 0
        for _ in self._threads:
            try:
                self._jobs.put_nowait(None)
            except queue.Full:
                drained = False
                break
        for thread in self._threads:
            thread.join(max(0, deadline - time.monotonic()))
        self._client.close()
        return drained and all(not thread.is_alive() for thread in self._threads)
