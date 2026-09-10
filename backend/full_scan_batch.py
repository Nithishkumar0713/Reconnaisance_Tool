"""
full_scan_batch.py — Runs a full Standard/Deep scan (the same run_scan() a
single-target scan uses) across a user-submitted list of up to 20 targets.

Structurally mirrors batch_scanner.py's BatchScanner/start_batch_scan (DB
row per batch + per-target row, semaphore-bounded concurrency, background
asyncio.Task, progress persisted so it can be polled) but is a separate,
independent code path — this never touches batch_scanner.py, its DB tables,
or its is_batch=True subdomain-batch semantics.

Each target here runs with is_batch=False — a completely normal, full
Standard or Deep scan, identical in module set to a single-target scan.
Cross-target safety comes from two places instead: the concurrency
semaphore below (bounds how many targets' full scans run at once), and the
module-level rate limiters inside reputation.py/email_gather.py themselves
(bound how fast/how many concurrent calls those specific external-API-heavy
modules make, regardless of how many targets are "running" at once).
"""

import asyncio
import json
import logging
from contextlib import contextmanager
from datetime import datetime
from typing import Any

from main import run_scan
from models import FullScanBatch, FullScanBatchTarget, ScanHistory
from database import SessionLocal

logger = logging.getLogger(__name__)

# Lower than module_batch.py's MAX_MODULE_BATCH_TARGETS (20) — each target
# here runs a full Standard/Deep scan (port scan, directory enum, subdomain
# enum, email gather, etc.), not one lightweight module check, so the same
# 20-target ceiling would mean a much heavier aggregate workload.
MAX_FULL_SCAN_BATCH_TARGETS = 10

# Deep mode runs port scans, directory enumeration, subdomain CLI tools, and
# hits several rate-limited external APIs per target — a low concurrency
# cap keeps aggregate resource usage and API load sane. Standard mode is all
# passive checks (no subprocess spawning, no rate-limited APIs), so it can
# afford noticeably more concurrent targets.
DEFAULT_CONCURRENCY = {"fast": 6, "standard": 6, "deep": 3, "detailed": 3}
MAX_CONCURRENCY = {"fast": 8, "standard": 8, "deep": 5, "detailed": 5}

# Each target scan already has its own internal per-module timeout/error
# isolation (_safe_module/with_timeout on every sub-module inside run_scan),
# so a whole-target retry here is a smaller safety net for transient
# whole-scan failures (e.g. a network blip), not the primary error handler —
# unlike batch_scanner.py's subdomain path, one retry is enough.
DEFAULT_MAX_RETRIES = 1
PER_TARGET_TIMEOUT_SECONDS = {"fast": 90, "standard": 90, "deep": 240, "detailed": 240}


@contextmanager
def get_db_session():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        try:
            db.close()
        except Exception as e:
            logger.error(f"[DB] Error closing session: {e}")


class FullScanBatchRunner:
    def __init__(
        self,
        batch_id: int,
        targets: list[str],
        mode: str,
        user_id: int,
        include_reputation: bool = True,
        max_concurrent: int | None = None,
        abuseipdb_api_key: str | None = None,
        virustotal_api_key: str | None = None,
    ):
        self.batch_id = batch_id
        self.targets = targets
        self.mode = mode
        self.user_id = user_id
        self.include_reputation = include_reputation

        mode_key = mode if mode in DEFAULT_CONCURRENCY else "deep"
        if max_concurrent is None:
            max_concurrent = DEFAULT_CONCURRENCY[mode_key]
        else:
            max_concurrent = max(1, min(max_concurrent, MAX_CONCURRENCY[mode_key]))
        self.max_concurrent = max_concurrent
        self.per_target_timeout = PER_TARGET_TIMEOUT_SECONDS[mode_key]

        self.abuseipdb_api_key = abuseipdb_api_key
        self.virustotal_api_key = virustotal_api_key
        self.semaphore: asyncio.Semaphore | None = None
        self.completed = 0
        self.failed = 0

    async def _init_async_resources(self):
        if self.semaphore is None:
            self.semaphore = asyncio.Semaphore(self.max_concurrent)

    async def _update_target_status(
        self,
        target: str,
        status: str,
        result_json: str | None = None,
        error_message: str | None = None,
        completed_at: bool = False,
    ) -> None:
        def _db_update():
            try:
                with get_db_session() as db:
                    row = db.query(FullScanBatchTarget).filter(
                        FullScanBatchTarget.batch_id == self.batch_id,
                        FullScanBatchTarget.target == target,
                    ).first()
                    if row:
                        row.status = status
                        if result_json is not None:
                            row.result_json = result_json
                        if error_message is not None:
                            row.error_message = error_message
                        if completed_at:
                            row.completed_at = datetime.utcnow()
                        if status == "running" and row.started_at is None:
                            row.started_at = datetime.utcnow()
                        db.commit()
            except Exception as e:
                logger.error(f"[FULL-BATCH-{self.batch_id}] Failed to update status for {target}: {e}")

        loop = asyncio.get_event_loop()
        try:
            await asyncio.wait_for(loop.run_in_executor(None, _db_update), timeout=10.0)
        except asyncio.TimeoutError:
            logger.error(f"[FULL-BATCH-{self.batch_id}] DB update timeout for {target}")
        except Exception as e:
            logger.error(f"[FULL-BATCH-{self.batch_id}] Error updating target status: {e}")

    async def _record_scan_history(self, target: str, result: dict[str, Any]) -> None:
        """Writes a ScanHistory row for a completed target, same table/shape
        the single-target /scan endpoint writes to. Without this, a
        full-scan-batch's results never show up in the user's scan
        history — this orchestrator calls run_scan() directly as a
        function, bypassing /scan and its history write entirely."""
        def _db_write():
            try:
                with get_db_session() as db:
                    db.add(ScanHistory(
                        user_id=self.user_id,
                        target=target,
                        mode=self.mode,
                        module=None,
                        result_json=json.dumps(result),
                    ))
                    db.commit()
            except Exception as e:
                logger.error(f"[FULL-BATCH-{self.batch_id}] Failed to write scan history for {target}: {e}")

        loop = asyncio.get_event_loop()
        try:
            await asyncio.wait_for(loop.run_in_executor(None, _db_write), timeout=10.0)
        except Exception as e:
            logger.error(f"[FULL-BATCH-{self.batch_id}] Scan history write error for {target}: {e}")

    async def _scan_one_with_retry(self, target: str) -> dict[str, Any]:
        last_error = None
        attempts = DEFAULT_MAX_RETRIES + 1

        for attempt in range(1, attempts + 1):
            try:
                await self._update_target_status(target, "running")

                adjusted_timeout = self.per_target_timeout + (attempt - 1) * 30
                result = await asyncio.wait_for(
                    run_scan(
                        target=target,
                        mode=self.mode,
                        include_reputation=self.include_reputation,
                        module=None,
                        port_range=None,
                        abuseipdb_api_key=self.abuseipdb_api_key,
                        virustotal_api_key=self.virustotal_api_key,
                        is_batch=False,
                    ),
                    timeout=adjusted_timeout,
                )

                await self._update_target_status(
                    target, "completed", result_json=json.dumps(result), completed_at=True
                )
                await self._record_scan_history(target, result)
                self.completed += 1
                return {"success": True, "target": target, "attempt": attempt}

            except asyncio.TimeoutError:
                last_error = f"Scan exceeded {adjusted_timeout}s on attempt {attempt}/{attempts}"
                if attempt < attempts:
                    await asyncio.sleep(2 ** attempt)
                    continue
                self.failed += 1
                await self._update_target_status(target, "timeout", error_message=last_error, completed_at=True)
                return {"success": False, "target": target, "error": "timeout"}

            except Exception as e:
                last_error = f"{type(e).__name__}: {str(e)[:150]}"
                if attempt < attempts:
                    await asyncio.sleep(2 ** attempt)
                    continue
                self.failed += 1
                await self._update_target_status(target, "failed", error_message=last_error, completed_at=True)
                return {"success": False, "target": target, "error": last_error}

        self.failed += 1
        await self._update_target_status(target, "failed", error_message=last_error or "Unknown error", completed_at=True)
        return {"success": False, "target": target, "error": last_error or "Unknown error"}

    async def _scan_with_limit(self, target: str) -> dict[str, Any]:
        async with self.semaphore:
            return await self._scan_one_with_retry(target)

    async def run(self) -> dict[str, Any]:
        await self._init_async_resources()

        def _init_rows():
            with get_db_session() as db:
                batch = db.query(FullScanBatch).filter(FullScanBatch.id == self.batch_id).first()
                if batch:
                    batch.status = "running"
                    batch.started_at = datetime.utcnow()
                    db.commit()
                for target in self.targets:
                    existing = db.query(FullScanBatchTarget).filter(
                        FullScanBatchTarget.batch_id == self.batch_id,
                        FullScanBatchTarget.target == target,
                    ).first()
                    if not existing:
                        db.add(FullScanBatchTarget(batch_id=self.batch_id, target=target, status="pending"))
                db.commit()

        loop = asyncio.get_event_loop()
        await asyncio.wait_for(loop.run_in_executor(None, _init_rows), timeout=30.0)

        results = await asyncio.gather(*[self._scan_with_limit(t) for t in self.targets], return_exceptions=True)

        def _finalize():
            with get_db_session() as db:
                batch = db.query(FullScanBatch).filter(FullScanBatch.id == self.batch_id).first()
                if batch:
                    if batch.status != "cancelled":
                        batch.status = "completed"
                    batch.completed_scans = self.completed
                    batch.failed_scans = self.failed
                    batch.total_targets = len(self.targets)
                    batch.completed_at = datetime.utcnow()
                    db.commit()

        await asyncio.wait_for(loop.run_in_executor(None, _finalize), timeout=30.0)

        return {
            "batch_id": self.batch_id,
            "total": len(self.targets),
            "completed": self.completed,
            "failed": self.failed,
            "results": results,
        }


async def start_full_scan_batch(
    batch_id: int,
    targets: list[str],
    mode: str,
    user_id: int,
    include_reputation: bool = True,
    max_concurrent: int | None = None,
    abuseipdb_api_key: str | None = None,
    virustotal_api_key: str | None = None,
) -> dict[str, Any]:
    """Entry point run as a background asyncio.Task from main.py."""
    try:
        runner = FullScanBatchRunner(
            batch_id=batch_id,
            targets=targets,
            mode=mode,
            user_id=user_id,
            include_reputation=include_reputation,
            max_concurrent=max_concurrent,
            abuseipdb_api_key=abuseipdb_api_key,
            virustotal_api_key=virustotal_api_key,
        )
        return await runner.run()
    except asyncio.CancelledError:
        logger.info(f"[FULL-BATCH-{batch_id}] Cancelled by user")

        def _mark_cancelled():
            with get_db_session() as db:
                db.query(FullScanBatchTarget).filter(
                    FullScanBatchTarget.batch_id == batch_id,
                    FullScanBatchTarget.status.in_(["pending", "running"]),
                ).update({"status": "cancelled"}, synchronize_session=False)
                batch = db.query(FullScanBatch).filter(FullScanBatch.id == batch_id).first()
                if batch:
                    batch.status = "cancelled"
                    batch.completed_at = datetime.utcnow()
                db.commit()

        try:
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, _mark_cancelled)
        except Exception:
            pass
        raise
    except Exception as e:
        logger.error(f"[FULL-BATCH-{batch_id}] Unexpected error: {type(e).__name__}: {e}", exc_info=True)

        def _mark_failed():
            with get_db_session() as db:
                batch = db.query(FullScanBatch).filter(FullScanBatch.id == batch_id).first()
                if batch:
                    batch.status = "failed"
                    batch.completed_at = datetime.utcnow()
                db.commit()

        try:
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, _mark_failed)
        except Exception:
            pass
        raise
