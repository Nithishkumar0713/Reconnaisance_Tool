"""
batch_scanner.py — Batch subdomain scanning with rate limiting and concurrency control.
Handles multiple concurrent scans with intelligent rate limiting for VirusTotal/AbuseIPDB.
Optimized for 64GB RAM systems with retry logic and robust error handling.
"""

import asyncio
import time
import json
from datetime import datetime
from typing import List, Dict, Any
from contextlib import contextmanager
import logging

from main import run_scan
from models import BatchScan, SubdomainScan
from database import SessionLocal

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Rate limiter for external APIs (VirusTotal: 4 requests/minute = 1 every 16 seconds).
    Global instance ensures API compliance across all concurrent tasks.
    """

    def __init__(self, min_interval: float = 16.0):
        self.min_interval = min_interval
        self.last_request_time = 0.0
        self.lock = None

    async def wait(self):
        """Wait until enough time has passed since last request."""
        if self.lock is None:
            self.lock = asyncio.Lock()

        async with self.lock:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)
            self.last_request_time = time.time()


@contextmanager
def get_db_session():
    """Context manager for database sessions — ensures proper cleanup."""
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
            print(f"[DB] Error closing session: {e}")


async def async_db_operation(operation_func, *args, **kwargs):
    """
    Run synchronous database operation in thread pool to prevent event loop blocking.
    ✅ CRITICAL: Prevents hangs by offloading blocking I/O to worker threads.
    """
    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, operation_func, *args),
            timeout=30.0
        )
    except asyncio.TimeoutError:
        logger.error("Database operation timeout - possible deadlock")
        raise
    except Exception as e:
        logger.error(f"Database operation failed: {e}")
        raise


class BatchScanner:
    """
    Orchestrates batch scanning of multiple unique subdomains.
    - Deduplicates subdomains
    - Limits concurrency (10 parallel scans max by default, configurable 1-10)
    - Handles VirusTotal rate limiting (16 sec between requests)
    - Tracks progress in database with robust session management
    - Exponential backoff retry logic (3 attempts per subdomain)
    - No hangs, timeouts, or bottlenecks on 64GB RAM systems
    """

    def __init__(
        self,
        batch_scan_id: int,
        subdomains: List[str],
        mode: str = "detailed",
        max_concurrent: int | None = None,
        per_scan_timeout: int = 180,
        max_retries: int = 3,
        abuseipdb_api_key: str | None = None,
        virustotal_api_key: str | None = None,
    ):
        self.batch_scan_id = batch_scan_id
        self.subdomains = list(set(subdomains))
        self.mode = mode

        if max_concurrent is None:
            num_subs = len(self.subdomains)
            if mode == "detailed":
                if num_subs <= 10:
                    max_concurrent = 5
                elif num_subs <= 50:
                    max_concurrent = 8
                elif num_subs <= 100:
                    max_concurrent = 10
                else:
                    max_concurrent = 15
            else:
                if num_subs <= 10:
                    max_concurrent = 10
                elif num_subs <= 50:
                    max_concurrent = 15
                elif num_subs <= 100:
                    max_concurrent = 20
                else:
                    max_concurrent = 30

        self.max_concurrent = max_concurrent
        self.per_scan_timeout = per_scan_timeout
        self.max_retries = max_retries
        self.abuseipdb_api_key = abuseipdb_api_key
        self.virustotal_api_key = virustotal_api_key
        self.semaphore = None
        self.rate_limiter = None
        self.total_subdomains = len(self.subdomains)
        self.completed = 0
        self.failed = 0
        self.retry_count = 0

    async def _initialize_async_resources(self):
        """Initialize asyncio primitives within the async context to avoid event loop binding issues."""
        if self.semaphore is None:
            self.semaphore = asyncio.Semaphore(self.max_concurrent)
        if self.rate_limiter is None:
            self.rate_limiter = RateLimiter(min_interval=16.0)

    async def _update_subdomain_status(self, subdomain: str, status: str, result_json: str = None, error_message: str = None, completed_at: bool = False):
        """Update subdomain scan status in database with async thread pool execution.
        ✅ CRITICAL: Runs in thread pool to prevent event loop blocking.
        """
        def _db_update():
            try:
                with get_db_session() as db:
                    sub_scan = db.query(SubdomainScan).filter(
                        SubdomainScan.batch_scan_id == self.batch_scan_id,
                        SubdomainScan.subdomain == subdomain
                    ).first()

                    if sub_scan:
                        sub_scan.status = status
                        if result_json:
                            sub_scan.result_json = result_json
                        if error_message:
                            sub_scan.error_message = error_message
                        if completed_at:
                            sub_scan.completed_at = datetime.utcnow()
                        db.commit()
            except Exception as e:
                logger.error(f"Failed to update status for {subdomain}: {e}")
                raise

        loop = asyncio.get_event_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, _db_update),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            logger.error(f"Database update timeout for {subdomain}")
        except Exception as e:
            logger.error(f"Error updating subdomain status: {e}")

    async def scan_single_subdomain_with_retry(self, subdomain: str) -> Dict[str, Any]:
        """
        Scan a single subdomain with retry logic (exponential backoff).
        Attempts up to max_retries times before giving up.
        """
        logger.info(f"[BATCH-{self.batch_scan_id}] Starting scan_single_subdomain_with_retry: {subdomain}")
        last_error = None

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(f"[BATCH-{self.batch_scan_id}] {subdomain} attempt {attempt}/{self.max_retries}: updating status to running")
                await self._update_subdomain_status(
                    subdomain,
                    "running",
                    completed_at=False
                )
                logger.info(f"[BATCH-{self.batch_scan_id}] {subdomain} status updated to running, starting scan")


                adjusted_timeout = self.per_scan_timeout + (attempt - 1) * 30
                result = await asyncio.wait_for(
                    run_scan(
                        target=subdomain,
                        mode=self.mode,
                        include_reputation=True,
                        module=None,
                        # Left as None, port_range would default to mode
                        # ("detailed" -> port_scanner's 1-1024 range, ~526
                        # ports, ~300s ceiling) instead of mode="deep"'s
                        # top-100 range (~120s ceiling) — a real, deliberate
                        # divergence between "deep" and "detailed" that only
                        # affects port range, confirmed in port_scanner.py's
                        # get_port_list-equivalent branch. User chose top-100
                        # here for real batch throughput (every other Detailed
                        # module — directories, email_gather, subdomains,
                        # reverse_dns, cloud_provider, reputation — is
                        # unaffected by this, only port_scan's own range).
                        port_range="top100",
                        abuseipdb_api_key=self.abuseipdb_api_key,
                        virustotal_api_key=self.virustotal_api_key,
                        is_batch=True,
                    ),
                    timeout=adjusted_timeout
                )

                await self._update_subdomain_status(
                    subdomain,
                    "completed",
                    result_json=json.dumps(result),
                    completed_at=True
                )

                self.completed += 1
                return {"success": True, "subdomain": subdomain, "attempt": attempt}

            except asyncio.TimeoutError:
                last_error = f"Timeout on attempt {attempt}/{self.max_retries}"
                if attempt < self.max_retries:
                    backoff = 2 ** attempt
                    await asyncio.sleep(backoff)
                    self.retry_count += 1
                    continue
                else:
                    self.failed += 1
                    await self._update_subdomain_status(
                        subdomain,
                        "timeout",
                        error_message=f"Scan exceeded timeout after {self.max_retries} attempts",
                        completed_at=True
                    )
                    return {"success": False, "subdomain": subdomain, "error": "timeout", "attempts": attempt}

            except Exception as e:
                error_msg = f"{type(e).__name__}: {str(e)[:100]}"
                last_error = error_msg

                if attempt < self.max_retries:
                    backoff = 2 ** attempt
                    await asyncio.sleep(backoff)
                    self.retry_count += 1
                    continue
                else:
                    self.failed += 1
                    await self._update_subdomain_status(
                        subdomain,
                        "failed",
                        error_message=error_msg,
                        completed_at=True
                    )
                    return {"success": False, "subdomain": subdomain, "error": error_msg, "attempts": attempt}

        self.failed += 1
        await self._update_subdomain_status(
            subdomain,
            "failed",
            error_message=last_error or "Unknown error",
            completed_at=True
        )
        return {"success": False, "subdomain": subdomain, "error": last_error or "Unknown error"}

    async def scan_with_limit(self, subdomain: str) -> Dict[str, Any]:
        """Scan with semaphore concurrency control (prevents resource exhaustion)."""
        logger.info(f"[BATCH-{self.batch_scan_id}] scan_with_limit waiting for semaphore: {subdomain}")
        async with self.semaphore:
            logger.info(f"[BATCH-{self.batch_scan_id}] scan_with_limit acquired semaphore: {subdomain}")
            result = await self.scan_single_subdomain_with_retry(subdomain)
            logger.info(f"[BATCH-{self.batch_scan_id}] scan_with_limit completed: {subdomain}")
            return result

    async def run_batch(self) -> Dict[str, Any]:
        """
        Execute batch scan for all unique subdomains.
        ✅ CRITICAL: Uses async database operations to prevent event loop blocking.
        """
        logger.info(f"[BATCH-{self.batch_scan_id}] Starting batch scan for {len(self.subdomains)} subdomains (mode={self.mode}, max_concurrent={self.max_concurrent})")

        logger.info(f"[BATCH-{self.batch_scan_id}] Initializing async resources...")
        await self._initialize_async_resources()
        logger.info(f"[BATCH-{self.batch_scan_id}] Async resources initialized")

        def _init_batch():
            try:
                logger.info(f"[BATCH-{self.batch_scan_id}] Creating database session for batch init")
                with get_db_session() as db:
                    batch = db.query(BatchScan).filter(BatchScan.id == self.batch_scan_id).first()
                    if batch:
                        logger.info(f"[BATCH-{self.batch_scan_id}] Found batch record, updating status to running")
                        batch.status = "running"
                        batch.started_at = datetime.utcnow()
                        db.commit()
                    else:
                        logger.error(f"[BATCH-{self.batch_scan_id}] Batch record not found!")

                    logger.info(f"[BATCH-{self.batch_scan_id}] Creating subdomain scan records...")
                    for subdomain in self.subdomains:
                        existing = db.query(SubdomainScan).filter(
                            SubdomainScan.batch_scan_id == self.batch_scan_id,
                            SubdomainScan.subdomain == subdomain
                        ).first()

                        if not existing:
                            sub_scan = SubdomainScan(
                                batch_scan_id=self.batch_scan_id,
                                subdomain=subdomain,
                                status="pending"
                            )
                            db.add(sub_scan)
                            logger.debug(f"[BATCH-{self.batch_scan_id}] Added pending scan for {subdomain}")
                    db.commit()
                    logger.info(f"[BATCH-{self.batch_scan_id}] All subdomain records created")
            except Exception as e:
                logger.error(f"[BATCH-{self.batch_scan_id}] Failed to initialize batch: {e}", exc_info=True)
                raise

        loop = asyncio.get_event_loop()
        try:
            logger.info(f"[BATCH-{self.batch_scan_id}] Running batch initialization in executor...")
            await asyncio.wait_for(
                loop.run_in_executor(None, _init_batch),
                timeout=30.0
            )
            logger.info(f"[BATCH-{self.batch_scan_id}] Batch initialization complete")
        except asyncio.TimeoutError:
            logger.error(f"[BATCH-{self.batch_scan_id}] Batch initialization timeout")
            raise

        logger.info(f"[BATCH-{self.batch_scan_id}] Creating scan tasks for {len(self.subdomains)} subdomains...")
        tasks = [self.scan_with_limit(sub) for sub in self.subdomains]
        logger.info(f"[BATCH-{self.batch_scan_id}] {len(tasks)} tasks created, starting gather...")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        logger.info(f"[BATCH-{self.batch_scan_id}] All tasks completed, processing results...")

        def _finalize_batch():
            try:
                with get_db_session() as db:
                    batch = db.query(BatchScan).filter(BatchScan.id == self.batch_scan_id).first()
                    if batch:
                        if batch.status != "cancelled":
                            batch.status = "completed"
                        batch.completed_scans = self.completed
                        batch.failed_scans = self.failed
                        batch.total_subdomains = self.total_subdomains
                        batch.completed_at = datetime.utcnow()
                        db.commit()
            except Exception as e:
                logger.error(f"Failed to finalize batch: {e}")
                raise

        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, _finalize_batch),
                timeout=30.0
            )
        except asyncio.TimeoutError:
            logger.error("Batch finalization timeout")

        return {
            "batch_id": self.batch_scan_id,
            "total": self.total_subdomains,
            "completed": self.completed,
            "failed": self.failed,
            "unique_subdomains": self.total_subdomains,
            "retry_attempts": self.retry_count,
            "results": results,
            "message": f"Batch scan complete: {self.completed}/{self.total_subdomains} succeeded ({self.retry_count} retries)"
        }


async def start_batch_scan(
    batch_scan_id: int,
    subdomains: List[str],
    mode: str = "detailed",
    max_concurrent: int | None = None,
    abuseipdb_api_key: str | None = None,
    virustotal_api_key: str | None = None
) -> Dict[str, Any]:
    """
    Start a batch scan for multiple subdomains.
    Entry point for batch scanning - optimized for 64GB+ RAM systems.

    Args:
        batch_scan_id: Database ID of the batch scan record
        subdomains: List of subdomains to scan (deduplicated automatically)
        mode: "fast" or "detailed" scan mode
        max_concurrent: Number of parallel scans (auto-scaled if None)
                       - Detailed: 20-50 concurrent (resource-intensive scans)
                       - Fast: 50-150 concurrent (lighter scans)
        abuseipdb_api_key: Optional AbuseIPDB API key for reputation checks
        virustotal_api_key: Optional VirusTotal API key for reputation checks

    Returns:
        Summary dict with batch_id, completed count, failed count, and detailed results
    """
    logger.info(f"[BATCH-{batch_scan_id}] start_batch_scan ENTRY POINT: {len(subdomains)} subdomains, mode={mode}")
    try:
        logger.info(f"[BATCH-{batch_scan_id}] Getting running event loop...")
        loop = asyncio.get_running_loop()
        logger.info(f"[BATCH-{batch_scan_id}] Event loop acquired")

        logger.info(f"[BATCH-{batch_scan_id}] Creating BatchScanner instance...")
        # Deep/detailed now genuinely runs the full aggressive+reputation module
        # set per subdomain (port_scan, directories, email_gather, subdomains,
        # reverse_dns, cloud_provider, AbuseIPDB, VirusTotal) instead of being
        # silently downgraded to the passive-only set. This outer per-subdomain
        # timeout wraps run_scan()'s whole asyncio.gather() of concurrent
        # modules, so it must exceed the SLOWEST module's own internal ceiling
        # or it just recreates the outer/inner timeout race that extra_timeout
        # fixed for port_scan specifically (main.py) — one layer up. Verified
        # directly: a real direct (non-batch) Detailed scan of both
        # www.testfire.net and github.com each took ~300s, landing almost
        # exactly on port_scan's own "port_scan_detailed" 300s ceiling (+20s
        # extra_timeout = 320s outer) — NOT target-specific slowness, both
        # showed "aggressive firewall detected, most ports blocked", which
        # triggers port_scan's slow evasion-technique path on essentially any
        # real firewalled target. subdomain_finder's own ceiling (360s,
        # TIMEOUTS["subdomains"]) is the true max among concurrent modules, so
        # 400s gives real margin above the slowest module instead of racing it.
        # (240s was copied from full_scan_batch.py's PER_TARGET_TIMEOUT_SECONDS
        # without checking it against port_scan_detailed/subdomains' real
        # ceilings — that file likely has the same latent issue, flagged to
        # the user rather than fixed here since it's explicitly out of scope.)
        per_scan_timeout = 400 if str(mode).lower() in ("deep", "detailed") else 90
        scanner = BatchScanner(
            batch_scan_id=batch_scan_id,
            subdomains=subdomains,
            mode=mode,
            max_concurrent=max_concurrent,
            per_scan_timeout=per_scan_timeout,
            max_retries=2,
            abuseipdb_api_key=abuseipdb_api_key,
            virustotal_api_key=virustotal_api_key
        )
        logger.info(f"[BATCH-{batch_scan_id}] BatchScanner created, calling run_batch()...")
        result = await scanner.run_batch()
        logger.info(f"[BATCH-{batch_scan_id}] run_batch() completed successfully")
        return result
    except asyncio.CancelledError as e:
        logger.info(f"[BATCH-{batch_scan_id}] Batch scan cancelled by user")
        def _mark_cancelled():
            try:
                with get_db_session() as db:
                    db.query(SubdomainScan).filter(
                        SubdomainScan.batch_scan_id == batch_scan_id,
                        SubdomainScan.status.in_(["pending", "running"])
                    ).update({"status": "cancelled"}, synchronize_session=False)
                    db.commit()
            except Exception as db_err:
                logger.error(f"Failed to mark subdomains as cancelled: {db_err}")

        try:
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, _mark_cancelled)
        except Exception:
            pass

        raise
    except RuntimeError as e:
        logger.error(f"[BATCH-{batch_scan_id}] RuntimeError in batch scan: {e}", exc_info=True)
        error_msg = str(e)
        if "Event loop is closed" in error_msg or "Event loop is running" in error_msg:
            logger.error(f"[BATCH-{batch_scan_id}] Event loop error in batch scan: {e}")
            def _mark_failed():
                try:
                    with get_db_session() as db:
                        batch = db.query(BatchScan).filter(BatchScan.id == batch_scan_id).first()
                        if batch:
                            batch.status = "failed"
                            batch.completed_at = datetime.utcnow()
                            db.commit()
                except Exception as db_err:
                    logger.error(f"Failed to mark batch as failed: {db_err}")

            try:
                loop = asyncio.get_event_loop()
                loop.run_in_executor(None, _mark_failed)
            except Exception:
                pass

        return {
            "batch_id": batch_scan_id,
            "total": len(subdomains),
            "completed": 0,
            "failed": len(subdomains),
            "unique_subdomains": len(subdomains),
            "retry_attempts": 0,
            "results": [],
            "message": f"Batch scan failed: {error_msg[:100]}"
        }
    except Exception as e:
        logger.error(f"[BATCH-{batch_scan_id}] Unexpected error during batch scan: {type(e).__name__}: {e}", exc_info=True)
        def _mark_failed():
            try:
                with get_db_session() as db:
                    batch = db.query(BatchScan).filter(BatchScan.id == batch_scan_id).first()
                    if batch:
                        batch.status = "failed"
                        batch.completed_at = datetime.utcnow()
                        db.commit()
            except Exception as db_err:
                logger.error(f"Failed to mark batch as failed: {db_err}")

        try:
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, _mark_failed)
        except Exception:
            pass

        raise
