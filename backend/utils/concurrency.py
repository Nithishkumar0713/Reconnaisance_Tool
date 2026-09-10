"""
Shared concurrency helpers.
"""

import asyncio

# Global, process-wide cap on real DNS resolution requests in flight at
# once — not per-module, per-target, or per-stage, but a ceiling shared by
# every real DNS call site in the app (subdomain resolution,
# resolve_target(), whois, dns_recon). This network forces all DNS through
# an internal/corporate resolver with a hard, measured throughput ceiling
# (~312 q/s sustained at concurrency=100 vs. a collapse to ~45 q/s at
# concurrency=500 — a real regression from adding more concurrency, not
# diminishing returns). No per-stage concurrency setting or thread-pool
# size can fix this from the Python side; 100 total slots is chosen with
# headroom below the measured good zone.
#
# Split into two pools rather than one shared 100-slot semaphore: a single
# FIFO semaphore would let a target's bulk subdomain-resolution burst
# (hundreds of low-priority lookups) queue ahead of a different target's
# single, fast, cascade-critical lookup (resolve_target/whois/dns_records).
# PRIORITY_DNS_SEMAPHORE is reserved for the one-shot-per-target calls
# where a single failure has outsized blast radius. BULK_DNS_SEMAPHORE is
# for subdomain enumeration's hundreds-of-lookups bruteforce/unresolved-
# resolution stages, which can tolerate queuing. Capping bulk at 70
# guarantees priority work always has at least 30 of the 100 slots free.
PRIORITY_DNS_SEMAPHORE = asyncio.Semaphore(30)
BULK_DNS_SEMAPHORE = asyncio.Semaphore(70)


async def run_bounded(items: list, worker_fn, concurrency: int, timeout: float) -> tuple[list, bool]:
    """
    Runs `worker_fn` over every item in `items` using a fixed pool of
    `concurrency` worker coroutines pulling from a shared queue, instead of
    creating one asyncio.Task per item up front (`asyncio.gather(*[worker_fn(x)
    for x in items])`, semaphore-throttled). The gather-everything approach
    is a real problem once a candidate list gets large — a full-scan
    subdomain bruteforce+permutation pass can carry 40,000+ candidates, and
    creating that many Task objects at once, even with a semaphore capping
    how many run concurrently, is enough scheduling overhead on its own to
    make the whole event loop briefly unresponsive. A bounded worker pool
    checks the exact same items with the exact same concurrency ceiling,
    using only `concurrency` Task objects total regardless of list size.

    Returns (results, timed_out) — results collected before a timeout are
    kept rather than discarded.
    """
    queue: asyncio.Queue = asyncio.Queue()
    for item in items:
        queue.put_nowait(item)

    results: list = []

    async def worker():
        while True:
            try:
                item = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                r = await worker_fn(item)
                if r:
                    results.append(r)
            except Exception:
                pass

    worker_count = max(1, min(concurrency, len(items)))
    workers = [asyncio.create_task(worker()) for _ in range(worker_count)]
    try:
        await asyncio.wait_for(asyncio.gather(*workers), timeout=timeout)
        return results, False
    except asyncio.TimeoutError:
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        return results, True
