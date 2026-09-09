"""
Shared concurrency helpers.
"""

import asyncio

# Global, process-wide cap on real DNS resolution requests in flight at
# once — not per-module, per-target, or per-stage, but a ceiling shared by
# every real DNS call site in the app (subdomain resolution,
# resolve_target(), whois, dns_recon). This environment's network policy
# forces ALL DNS through an internal/corporate resolver (confirmed
# directly: a raw query to 1.1.1.1 on port 53 times out — external DNS is
# blocked outright, so there's no faster resolver to switch to), and that
# resolver has a hard, real throughput ceiling measured directly via an
# isolated stress test against real (non-cached) hostnames:
#   concurrency=100 -> ~312 q/s sustained, p50 ~100ms   (reproduced twice)
#   concurrency=500 -> ~45 q/s sustained, p50 1.2s+,     (reproduced twice)
#                       some individual queries 11+ seconds
# That's not diminishing returns, it's a 7x throughput *regression* from
# adding more concurrency — a classic saturated-queue collapse. This
# single number explains the DNS-resolution-cascade failures observed
# across every Deep-mode batch tested (5 concurrent targets x 60
# bruteforce threads alone = 300, comfortably in the collapse zone). No
# per-stage concurrency setting or thread-pool size can fix this from the
# Python side — the ceiling is in the real resolver this network forces
# all queries through. 100 total slots is chosen with headroom below the
# measured good zone.
#
# Split into two pools rather than one shared 100-slot semaphore: a single
# plain FIFO semaphore lets a target's bulk subdomain-resolution burst
# (hundreds of low-priority lookups) sit ahead in the queue of a *different*
# target's single, fast, cascade-critical lookup (resolve_target/whois/
# dns_records) — verified directly: dns_records timeouts increased right
# after the shared semaphore went in, consistent with exactly this queuing.
# PRIORITY_DNS_SEMAPHORE is reserved for the one-shot-per-target calls
# where a single failure has outsized blast radius (resolve_target cascades
# into 7+ modules; whois/dns_records/reverse_dns each gate one module).
# BULK_DNS_SEMAPHORE is for subdomain enumeration's hundreds-of-lookups
# bruteforce/unresolved-resolution stages, which can tolerate queuing —
# nothing else is waiting on any single one of those results. Capping bulk
# at 70 guarantees priority work always has at least 30 of the 100
# measured-safe total slots free, regardless of how aggressively any one
# target's subdomain enumeration is currently running.
PRIORITY_DNS_SEMAPHORE = asyncio.Semaphore(30)
BULK_DNS_SEMAPHORE = asyncio.Semaphore(70)


async def run_bounded(items: list, worker_fn, concurrency: int, timeout: float) -> tuple[list, bool]:
    """
    Runs `worker_fn` over every item in `items` using a fixed pool of
    `concurrency` worker coroutines pulling from a shared queue, instead of
    creating one asyncio.Task per item up front (`asyncio.gather(*[worker_fn(x)
    for x in items])`, semaphore-throttled). Verified directly (asyncio
    debug-mode instrumentation) that the gather-everything approach is a
    real problem once a candidate list gets large: a full-scan subdomain
    bruteforce+permutation pass can carry 40,000+ candidates, and creating
    that many Task objects at once — even with a semaphore capping how many
    run *concurrently* — is enough scheduling overhead on its own to make
    the whole event loop briefly unresponsive (observed: "Executing ...
    took 14.9 seconds" on unrelated coroutines, tens of thousands of
    pending tasks, worse still once several targets' full scans do this at
    the same time in a batch). A bounded worker pool checks the exact same
    items with the exact same concurrency ceiling, using only `concurrency`
    Task objects total regardless of list size — measured directly: 40,000
    items dropped from 40,000 created tasks to 61.

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
