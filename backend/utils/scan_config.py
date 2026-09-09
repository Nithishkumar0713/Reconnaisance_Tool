"""
Scan configuration and mode management.
Defines which modules run in which scan modes to balance speed, safety, and data quality.
"""

import logging

logger = logging.getLogger(__name__)

SCAN_MODES = {
    "fast": {
        "description": "Quick scan - passive modules only",
        "include_aggressive": False,
        "include_reputation": False,
        "timeout": 30,
    },
    "standard": {
        "description": "Standard scan - passive modules only (batch/standard mode)",
        "include_aggressive": False,
        "include_reputation": False,
        "timeout": 35,
    },
    "deep": {
        "description": "Deep scan - standard checks plus port scan, directory enum, reverse DNS, and reputation checks",
        "include_aggressive": True,
        "include_reputation": True,
        "timeout": 180,
    },
    "detailed": {
        "description": "Detailed scan - includes aggressive modules + reputation",
        "include_aggressive": True,
        "include_reputation": True,
        "timeout": 180,
    },
}

AGGRESSIVE_MODULES = [
    "port_scan",
    "directories",
    "waf_detect",
]

REPUTATION_MODULES = [
    "abuseipdb",
    "virustotal",
]


def should_include_aggressive_modules(mode: str, is_batch: bool) -> bool:
    """
    Determine if aggressive modules should run based on scan mode.

    Args:
        mode: Scan mode ("fast", "standard", "deep", "detailed", etc.)
        is_batch: Whether this is part of a batch scan (subdomain-batch or
            full-scan-batch). No longer a hard override — mode is the sole
            driver, so a batch scan runs exactly the same module set as a
            solo scan of the same mode would. Kept as a parameter (used
            elsewhere for timeout scaling) and for logging/back-compat.

    Returns:
        True if aggressive modules should run, False otherwise

    Logic:
    - If mode in ["standard", "fast"]: NEVER run aggressive modules
    - If mode in ["deep", "detailed"]: run aggressive modules — whether or
      not this is part of a batch. Safety for large/auto-discovered batches
      comes from the per-batch concurrency cap and each module's own
      rate limiter (VirusTotal/AbuseIPDB/email_gather), not from silently
      disabling modules regardless of the user's chosen mode.
    - Default: check mode configuration
    """
    mode_lower = str(mode).strip().lower()
    if mode_lower in ["standard", "fast"]:
        logger.debug(f"Scan mode '{mode}' detected: skipping aggressive modules for safety")
        return False

    config = SCAN_MODES.get(mode_lower, {})
    include = config.get("include_aggressive", False)
    logger.debug(f"Scan mode '{mode}': include_aggressive={include}")
    return include


def should_include_reputation_checks(mode: str, is_batch: bool, include_reputation: bool = True) -> bool:
    """
    Determine if reputation checks should run.

    Args:
        mode: Scan mode
        is_batch: Whether this is part of a batch scan. No longer a hard
            override — see should_include_aggressive_modules for why.
        include_reputation: User's preference for reputation checks

    Returns:
        True if reputation checks should run

    Logic:
    - If include_reputation=False (user opted out, or no API key configured): NEVER run
    - If mode in ["standard", "fast"]: NEVER run
    - If mode in ["deep", "detailed"]: run — batch or not. VirusTotal/AbuseIPDB
      pacing is enforced process-wide inside modules/reputation.py itself,
      so concurrent batch targets queue safely instead of violating rate limits.
    - Default: check mode configuration
    """
    if not include_reputation:
        logger.debug("User disabled reputation checks")
        return False

    mode_lower = str(mode).strip().lower()
    if mode_lower in ["standard", "fast"]:
        logger.debug(f"Scan mode '{mode}': skipping reputation checks for safety")
        return False

    config = SCAN_MODES.get(mode_lower, {})
    include = config.get("include_reputation", False)
    logger.debug(f"Scan mode '{mode}': include_reputation={include}")
    return include


def get_scan_timeout(mode: str, is_batch: bool) -> int:
    """Get appropriate timeout for scan mode."""
    mode_lower = str(mode).strip().lower()
    config = SCAN_MODES.get(mode_lower, SCAN_MODES["detailed"])
    timeout = config.get("timeout", 180)

    if is_batch:
        return int(timeout * 1.2)

    return timeout


def validate_scan_mode(mode: str) -> str:
    """Normalize and validate scan mode."""
    mode_lower = str(mode).strip().lower()

    aliases = {
        "fast": "fast",
        "quick": "fast",
        "standard": "standard",
        "default": "standard",
        "deep": "deep",
        "detailed": "detailed",
        "full": "detailed",
        "comprehensive": "detailed",
    }

    normalized = aliases.get(mode_lower, mode_lower)

    if normalized not in SCAN_MODES:
        logger.warning(f"Unknown scan mode '{mode}', defaulting to 'standard'")
        return "standard"

    return normalized
