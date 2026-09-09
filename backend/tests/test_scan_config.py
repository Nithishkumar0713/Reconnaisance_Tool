"""
Unit tests for scan configuration logic.
Tests the module loading decisions based on scan mode and batch flag.
"""

import pytest
from utils.scan_config import (
    should_include_aggressive_modules,
    should_include_reputation_checks,
    validate_scan_mode,
    SCAN_MODES,
)


class TestAggressiveModuleLogic:
    """Test when aggressive modules should be included/excluded."""

    def test_batch_fast_standard_skips_aggressive(self):
        """Fast/standard batch targets should skip aggressive modules, same as solo scans."""
        assert not should_include_aggressive_modules("fast", is_batch=True)
        assert not should_include_aggressive_modules("standard", is_batch=True)

    def test_batch_deep_detailed_includes_aggressive(self):
        """Deep/detailed batch targets should run aggressive modules just like a solo
        scan of the same mode — is_batch no longer forces a skip. Safety for batches
        comes from the batch's own concurrency cap and each module's rate limiter."""
        assert should_include_aggressive_modules("detailed", is_batch=True)
        assert should_include_aggressive_modules("deep", is_batch=True)

    def test_standard_mode_skips_aggressive(self):
        """Standard mode should skip aggressive modules."""
        assert not should_include_aggressive_modules("standard", is_batch=False)

    def test_deep_mode_includes_aggressive(self):
        """Deep mode is a full synonym of detailed and should include aggressive modules."""
        assert should_include_aggressive_modules("deep", is_batch=False)

    def test_fast_mode_skips_aggressive(self):
        """Fast mode should skip aggressive modules."""
        assert not should_include_aggressive_modules("fast", is_batch=False)

    def test_detailed_mode_includes_aggressive(self):
        """Detailed mode (individual scan) should include aggressive modules."""
        assert should_include_aggressive_modules("detailed", is_batch=False)

    def test_unknown_mode_defaults_to_config(self):
        """Unknown modes should check SCAN_MODES config."""
        result = should_include_aggressive_modules("unknown_mode", is_batch=False)
        assert result == False


class TestReputationCheckLogic:
    """Test when reputation checks should be included/excluded."""

    def test_batch_fast_skips_reputation(self):
        """Fast batch targets should skip reputation checks, same as a solo fast scan."""
        assert not should_include_reputation_checks("fast", is_batch=True, include_reputation=True)

    def test_batch_detailed_includes_reputation(self):
        """Detailed batch targets should run reputation checks just like a solo detailed
        scan — is_batch no longer forces a skip. VirusTotal/AbuseIPDB pacing is enforced
        process-wide inside modules/reputation.py, so concurrent batch targets queue
        safely instead of violating rate limits."""
        assert should_include_reputation_checks("detailed", is_batch=True, include_reputation=True)

    def test_user_disable_skips_reputation(self):
        """If user disables reputation, should not run even in detailed mode."""
        assert not should_include_reputation_checks("detailed", is_batch=False, include_reputation=False)

    def test_standard_mode_skips_reputation(self):
        """Standard mode should skip reputation checks."""
        assert not should_include_reputation_checks("standard", is_batch=False, include_reputation=True)

    def test_deep_mode_includes_reputation(self):
        """Deep mode is a full synonym of detailed and should include reputation checks."""
        assert should_include_reputation_checks("deep", is_batch=False, include_reputation=True)

    def test_detailed_mode_includes_reputation(self):
        """Detailed mode (individual scan) should include reputation checks."""
        assert should_include_reputation_checks("detailed", is_batch=False, include_reputation=True)


class TestScanModeValidation:
    """Test scan mode normalization."""

    def test_lowercase_normalization(self):
        """Modes should be normalized to lowercase."""
        assert validate_scan_mode("DETAILED") == "detailed"
        assert validate_scan_mode("Standard") == "standard"

    def test_alias_handling(self):
        """Aliases should be mapped to standard modes."""
        assert validate_scan_mode("quick") == "fast"
        assert validate_scan_mode("default") == "standard"
        assert validate_scan_mode("full") == "detailed"
        assert validate_scan_mode("comprehensive") == "detailed"

    def test_unknown_mode_defaults_to_standard(self):
        """Unknown modes should default to standard."""
        assert validate_scan_mode("unknown_mode_xyz") == "standard"

    def test_whitespace_trimming(self):
        """Whitespace should be trimmed."""
        assert validate_scan_mode("  detailed  ") == "detailed"


class TestScanModeConfiguration:
    """Test SCAN_MODES configuration."""

    def test_all_modes_have_required_fields(self):
        """Each mode should have required configuration fields."""
        for mode_name, config in SCAN_MODES.items():
            assert "description" in config, f"Mode {mode_name} missing description"
            assert "include_aggressive" in config, f"Mode {mode_name} missing include_aggressive"
            assert "include_reputation" in config, f"Mode {mode_name} missing include_reputation"
            assert "timeout" in config, f"Mode {mode_name} missing timeout"

    def test_aggressive_disabled_in_safe_modes(self):
        """Safe modes should have aggressive=False. 'deep' is a full synonym of
        'detailed' (not a safe/passive mode) — see test_deep_mode_matches_detailed."""
        for mode in ["fast", "standard"]:
            assert SCAN_MODES[mode]["include_aggressive"] == False, f"{mode} should have aggressive=False"

    def test_reputation_disabled_in_safe_modes(self):
        """Safe modes should have reputation=False. 'deep' is a full synonym of
        'detailed' (not a safe/passive mode) — see test_deep_mode_matches_detailed."""
        for mode in ["fast", "standard"]:
            assert SCAN_MODES[mode]["include_reputation"] == False, f"{mode} should have reputation=False"

    def test_deep_mode_matches_detailed(self):
        """'deep' and 'detailed' are treated as full synonyms throughout the app —
        their SCAN_MODES config must stay identical on the fields that matter."""
        assert SCAN_MODES["deep"]["include_aggressive"] == SCAN_MODES["detailed"]["include_aggressive"] == True
        assert SCAN_MODES["deep"]["include_reputation"] == SCAN_MODES["detailed"]["include_reputation"] == True

    def test_detailed_mode_aggressive_enabled(self):
        """Detailed mode should have aggressive=True."""
        assert SCAN_MODES["detailed"]["include_aggressive"] == True

    def test_detailed_mode_reputation_enabled(self):
        """Detailed mode should have reputation=True."""
        assert SCAN_MODES["detailed"]["include_reputation"] == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
