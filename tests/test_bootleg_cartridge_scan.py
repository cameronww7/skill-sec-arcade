#!/usr/bin/env python3
# ******************************************************************************
# * TITLE:        Bootleg Cartridge Scan Test Suite
# * FILE:         test_bootleg_cartridge_scan.py
# * PART OF:      bootleg-cartridge-check skill (skill-sec-arcade repo).
# * PURPOSE:      Exercises scripts/bootleg_cartridge_scan.py against two
# *               fixture skill directories under
# *               tests/fixtures/bootleg_cartridge/: benign_skill (should
# *               produce zero findings and zero coverage gaps) and
# *               malicious_skill (plants a representative sample of known-bad
# *               patterns across every severity band, plus a
# *               password-protected archive, an unsupported archive format,
# *               a binary file, and a symlink, to exercise coverage-gap
# *               reporting). Confirms both the benign-quiet case and the
# *               malicious-detect case, since a scanner that is noisy on
# *               ordinary content is as useless as one that misses real
# *               findings.
# * HOW IT WORKS: Standard library unittest. Calls
# *               bootleg_cartridge_scan.scan_skill_directory() directly
# *               against each fixture directory, no subprocess invocation
# *               needed since the function is a pure, read-only function of
# *               the filesystem.
# * USAGE:        python3 -m unittest tests.test_bootleg_cartridge_scan -v
# *               (run from the repo root)
# * ARGUMENTS:    None (standard unittest discovery).
# * INPUTS:       tests/fixtures/bootleg_cartridge/*.
# * OUTPUTS:      Test results to stdout/stderr via unittest's runner. No
# *               files written anywhere.
# * EXIT CODES:   Standard unittest exit codes (0 = all passed).
# * DEPENDENCIES: Python 3 standard library only (os, sys, unittest).
# *               Imports bootleg_cartridge_scan.py directly from
# *               ../scripts via sys.path, the same pattern
# *               test_trim_reaper_scan.py uses for trim_reaper_scan.py.
# * PERMISSIONS:  Read-only. No network, no writes.
# * ASSUMPTIONS:  Run from an environment with Python 3.10+.
# * FAILURE MODES:A missing or renamed fixture file fails the specific test
# *               that depends on it, not the whole suite.
# * SAFE TO RERUN:Yes. Every test is read-only.
# *
# * AUTHOR:       cameronww7
# * LAST UPDATED: 2026-11-20
# ******************************************************************************

"""Tests for scripts/bootleg_cartridge_scan.py's scan_skill_directory(),
against the benign and malicious fixtures under
tests/fixtures/bootleg_cartridge/. See the module header above for what
each fixture covers and why."""

import os
import sys
import unittest

SCRIPTS_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS_DIRECTORY))

import bootleg_cartridge_scan  # noqa: E402

FIXTURES_DIRECTORY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "bootleg_cartridge")


def findings_by_rule_id(findings, rule_id):
    """Test helper: returns every finding dict matching rule_id. Returns
    an empty list, never raises, so callers can assert on length/emptiness
    directly instead of handling a lookup failure."""
    return [finding for finding in findings if finding["rule_id"] == rule_id]


class BenignFixtureTests(unittest.TestCase):
    """benign_skill: ordinary, harmless skill content. The scanner must
    stay completely quiet here, zero findings and zero coverage gaps, or
    it is too noisy to be useful against real, legitimate skills."""

    def setUp(self):
        self.root = os.path.join(FIXTURES_DIRECTORY, "benign_skill")
        self.result = bootleg_cartridge_scan.scan_skill_directory(self.root)

    def test_zero_findings(self):
        self.assertEqual(self.result["findings"], [])

    def test_zero_coverage_gaps(self):
        self.assertEqual(self.result["coverage_gaps"], [])

    def test_inventories_every_file(self):
        self.assertEqual(
            self.result["files_inventoried"],
            ["README.md", "SKILL.md", "scripts/helper.py"],
        )


class MaliciousFixtureCriticalFindingsTests(unittest.TestCase):
    """malicious_skill: every Critical-band pattern planted in the
    fixture must be detected by its specific rule_id."""

    def setUp(self):
        self.root = os.path.join(FIXTURES_DIRECTORY, "malicious_skill")
        self.result = bootleg_cartridge_scan.scan_skill_directory(self.root)

    def test_detects_anthropic_base_url_override(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-C01")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "settings.json")
        self.assertEqual(matches[0]["band"], "critical")

    def test_detects_symlink_to_sensitive_target(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-C03")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "docs/vid.mp4")

    def test_detects_ioc_domain_match(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-C04")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "notes.txt")

    def test_detects_git_remote_force_push(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-C02")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "scripts/exploit.sh")

    def test_detects_backtick_in_quoted_string(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-C05")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "scripts/exploit.sh")

    def test_detects_unsafe_deserialization(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-C08")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "scripts/unsafe.py")

    def test_detects_mcp_command_shell_metacharacters(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-C07")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], ".mcp.json")

    def test_detects_disable_2fa_phrasing(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-C12")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "SKILL.md")


class MaliciousFixtureHighFindingsTests(unittest.TestCase):
    """malicious_skill: every High-band pattern planted in the fixture
    must be detected by its specific rule_id."""

    def setUp(self):
        self.root = os.path.join(FIXTURES_DIRECTORY, "malicious_skill")
        self.result = bootleg_cartridge_scan.scan_skill_directory(self.root)

    def test_detects_important_tag(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-H02")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "SKILL.md")

    def test_detects_refusal_suppression(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-H09")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "SKILL.md")

    def test_detects_shell_metacharacters_in_subprocess_argument(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-H17")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "scripts/unsafe.py")

    def test_detects_dotfile_executable_code(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-H11")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "scripts/.helper")

    def test_detects_password_protected_archive(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-H12")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "docs/payload.zip")

    def test_detects_wildcard_bash_permission(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-M10")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "settings.json")
        self.assertEqual(matches[0]["band"], "high")


class MaliciousFixtureMediumFindingsTests(unittest.TestCase):
    """malicious_skill: every Medium-band pattern planted in the fixture
    must be detected by its specific rule_id."""

    def setUp(self):
        self.root = os.path.join(FIXTURES_DIRECTORY, "malicious_skill")
        self.result = bootleg_cartridge_scan.scan_skill_directory(self.root)

    def test_detects_zalgo_density(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-M13")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "notes.txt")

    def test_detects_hardcoded_aws_key(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-M05")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "scripts/unsafe.py")

    def test_detects_private_rfc1918_ip(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-M06")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "scripts/unsafe.py")

    def test_detects_missing_allowed_tools_frontmatter(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-M07")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "SKILL.md")


class MaliciousFixtureLowFindingsTests(unittest.TestCase):
    """malicious_skill: the Low-band correlation-only signal planted in
    the fixture must still be reported, informational severity or not."""

    def setUp(self):
        self.root = os.path.join(FIXTURES_DIRECTORY, "malicious_skill")
        self.result = bootleg_cartridge_scan.scan_skill_directory(self.root)

    def test_detects_outbound_network_call(self):
        matches = findings_by_rule_id(self.result["findings"], "BC-L02")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["file"], "scripts/unsafe.py")


class MaliciousFixtureCoverageGapTests(unittest.TestCase):
    """malicious_skill: every file the scanner cannot safely read as text
    must show up as an explicit coverage gap, never silently dropped."""

    def setUp(self):
        self.root = os.path.join(FIXTURES_DIRECTORY, "malicious_skill")
        self.result = bootleg_cartridge_scan.scan_skill_directory(self.root)

    def test_flags_unsupported_archive_format(self):
        gap_files = [gap["file"] for gap in self.result["coverage_gaps"]]
        self.assertIn("docs/archive.7z", gap_files)

    def test_flags_binary_file(self):
        gap_files = [gap["file"] for gap in self.result["coverage_gaps"]]
        self.assertIn("docs/image.bin", gap_files)

    def test_flags_symlink(self):
        gap_files = [gap["file"] for gap in self.result["coverage_gaps"]]
        self.assertIn("docs/vid.mp4", gap_files)


class MaliciousFixtureUrlExtractionTests(unittest.TestCase):
    """malicious_skill: every URL referenced anywhere in the fixture must
    be extracted for human follow-up, and none of this script's own
    behavior should ever fetch one."""

    def setUp(self):
        self.root = os.path.join(FIXTURES_DIRECTORY, "malicious_skill")
        self.result = bootleg_cartridge_scan.scan_skill_directory(self.root)

    def test_extracts_the_ioc_url(self):
        urls = [entry["url"] for entry in self.result["urls_found"]]
        self.assertIn("https://clawhavoc.io/beacon", urls)

    def test_extracts_the_mcp_payload_url(self):
        urls = [entry["url"] for entry in self.result["urls_found"]]
        self.assertTrue(any("payload.sh" in url for url in urls))


if __name__ == "__main__":
    unittest.main()
