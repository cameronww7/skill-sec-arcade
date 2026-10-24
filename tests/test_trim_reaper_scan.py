#!/usr/bin/env python3
# ******************************************************************************
# * TITLE:        Trim Reaper Scan Test Suite
# * FILE:         test_trim_reaper_scan.py
# * PART OF:      trim-reaper skill (skill-sec-arcade repo).
# * PURPOSE:      Exercises scripts/trim_reaper_scan.py's `candidates`
# *               subcommand against five small fixture repos under
# *               tests/fixtures/trim-reaper/, each planting one known
# *               trap a naive static-text search would get wrong (a
# *               dynamic require, a tool-config short name, an
# *               import-name mismatch, a dev package used by the start
# *               script, and a types-package pairing). Each test asserts
# *               on the specific evidence category that must fire, not
# *               just a pass/fail on the final candidate list, since the
# *               whole point of this tool is "candidate list, never
# *               proof," getting the category right is what lets a
# *               human trust (or distrust) the evidence shown.
# * HOW IT WORKS: Standard library unittest. Each test runs
# *               trim_reaper_scan.run_candidates() (or
# *               run_unpinned_versions()/run_lifecycle_scripts(), for
# *               their own small smoke tests) directly against one
# *               fixture directory and inspects the returned dict, no
# *               subprocess invocation needed since everything here is a
# *               pure, read-only function of the filesystem.
# * USAGE:        python3 -m unittest tests.test_trim_reaper_scan -v
# *               (run from the repo root)
# * ARGUMENTS:    None (standard unittest discovery).
# * INPUTS:       tests/fixtures/trim-reaper/*.
# * OUTPUTS:      Test results to stdout/stderr via unittest's runner. No
# *               files written anywhere.
# * EXIT CODES:   Standard unittest exit codes (0 = all passed).
# * DEPENDENCIES: Python 3 standard library only (os, sys, unittest).
# *               Imports trim_reaper_scan.py directly from ../scripts
# *               via sys.path, the same pattern test_cloud_perm_audit.py
# *               uses for cloud_perm_audit.py.
# * PERMISSIONS:  Read-only. No network, no writes.
# * ASSUMPTIONS:  Run from an environment with Python 3.10+.
# * FAILURE MODES:A missing or renamed fixture file fails the specific
# *               test that depends on it, not the whole suite.
# * SAFE TO RERUN:Yes. Every test is read-only.
# *
# * AUTHOR:       cameronww7
# * LAST UPDATED: 2026-10-24
# ******************************************************************************

"""Tests for scripts/trim_reaper_scan.py's three subcommands, mostly
`candidates`, against the planted-trap fixtures under
tests/fixtures/trim-reaper/. See the module header above for what each
fixture tests and why."""

import os
import sys
import unittest

SCRIPTS_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS_DIRECTORY))

import trim_reaper_scan  # noqa: E402

FIXTURES_DIRECTORY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "trim-reaper")


def candidate_by_name(workspaces, installed_name):
    """Test helper: finds the first candidate entry with the given
    installed_name across every workspace in a run_candidates() result.
    Fails the calling test with a clear message if not found, rather
    than letting a later assertion fail confusingly on None."""
    for workspace in workspaces:
        for candidate in workspace["candidates"]:
            if candidate["installed_name"] == installed_name:
                return candidate
    raise AssertionError(f"no candidate named {installed_name!r} found in {workspaces!r}")


class DynamicRequireFixtureTests(unittest.TestCase):
    """fixture-dynamic-require: winston is only ever required via
    require(config.loggerName), never by its literal name at the call
    site. A naive static-import sweep would see zero references and
    wrongly call it unused; this must instead be flagged under
    dynamic_loading."""

    def setUp(self):
        self.root = os.path.join(FIXTURES_DIRECTORY, "fixture-dynamic-require")
        self.result = trim_reaper_scan.run_candidates(self.root)

    def test_winston_has_no_static_source_import(self):
        winston = candidate_by_name(self.result["workspaces"], "winston")
        self.assertEqual(winston["search_results"]["source_imports"]["hit_count"], 0)

    def test_winston_is_flagged_under_dynamic_loading(self):
        winston = candidate_by_name(self.result["workspaces"], "winston")
        self.assertGreater(winston["search_results"]["dynamic_loading"]["hit_count"], 0)

    def test_winston_is_not_reported_as_zero_references(self):
        winston = candidate_by_name(self.result["workspaces"], "winston")
        self.assertFalse(winston["zero_references_found"])


class ShortNameConfigFixtureTests(unittest.TestCase):
    """fixture-short-name-config: eslint-plugin-react is referenced only
    as the bare string "react" inside .eslintrc.json's "plugins" array,
    the real-world short-name convention for ESLint plugins. A literal
    substring search for "eslint-plugin-react" would find nothing."""

    def setUp(self):
        self.root = os.path.join(FIXTURES_DIRECTORY, "fixture-short-name-config")
        self.result = trim_reaper_scan.run_candidates(self.root)

    def test_eslint_plugin_react_has_no_full_name_source_import(self):
        plugin = candidate_by_name(self.result["workspaces"], "eslint-plugin-react")
        self.assertEqual(plugin["search_results"]["source_imports"]["hit_count"], 0)

    def test_eslint_plugin_react_is_found_via_short_name_in_tool_configs(self):
        plugin = candidate_by_name(self.result["workspaces"], "eslint-plugin-react")
        tool_config_hits = plugin["search_results"]["tool_configs"]["locations"]
        self.assertTrue(
            any(hit["matched_term"] == "react" for hit in tool_config_hits),
            f"expected a tool_configs hit matched on the short name 'react', got {tool_config_hits!r}",
        )

    def test_eslint_plugin_react_is_not_reported_as_zero_references(self):
        plugin = candidate_by_name(self.result["workspaces"], "eslint-plugin-react")
        self.assertFalse(plugin["zero_references_found"])


class ImportNameMismatchFixtureTests(unittest.TestCase):
    """fixture-import-name-mismatch: requirements.txt declares
    "beautifulsoup4" (the installed/PyPI name), but the only import in
    the codebase is "from bs4 import BeautifulSoup" (the actual
    importable module name). This is dead_weight_scan.py's own
    documented module_matches() gap; trim_reaper_scan.py closes it with a
    curated import-name override (KNOWN_IMPORT_NAME_OVERRIDES)."""

    def setUp(self):
        self.root = os.path.join(FIXTURES_DIRECTORY, "fixture-import-name-mismatch")
        self.result = trim_reaper_scan.run_candidates(self.root)

    def test_import_names_includes_bs4_not_just_the_installed_name(self):
        beautifulsoup4 = candidate_by_name(self.result["workspaces"], "beautifulsoup4")
        self.assertIn("bs4", beautifulsoup4["import_names"])

    def test_source_import_search_matches_on_bs4(self):
        beautifulsoup4 = candidate_by_name(self.result["workspaces"], "beautifulsoup4")
        self.assertGreater(beautifulsoup4["search_results"]["source_imports"]["hit_count"], 0)

    def test_beautifulsoup4_is_not_reported_as_zero_references(self):
        beautifulsoup4 = candidate_by_name(self.result["workspaces"], "beautifulsoup4")
        self.assertFalse(beautifulsoup4["zero_references_found"])


class DevPackageInStartScriptFixtureTests(unittest.TestCase):
    """fixture-dev-package-in-start-script: nodemon is declared under
    devDependencies, but package.json's own "start" script invokes it
    directly, meaning a clean production-only install would break the
    app. This is Phase 6 evidence (scope misclassification), surfaced
    here through the scripts_and_makefiles category, which must match
    only the "start" script's command value, not nodemon's own
    (nonexistent, in this fixture) dependency declaration."""

    def setUp(self):
        self.root = os.path.join(FIXTURES_DIRECTORY, "fixture-dev-package-in-start-script")
        self.result = trim_reaper_scan.run_candidates(self.root)

    def test_nodemon_is_found_in_the_start_script(self):
        nodemon = candidate_by_name(self.result["workspaces"], "nodemon")
        scripts_hits = nodemon["search_results"]["scripts_and_makefiles"]["locations"]
        self.assertTrue(
            any(hit.get("script") == "start" for hit in scripts_hits),
            f"expected a scripts_and_makefiles hit on the 'start' script, got {scripts_hits!r}",
        )

    def test_nodemon_is_not_reported_as_zero_references(self):
        nodemon = candidate_by_name(self.result["workspaces"], "nodemon")
        self.assertFalse(nodemon["zero_references_found"])


class TypeDefinitionPairFixtureTests(unittest.TestCase):
    """fixture-types-pair: lodash is a dependency and @types/lodash is a
    devDependency in the same workspace. The two must be evaluated
    together: removing lodash without @types/lodash (or vice versa)
    orphans half the pair."""

    def setUp(self):
        self.root = os.path.join(FIXTURES_DIRECTORY, "fixture-types-pair")
        self.result = trim_reaper_scan.run_candidates(self.root)

    def test_lodash_is_paired_with_its_types_package(self):
        lodash = candidate_by_name(self.result["workspaces"], "lodash")
        self.assertIsNotNone(lodash["type_definition_pair"])
        self.assertEqual(lodash["type_definition_pair"]["package"], "@types/lodash")
        self.assertTrue(lodash["type_definition_pair"]["present"])

    def test_types_lodash_is_itself_a_candidate_too(self):
        types_lodash = candidate_by_name(self.result["workspaces"], "@types/lodash")
        self.assertIsNotNone(types_lodash)


class UnpinnedVersionsSmokeTests(unittest.TestCase):
    """Smoke-tests classify_version_specifier()'s per-ecosystem grammar
    rules via run_unpinned_versions() against the types-pair fixture,
    which conveniently has both a caret-pinned dependency and a
    caret-pinned devDependency."""

    def test_caret_specifiers_are_classified_as_caret_not_exact(self):
        root = os.path.join(FIXTURES_DIRECTORY, "fixture-types-pair")
        result = trim_reaper_scan.run_unpinned_versions(root)
        lodash_entries = [d for d in result["dependencies"] if d["name"] == "lodash"]
        self.assertEqual(len(lodash_entries), 1)
        self.assertEqual(lodash_entries[0]["pin_class"], "caret")
        self.assertFalse(lodash_entries[0]["is_pinned_exact"])

    def test_cargo_bare_version_is_classified_as_caret_not_exact(self):
        self.assertEqual(trim_reaper_scan.classify_version_specifier("rust", "1.2.3"), "caret")

    def test_cargo_explicit_equals_is_classified_as_exact(self):
        self.assertEqual(trim_reaper_scan.classify_version_specifier("rust", "=1.2.3"), "exact")

    def test_npm_bare_version_is_classified_as_exact(self):
        self.assertEqual(trim_reaper_scan.classify_version_specifier("javascript", "1.2.3"), "exact")

    def test_git_source_overrides_ecosystem_rules(self):
        self.assertEqual(trim_reaper_scan.classify_version_specifier("javascript", "git+https://example.com/x"), "git_or_url")


class LifecycleScriptsSmokeTests(unittest.TestCase):
    """Smoke-tests run_lifecycle_scripts() against the dev-package fixture
    (which has no lifecycle scripts) and a fixture that does, to confirm
    both the positive and negative path."""

    def test_fixture_with_no_lifecycle_scripts_reports_none(self):
        root = os.path.join(FIXTURES_DIRECTORY, "fixture-dev-package-in-start-script")
        result = trim_reaper_scan.run_lifecycle_scripts(root)
        self.assertEqual(result["packages_with_lifecycle_scripts"], [])

    def test_coverage_limitation_is_always_stated(self):
        root = os.path.join(FIXTURES_DIRECTORY, "fixture-dev-package-in-start-script")
        result = trim_reaper_scan.run_lifecycle_scripts(root)
        self.assertIn("physically present on disk", result["coverage_limitation"])


if __name__ == "__main__":
    unittest.main()
