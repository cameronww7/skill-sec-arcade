#!/usr/bin/env python3
# ******************************************************************************
# * TITLE:        Cloud Perm Audit Test Suite
# * FILE:         test_cloud_perm_audit.py
# * PART OF:      cloud-player-perm-audit skill (skill-sec-arcade repo).
# * PURPOSE:      Exercises scripts/cloud_perm_audit.py's deterministic,
# *               no-AWS-call logic (the GRANTED/USED/EXCESS math, trust
# *               policy summarization, cloudsplaining risk mapping, and
# *               redaction) without needing live AWS credentials, plus
# *               one end-to-end pipeline-wiring smoke test driven by
# *               synthetic fixtures under tests/fixtures/.
# * HOW IT WORKS: Standard library unittest. Pure functions are called
# *               directly with hand-crafted inputs. The end-to-end test
# *               sets CLOUD_PERM_AUDIT_FIXTURES_DIR so collect_*()
# *               functions read from tests/fixtures/ instead of calling
# *               the `aws` CLI, then runs analyze (against a real local
# *               cloudsplaining install, which needs no AWS credentials
# *               itself) and normalize for real.
# * USAGE:        python3 -m unittest tests.test_cloud_perm_audit -v
# *               (run from the repo root)
# * ARGUMENTS:    None (standard unittest discovery).
# * INPUTS:       tests/fixtures/*.json. The end-to-end test also shells
# *               out to a locally-installed `cloudsplaining` binary if
# *               one is present; it's skipped otherwise.
# * OUTPUTS:      Test results to stdout/stderr via unittest's runner.
# *               No files are written outside of a temp directory the
# *               end-to-end test creates and manages itself.
# * EXIT CODES:   Standard unittest exit codes (0 = all passed).
# * DEPENDENCIES: Python 3 standard library only (json, os, sys, tempfile,
# *               unittest). Imports cloud_perm_audit.py directly from
# *               ../scripts via sys.path, the same pattern
# *               dead_weight_scan.py uses to import cartridge_scan.py.
# * PERMISSIONS:  No AWS access at all, not even read-only; every test
# *               here either calls a pure function directly or runs
# *               cloud_perm_audit.py in fixture mode, which never shells
# *               out to the `aws` CLI.
# * ASSUMPTIONS:  Run from an environment with Python 3.10+. The
# *               end-to-end cloudsplaining test is skipped (not failed)
# *               if cloudsplaining isn't installed locally.
# * FAILURE MODES:A missing fixture file fails the specific test that
# *               depends on it, not the whole suite.
# * SAFE TO RERUN:Yes. Every test is read-only except for the end-to-end
# *               test's own temp directory, which it creates and never
# *               reuses across runs.
# *
# * AUTHOR:       cameronww7
# * LAST UPDATED: 2026-10-10
# ******************************************************************************

"""Tests for scripts/cloud_perm_audit.py's deterministic logic. See the
module header above for how this suite avoids needing live AWS
credentials."""

import json
import os
import sys
import tempfile
import unittest

SCRIPTS_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS_DIRECTORY))

import cloud_perm_audit  # noqa: E402

FIXTURES_DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class ComputeExcessTests(unittest.TestCase):
    """Tests compute_excess(): the GRANTED minus USED calculation."""

    def test_whole_service_never_used_is_excess_service(self):
        granted = {"iam": {"iam:CreatePolicyVersion", "iam:PassRole"}}
        used_coverage = {}
        excess_services, excess_actions = cloud_perm_audit.compute_excess(granted, used_coverage, {})
        self.assertEqual(excess_services, ["iam"])
        self.assertEqual(excess_actions, {})

    def test_action_level_service_flags_only_unused_actions_as_excess(self):
        granted = {"s3": {"s3:ListBucket", "s3:PutBucketPolicy"}}
        used_coverage = {
            "s3": {"coverage": "action_level", "used_actions": {"s3:ListBucket"}, "used_at_all": True, "last_used": "x"},
        }
        excess_services, excess_actions = cloud_perm_audit.compute_excess(granted, used_coverage, {})
        self.assertEqual(excess_services, [])
        self.assertEqual(excess_actions, {"s3": ["s3:PutBucketPolicy"]})

    def test_service_level_only_usage_never_produces_excess_actions(self):
        granted = {"dynamodb": {"dynamodb:Scan", "dynamodb:PutItem"}}
        used_coverage = {
            "dynamodb": {"coverage": "service_level_only", "used_actions": set(), "used_at_all": True, "last_used": "x"},
        }
        excess_services, excess_actions = cloud_perm_audit.compute_excess(granted, used_coverage, {})
        self.assertEqual(excess_services, [])
        self.assertEqual(excess_actions, {})

    def test_data_plane_actions_are_never_counted_as_excess(self):
        granted = {"s3": {"s3:GetObject", "s3:PutBucketPolicy"}}
        used_coverage = {
            "s3": {"coverage": "action_level", "used_actions": set(), "used_at_all": True, "last_used": "x"},
        }
        data_plane = {"s3": {"s3:getobject"}}
        excess_services, excess_actions = cloud_perm_audit.compute_excess(granted, used_coverage, data_plane)
        self.assertEqual(excess_services, [])
        self.assertEqual(excess_actions, {"s3": ["s3:PutBucketPolicy"]})

    def test_full_service_wildcard_grant_is_never_enumerated(self):
        granted = {"s3": "ALL"}
        used_coverage = {
            "s3": {"coverage": "action_level", "used_actions": {"s3:ListBucket"}, "used_at_all": True, "last_used": "x"},
        }
        excess_services, excess_actions = cloud_perm_audit.compute_excess(granted, used_coverage, {})
        self.assertEqual(excess_services, [])
        self.assertEqual(excess_actions, {})

    def test_case_insensitive_comparison(self):
        granted = {"iam": {"iam:PassRole"}}
        used_coverage = {
            "iam": {"coverage": "action_level", "used_actions": {"iam:passrole"}, "used_at_all": True, "last_used": "x"},
        }
        excess_services, excess_actions = cloud_perm_audit.compute_excess(granted, used_coverage, {})
        self.assertEqual(excess_services, [])
        self.assertEqual(excess_actions, {})


class ComputeUnknownUsageTests(unittest.TestCase):
    """Tests compute_unknown_usage(): the quarantine list for anything
    compute_excess() couldn't safely classify."""

    def test_service_level_only_whole_action_set_is_unknown(self):
        granted = {"dynamodb": {"dynamodb:Scan", "dynamodb:PutItem"}}
        used_coverage = {
            "dynamodb": {"coverage": "service_level_only", "used_actions": set(), "used_at_all": True, "last_used": "x"},
        }
        unknown = cloud_perm_audit.compute_unknown_usage(granted, used_coverage, [], {})
        self.assertEqual(unknown, {"dynamodb": ["dynamodb:PutItem", "dynamodb:Scan"]})

    def test_data_plane_actions_are_quarantined_even_with_action_level_data(self):
        granted = {"s3": {"s3:GetObject", "s3:ListBucket"}}
        used_coverage = {
            "s3": {"coverage": "action_level", "used_actions": {"s3:ListBucket"}, "used_at_all": True, "last_used": "x"},
        }
        data_plane = {"s3": {"s3:getobject"}}
        unknown = cloud_perm_audit.compute_unknown_usage(granted, used_coverage, [], data_plane)
        self.assertEqual(unknown, {"s3": ["s3:GetObject"]})

    def test_whole_service_already_excess_is_not_also_unknown(self):
        granted = {"iam": {"iam:PassRole"}}
        used_coverage = {}
        unknown = cloud_perm_audit.compute_unknown_usage(granted, used_coverage, ["iam"], {})
        self.assertEqual(unknown, {})

    def test_full_wildcard_grant_is_never_marked_unknown(self):
        granted = {"s3": "ALL"}
        used_coverage = {
            "s3": {"coverage": "service_level_only", "used_actions": set(), "used_at_all": True, "last_used": "x"},
        }
        unknown = cloud_perm_audit.compute_unknown_usage(granted, used_coverage, [], {})
        self.assertEqual(unknown, {})


class SummarizeTrustPolicyTests(unittest.TestCase):
    """Tests summarize_trust_policy(): trust policy -> boolean/structural
    risk signals."""

    def test_wildcard_principal_detected(self):
        document = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
        result = cloud_perm_audit.summarize_trust_policy(document, "123456789012")
        self.assertTrue(result["assumable_by_wildcard_principal"])

    def test_cross_account_detected_and_self_account_excluded(self):
        document = {
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"},
                {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:role/some-role"}, "Action": "sts:AssumeRole"},
            ]
        }
        result = cloud_perm_audit.summarize_trust_policy(document, "123456789012")
        self.assertTrue(result["assumable_by_other_account"])
        self.assertEqual(result["external_account_ids"], ["999999999999"])

    def test_oidc_without_repo_condition_flagged(self):
        document = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                }
            ]
        }
        result = cloud_perm_audit.summarize_trust_policy(document, "123456789012")
        self.assertTrue(result["assumable_by_federated_oidc"])
        self.assertTrue(result["oidc_missing_repo_condition"])

    def test_oidc_with_repo_condition_not_flagged(self):
        document = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringLike": {"token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:*"},
                    },
                }
            ]
        }
        result = cloud_perm_audit.summarize_trust_policy(document, "123456789012")
        self.assertTrue(result["assumable_by_federated_oidc"])
        self.assertFalse(result["oidc_missing_repo_condition"])

    def test_service_principal_collected(self):
        document = {"Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        result = cloud_perm_audit.summarize_trust_policy(document, "123456789012")
        self.assertEqual(result["assumable_service_principals"], ["ec2.amazonaws.com"])
        self.assertFalse(result["assumable_by_other_account"])
        self.assertFalse(result["assumable_by_wildcard_principal"])


class RedactFindingsTests(unittest.TestCase):
    """Tests redact_findings() and its helpers: the unconditional
    redaction choke point."""

    def test_local_model_location_is_a_no_op(self):
        document = {"account_id": "123456789012", "roles": [{"role_arn": "arn:aws:iam::123456789012:role/x"}]}
        result = cloud_perm_audit.redact_findings(dict(document), "local")
        self.assertFalse(result["redaction_applied"])
        self.assertEqual(result["account_id"], "123456789012")

    def test_hosted_redacts_self_account_id_and_arn(self):
        document = {
            "account_id": "123456789012",
            "roles": [{"role_arn": "arn:aws:iam::123456789012:role/svc-payments-ci-deployer"}],
        }
        result = cloud_perm_audit.redact_findings(dict(document), "hosted")
        self.assertTrue(result["redaction_applied"])
        self.assertEqual(result["account_id"], "ACCOUNT_SELF")
        self.assertNotIn("123456789012", result["roles"][0]["role_arn"])
        self.assertTrue(result["roles"][0]["role_arn"].startswith("ARN_SELF_"))

    def test_same_raw_value_maps_to_same_token_within_one_run(self):
        document = {
            "account_id": "123456789012",
            "roles": [
                {"role_arn": "arn:aws:iam::999999999999:role/a", "note": "arn:aws:iam::999999999999:role/a again"},
            ],
        }
        result = cloud_perm_audit.redact_findings(dict(document), "hosted")
        self.assertTrue(result["roles"][0]["note"].startswith(result["roles"][0]["role_arn"] + " "))

    def test_bare_account_id_outside_an_arn_is_still_redacted(self):
        document = {"account_id": "123456789012", "note": "shared with 999999999999 directly"}
        result = cloud_perm_audit.redact_findings(dict(document), "hosted")
        self.assertNotIn("999999999999", result["note"])
        self.assertTrue(result["note"].startswith("shared with ACCOUNT_EXTERNAL_"))


class ConfigValidationTests(unittest.TestCase):
    """Tests config_validation_errors(): every required field's absence
    is individually reported."""

    def _valid_config(self):
        return {
            "aws_profile": "readonly-iam-auditor",
            "scope": {"type": "role_prefix", "role_prefix": "payments-"},
            "profile_arn_allowlist": ["arn:aws:sts::*:assumed-role/readonly-iam-auditor/*"],
            "pinned_tool_versions": {"cloudsplaining": "0.9.1"},
        }

    def test_valid_config_has_no_errors(self):
        self.assertEqual(cloud_perm_audit.config_validation_errors(self._valid_config()), [])

    def test_missing_aws_profile_reported(self):
        config = self._valid_config()
        del config["aws_profile"]
        errors = cloud_perm_audit.config_validation_errors(config)
        self.assertTrue(any("aws_profile" in error for error in errors))

    def test_missing_scope_reported(self):
        config = self._valid_config()
        del config["scope"]
        errors = cloud_perm_audit.config_validation_errors(config)
        self.assertTrue(any("scope" in error for error in errors))

    def test_missing_profile_arn_allowlist_reported(self):
        config = self._valid_config()
        config["profile_arn_allowlist"] = []
        errors = cloud_perm_audit.config_validation_errors(config)
        self.assertTrue(any("profile_arn_allowlist" in error for error in errors))

    def test_missing_pinned_cloudsplaining_version_reported(self):
        config = self._valid_config()
        config["pinned_tool_versions"] = {}
        errors = cloud_perm_audit.config_validation_errors(config)
        self.assertTrue(any("cloudsplaining" in error for error in errors))

    def test_model_location_is_never_required(self):
        config = self._valid_config()
        self.assertNotIn("model_location", config)
        self.assertEqual(cloud_perm_audit.config_validation_errors(config), [])
        self.assertEqual(cloud_perm_audit.resolve_model_location(config), "hosted")


class MapCloudsplainingRiskFlagsTests(unittest.TestCase):
    """Tests map_cloudsplaining_risk_flags() against the real
    cloudsplaining output fixture, including the fix for a wholly-unused
    service's enumerated actions (see this skill's SKILL.md Step 2/3
    for why this matters)."""

    def setUp(self):
        self.cloudsplaining_output = cloud_perm_audit.read_json_file(
            os.path.join(FIXTURES_DIRECTORY, "cloudsplaining_output.json")
        )

    def test_none_output_returns_none(self):
        result = cloud_perm_audit.map_cloudsplaining_risk_flags("svc-payments-ci-deployer", None, {}, [], {})
        self.assertIsNone(result)

    def test_unknown_role_returns_empty_list(self):
        result = cloud_perm_audit.map_cloudsplaining_risk_flags(
            "some-other-role", self.cloudsplaining_output, {}, [], {},
        )
        self.assertEqual(result, [])

    def test_wholly_unused_service_actions_still_flag_risk_categories(self):
        # "iam" is wholly unused (excess_services), granted as a specific
        # set (not ALL); iam:CreatePolicyVersion and iam:PassRole must
        # still be checked against cloudsplaining's per-action findings,
        # even though compute_excess() never puts them in excess_actions
        # for a wholly-excess service.
        granted = {"iam": {"iam:CreatePolicyVersion", "iam:PassRole"}, "s3": "ALL"}
        excess_services = ["iam"]
        excess_actions = {}
        result = cloud_perm_audit.map_cloudsplaining_risk_flags(
            "svc-payments-ci-deployer", self.cloudsplaining_output, granted, excess_services, excess_actions,
        )
        self.assertIn("PrivilegeEscalation", result)
        self.assertIn("ResourceExposure", result)
        self.assertIn("InfrastructureModification", result)

    def test_used_wildcard_service_does_not_spuriously_flag_service_wildcard(self):
        # s3 is granted ALL but is NOT in excess_services (it's used);
        # ServiceWildcard must not fire since s3 isn't verified excess.
        granted = {"iam": {"iam:CreatePolicyVersion", "iam:PassRole"}, "s3": "ALL"}
        excess_services = ["iam"]
        excess_actions = {}
        result = cloud_perm_audit.map_cloudsplaining_risk_flags(
            "svc-payments-ci-deployer", self.cloudsplaining_output, granted, excess_services, excess_actions,
        )
        self.assertNotIn("ServiceWildcard", result)
        self.assertNotIn("DataExfiltration", result)


class EndToEndFixtureSmokeTest(unittest.TestCase):
    """Runs the full preflight-skipped collect -> analyze -> normalize
    pipeline against tests/fixtures/, using CLOUD_PERM_AUDIT_FIXTURES_DIR
    to avoid any live AWS call. analyze runs a real local cloudsplaining
    scan (needs no AWS credentials); the test is skipped if
    cloudsplaining isn't installed."""

    def test_collect_analyze_normalize_pipeline_wiring(self):
        if cloud_perm_audit.get_pip_package_version("cloudsplaining") is None:
            self.skipTest("cloudsplaining is not installed in this environment")

        config_dict = {
            "aws_profile": "unused-in-fixture-mode",
            "scope": {"type": "role_prefix", "role_prefix": "svc-"},
            "observation_window_days": 90,
            "model_location": "hosted",
            "profile_arn_allowlist": ["*"],
            "pinned_tool_versions": {"cloudsplaining": cloud_perm_audit.get_pip_package_version("cloudsplaining")},
            "enable_parliament": False,
            "enable_pmapper": False,
        }

        with tempfile.TemporaryDirectory() as temp_directory:
            config_path = os.path.join(temp_directory, "config.json")
            with open(config_path, "w", encoding="utf-8") as config_file:
                json.dump(config_dict, config_file)

            previous_fixtures_dir = os.environ.get("CLOUD_PERM_AUDIT_FIXTURES_DIR")
            os.environ["CLOUD_PERM_AUDIT_FIXTURES_DIR"] = FIXTURES_DIRECTORY
            try:
                collect_manifest = cloud_perm_audit.run_collect(config_path)
            finally:
                if previous_fixtures_dir is None:
                    del os.environ["CLOUD_PERM_AUDIT_FIXTURES_DIR"]
                else:
                    os.environ["CLOUD_PERM_AUDIT_FIXTURES_DIR"] = previous_fixtures_dir

            self.assertTrue(collect_manifest["ok"])
            self.assertEqual(collect_manifest["scoped_role_count"], 3)
            run_directory = collect_manifest["run_directory"]

            analyze_manifest = cloud_perm_audit.run_analyze(run_directory, config_dict)
            self.assertTrue(analyze_manifest["tools_run"]["cloudsplaining"]["ran"])

            findings = cloud_perm_audit.run_normalize(run_directory, config_path)
            self.assertEqual(findings["mode"], "normalize")
            self.assertTrue(findings["redaction_applied"])
            self.assertEqual(findings["account_id"], "ACCOUNT_SELF")
            self.assertEqual(len(findings["roles"]), 3)

            role_names = {role["role_name"] for role in findings["roles"]}
            self.assertEqual(role_names, {"svc-payments-ci-deployer", "svc-data-reader-role", "svc-external-partner-role"})

            payments_role = next(role for role in findings["roles"] if role["role_name"] == "svc-payments-ci-deployer")
            self.assertIn("iam", payments_role["excess_services"])
            self.assertIsNotNone(payments_role["risk_flags"])


if __name__ == "__main__":
    unittest.main()
