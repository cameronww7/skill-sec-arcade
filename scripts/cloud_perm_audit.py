#!/usr/bin/env python3
# ******************************************************************************
# * TITLE:        Cloud Player Perm Audit
# * FILE:         cloud_perm_audit.py
# * PART OF:      cloud-player-perm-audit skill (skill-sec-arcade repo).
# * PURPOSE:      Answers "is this IAM role overprovisioned, and how
# *               risky is the excess" with GRANTED minus USED math owned
# *               entirely by this script, never guessed by the AI layer.
# *               It exists because an AI reading a raw policy document
# *               cannot reliably compute what's actually unused, but it
# *               can explain and rank a pre-computed excess set in plain
# *               language. This script does the former; the skill's
# *               SKILL.md does the latter.
# *
# * HOW IT WORKS: Four independent modes, chosen by the first CLI
# *               argument, meant to run in this order:
# *               1) `preflight <config_path>`: validates the config
# *                  file and makes a handful of cheap, read-only AWS
# *                  calls to confirm credentials and permissions are in
# *                  place before anything expensive runs.
# *               2) `collect <config_path>`: read-only AWS CLI calls
# *                  (get-account-authorization-details, service
# *                  last-accessed reports, CloudTrail Event history,
# *                  role metadata) scoped to the roles the config
# *                  selects. Writes raw JSON to a temp run directory and
# *                  prints a small manifest, never the raw data itself.
# *               3) `analyze <run_directory> <config_path>`: shells out
# *                  to cloudsplaining (required) and, if enabled,
# *                  parliament and pmapper (both optional), against the
# *                  file collect wrote. No AWS calls in this mode.
# *               4) `normalize <run_directory> <config_path>`: pure
# *                  Python. Computes GRANTED - USED = EXCESS per role,
# *                  quarantines anything that can't be verified into
# *                  unknown_usage, folds in cloudsplaining's risk
# *                  categories, and redacts account IDs/ARNs before
# *                  printing `findings.json` to stdout. This is the only
# *                  mode whose output is meant for Claude to read in
# *                  full; the other three only ever print small
# *                  manifests.
# *
# * USAGE:        python3 cloud_perm_audit.py preflight config.json
# *               python3 cloud_perm_audit.py collect config.json
# *               python3 cloud_perm_audit.py analyze /tmp/run_dir config.json
# *               python3 cloud_perm_audit.py normalize /tmp/run_dir config.json
# * ARGUMENTS:    mode (positional, str, required) - one of preflight,
# *               collect, analyze, normalize.
# *               config_path (positional, str, required in every mode) -
# *               path to this skill's JSON config file (aws_profile,
# *               scope, observation_window_days, model_location,
# *               profile_arn_allowlist, pinned_tool_versions,
# *               enable_parliament, enable_pmapper).
# *               run_directory (positional, str, required for analyze
# *               and normalize) - the temp directory `collect` created
# *               and printed in its manifest's "run_directory" field.
# * INPUTS:       preflight/collect: live AWS API calls via the `aws` CLI
# *               under the configured profile. analyze: the files
# *               collect wrote, plus the cloudsplaining (required) and
# *               parliament/pmapper (optional) binaries. normalize: the
# *               files collect and analyze wrote. No mode reads
# *               anything from the repo being reviewed by other skills
# *               in this plugin; this script only ever talks to AWS and
# *               to locally-installed IAM tooling.
# * OUTPUTS:      One JSON object printed to stdout per invocation.
# *               collect and analyze also write raw JSON files into the
# *               run directory for the next mode to read; normalize
# *               reads those files but writes nothing itself, it only
# *               prints findings.json.
# * EXIT CODES:   0 = success. 1 = missing/invalid CLI arguments, an
# *               unrecognized mode, or a config file that doesn't exist
# *               or isn't valid JSON.
# * DEPENDENCIES: Python 3 standard library only (datetime, fnmatch,
# *               json, os, re, subprocess, sys, tempfile, time). Shells
# *               out to the `aws` CLI v2 (required), `cloudsplaining`
# *               (required), and optionally `parliament`/`pmapper`, all
# *               installed separately by the user, never bundled here.
# * PERMISSIONS:  preflight/collect: read-only AWS API calls under the
# *               configured profile (see the required-permissions list
# *               in this skill's SKILL.md). analyze/normalize: no AWS
# *               access at all, local filesystem and subprocess only.
# * ASSUMPTIONS:  The config file's aws_profile is a read-only role; this
# *               script never calls an AWS API that creates, modifies,
# *               or deletes anything. normalize assumes collect and
# *               analyze already ran against the same run_directory.
# * FAILURE MODES:A collection error for one role (e.g. a last-accessed
# *               job that times out) is recorded in collect's
# *               "collection_errors" list rather than aborting the whole
# *               run; normalize then reports that role's affected
# *               fields as unknown rather than guessing. cloudsplaining
# *               failing to run is recorded in analyze's "errors" list;
# *               normalize then reports an empty risk_flags list for
# *               every role and says why, it never invents a risk
# *               verdict cloudsplaining didn't actually produce.
# * SAFE TO RERUN:Yes. Every mode is read-only with respect to AWS.
# *               collect/analyze write into a fresh temp directory each
# *               run (never reused), so reruns never corrupt a prior
# *               run's data.
# *
# * AUTHOR:       cameronww7
# * LAST UPDATED: 2026-10-10
# ******************************************************************************

"""Collects and normalizes AWS IAM role permission data so an AI layer can
explain and rank excess permissions without ever computing GRANTED - USED
math itself. See the module-level comment block above for the full
four-mode pipeline (preflight, collect, analyze, normalize).

This script never calls AWS from `analyze` or `normalize`, and never
writes or changes anything in AWS from any mode. It is read-only and
advisory-only end to end.
"""

import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone


# ===== CONFIGURATION =====

# This skill reads/writes JSON for its own IPC between modes, and tests
# have confirmed Python 3.10-3.14 all work correctly against this script;
# PYTHON_MAX_VERSION reflects the pinned range from preflight's design
# brief (cloudsplaining's own stated minimum is 3.10), not a hard
# technical ceiling in this file itself.
PYTHON_MIN_VERSION = (3, 10)
PYTHON_MAX_VERSION = (3, 12)

DEFAULT_OBSERVATION_WINDOW_DAYS = 90

# Real-world timings observed while building this script: a single `aws`
# CLI call is almost always a one-off network round trip; 60s gives wide
# margin without letting one hung call stall an entire run indefinitely.
AWS_CLI_TIMEOUT_SECONDS = 60
PIP_SHOW_TIMEOUT_SECONDS = 15
EXTERNAL_TOOL_TIMEOUT_SECONDS = 180

# A service last-accessed job is usually done in a few seconds; this caps
# the worst case at one minute per role (30 attempts x 2s) rather than
# polling forever if a job never completes.
LAST_ACCESSED_POLL_INTERVAL_SECONDS = 2
LAST_ACCESSED_MAX_POLL_ATTEMPTS = 30

# Bounds the worst case for any manually-paginated `aws` CLI loop in
# this script (get-account-authorization-details, cloudtrail
# lookup-events), one page per `aws` call, so a very large account or a
# very noisy CloudTrail history can't turn `collect` into an unbounded loop.
AWS_PAGINATION_MAX_PAGES = 50

# These calls are not fully covered by free CloudTrail management-event
# history, and IAM last-accessed's action-level tracking is not treated
# as a substitute for them either in this script: granted actions in this
# list are always quarantined into unknown_usage, never counted as
# excess, regardless of what the collected usage data suggests. See
# references/iam-data-coverage-and-tools.md for the fuller explanation.
# Stored lowercase; all comparisons in this script lowercase both sides.
DATA_PLANE_ACTIONS_BY_SERVICE = {
    "s3": {
        "s3:getobject", "s3:putobject", "s3:deleteobject",
        "s3:getobjectversion", "s3:headobject",
    },
    "dynamodb": {
        "dynamodb:getitem", "dynamodb:putitem", "dynamodb:deleteitem",
        "dynamodb:query", "dynamodb:scan", "dynamodb:updateitem",
        "dynamodb:batchgetitem", "dynamodb:batchwriteitem",
    },
    "lambda": {
        "lambda:invokefunction", "lambda:invokeasync",
    },
}

# The exact category keys cloudsplaining's results JSON uses per policy,
# confirmed against a real `cloudsplaining scan` run (version 0.9.1)
# rather than guessed from its docs alone.
RISK_CATEGORY_NAMES = (
    "PrivilegeEscalation", "DataExfiltration", "ResourceExposure",
    "ServiceWildcard", "CredentialsExposure", "InfrastructureModification",
)

# The CLI binary name (what this script shells out to) is not always the
# PyPI package name (what `pip show` needs); pmapper is the one case
# here where they differ.
PACKAGE_NAME_BY_TOOL = {
    "cloudsplaining": "cloudsplaining",
    "parliament": "parliament",
    "pmapper": "principalmapper",
}

USAGE_MESSAGE = (
    "usage: cloud_perm_audit.py preflight <config_path> | "
    "collect <config_path> | "
    "analyze <run_directory> <config_path> | "
    "normalize <run_directory> <config_path>"
)

PIP_SHOW_VERSION_PATTERN = re.compile(r"^Version:\s*(.+)$", re.MULTILINE)
ARN_PATTERN = re.compile(
    r"arn:aws:[A-Za-z0-9\-]+:[A-Za-z0-9\-]*:(?:\d{12})?:[^\s\"',}\]]+"
)
BARE_ACCOUNT_ID_PATTERN = re.compile(r"(?<!\d)\d{12}(?!\d)")
ACCOUNT_ID_IN_ARN_PATTERN = re.compile(r"^arn:aws:[^:]*:[^:]*:(\d{12}):")
ROLE_NAME_FROM_ASSUMED_ROLE_ARN_PATTERN = re.compile(r":assumed-role/([^/]+)/")
ROLE_NAME_FROM_IAM_ROLE_ARN_PATTERN = re.compile(r":role/(?:.*/)?([^/]+)$")

LIMITATIONS_TEXT = [
    "Data-plane calls (S3 object reads, DynamoDB item reads, Lambda "
    "invoke) are quarantined into unknown_usage and never counted as "
    "excess, even when the collected usage data suggests they are unused.",
    "Action-level last-accessed data only covers a subset of AWS "
    "services; other services receive a service-level-only verdict and "
    "their granted actions are reported as unknown rather than excess.",
    "The observation_window_days above is what this run actually "
    "covers; IAM last-accessed data itself can look back up to 400 "
    "days, which may not match this window.",
    "Findings reflect identity policies only (inline and attached "
    "managed policies). Service control policies and permission "
    "boundaries are not evaluated, so real effective access may be "
    "lower than what is reported as granted.",
    "This tool evaluates Allow statements only; explicit Deny "
    "statements and NotAction clauses are not evaluated, so computed "
    "granted permissions may be broader than what a role can actually "
    "do once Deny statements are applied.",
    "Single AWS account per run.",
    "This report is advisory text only. Nothing here is applied to AWS.",
]


# ===== HELPERS: FILESYSTEM AND SMALL UTILITIES =====

################################################################################
# FUNCTION: read_json_file
#
# PURPOSE
#     Reads a JSON file written by an earlier mode of this same script
#     without ever raising, so a missing or corrupted intermediate file
#     degrades to an honest "no data" rather than crashing the whole run.
#
# RESPONSIBILITIES
#     - Open and parse the file at the given path as JSON.
#     - Return None for any failure instead of raising.
#
# PROCESS OVERVIEW
#     1. Attempt to open and read the file.
#     2. Attempt to parse its contents as JSON.
#     3. Return the parsed value, or None if either step failed.
#
# IMPORTANT DETAILS
#     - Callers must treat None as "not available," distinct from an
#       empty dict or list, which mean the file existed and was valid
#       JSON but genuinely had nothing in it.
#
# PARAMETERS
#     path (str)
#         Filesystem path to read.
#
# RETURNS
#     Any or None
#         The parsed JSON value, or None if the file is missing, unreadable,
#         or not valid JSON.
#
# FAILURE CASES
#     - File does not exist or is unreadable: returns None.
#     - File content is not valid JSON: returns None.
################################################################################
def read_json_file(path):
    """Reads path as JSON, returning None on any failure instead of
    raising."""
    try:
        with open(path, "r", encoding="utf-8") as file_handle:
            return json.load(file_handle)
    except (OSError, ValueError):
        return None


################################################################################
# FUNCTION: write_json_file
#
# PURPOSE
#     Writes a Python value to disk as indented JSON, the single choke
#     point every collect/analyze function uses to persist intermediate
#     data for the next mode to read.
#
# RESPONSIBILITIES
#     - Serialize the given value as JSON.
#     - Write it to the given path.
#
# PROCESS OVERVIEW
#     1. Open the target path for writing.
#     2. Serialize and write the value as indented JSON.
#
# IMPORTANT DETAILS
#     - Overwrites the target path unconditionally; callers are
#       responsible for choosing a path that's safe to overwrite (always
#       a fresh temp run directory in this script, never a path under
#       the account being reviewed or any save-state location).
#
# PARAMETERS
#     path (str)
#         Filesystem path to write.
#     value (Any)
#         Any JSON-serializable Python value.
#
# RETURNS
#     None
#
# FAILURE CASES
#     - Target directory does not exist or isn't writable: raises OSError,
#       intentionally not caught here since a failed write is a real
#       problem the caller's mode should surface, not silently swallow.
################################################################################
def write_json_file(path, value):
    """Writes value to path as indented JSON, overwriting any existing
    file there."""
    with open(path, "w", encoding="utf-8") as file_handle:
        json.dump(value, file_handle, indent=2)


################################################################################
# FUNCTION: coerce_value_to_list
#
# PURPOSE
#     IAM policy JSON allows a field to be either a single string or a
#     list of strings (e.g. a Principal's "AWS" value, or an Action
#     value). This normalizes both shapes into a list so callers never
#     need to branch on which shape they received.
#
# RESPONSIBILITIES
#     - Return an empty list for a missing value.
#     - Wrap a single string in a one-element list.
#     - Pass an existing list through as a list.
#
# PROCESS OVERVIEW
#     1. If the value is None, return an empty list.
#     2. If the value is a string, return a one-element list containing it.
#     3. Otherwise, return it converted to a list.
#
# IMPORTANT DETAILS
#     - None of this file's callers pass anything other than None, a
#       string, or a list/tuple here; a dict or other type would raise
#       inside list(), which is an acceptable failure since it would
#       indicate malformed policy JSON this script doesn't know how to
#       interpret anyway.
#
# PARAMETERS
#     value (str, list, tuple, or None)
#         The raw policy field value.
#
# RETURNS
#     list
#         Always a list, never a bare string or None.
#
# FAILURE CASES
#     - None.
################################################################################
def coerce_value_to_list(value):
    """Normalizes a policy field that may be a bare string, a list, or
    missing entirely into a plain list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


# ===== HELPERS: CONFIG =====

################################################################################
# FUNCTION: load_config
#
# PURPOSE
#     Reads this skill's JSON config file and fills in defaults for the
#     optional fields, so every other function in this script can assume
#     a fully-populated config dict rather than re-checking for missing
#     optional keys itself.
#
# RESPONSIBILITIES
#     - Parse the config file as JSON.
#     - Apply defaults for observation_window_days, enable_parliament,
#       enable_pmapper, profile_arn_allowlist, and pinned_tool_versions.
#
# PROCESS OVERVIEW
#     1. Attempt to open and parse the config file as JSON.
#     2. Return None immediately on any failure.
#     3. Fill in default values for optional fields that are absent.
#     4. Return the resulting dict.
#
# IMPORTANT DETAILS
#     - Does not validate required fields; that is
#       config_validation_errors()'s job, kept separate so a caller can
#       distinguish "file not found/not JSON" (this function returning
#       None) from "file parsed fine but is missing required fields"
#       (this function returning a dict that config_validation_errors()
#       then flags).
#     - model_location is deliberately NOT defaulted here; its absence is
#       meaningful and is resolved explicitly by resolve_model_location()
#       at the point of use, fail-safe to "hosted".
#
# PARAMETERS
#     config_path (str)
#         Path to the JSON config file.
#
# RETURNS
#     dict or None
#         The parsed, defaults-filled config, or None if the file is
#         missing, unreadable, or not valid JSON.
#
# FAILURE CASES
#     - Config file missing, unreadable, or not valid JSON: returns None.
################################################################################
def load_config(config_path):
    """Reads and parses config_path as JSON, filling in defaults for
    optional fields. Returns None if the file is missing or invalid."""
    raw_config = read_json_file(config_path)
    if raw_config is None or not isinstance(raw_config, dict):
        return None

    config_dict = dict(raw_config)
    config_dict.setdefault("observation_window_days", DEFAULT_OBSERVATION_WINDOW_DAYS)
    config_dict.setdefault("enable_parliament", False)
    config_dict.setdefault("enable_pmapper", False)
    config_dict.setdefault("profile_arn_allowlist", [])
    config_dict.setdefault("pinned_tool_versions", {})
    return config_dict


################################################################################
# FUNCTION: config_validation_errors
#
# PURPOSE
#     Produces a human-readable list of everything wrong with a parsed
#     config, so preflight can report every missing field at once rather
#     than making the user fix and rerun one error at a time.
#
# RESPONSIBILITIES
#     - Check aws_profile is present.
#     - Check scope is a well-formed tag or role_prefix scope.
#     - Check profile_arn_allowlist is a non-empty list.
#     - Check pinned_tool_versions.cloudsplaining is present (the one
#       tool this skill cannot run without).
#
# PROCESS OVERVIEW
#     1. Check each required field/shape in turn.
#     2. Collect a human-readable error string for each one that's
#        missing or malformed.
#     3. Return the full list (empty list means the config is valid).
#
# IMPORTANT DETAILS
#     - model_location is intentionally never validated as "required"
#       here; an absent or invalid value has a defined, safe fallback
#       (resolve_model_location() treats it as "hosted"), so it is not a
#       blocking configuration error.
#
# PARAMETERS
#     config_dict (dict)
#         A config dict as returned by load_config().
#
# RETURNS
#     list[str]
#         One human-readable error string per problem found. Empty list
#         means the config is valid.
#
# FAILURE CASES
#     - None; this function only inspects its input, it never raises.
################################################################################
def config_validation_errors(config_dict):
    """Returns a list of human-readable error strings for every missing
    or malformed required field in config_dict. Empty list means valid."""
    errors = []

    if not config_dict.get("aws_profile"):
        errors.append("config is missing required field: aws_profile")

    scope = config_dict.get("scope")
    if not isinstance(scope, dict) or scope.get("type") not in ("tag", "role_prefix"):
        errors.append(
            "config is missing a valid scope "
            '({"type": "tag", "tag_key": ..., "tag_value": ...} or '
            '{"type": "role_prefix", "role_prefix": ...})'
        )
    elif scope.get("type") == "tag" and not (scope.get("tag_key") and scope.get("tag_value")):
        errors.append('config scope.type is "tag" but tag_key/tag_value are missing')
    elif scope.get("type") == "role_prefix" and not scope.get("role_prefix"):
        errors.append('config scope.type is "role_prefix" but role_prefix is missing')

    if not config_dict.get("profile_arn_allowlist"):
        errors.append(
            "config is missing required field: profile_arn_allowlist "
            "(must be a non-empty list of ARN glob patterns)"
        )

    if not config_dict.get("pinned_tool_versions", {}).get("cloudsplaining"):
        errors.append("config is missing required field: pinned_tool_versions.cloudsplaining")

    return errors


################################################################################
# FUNCTION: resolve_model_location
#
# PURPOSE
#     Decides, in exactly one place, whether redaction is required before
#     normalize prints findings.json. This is the single source of truth
#     every other part of the pipeline defers to.
#
# RESPONSIBILITIES
#     - Treat the literal string "local" as the only way to disable
#       redaction.
#     - Treat everything else, including a missing or misspelled value,
#       as "hosted".
#
# PROCESS OVERVIEW
#     1. Read config_dict["model_location"].
#     2. Return "local" only if it is exactly the string "local".
#     3. Otherwise return "hosted".
#
# IMPORTANT DETAILS
#     - This fail-safe direction is deliberate: a typo or an unset field
#       must never silently skip redaction. Getting this wrong in the
#       other direction (defaulting to "local") would be a data exposure
#       bug, not just a cosmetic one.
#
# PARAMETERS
#     config_dict (dict)
#         A config dict as returned by load_config().
#
# RETURNS
#     str
#         Exactly "local" or "hosted".
#
# FAILURE CASES
#     - None.
################################################################################
def resolve_model_location(config_dict):
    """Returns "local" only if config_dict["model_location"] is exactly
    "local"; anything else, including missing or misspelled, resolves to
    "hosted" so redaction fails safe."""
    return "local" if config_dict.get("model_location") == "local" else "hosted"


# ===== HELPERS: AWS CLI AND EXTERNAL TOOLS =====

################################################################################
# FUNCTION: run_aws_cli_json
#
# PURPOSE
#     The single choke point every AWS-calling function in this script
#     routes through. Exists so every caller handles a failed, timed-out,
#     or malformed `aws` CLI invocation the exact same way, instead of
#     each collection function reimplementing its own subprocess and
#     JSON-parsing error handling.
#
# RESPONSIBILITIES
#     - Run the `aws` CLI with the given arguments under the given
#       profile, forcing JSON output.
#     - Parse stdout as JSON on success.
#     - Never raise; report failure in the returned dict instead.
#
# PROCESS OVERVIEW
#     1. Build the full `aws ... --profile <profile> --output json`
#        command line.
#     2. Run it as a subprocess, bounded by AWS_CLI_TIMEOUT_SECONDS.
#     3. If the process can't even start, or times out, report failure.
#     4. If it exits non-zero, report failure with its stderr text.
#     5. If stdout is empty, treat that as a successful call with no data.
#     6. Otherwise parse stdout as JSON; report failure if it isn't valid.
#
# IMPORTANT DETAILS
#     - Makes exactly one live network call to AWS per invocation.
#     - Deliberately does not retry; a bounded retry loop belongs to a
#       specific caller that knows retrying is appropriate (e.g.
#       poll_last_accessed_job()), not to this generic helper.
#
# PARAMETERS
#     command_args (list[str])
#         The `aws` subcommand and its arguments, e.g.
#         ["iam", "get-role", "--role-name", "foo"]. Must not include
#         --profile or --output, this function adds those itself.
#     aws_profile (str)
#         The AWS CLI profile name to run under.
#
# RETURNS
#     dict
#         {"ok": bool, "data": dict or None, "stderr": str, "returncode": int or None}.
#         "data" is the parsed JSON on success, None on any failure.
#
# FAILURE CASES
#     - `aws` binary not found, or the call times out: ok=False, returncode=None.
#     - Non-zero exit: ok=False, stderr carries the CLI's error message.
#     - Stdout is not valid JSON: ok=False.
################################################################################
def run_aws_cli_json(command_args, aws_profile):
    """Runs `aws <command_args> --profile <aws_profile> --output json`,
    returning {"ok", "data", "stderr", "returncode"}. Never raises."""
    full_command = ["aws"] + command_args + ["--profile", aws_profile, "--output", "json"]
    try:
        completed_process = subprocess.run(
            full_command, capture_output=True, text=True, timeout=AWS_CLI_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ok": False, "data": None, "stderr": str(error), "returncode": None}

    if completed_process.returncode != 0:
        return {
            "ok": False, "data": None,
            "stderr": completed_process.stderr, "returncode": completed_process.returncode,
        }

    stdout_text = completed_process.stdout.strip()
    if not stdout_text:
        return {"ok": True, "data": {}, "stderr": completed_process.stderr, "returncode": 0}

    try:
        parsed_data = json.loads(stdout_text)
    except ValueError:
        return {
            "ok": False, "data": None,
            "stderr": "aws cli returned output that was not valid JSON",
            "returncode": completed_process.returncode,
        }

    return {"ok": True, "data": parsed_data, "stderr": completed_process.stderr, "returncode": 0}


################################################################################
# FUNCTION: get_pip_package_version
#
# PURPOSE
#     Answers "is this third-party tool installed, and at what version"
#     using the same Python/pip environment this script itself is
#     running under, rather than assuming a particular CLI binary
#     exposes a --version flag (several don't, or format it
#     inconsistently).
#
# RESPONSIBILITIES
#     - Run `pip show <package_name>` via the current interpreter.
#     - Extract the Version: line from its output.
#
# PROCESS OVERVIEW
#     1. Run `<sys.executable> -m pip show <package_name>`.
#     2. If that fails to run, times out, or exits non-zero, return None.
#     3. Search its stdout for a line starting with "Version:".
#     4. Return the version string, or None if no such line was found.
#
# IMPORTANT DETAILS
#     - Assumes the tool was pip-installed into the same Python
#       environment running this script. A tool installed into a
#       different venv or via a system package manager would report as
#       not installed here even if its CLI binary is on PATH; this is a
#       deliberate, documented tradeoff (see this skill's README) in
#       exchange for not depending on each tool's own --version flag
#       format.
#
# PARAMETERS
#     package_name (str)
#         The PyPI package name (not necessarily the CLI binary name,
#         see PACKAGE_NAME_BY_TOOL for the one case where they differ).
#
# RETURNS
#     str or None
#         The installed version string, or None if not installed, pip
#         itself isn't available, or the call times out.
#
# FAILURE CASES
#     - Package not installed: `pip show` exits non-zero, returns None.
#     - pip itself unavailable or the call times out: returns None.
################################################################################
def get_pip_package_version(package_name):
    """Returns the installed version of package_name via `pip show`
    under the current interpreter, or None if not installed."""
    try:
        completed_process = subprocess.run(
            [sys.executable, "-m", "pip", "show", package_name],
            capture_output=True, text=True, timeout=PIP_SHOW_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if completed_process.returncode != 0:
        return None

    match = PIP_SHOW_VERSION_PATTERN.search(completed_process.stdout)
    return match.group(1).strip() if match else None


################################################################################
# FUNCTION: is_access_denied_error
#
# PURPOSE
#     Lets preflight's dry-run checks distinguish "this profile isn't
#     authorized to make this call" (a real, actionable configuration
#     problem) from a transient network/throttling failure, without
#     parsing full AWS error response structures.
#
# RESPONSIBILITIES
#     - Recognize the handful of substrings the `aws` CLI's stderr text
#       uses for an authorization failure.
#
# PROCESS OVERVIEW
#     1. Check stderr_text for any of a short list of known
#        authorization-failure substrings.
#     2. Return True if any match, False otherwise (including for an
#        empty/None stderr_text).
#
# IMPORTANT DETAILS
#     - This is a best-effort text match against the AWS CLI's current
#       error message wording, not a parse of a structured error code.
#       It is only ever used for a preflight check's human-readable
#       "detail" field, never for a decision this script takes
#       automatically, so a missed match just means a slightly less
#       specific message, not a wrong pass/fail verdict.
#
# PARAMETERS
#     stderr_text (str or None)
#         The stderr text from a failed `aws` CLI invocation.
#
# RETURNS
#     bool
#         True if stderr_text looks like an authorization failure.
#
# FAILURE CASES
#     - None.
################################################################################
def is_access_denied_error(stderr_text):
    """Returns True if stderr_text looks like an AWS authorization
    failure rather than a transient/other error."""
    if not stderr_text:
        return False
    return (
        "AccessDenied" in stderr_text
        or "is not authorized to perform" in stderr_text
        or "UnauthorizedAccess" in stderr_text
    )


# ===== MODE: PREFLIGHT =====

################################################################################
# FUNCTION: check_python_version
#
# PURPOSE
#     Confirms the Python running this script is within the range this
#     skill's tooling (cloudsplaining's own stated minimum, in
#     particular) is expected to work with, before anything else runs.
#
# RESPONSIBILITIES
#     - Compare the running interpreter's version against
#       PYTHON_MIN_VERSION and PYTHON_MAX_VERSION.
#
# PROCESS OVERVIEW
#     1. Read sys.version_info.
#     2. Compare its (major, minor) against the configured min/max.
#     3. Return a pass/fail check result with the full version string.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     None.
#
# RETURNS
#     dict
#         {"name": "python_version", "status": "pass" or "fail", "detail": str}.
#
# FAILURE CASES
#     - Running interpreter is outside PYTHON_MIN_VERSION..PYTHON_MAX_VERSION:
#       status is "fail".
################################################################################
def check_python_version():
    """Checks the running Python interpreter is within this skill's
    supported version range."""
    version_info = sys.version_info
    version_string = f"{version_info.major}.{version_info.minor}.{version_info.micro}"
    current = (version_info.major, version_info.minor)
    is_supported = PYTHON_MIN_VERSION <= current <= PYTHON_MAX_VERSION
    return {"name": "python_version", "status": "pass" if is_supported else "fail", "detail": version_string}


################################################################################
# FUNCTION: check_aws_cli_v2_installed
#
# PURPOSE
#     Confirms the `aws` CLI is on PATH and is major version 2, since
#     every collection call in this script assumes v2's JSON output
#     behavior.
#
# RESPONSIBILITIES
#     - Run `aws --version` and check its output names version 2.
#
# PROCESS OVERVIEW
#     1. Run `aws --version`.
#     2. If the binary can't be found or the call fails, report failure.
#     3. Check whether its output contains "aws-cli/2.".
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     None.
#
# RETURNS
#     dict
#         {"name": "aws_cli_v2", "status": "pass" or "fail", "detail": str}.
#
# FAILURE CASES
#     - `aws` not found on PATH: status "fail".
#     - `aws --version` reports a v1 (or other) install: status "fail".
################################################################################
def check_aws_cli_v2_installed():
    """Checks the `aws` CLI is on PATH and reports itself as major
    version 2."""
    try:
        completed_process = subprocess.run(
            ["aws", "--version"], capture_output=True, text=True, timeout=AWS_CLI_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"name": "aws_cli_v2", "status": "fail", "detail": "aws CLI not found on PATH"}

    version_text = (completed_process.stdout or completed_process.stderr).strip()
    is_v2 = "aws-cli/2." in version_text
    return {"name": "aws_cli_v2", "status": "pass" if is_v2 else "fail", "detail": version_text or "unknown"}


################################################################################
# FUNCTION: check_required_tool_installed
#
# PURPOSE
#     Confirms a required external tool (currently only cloudsplaining)
#     is pip-installed at the pinned version, so a version drift between
#     devs can't silently change what a run flags as risky.
#
# RESPONSIBILITIES
#     - Resolve tool_key to its PyPI package name.
#     - Check it's installed, and at the pinned version if one was given.
#
# PROCESS OVERVIEW
#     1. Resolve the PyPI package name for tool_key via PACKAGE_NAME_BY_TOOL.
#     2. Look up its installed version with get_pip_package_version().
#     3. Fail if not installed.
#     4. Fail if an expected_version was given and doesn't match.
#     5. Otherwise pass, reporting the installed version.
#
# IMPORTANT DETAILS
#     - A missing expected_version (None or empty string) skips the
#       version match, only presence is checked in that case.
#
# PARAMETERS
#     tool_key (str)
#         One of "cloudsplaining", "parliament", "pmapper".
#     expected_version (str or None)
#         The pinned version from config, or None/empty to skip the
#         version check.
#
# RETURNS
#     dict
#         {"name": "<tool_key>_installed", "status": "pass" or "fail", "detail": str}.
#
# FAILURE CASES
#     - Tool not pip-installed: status "fail".
#     - Installed version doesn't match expected_version: status "fail".
################################################################################
def check_required_tool_installed(tool_key, expected_version):
    """Checks tool_key is pip-installed, and at expected_version if one
    was given."""
    package_name = PACKAGE_NAME_BY_TOOL.get(tool_key, tool_key)
    installed_version = get_pip_package_version(package_name)

    if installed_version is None:
        return {"name": f"{tool_key}_installed", "status": "fail", "detail": f"{tool_key} is not pip-installed"}

    if expected_version and installed_version != expected_version:
        return {
            "name": f"{tool_key}_installed", "status": "fail",
            "detail": f"installed {installed_version}, pinned version is {expected_version}",
        }

    return {"name": f"{tool_key}_installed", "status": "pass", "detail": installed_version}


################################################################################
# FUNCTION: check_optional_tool_preflight
#
# PURPOSE
#     Applies the same installed/pinned-version check as
#     check_required_tool_installed(), but for parliament/pmapper, which
#     are only relevant at all if the config opted into them.
#
# RESPONSIBILITIES
#     - Skip the check entirely, without failing, if the tool isn't
#       enabled in config.
#     - Otherwise delegate to check_required_tool_installed().
#
# PROCESS OVERVIEW
#     1. If is_enabled is False, return a "skipped" result immediately.
#     2. Otherwise return check_required_tool_installed()'s result.
#
# IMPORTANT DETAILS
#     - "skipped" is a distinct status from "pass"/"fail" specifically so
#       preflight's blocking-failure logic never treats an intentionally
#       unused optional tool as a reason to stop the run.
#
# PARAMETERS
#     tool_key (str)
#         "parliament" or "pmapper".
#     expected_version (str or None)
#         The pinned version from config, or None to skip the version check.
#     is_enabled (bool)
#         Whether config opted into this tool (enable_parliament /
#         enable_pmapper).
#
# RETURNS
#     dict
#         {"name": "<tool_key>_installed", "status": "pass"/"fail"/"skipped", "detail": str}.
#
# FAILURE CASES
#     - Enabled but not installed, or installed at the wrong version:
#       status "fail".
################################################################################
def check_optional_tool_preflight(tool_key, expected_version, is_enabled):
    """Checks tool_key is installed at the pinned version, but only if
    is_enabled; otherwise returns a non-blocking "skipped" result."""
    if not is_enabled:
        return {"name": f"{tool_key}_installed", "status": "skipped", "detail": "not enabled in config"}
    return check_required_tool_installed(tool_key, expected_version)


################################################################################
# FUNCTION: check_caller_identity
#
# PURPOSE
#     Confirms the configured AWS profile can actually authenticate, and
#     captures the caller's ARN for the allowlist check and the
#     assumed-role dry-run checks that follow it.
#
# RESPONSIBILITIES
#     - Call sts:GetCallerIdentity under the configured profile.
#
# PROCESS OVERVIEW
#     1. Call `aws sts get-caller-identity`.
#     2. Return a failing check result and None if it fails.
#     3. Otherwise return a passing check result and the caller's ARN.
#
# IMPORTANT DETAILS
#     - Every subsequent preflight check that needs the caller's own ARN
#       (the allowlist check, the probe-role-name derivation) depends on
#       this one succeeding first.
#
# PARAMETERS
#     aws_profile (str)
#         The AWS CLI profile name to check.
#
# RETURNS
#     tuple[dict, str or None]
#         (check_result, caller_arn). caller_arn is None if the call failed.
#
# FAILURE CASES
#     - Call fails (bad credentials, network issue, etc.): check_result's
#       status is "fail", caller_arn is None.
################################################################################
def check_caller_identity(aws_profile):
    """Calls sts:GetCallerIdentity under aws_profile, returning
    (check_result, caller_arn_or_None)."""
    response = run_aws_cli_json(["sts", "get-caller-identity"], aws_profile)
    if not response["ok"]:
        return {"name": "caller_identity", "status": "fail", "detail": response["stderr"]}, None

    caller_arn = response["data"].get("Arn")
    return {"name": "caller_identity", "status": "pass", "detail": caller_arn}, caller_arn


################################################################################
# FUNCTION: check_profile_arn_allowlisted
#
# PURPOSE
#     Stops someone from accidentally running this skill with an
#     over-privileged profile by requiring the caller's ARN to match a
#     configured allowlist of designated read-only roles.
#
# RESPONSIBILITIES
#     - Match caller_arn against every glob pattern in allowlist.
#
# PROCESS OVERVIEW
#     1. If caller_arn is None (the identity check already failed), fail
#        immediately.
#     2. Check caller_arn against each pattern in allowlist using glob
#        matching.
#     3. Pass if any pattern matches, fail otherwise.
#
# IMPORTANT DETAILS
#     - Uses shell-glob-style matching (fnmatch), not regex, so config
#       authors can write patterns like
#       "arn:aws:sts::*:assumed-role/readonly-iam-auditor/*" without
#       needing to escape regex metacharacters.
#
# PARAMETERS
#     caller_arn (str or None)
#         The ARN from check_caller_identity(), or None if that check failed.
#     allowlist (list[str])
#         Glob patterns from config's profile_arn_allowlist.
#
# RETURNS
#     dict
#         {"name": "profile_arn_allowlisted", "status": "pass" or "fail", "detail": str}.
#
# FAILURE CASES
#     - caller_arn is None: status "fail".
#     - caller_arn matches none of allowlist's patterns: status "fail".
################################################################################
def check_profile_arn_allowlisted(caller_arn, allowlist):
    """Checks caller_arn matches at least one glob pattern in
    allowlist."""
    if not caller_arn:
        return {
            "name": "profile_arn_allowlisted", "status": "fail",
            "detail": "no caller ARN available (caller_identity check failed)",
        }

    is_allowed = any(fnmatch.fnmatch(caller_arn, pattern) for pattern in allowlist)
    return {"name": "profile_arn_allowlisted", "status": "pass" if is_allowed else "fail", "detail": caller_arn}


################################################################################
# FUNCTION: extract_role_name_from_arn
#
# PURPOSE
#     Pulls a role name out of either an IAM role ARN
#     (arn:aws:iam::<acct>:role/<path>/<name>) or an STS assumed-role
#     session ARN (arn:aws:sts::<acct>:assumed-role/<name>/<session>),
#     the two ARN shapes this script needs to recognize a role by name
#     from.
#
# RESPONSIBILITIES
#     - Try the assumed-role pattern first (the more common shape seen in
#       CloudTrail events and STS caller identities).
#     - Fall back to the IAM role ARN pattern.
#
# PROCESS OVERVIEW
#     1. Return None immediately for an empty/None input.
#     2. Try matching the assumed-role pattern; return its captured name
#        if found.
#     3. Try matching the IAM role ARN pattern; return its captured name
#        if found.
#     4. Return None if neither matched.
#
# IMPORTANT DETAILS
#     - A user or root principal ARN matches neither pattern and
#       correctly returns None; callers must treat that as "not a role",
#       not as an error.
#
# PARAMETERS
#     arn (str or None)
#         The ARN to extract a role name from.
#
# RETURNS
#     str or None
#         The role name, or None if arn is empty or isn't a role/assumed-role ARN.
#
# FAILURE CASES
#     - arn is a user or root ARN: returns None.
#     - arn is malformed: returns None.
################################################################################
def extract_role_name_from_arn(arn):
    """Extracts a role name from either an IAM role ARN or an STS
    assumed-role session ARN. Returns None if arn is neither."""
    if not arn:
        return None

    assumed_role_match = ROLE_NAME_FROM_ASSUMED_ROLE_ARN_PATTERN.search(arn)
    if assumed_role_match:
        return assumed_role_match.group(1)

    iam_role_match = ROLE_NAME_FROM_IAM_ROLE_ARN_PATTERN.search(arn)
    if iam_role_match:
        return iam_role_match.group(1)

    return None


################################################################################
# FUNCTION: check_dry_run_get_account_authorization_details
#
# PURPOSE
#     Confirms the profile can call the one API the entire `collect`
#     mode depends on most, before the real run makes that call for real
#     across potentially hundreds of roles.
#
# RESPONSIBILITIES
#     - Make a minimal get-account-authorization-details call.
#
# PROCESS OVERVIEW
#     1. Call `aws iam get-account-authorization-details --max-items 1`.
#     2. Report pass/fail based on whether it succeeded.
#
# IMPORTANT DETAILS
#     - --max-items 1 keeps this check cheap regardless of account size;
#       it is not meant to validate pagination, only authorization.
#
# PARAMETERS
#     aws_profile (str)
#         The AWS CLI profile name to check.
#
# RETURNS
#     dict
#         {"name": "dry_run_get_account_authorization_details", "status": "pass" or "fail", "detail": str or None}.
#
# FAILURE CASES
#     - Call fails for any reason (most commonly AccessDenied): status "fail".
################################################################################
def check_dry_run_get_account_authorization_details(aws_profile):
    """Makes a minimal get-account-authorization-details call to confirm
    authorization before the real collect run makes it at scale."""
    response = run_aws_cli_json(
        ["iam", "get-account-authorization-details", "--max-items", "1"], aws_profile,
    )
    if response["ok"]:
        return {"name": "dry_run_get_account_authorization_details", "status": "pass", "detail": None}
    return {
        "name": "dry_run_get_account_authorization_details", "status": "fail",
        "detail": response["stderr"],
    }


################################################################################
# FUNCTION: check_dry_run_get_role_and_list_role_tags
#
# PURPOSE
#     Confirms the profile can call get-role and list-role-tags, the two
#     calls `collect`'s role-metadata step depends on, using the caller's
#     own role as a free, always-available probe target.
#
# RESPONSIBILITIES
#     - Call get-role and list-role-tags against probe_role_name.
#
# PROCESS OVERVIEW
#     1. If probe_role_name is None (caller isn't an assumed-role
#        principal), skip this check rather than failing it.
#     2. Call get-role against probe_role_name; fail if it fails.
#     3. Call list-role-tags against probe_role_name; fail if it fails.
#     4. Pass if both succeeded.
#
# IMPORTANT DETAILS
#     - A "skipped" result here is not a failure: it just means the
#       caller used to run this skill is a user or root principal, not a
#       role, so there's no free probe target. The real collect run can
#       still succeed against whatever roles the scope config selects.
#
# PARAMETERS
#     aws_profile (str)
#         The AWS CLI profile name to check.
#     probe_role_name (str or None)
#         The caller's own role name, from derive_probe_role_name(), or
#         None if the caller isn't an assumed-role principal.
#
# RETURNS
#     dict
#         {"name": "dry_run_get_role_and_list_role_tags", "status": "pass"/"fail"/"skipped", "detail": str or None}.
#
# FAILURE CASES
#     - get-role or list-role-tags fails against the probe role: status "fail".
################################################################################
def check_dry_run_get_role_and_list_role_tags(aws_profile, probe_role_name):
    """Checks get-role and list-role-tags both succeed against
    probe_role_name, skipping entirely if there's no probe role
    available."""
    if not probe_role_name:
        return {
            "name": "dry_run_get_role_and_list_role_tags", "status": "skipped",
            "detail": "caller is not an assumed-role principal",
        }

    role_response = run_aws_cli_json(["iam", "get-role", "--role-name", probe_role_name], aws_profile)
    if not role_response["ok"]:
        return {
            "name": "dry_run_get_role_and_list_role_tags", "status": "fail",
            "detail": role_response["stderr"],
        }

    tags_response = run_aws_cli_json(["iam", "list-role-tags", "--role-name", probe_role_name], aws_profile)
    if not tags_response["ok"]:
        return {
            "name": "dry_run_get_role_and_list_role_tags", "status": "fail",
            "detail": tags_response["stderr"],
        }

    return {"name": "dry_run_get_role_and_list_role_tags", "status": "pass", "detail": None}


################################################################################
# FUNCTION: check_dry_run_service_last_accessed
#
# PURPOSE
#     Confirms the profile can both start and read back a service
#     last-accessed job, the two-call sequence `collect` depends on for
#     every scoped role.
#
# RESPONSIBILITIES
#     - Call generate-service-last-accessed-details against the caller's
#       own ARN, then one get-service-last-accessed-details poll.
#
# PROCESS OVERVIEW
#     1. If caller_arn is None, skip this check.
#     2. Call generate-service-last-accessed-details against caller_arn.
#     3. Call get-service-last-accessed-details once against the
#        returned job ID, not waiting for completion, only confirming
#        the call itself is authorized.
#
# IMPORTANT DETAILS
#     - Deliberately makes only one poll call rather than waiting for the
#       job to finish; this check exists to validate permissions, not to
#       exercise the full polling loop (poll_last_accessed_job() in
#       `collect` does that).
#
# PARAMETERS
#     aws_profile (str)
#         The AWS CLI profile name to check.
#     caller_arn (str or None)
#         The caller's own ARN, used as the probe target.
#
# RETURNS
#     dict
#         {"name": "dry_run_service_last_accessed", "status": "pass"/"fail"/"skipped", "detail": str or None}.
#
# FAILURE CASES
#     - generate- or get-service-last-accessed-details fails: status "fail".
################################################################################
def check_dry_run_service_last_accessed(aws_profile, caller_arn):
    """Checks generate-service-last-accessed-details and one
    get-service-last-accessed-details poll both succeed against
    caller_arn."""
    if not caller_arn:
        return {
            "name": "dry_run_service_last_accessed", "status": "skipped",
            "detail": "no caller ARN available",
        }

    generate_response = run_aws_cli_json(
        ["iam", "generate-service-last-accessed-details", "--arn", caller_arn], aws_profile,
    )
    if not generate_response["ok"]:
        return {
            "name": "dry_run_service_last_accessed", "status": "fail",
            "detail": generate_response["stderr"],
        }

    job_id = generate_response["data"].get("JobId")
    if not job_id:
        return {
            "name": "dry_run_service_last_accessed", "status": "fail",
            "detail": "generate-service-last-accessed-details returned no JobId",
        }

    poll_response = run_aws_cli_json(["iam", "get-service-last-accessed-details", "--job-id", job_id], aws_profile)
    if not poll_response["ok"]:
        return {
            "name": "dry_run_service_last_accessed", "status": "fail",
            "detail": poll_response["stderr"],
        }

    return {"name": "dry_run_service_last_accessed", "status": "pass", "detail": None}


################################################################################
# FUNCTION: check_cloudtrail_lookup_events
#
# PURPOSE
#     Confirms the profile can call CloudTrail's LookupEvents, the call
#     `collect` depends on for action-level usage data on services that
#     last-accessed only tracks at the service level.
#
# RESPONSIBILITIES
#     - Make a minimal lookup-events call.
#
# PROCESS OVERVIEW
#     1. Call `aws cloudtrail lookup-events --max-results 1`.
#     2. Report pass/fail based on whether it succeeded.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     aws_profile (str)
#         The AWS CLI profile name to check.
#
# RETURNS
#     dict
#         {"name": "cloudtrail_lookup_events", "status": "pass" or "fail", "detail": str or None}.
#
# FAILURE CASES
#     - Call fails for any reason: status "fail".
################################################################################
def check_cloudtrail_lookup_events(aws_profile):
    """Makes a minimal cloudtrail lookup-events call to confirm
    authorization."""
    response = run_aws_cli_json(["cloudtrail", "lookup-events", "--max-results", "1"], aws_profile)
    if response["ok"]:
        return {"name": "cloudtrail_lookup_events", "status": "pass", "detail": None}
    return {"name": "cloudtrail_lookup_events", "status": "fail", "detail": response["stderr"]}


################################################################################
# FUNCTION: check_scope_configured
#
# PURPOSE
#     Confirms the config's scope selection (which roles this run will
#     touch) is present and internally consistent before collect tries
#     to use it.
#
# RESPONSIBILITIES
#     - Validate the scope shape matches one of the two supported types.
#
# PROCESS OVERVIEW
#     1. Read config_dict["scope"].
#     2. Check it's a "tag" scope with both tag_key and tag_value set, or
#        a "role_prefix" scope with role_prefix set.
#     3. Pass or fail accordingly.
#
# IMPORTANT DETAILS
#     - This duplicates part of config_validation_errors()'s scope
#       check, deliberately: config_validation_errors() is checked
#       before any AWS calls are made at all (fail fast on a broken
#       config), while this check exists so the full checks list in
#       preflight's output always shows a scope_configured entry for a
#       human skimming the report, even though a genuinely invalid scope
#       would already have stopped the run earlier.
#
# PARAMETERS
#     config_dict (dict)
#         A config dict as returned by load_config().
#
# RETURNS
#     dict
#         {"name": "scope_configured", "status": "pass" or "fail", "detail": str}.
#
# FAILURE CASES
#     - scope is missing or doesn't match either supported shape: status "fail".
################################################################################
def check_scope_configured(config_dict):
    """Checks config_dict's scope is a well-formed tag or role_prefix
    scope."""
    scope = config_dict.get("scope") or {}
    scope_type = scope.get("type")

    if scope_type == "tag" and scope.get("tag_key") and scope.get("tag_value"):
        return {"name": "scope_configured", "status": "pass", "detail": f"tag {scope['tag_key']}={scope['tag_value']}"}

    if scope_type == "role_prefix" and scope.get("role_prefix"):
        return {"name": "scope_configured", "status": "pass", "detail": f"role_prefix={scope['role_prefix']}"}

    return {
        "name": "scope_configured", "status": "fail",
        "detail": 'scope must be {"type": "tag", ...} or {"type": "role_prefix", ...}',
    }


################################################################################
# FUNCTION: check_model_location_configured
#
# PURPOSE
#     Surfaces, in preflight's output, exactly which redaction behavior
#     this run will use, since a missing or invalid model_location is
#     not a blocking error (it fails safe to "hosted") but is still
#     worth stating loudly rather than leaving silent.
#
# RESPONSIBILITIES
#     - Report whether model_location was explicitly and validly set,
#       and what it resolves to either way.
#
# PROCESS OVERVIEW
#     1. Read the raw model_location value from config.
#     2. Resolve it via resolve_model_location().
#     3. Always return status "pass"; the detail field states whether
#        the value was explicit or defaulted.
#
# IMPORTANT DETAILS
#     - Always passes by design: the fail-safe default (hosted ->
#       redaction on) is itself safe, so an unset/invalid value is a
#       loud warning in "detail", never a blocking failure.
#
# PARAMETERS
#     config_dict (dict)
#         A config dict as returned by load_config().
#
# RETURNS
#     dict
#         {"name": "model_location_configured", "status": "pass", "detail": str}.
#
# FAILURE CASES
#     - None; this check never fails.
################################################################################
def check_model_location_configured(config_dict):
    """Reports whether model_location was explicitly set, and what it
    resolves to. Always passes; an unset/invalid value is a loud warning
    in "detail", not a failure."""
    raw_value = config_dict.get("model_location")
    resolved = resolve_model_location(config_dict)
    if raw_value in ("local", "hosted"):
        return {"name": "model_location_configured", "status": "pass", "detail": resolved}
    return {
        "name": "model_location_configured", "status": "pass",
        "detail": f"not set or invalid, defaulting to {resolved} (redaction forced on)",
    }


################################################################################
# FUNCTION: run_preflight
#
# PURPOSE
#     Orchestrates every preflight check in order and decides whether
#     this run is safe to proceed, so SKILL.md's Step 0 can stop with a
#     clear, complete picture rather than failing partway through a real
#     collection run.
#
# RESPONSIBILITIES
#     - Load and validate the config file first, before any AWS calls.
#     - Run every check in sequence, building the full checks list.
#     - Decide overall ok/not-ok from whether any check's status is "fail".
#
# PROCESS OVERVIEW
#     1. Load the config file; fail immediately if it's missing or invalid.
#     2. Validate required config fields; fail immediately if any are missing.
#     3. Run the tool-installation checks (python, aws cli, cloudsplaining,
#        parliament, pmapper).
#     4. Run check_caller_identity(), capturing the caller ARN for later checks.
#     5. Run the allowlist, dry-run, and scope/model-location checks.
#     6. Collect every check with status "fail" into blocking_failures.
#     7. Return the full result.
#
# IMPORTANT DETAILS
#     - "skipped" checks never count as blocking failures; only "fail" does.
#     - Config problems short-circuit before any AWS call is made, so a
#       broken config never burns API calls or produces a misleading
#       partial checks list.
#
# PARAMETERS
#     config_path (str)
#         Path to the JSON config file.
#
# RETURNS
#     dict
#         {"mode": "preflight", "ok": bool, "checks": list[dict], "blocking_failures": list[str]}.
#
# FAILURE CASES
#     - Config file missing/invalid, or missing required fields: returns
#       immediately with ok=False and an empty checks list.
#     - Any individual check failing: reflected in blocking_failures and ok=False.
################################################################################
def run_preflight(config_path):
    """Runs every preflight check in order and returns the full result,
    stopping before any AWS call if the config itself is invalid."""
    config_dict = load_config(config_path)
    if config_dict is None:
        return {
            "mode": "preflight", "ok": False, "checks": [],
            "blocking_failures": [f"config file not found or not valid JSON: {config_path}"],
        }

    validation_errors = config_validation_errors(config_dict)
    if validation_errors:
        return {"mode": "preflight", "ok": False, "checks": [], "blocking_failures": validation_errors}

    aws_profile = config_dict["aws_profile"]
    pinned_versions = config_dict.get("pinned_tool_versions", {})

    checks = [
        check_python_version(),
        check_aws_cli_v2_installed(),
        check_required_tool_installed("cloudsplaining", pinned_versions.get("cloudsplaining")),
        check_optional_tool_preflight(
            "parliament", pinned_versions.get("parliament"), config_dict.get("enable_parliament", False),
        ),
        check_optional_tool_preflight(
            "pmapper", pinned_versions.get("pmapper"), config_dict.get("enable_pmapper", False),
        ),
    ]

    caller_identity_check, caller_arn = check_caller_identity(aws_profile)
    checks.append(caller_identity_check)
    checks.append(check_profile_arn_allowlisted(caller_arn, config_dict.get("profile_arn_allowlist", [])))

    probe_role_name = extract_role_name_from_arn(caller_arn)
    checks.append(check_dry_run_get_account_authorization_details(aws_profile))
    checks.append(check_dry_run_get_role_and_list_role_tags(aws_profile, probe_role_name))
    checks.append(check_dry_run_service_last_accessed(aws_profile, caller_arn))
    checks.append(check_cloudtrail_lookup_events(aws_profile))
    checks.append(check_scope_configured(config_dict))
    checks.append(check_model_location_configured(config_dict))

    blocking_failures = [check["name"] for check in checks if check["status"] == "fail"]
    return {"mode": "preflight", "ok": len(blocking_failures) == 0, "checks": checks, "blocking_failures": blocking_failures}


# ===== MODE: COLLECT =====

################################################################################
# FUNCTION: make_run_directory
#
# PURPOSE
#     Creates a fresh, private temp directory for one collect/analyze/
#     normalize run, deliberately outside the target repo and outside
#     any save-state location, since raw collected data can contain
#     unredacted account IDs and ARNs before normalize's redaction step
#     ever runs.
#
# RESPONSIBILITIES
#     - Create a new, uniquely-named temp directory.
#
# PROCESS OVERVIEW
#     1. Create a temp directory with a recognizable prefix.
#     2. Return its absolute path.
#
# IMPORTANT DETAILS
#     - Never reused across runs; each `collect` invocation gets its own
#       directory, so a rerun can't mix stale data from a previous run.
#
# PARAMETERS
#     None.
#
# RETURNS
#     str
#         Absolute path to the new temp directory.
#
# FAILURE CASES
#     - Filesystem out of space or unwritable temp dir: raises OSError,
#       intentionally uncaught, since collect cannot proceed without it.
################################################################################
def make_run_directory():
    """Creates and returns the path to a fresh temp directory for one
    run's raw collected data."""
    return tempfile.mkdtemp(prefix="cloud_perm_audit_")


################################################################################
# FUNCTION: merge_authorization_details_pages
#
# PURPOSE
#     Combines multiple pages of get-account-authorization-details
#     output into one document, since this script pages through results
#     manually rather than relying on the AWS CLI's own paginator.
#
# RESPONSIBILITIES
#     - Concatenate each page's UserDetailList, GroupDetailList,
#       RoleDetailList, and Policies.
#
# PROCESS OVERVIEW
#     1. Start with empty lists for each of the four fields.
#     2. For each page, extend each field with that page's entries.
#     3. Return the merged document.
#
# IMPORTANT DETAILS
#     - Only these four fields are kept; other top-level fields a page
#       might carry (e.g. "Marker", "IsTruncated") are pagination
#       metadata, not data, and are intentionally dropped from the
#       merged result.
#
# PARAMETERS
#     pages (list[dict])
#         Each page's parsed get-account-authorization-details response.
#
# RETURNS
#     dict
#         {"UserDetailList": [...], "GroupDetailList": [...], "RoleDetailList": [...], "Policies": [...]}.
#
# FAILURE CASES
#     - None.
################################################################################
def merge_authorization_details_pages(pages):
    """Concatenates UserDetailList/GroupDetailList/RoleDetailList/Policies
    across every page into one document."""
    merged = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    for page in pages:
        merged["UserDetailList"].extend(page.get("UserDetailList", []))
        merged["GroupDetailList"].extend(page.get("GroupDetailList", []))
        merged["RoleDetailList"].extend(page.get("RoleDetailList", []))
        merged["Policies"].extend(page.get("Policies", []))
    return merged


################################################################################
# FUNCTION: collect_authorization_details
#
# PURPOSE
#     Gets every role's policies and trust policy in one pass, the
#     single most important collected artifact: everything downstream
#     (granted-permission computation, cloudsplaining's scan) reads from
#     the file this function writes.
#
# RESPONSIBILITIES
#     - Page through get-account-authorization-details until exhausted,
#       or read the fixture file in test mode.
#     - Write the merged result to the run directory.
#
# PROCESS OVERVIEW
#     1. In fixture mode, read the fixture file directly.
#     2. Otherwise, call get-account-authorization-details repeatedly,
#        following its Marker field, until IsTruncated is false.
#     3. Merge all pages into one document.
#     4. Write it to <run_directory>/iam_authorization_details.json.
#
# IMPORTANT DETAILS
#     - Uses --no-paginate on every call and follows "Marker"/
#       "IsTruncated" manually, rather than relying on the AWS CLI's own
#       paginator, so this function's behavior is explicit and
#       predictable regardless of CLI version/config defaults.
#     - fixtures_dir is a test-only override (see CLOUD_PERM_AUDIT_FIXTURES_DIR
#       in run_collect()); it is never documented to or used by an end user.
#
# PARAMETERS
#     aws_profile (str)
#         The AWS CLI profile to collect under.
#     run_directory (str)
#         Where to write the merged result.
#     fixtures_dir (str or None)
#         If set, read the fixture file from here instead of calling AWS.
#
# RETURNS
#     tuple[str or None, str or None]
#         (output_path, error_detail). error_detail is None on success,
#         output_path is None on failure.
#
# FAILURE CASES
#     - Any page's AWS call fails: returns (None, that page's stderr).
#     - Fixture file missing or invalid in fixture mode: returns (None, a
#       message naming the missing file).
################################################################################
def collect_authorization_details(aws_profile, run_directory, fixtures_dir=None):
    """Pages through get-account-authorization-details (or reads the
    fixture file in test mode) and writes the merged result to
    run_directory. Returns (output_path, error_detail)."""
    if fixtures_dir:
        data = read_json_file(os.path.join(fixtures_dir, "iam_authorization_details.json"))
        if data is None:
            return None, "fixture file iam_authorization_details.json not found or invalid"
    else:
        pages = []
        marker = None
        for _ in range(AWS_PAGINATION_MAX_PAGES):
            command_args = ["iam", "get-account-authorization-details", "--no-paginate"]
            if marker:
                command_args += ["--marker", marker]
            response = run_aws_cli_json(command_args, aws_profile)
            if not response["ok"]:
                return None, response["stderr"]
            page_data = response["data"]
            pages.append(page_data)
            if not page_data.get("IsTruncated"):
                break
            marker = page_data.get("Marker")
            if not marker:
                break
        data = merge_authorization_details_pages(pages)

    output_path = os.path.join(run_directory, "iam_authorization_details.json")
    write_json_file(output_path, data)
    return output_path, None


################################################################################
# FUNCTION: scope_roles
#
# PURPOSE
#     Filters the full account role list down to just the roles this run
#     should touch, before any of the expensive per-role calls
#     (last-accessed, role metadata) run, so scope actually bounds cost
#     rather than just bounding what gets reported.
#
# RESPONSIBILITIES
#     - Match each role against the configured tag or role_prefix scope.
#
# PROCESS OVERVIEW
#     1. Read the scope type from scope_config.
#     2. For "role_prefix", keep roles whose RoleName starts with the
#        configured prefix.
#     3. For "tag", keep roles that carry the configured tag key/value
#        pair (get-account-authorization-details already includes each
#        role's Tags, no extra call needed here).
#
# IMPORTANT DETAILS
#     - config_validation_errors() already guarantees scope_config is one
#       of these two well-formed shapes by the time this runs; this
#       function does not re-validate it.
#
# PARAMETERS
#     authorization_details (dict)
#         The merged get-account-authorization-details document.
#     scope_config (dict)
#         config_dict["scope"].
#
# RETURNS
#     list[dict]
#         The subset of RoleDetailList entries matching scope_config.
#
# FAILURE CASES
#     - None; an empty result just means no role matched, not an error.
################################################################################
def scope_roles(authorization_details, scope_config):
    """Filters authorization_details's RoleDetailList down to roles
    matching scope_config's tag or role_prefix selector."""
    role_detail_list = authorization_details.get("RoleDetailList", [])
    scope_type = scope_config.get("type")
    scoped = []

    for role_detail in role_detail_list:
        if scope_type == "role_prefix":
            if role_detail.get("RoleName", "").startswith(scope_config.get("role_prefix", "")):
                scoped.append(role_detail)
        elif scope_type == "tag":
            tags = role_detail.get("Tags", [])
            matches_tag = any(
                tag.get("Key") == scope_config.get("tag_key") and tag.get("Value") == scope_config.get("tag_value")
                for tag in tags
            )
            if matches_tag:
                scoped.append(role_detail)

    return scoped


################################################################################
# FUNCTION: collect_role_metadata
#
# PURPOSE
#     Gets each scoped role's tags and last-used date, the two pieces of
#     context normalize needs that get-account-authorization-details
#     doesn't reliably carry (RoleLastUsed in particular is only
#     returned by get-role, not by the bulk export).
#
# RESPONSIBILITIES
#     - Call get-role and list-role-tags per scoped role, or read the
#       fixture file in test mode.
#
# PROCESS OVERVIEW
#     1. In fixture mode, read the fixture file directly.
#     2. Otherwise, for each scoped role name: call get-role for
#        RoleLastUsed, call list-role-tags for its tags, and record any
#        per-role failure rather than aborting the whole loop.
#     3. Write the result, keyed by role name, to the run directory.
#
# IMPORTANT DETAILS
#     - Uses list-role-tags rather than the Tags already present in
#       get-account-authorization-details's export, even though they
#       usually agree, specifically so this function exercises (and
#       preflight validates) the iam:ListRoleTags permission this
#       skill's documented permission list calls for.
#
# PARAMETERS
#     aws_profile (str)
#         The AWS CLI profile to collect under.
#     scoped_role_names (list[str])
#         Role names to collect metadata for.
#     run_directory (str)
#         Where to write the result.
#     fixtures_dir (str or None)
#         If set, read the fixture file from here instead of calling AWS.
#
# RETURNS
#     str
#         The output file path.
#
# FAILURE CASES
#     - get-role or list-role-tags fails for a given role: that role's
#       entry gets collection_error set and role_last_used_date/tags left
#       as None/empty, the loop continues for the remaining roles.
################################################################################
def collect_role_metadata(aws_profile, scoped_role_names, run_directory, fixtures_dir=None):
    """Collects RoleLastUsed and tags per scoped role name (or reads the
    fixture file in test mode), writing the result to run_directory."""
    if fixtures_dir:
        metadata = read_json_file(os.path.join(fixtures_dir, "role_metadata.json")) or {}
    else:
        metadata = {}
        for role_name in scoped_role_names:
            role_response = run_aws_cli_json(["iam", "get-role", "--role-name", role_name], aws_profile)
            tags_response = run_aws_cli_json(["iam", "list-role-tags", "--role-name", role_name], aws_profile)

            role_last_used_date = None
            if role_response["ok"]:
                role_last_used_date = role_response["data"].get("Role", {}).get("RoleLastUsed", {}).get("LastUsedDate")

            tags = tags_response["data"].get("Tags", []) if tags_response["ok"] else []
            both_succeeded = role_response["ok"] and tags_response["ok"]

            metadata[role_name] = {
                "tags": {tag.get("Key"): tag.get("Value") for tag in tags},
                "role_last_used_date": role_last_used_date,
                "collection_error": None if both_succeeded else "get-role or list-role-tags failed for this role",
            }

    output_path = os.path.join(run_directory, "role_metadata.json")
    write_json_file(output_path, metadata)
    return output_path


################################################################################
# FUNCTION: poll_last_accessed_job
#
# PURPOSE
#     Waits for an asynchronous service-last-accessed job to finish,
#     since generate-service-last-accessed-details only starts the job,
#     it doesn't return results itself.
#
# RESPONSIBILITIES
#     - Poll get-service-last-accessed-details until the job reports
#       COMPLETED or FAILED, bounded to a fixed number of attempts.
#
# PROCESS OVERVIEW
#     1. Call get-service-last-accessed-details for job_id.
#     2. If the call itself fails, report the job as FAILED immediately.
#     3. If JobStatus is COMPLETED or FAILED, return that response.
#     4. Otherwise sleep briefly and poll again, up to
#        LAST_ACCESSED_MAX_POLL_ATTEMPTS times.
#     5. If the job never finishes within that many attempts, report a
#        "timed_out" status rather than polling forever.
#
# IMPORTANT DETAILS
#     - "timed_out" is a status this script invents for its own
#       bookkeeping; it's not an AWS-defined JobStatus value, callers
#       must check for it explicitly if they care about distinguishing
#       it from "FAILED".
#
# PARAMETERS
#     aws_profile (str)
#         The AWS CLI profile to poll under.
#     job_id (str)
#         The JobId from generate-service-last-accessed-details.
#
# RETURNS
#     dict
#         The completed job's response data (with "ServicesLastAccessed"),
#         or {"JobStatus": "FAILED"/"timed_out", "ServicesLastAccessed": []}
#         if it never completed successfully.
#
# FAILURE CASES
#     - The polling call itself fails: returns a synthetic FAILED result.
#     - Job never reaches COMPLETED/FAILED within the attempt budget:
#       returns a synthetic "timed_out" result.
################################################################################
def poll_last_accessed_job(aws_profile, job_id):
    """Polls get-service-last-accessed-details for job_id until it
    reports COMPLETED or FAILED, bounded to
    LAST_ACCESSED_MAX_POLL_ATTEMPTS attempts."""
    for _ in range(LAST_ACCESSED_MAX_POLL_ATTEMPTS):
        response = run_aws_cli_json(["iam", "get-service-last-accessed-details", "--job-id", job_id], aws_profile)
        if not response["ok"]:
            return {"JobStatus": "FAILED", "ServicesLastAccessed": []}

        job_status = response["data"].get("JobStatus")
        if job_status in ("COMPLETED", "FAILED"):
            return response["data"]

        time.sleep(LAST_ACCESSED_POLL_INTERVAL_SECONDS)

    return {"JobStatus": "timed_out", "ServicesLastAccessed": []}


################################################################################
# FUNCTION: collect_service_last_accessed
#
# PURPOSE
#     Gets per-role, per-service (and where supported, per-action) usage
#     data, the core "USED" half of the GRANTED - USED calculation this
#     whole skill exists to compute.
#
# RESPONSIBILITIES
#     - Start and poll a last-accessed job per scoped role, or read the
#       fixture file in test mode.
#     - Record a collection error per role whose job fails or times out,
#       without aborting the rest of the roles.
#
# PROCESS OVERVIEW
#     1. Create the last_accessed/ subdirectory.
#     2. In fixture mode, write the single fixture file's content as
#        every scoped role's result (sufficient for pipeline-wiring
#        tests; see this skill's test suite for the pure-function-level
#        tests that actually vary this data).
#     3. Otherwise, for each scoped role: call
#        generate-service-last-accessed-details, poll the job, write its
#        result, and record an error if it didn't complete.
#
# IMPORTANT DETAILS
#     - ACTION_LEVEL granularity is always requested; AWS silently
#       returns only service-level data for services that don't support
#       action-level tracking, this script relies on that behavior
#       rather than needing to know in advance which services qualify.
#
# PARAMETERS
#     aws_profile (str)
#         The AWS CLI profile to collect under.
#     scoped_role_arns_by_name (dict[str, str])
#         Role name -> role ARN, for the roles to collect.
#     run_directory (str)
#         Where to write per-role result files.
#     fixtures_dir (str or None)
#         If set, read the fixture file from here instead of calling AWS.
#
# RETURNS
#     tuple[str, list[dict]]
#         (last_accessed_dir, collection_errors).
#
# FAILURE CASES
#     - A role's job fails to start, fails, or times out: recorded in
#       collection_errors, that role's file still gets written with
#       whatever poll_last_accessed_job() returned.
################################################################################
def collect_service_last_accessed(aws_profile, scoped_role_arns_by_name, run_directory, fixtures_dir=None):
    """Starts and polls a service-last-accessed job per scoped role (or
    reuses the fixture file in test mode), writing one result file per
    role. Returns (last_accessed_dir, collection_errors)."""
    last_accessed_dir = os.path.join(run_directory, "last_accessed")
    os.makedirs(last_accessed_dir, exist_ok=True)
    collection_errors = []

    if fixtures_dir:
        fixture_data = read_json_file(os.path.join(fixtures_dir, "service_last_accessed_job.json")) or {}
        for role_name in scoped_role_arns_by_name:
            write_json_file(os.path.join(last_accessed_dir, f"{role_name}.json"), fixture_data)
        return last_accessed_dir, collection_errors

    for role_name, role_arn in scoped_role_arns_by_name.items():
        generate_response = run_aws_cli_json(
            ["iam", "generate-service-last-accessed-details", "--arn", role_arn, "--granularity", "ACTION_LEVEL"],
            aws_profile,
        )
        if not generate_response["ok"]:
            collection_errors.append({"stage": "last_accessed", "role_name": role_name, "detail": generate_response["stderr"]})
            write_json_file(os.path.join(last_accessed_dir, f"{role_name}.json"), {"JobStatus": "FAILED", "ServicesLastAccessed": []})
            continue

        job_id = generate_response["data"].get("JobId")
        job_result = poll_last_accessed_job(aws_profile, job_id)
        write_json_file(os.path.join(last_accessed_dir, f"{role_name}.json"), job_result)
        if job_result.get("JobStatus") != "COMPLETED":
            collection_errors.append(
                {"stage": "last_accessed", "role_name": role_name, "detail": f"job ended with status {job_result.get('JobStatus')}"}
            )

    return last_accessed_dir, collection_errors


################################################################################
# FUNCTION: collect_cloudtrail_events
#
# PURPOSE
#     Gets the account's CloudTrail management-event history over the
#     observation window, which fills in per-action usage evidence for
#     services last-accessed only tracks at the service level.
#
# RESPONSIBILITIES
#     - Page through cloudtrail lookup-events over the observation
#       window, or read the fixture file in test mode.
#
# PROCESS OVERVIEW
#     1. In fixture mode, read the fixture file directly.
#     2. Otherwise, compute the start/end time from
#        observation_window_days, then page through lookup-events via
#        its NextToken field, bounded by AWS_PAGINATION_MAX_PAGES.
#     3. Write the combined event list to the run directory.
#
# IMPORTANT DETAILS
#     - This is CloudTrail's free, no-trail-required Event history,
#       which only covers management events, not data events (S3 object
#       reads, etc., see DATA_PLANE_ACTIONS_BY_SERVICE).
#     - A page that fails partway through simply stops the loop with
#       whatever events were already collected, rather than discarding
#       them; this is intentionally lenient since partial CloudTrail
#       coverage is still useful evidence, never treated as proof of
#       non-use (see compute_excess()/compute_unknown_usage()).
#
# PARAMETERS
#     aws_profile (str)
#         The AWS CLI profile to collect under.
#     observation_window_days (int)
#         How many days back to query.
#     run_directory (str)
#         Where to write the result.
#     fixtures_dir (str or None)
#         If set, read the fixture file from here instead of calling AWS.
#
# RETURNS
#     str
#         The output file path.
#
# FAILURE CASES
#     - A page's lookup-events call fails: the loop stops there, keeping
#       whatever events were already collected across earlier pages.
################################################################################
def collect_cloudtrail_events(aws_profile, observation_window_days, run_directory, fixtures_dir=None):
    """Pages through cloudtrail lookup-events over the observation
    window (or reads the fixture file in test mode), writing the
    combined event list to run_directory."""
    if fixtures_dir:
        data = read_json_file(os.path.join(fixtures_dir, "cloudtrail_events.json")) or {"Events": []}
    else:
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=observation_window_days)
        events = []
        next_token = None

        for _ in range(AWS_PAGINATION_MAX_PAGES):
            command_args = [
                "cloudtrail", "lookup-events", "--no-paginate",
                "--start-time", start_time.isoformat(), "--end-time", end_time.isoformat(),
            ]
            if next_token:
                command_args += ["--next-token", next_token]

            response = run_aws_cli_json(command_args, aws_profile)
            if not response["ok"]:
                break

            events.extend(response["data"].get("Events", []))
            next_token = response["data"].get("NextToken")
            if not next_token:
                break

        data = {"Events": events}

    output_path = os.path.join(run_directory, "cloudtrail_events.json")
    write_json_file(output_path, data)
    return output_path


################################################################################
# FUNCTION: build_collect_manifest
#
# PURPOSE
#     Assembles the small, Claude-facing summary `collect` prints to
#     stdout, deliberately leaving the (potentially huge) raw data out
#     of it entirely.
#
# RESPONSIBILITIES
#     - Report the run directory, scope size, observation window, file
#       paths, collection errors, and a timestamp.
#
# PROCESS OVERVIEW
#     1. Assemble the manifest dict from the given arguments.
#
# IMPORTANT DETAILS
#     - This is the only thing SKILL.md's Step 1 reads; the raw JSON
#       files this manifest points at are read later, by `analyze` and
#       `normalize`, never directly by Claude.
#
# PARAMETERS
#     run_directory (str)
#         The temp directory collect wrote everything to.
#     scoped_role_names (list[str])
#         The roles this run actually collected.
#     collection_errors (list[dict])
#         Per-stage/per-role errors recorded during collection.
#     observation_window_days (int)
#         The window this run used.
#     files_written (dict or None)
#         Paths to each raw file written, or None if collection stopped
#         before any were written.
#
# RETURNS
#     dict
#         The full collect-mode stdout object.
#
# FAILURE CASES
#     - None.
################################################################################
def build_collect_manifest(run_directory, scoped_role_names, collection_errors, observation_window_days, files_written=None):
    """Assembles collect mode's stdout manifest."""
    return {
        "mode": "collect",
        "ok": True,
        "run_directory": run_directory,
        "scoped_role_count": len(scoped_role_names),
        "observation_window_days": observation_window_days,
        "files_written": files_written or {},
        "collection_errors": collection_errors,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
    }


################################################################################
# FUNCTION: run_collect
#
# PURPOSE
#     Orchestrates the full collect mode: loads config, creates the run
#     directory, and calls each collector in turn, so SKILL.md's Step 1
#     is a single script invocation rather than a sequence of raw AWS
#     CLI commands.
#
# RESPONSIBILITIES
#     - Validate config before making any AWS call.
#     - Scope roles before any expensive per-role call runs.
#     - Call every collector and assemble the final manifest.
#
# PROCESS OVERVIEW
#     1. Load and validate config; fail immediately if invalid.
#     2. Create a fresh run directory.
#     3. Collect authorization details; if that fails, return a manifest
#        with that one error and nothing else collected.
#     4. Scope the role list from the collected authorization details.
#     5. Collect role metadata, service last-accessed data, and
#        CloudTrail events for the scoped roles.
#     6. Build and return the final manifest.
#
# IMPORTANT DETAILS
#     - Honors CLOUD_PERM_AUDIT_FIXTURES_DIR, a test-only environment
#       variable override that redirects every collector to read from a
#       local fixtures directory instead of calling AWS. This is never
#       documented in SKILL.md or surfaced to an end user; it exists
#       solely so this script's file-handling and manifest-building logic
#       can be exercised without live AWS credentials.
#
# PARAMETERS
#     config_path (str)
#         Path to the JSON config file.
#
# RETURNS
#     dict
#         collect mode's stdout manifest (see build_collect_manifest()).
#
# FAILURE CASES
#     - Config invalid: returns {"mode": "collect", "ok": False, "errors": [...]}.
#     - Authorization details collection fails: returns a manifest with
#       scoped_role_count 0 and that error in collection_errors.
################################################################################
def run_collect(config_path):
    """Orchestrates the full collect mode and returns its stdout
    manifest."""
    config_dict = load_config(config_path)
    validation_errors = config_validation_errors(config_dict) if config_dict else ["config file not found or not valid JSON"]
    if validation_errors:
        return {"mode": "collect", "ok": False, "errors": validation_errors}

    fixtures_dir = os.environ.get("CLOUD_PERM_AUDIT_FIXTURES_DIR")
    run_directory = make_run_directory()
    aws_profile = config_dict["aws_profile"]
    observation_window_days = config_dict.get("observation_window_days", DEFAULT_OBSERVATION_WINDOW_DAYS)

    authorization_details_path, collect_error = collect_authorization_details(aws_profile, run_directory, fixtures_dir)
    if collect_error:
        collection_errors = [{"stage": "authorization_details", "role_name": None, "detail": collect_error}]
        return build_collect_manifest(run_directory, [], collection_errors, observation_window_days)

    authorization_details = read_json_file(authorization_details_path)
    scoped_role_details = scope_roles(authorization_details, config_dict.get("scope", {}))
    scoped_role_names = [role_detail["RoleName"] for role_detail in scoped_role_details]
    scoped_role_arns_by_name = {role_detail["RoleName"]: role_detail["Arn"] for role_detail in scoped_role_details}

    role_metadata_path = collect_role_metadata(aws_profile, scoped_role_names, run_directory, fixtures_dir)
    last_accessed_dir, last_accessed_errors = collect_service_last_accessed(
        aws_profile, scoped_role_arns_by_name, run_directory, fixtures_dir,
    )
    cloudtrail_events_path = collect_cloudtrail_events(aws_profile, observation_window_days, run_directory, fixtures_dir)

    files_written = {
        "authorization_details": authorization_details_path,
        "role_metadata": role_metadata_path,
        "last_accessed_dir": last_accessed_dir,
        "cloudtrail_events": cloudtrail_events_path,
    }
    return build_collect_manifest(
        run_directory, scoped_role_names, last_accessed_errors, observation_window_days, files_written=files_written,
    )


# ===== MODE: ANALYZE =====

################################################################################
# FUNCTION: run_cloudsplaining
#
# PURPOSE
#     Runs cloudsplaining's scan against the authorization-details file
#     `collect` wrote, the required deterministic source for every risk
#     category normalize later maps onto a role's excess permissions.
#
# RESPONSIBILITIES
#     - Invoke `cloudsplaining scan` with the right input/output paths.
#     - Locate the results JSON file it produces.
#
# PROCESS OVERVIEW
#     1. Create the output directory (cloudsplaining requires it to
#        already exist, confirmed by direct testing against a real
#        install).
#     2. Run `cloudsplaining scan -i <input> -o <output_dir> -s`.
#     3. If the process fails to start, times out, or exits non-zero,
#        report that failure.
#     4. Derive the expected results filename
#        (iam-results-<input_basename>.json) and confirm it exists.
#
# IMPORTANT DETAILS
#     - -s (--skip-open-report) is required for unattended use; without
#       it cloudsplaining tries to open its HTML report in a browser.
#     - The output filename pattern (iam-results-<basename>.json) was
#       confirmed by running cloudsplaining 0.9.1 directly against a
#       synthetic authorization-details file, not assumed from its docs.
#     - A failure here does not raise and does not abort `analyze`'s
#       other tools; normalize treats a missing/unreadable results file
#       as "no risk flags available for any role" and says so plainly,
#       it never invents a verdict cloudsplaining didn't produce.
#
# PARAMETERS
#     run_directory (str)
#         The directory collect wrote iam_authorization_details.json
#         into, and where this function writes its own output.
#
# RETURNS
#     dict
#         {"ran": True, "output_file": str, "version": str or None} on
#         success, or {"ran": False, "reason": str} on failure.
#
# FAILURE CASES
#     - cloudsplaining not on PATH, times out, or exits non-zero: "ran" False.
#     - Exits 0 but the expected results file is missing: "ran" False.
################################################################################
def run_cloudsplaining(run_directory):
    """Runs `cloudsplaining scan` against run_directory's
    iam_authorization_details.json, returning {"ran", "output_file",
    "version"} on success or {"ran": False, "reason"} on failure."""
    input_file = os.path.join(run_directory, "iam_authorization_details.json")
    output_dir = os.path.join(run_directory, "cloudsplaining_output")
    os.makedirs(output_dir, exist_ok=True)

    try:
        completed_process = subprocess.run(
            ["cloudsplaining", "scan", "-i", input_file, "-o", output_dir, "-s"],
            capture_output=True, text=True, timeout=EXTERNAL_TOOL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ran": False, "reason": f"cloudsplaining invocation failed: {error}"}

    if completed_process.returncode != 0:
        return {"ran": False, "reason": f"cloudsplaining exited {completed_process.returncode}: {completed_process.stderr.strip()[:500]}"}

    input_basename = os.path.splitext(os.path.basename(input_file))[0]
    results_path = os.path.join(output_dir, f"iam-results-{input_basename}.json")
    if not os.path.isfile(results_path):
        return {"ran": False, "reason": "cloudsplaining exited 0 but did not produce the expected results file"}

    return {"ran": True, "output_file": results_path, "version": get_pip_package_version("cloudsplaining")}


################################################################################
# FUNCTION: parse_parliament_output
#
# PURPOSE
#     Parses parliament's --json output, which may be either a single
#     JSON array or one JSON object per line, into a flat Python list,
#     without this script assuming either shape in advance.
#
# RESPONSIBILITIES
#     - Try parsing the whole text as one JSON value first.
#     - Fall back to parsing it as newline-delimited JSON objects.
#
# PROCESS OVERVIEW
#     1. Strip the input text; return an empty list if it's empty.
#     2. Try json.loads() on the whole text; if it succeeds, return it
#        as a list (wrapping a single object if needed).
#     3. Otherwise, parse each non-empty line independently as JSON,
#        skipping any line that doesn't parse.
#
# IMPORTANT DETAILS
#     - A line that fails to parse is silently skipped rather than
#       treated as an error; parliament's stderr/log lines could end up
#       mixed into stdout depending on verbosity settings, and this
#       function's job is only to extract whatever valid JSON findings
#       are present, not to validate parliament's full output.
#
# PARAMETERS
#     stdout_text (str)
#         parliament's raw stdout.
#
# RETURNS
#     list
#         Zero or more parsed finding objects.
#
# FAILURE CASES
#     - Input is empty or contains no valid JSON: returns an empty list.
################################################################################
def parse_parliament_output(stdout_text):
    """Parses parliament's --json stdout as either one JSON value or
    newline-delimited JSON objects, returning a flat list."""
    stripped = stdout_text.strip()
    if not stripped:
        return []

    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, list) else [parsed]
    except ValueError:
        pass

    findings = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except ValueError:
            continue
    return findings


################################################################################
# FUNCTION: run_parliament
#
# PURPOSE
#     Runs parliament's policy linter against the collected
#     authorization-details file, if the config opted into it, to catch
#     malformed/sloppy policies cloudsplaining doesn't check for.
#
# RESPONSIBILITIES
#     - Skip gracefully, without error, when not enabled or not installed.
#     - Otherwise invoke parliament and write its parsed findings.
#
# PROCESS OVERVIEW
#     1. If not enabled in config, return a "not_enabled_in_config" skip.
#     2. If not pip-installed, return a "not_installed" skip.
#     3. Run `parliament --auth-details-file <file> --json`.
#     4. Parse its output and write the findings to the run directory.
#
# IMPORTANT DETAILS
#     - Account-wide findings only; parliament's JSON output in this
#       mode does not reliably carry a per-role ARN field, so this
#       script reports a total finding count rather than attributing
#       individual findings to specific roles (see
#       references/iam-data-coverage-and-tools.md).
#
# PARAMETERS
#     run_directory (str)
#         The directory collect wrote iam_authorization_details.json
#         into, and where this function writes its own output.
#     is_enabled (bool)
#         config_dict.get("enable_parliament", False).
#
# RETURNS
#     dict
#         {"ran": True, "output_file": str, "finding_count": int} on
#         success, or {"ran": False, "reason": str} otherwise.
#
# FAILURE CASES
#     - Not enabled: {"ran": False, "reason": "not_enabled_in_config"}.
#     - Not installed: {"ran": False, "reason": "not_installed"}.
#     - Invocation fails/times out: {"ran": False, "reason": "..."}.
################################################################################
def run_parliament(run_directory, is_enabled):
    """Runs parliament against run_directory's
    iam_authorization_details.json if is_enabled and installed, writing
    its parsed findings. Skips gracefully otherwise."""
    if not is_enabled:
        return {"ran": False, "reason": "not_enabled_in_config"}

    if get_pip_package_version(PACKAGE_NAME_BY_TOOL["parliament"]) is None:
        return {"ran": False, "reason": "not_installed"}

    input_file = os.path.join(run_directory, "iam_authorization_details.json")
    try:
        completed_process = subprocess.run(
            ["parliament", "--auth-details-file", input_file, "--json"],
            capture_output=True, text=True, timeout=EXTERNAL_TOOL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ran": False, "reason": f"parliament invocation failed: {error}"}

    findings = parse_parliament_output(completed_process.stdout)
    output_path = os.path.join(run_directory, "parliament_output.json")
    write_json_file(output_path, findings)
    return {"ran": True, "output_file": output_path, "finding_count": len(findings)}


################################################################################
# FUNCTION: run_pmapper
#
# PURPOSE
#     Runs PMapper's privilege-escalation-path query against the live
#     AWS account, if the config opted into it, to catch multi-hop
#     escalation chains cloudsplaining's single-policy analysis can't see.
#
# RESPONSIBILITIES
#     - Skip gracefully, without error, when not enabled or not installed.
#     - Otherwise build PMapper's graph and run its privesc-path preset
#       query.
#
# PROCESS OVERVIEW
#     1. If not enabled in config, return a "not_enabled_in_config" skip.
#     2. If not pip-installed, return a "not_installed" skip.
#     3. Run `pmapper --profile <profile> graph create`.
#     4. Run `pmapper --profile <profile> query -s 'preset privesc *'`.
#     5. Write the query's raw text output to the run directory.
#
# IMPORTANT DETAILS
#     - PMapper's query output is plain text, not JSON (confirmed
#       against its own documented CLI usage); this function stores that
#       raw text as-is rather than attempting to parse a structure out
#       of it. SKILL.md quotes it verbatim rather than treating it as
#       machine-parseable data.
#     - graph create is itself a live, read-only set of AWS calls
#       (distinct from the other collect/analyze AWS calls elsewhere in
#       this script); this is the one place in `analyze` mode that
#       touches AWS, and only when pmapper is explicitly enabled.
#
# PARAMETERS
#     run_directory (str)
#         Where to write the raw query output.
#     is_enabled (bool)
#         config_dict.get("enable_pmapper", False).
#     aws_profile (str)
#         The AWS CLI profile PMapper should build its graph from.
#
# RETURNS
#     dict
#         {"ran": True, "output_file": str} on success, or
#         {"ran": False, "reason": str} otherwise.
#
# FAILURE CASES
#     - Not enabled: {"ran": False, "reason": "not_enabled_in_config"}.
#     - Not installed: {"ran": False, "reason": "not_installed"}.
#     - graph create exits non-zero, or either call times out:
#       {"ran": False, "reason": "..."}.
################################################################################
def run_pmapper(run_directory, is_enabled, aws_profile):
    """Builds PMapper's graph and runs its privesc-path preset query if
    is_enabled and installed, writing the raw text output. Skips
    gracefully otherwise."""
    if not is_enabled:
        return {"ran": False, "reason": "not_enabled_in_config"}

    if get_pip_package_version(PACKAGE_NAME_BY_TOOL["pmapper"]) is None:
        return {"ran": False, "reason": "not_installed"}

    try:
        create_result = subprocess.run(
            ["pmapper", "--profile", aws_profile, "graph", "create"],
            capture_output=True, text=True, timeout=EXTERNAL_TOOL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ran": False, "reason": f"pmapper graph create invocation failed: {error}"}

    if create_result.returncode != 0:
        return {"ran": False, "reason": f"pmapper graph create exited {create_result.returncode}: {create_result.stderr.strip()[:500]}"}

    try:
        query_result = subprocess.run(
            ["pmapper", "--profile", aws_profile, "query", "-s", "preset privesc *"],
            capture_output=True, text=True, timeout=EXTERNAL_TOOL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ran": False, "reason": f"pmapper query invocation failed: {error}"}

    output_path = os.path.join(run_directory, "pmapper_output.json")
    write_json_file(output_path, {"raw_text": query_result.stdout})
    return {"ran": True, "output_file": output_path}


################################################################################
# FUNCTION: run_analyze
#
# PURPOSE
#     Orchestrates the full analyze mode: runs cloudsplaining and, if
#     enabled, parliament and pmapper, so SKILL.md's Step 2 is a single
#     script invocation.
#
# RESPONSIBILITIES
#     - Run each tool and assemble the final manifest.
#
# PROCESS OVERVIEW
#     1. Run cloudsplaining (always).
#     2. Run parliament and pmapper (only if enabled in config).
#     3. Collect any tool failures into an errors list.
#     4. Return the full result.
#
# IMPORTANT DETAILS
#     - cloudsplaining failing is recorded as an error but does not raise
#       or stop this function; normalize is responsible for reporting
#       the downstream consequence (no risk flags available) honestly.
#
# PARAMETERS
#     run_directory (str)
#         The directory collect wrote its raw files into.
#     config_dict (dict)
#         A config dict as returned by load_config().
#
# RETURNS
#     dict
#         {"mode": "analyze", "run_directory": str, "tools_run": dict, "errors": list[dict]}.
#
# FAILURE CASES
#     - Any tool failing is reflected in "errors" and that tool's entry
#       in "tools_run"; this function itself never raises.
################################################################################
def run_analyze(run_directory, config_dict):
    """Orchestrates the full analyze mode and returns its stdout
    manifest."""
    cloudsplaining_result = run_cloudsplaining(run_directory)
    parliament_result = run_parliament(run_directory, config_dict.get("enable_parliament", False))
    pmapper_result = run_pmapper(run_directory, config_dict.get("enable_pmapper", False), config_dict["aws_profile"])

    errors = []
    if not cloudsplaining_result.get("ran"):
        errors.append({"tool": "cloudsplaining", "detail": cloudsplaining_result.get("reason")})

    return {
        "mode": "analyze",
        "run_directory": run_directory,
        "tools_run": {
            "cloudsplaining": cloudsplaining_result,
            "parliament": parliament_result,
            "pmapper": pmapper_result,
        },
        "errors": errors,
    }


# ===== MODE: NORMALIZE =====

################################################################################
# FUNCTION: index_managed_policies_by_arn
#
# PURPOSE
#     Builds a lookup from a managed policy's ARN to its default
#     version's actual policy document, since
#     get-account-authorization-details returns managed policy documents
#     separately from the roles that attach them, keyed only by ARN
#     reference on the role side.
#
# RESPONSIBILITIES
#     - For each policy, find its default version's document.
#
# PROCESS OVERVIEW
#     1. For each policy entry, read its DefaultVersionId.
#     2. Search its PolicyVersionList for the version matching that ID
#        (or flagged IsDefaultVersion).
#     3. Record that version's Document under the policy's Arn.
#
# IMPORTANT DETAILS
#     - Only the default version is ever used; older, non-default
#       versions are what a role is no longer actually granted by, so
#       they're intentionally never read here.
#
# PARAMETERS
#     policies (list[dict])
#         The top-level "Policies" list from
#         get-account-authorization-details.
#
# RETURNS
#     dict[str, dict]
#         Policy ARN -> its default version's PolicyDocument.
#
# FAILURE CASES
#     - A policy with no matching default version found: simply isn't
#       added to the result; compute_granted_services_and_actions()
#       treats a missing ARN lookup as "no document", not an error.
################################################################################
def index_managed_policies_by_arn(policies):
    """Builds a policy ARN -> default-version PolicyDocument lookup from
    get-account-authorization-details's top-level "Policies" list."""
    documents_by_arn = {}
    for policy in policies:
        arn = policy.get("Arn")
        default_version_id = policy.get("DefaultVersionId")
        for version in policy.get("PolicyVersionList", []):
            if version.get("VersionId") == default_version_id or version.get("IsDefaultVersion"):
                documents_by_arn[arn] = version.get("Document", {})
                break
    return documents_by_arn


################################################################################
# FUNCTION: merge_policy_document_into_granted
#
# PURPOSE
#     Folds one policy document's Allow statements into a role's
#     accumulating granted-permissions set, the core unit of work behind
#     compute_granted_services_and_actions().
#
# RESPONSIBILITIES
#     - Walk every Allow statement's Action list.
#     - Record a full-service wildcard ("service:*") as "ALL" for that
#       service.
#     - Otherwise add the specific action to that service's set.
#
# PROCESS OVERVIEW
#     1. Normalize Statement into a list (it may be a single dict).
#     2. Skip any statement whose Effect is not "Allow".
#     3. For each action string in the statement (normalized to a
#        list), split it into service/action_name.
#     4. If action_name is "*", mark the whole service "ALL".
#     5. Otherwise, if the service isn't already "ALL", add the
#        specific action to its set.
#
# IMPORTANT DETAILS
#     - Deny statements and NotAction clauses are never evaluated (see
#       LIMITATIONS_TEXT); this function only ever adds permissions, it
#       never removes one a prior statement granted.
#     - Once a service is marked "ALL", later specific actions for that
#       same service are skipped rather than (incorrectly) building a
#       set alongside a string; "ALL" always wins since it's a superset
#       of any enumerated action.
#
# PARAMETERS
#     document (dict)
#         A policy document ({"Statement": [...]}).
#     granted (dict)
#         The accumulating result, mutated in place: service (str) ->
#         "ALL" or set of "service:action" strings.
#
# RETURNS
#     None
#         Mutates granted in place.
#
# FAILURE CASES
#     - An action string with no ":" in it is skipped (malformed policy,
#       not a valid IAM action).
################################################################################
def merge_policy_document_into_granted(document, granted):
    """Folds document's Allow statements into granted (service -> "ALL"
    or set of actions), mutated in place."""
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        for action in coerce_value_to_list(statement.get("Action")):
            if ":" not in action:
                continue
            service, action_name = action.split(":", 1)
            service = service.lower()

            if action_name == "*":
                granted[service] = "ALL"
                continue

            if granted.get(service) == "ALL":
                continue

            granted.setdefault(service, set())
            granted[service].add(f"{service}:{action_name}")


################################################################################
# FUNCTION: compute_granted_services_and_actions
#
# PURPOSE
#     Computes the "GRANTED" half of this skill's core calculation for
#     one role: every service and action its inline and attached managed
#     policies allow.
#
# RESPONSIBILITIES
#     - Gather every policy document attached to the role (inline and
#       managed).
#     - Fold them all into one granted set.
#
# PROCESS OVERVIEW
#     1. Collect each inline policy's document directly from the role
#        detail.
#     2. Resolve each attached managed policy's ARN to its document via
#        managed_policy_documents_by_arn.
#     3. Fold every document into one accumulating granted dict.
#
# IMPORTANT DETAILS
#     - An attached managed policy whose ARN isn't found in
#       managed_policy_documents_by_arn (e.g. an AWS-managed policy
#       get-account-authorization-details didn't expand) is silently
#       skipped rather than guessed; this is a known, accepted gap for
#       AWS-managed policies specifically (see
#       references/iam-data-coverage-and-tools.md).
#
# PARAMETERS
#     role_detail (dict)
#         One entry from get-account-authorization-details's
#         RoleDetailList.
#     managed_policy_documents_by_arn (dict[str, dict])
#         From index_managed_policies_by_arn().
#
# RETURNS
#     dict
#         service (str) -> "ALL" or set of "service:action" strings.
#
# FAILURE CASES
#     - None; a role with no policies at all simply returns an empty dict.
################################################################################
def compute_granted_services_and_actions(role_detail, managed_policy_documents_by_arn):
    """Computes the granted service/action set for one role from its
    inline and attached managed policies."""
    granted = {}
    documents = [inline_policy.get("PolicyDocument", {}) for inline_policy in role_detail.get("RolePolicyList", [])]

    for attached_policy in role_detail.get("AttachedManagedPolicies", []):
        document = managed_policy_documents_by_arn.get(attached_policy.get("PolicyArn"))
        if document:
            documents.append(document)

    for document in documents:
        merge_policy_document_into_granted(document, granted)

    return granted


################################################################################
# FUNCTION: service_namespace_from_event_source
#
# PURPOSE
#     Converts a CloudTrail event's EventSource field (e.g.
#     "s3.amazonaws.com") into the same lowercase service namespace
#     ("s3") used everywhere else in this script, so CloudTrail-derived
#     usage can be merged with last-accessed data for the same service.
#
# RESPONSIBILITIES
#     - Strip the ".amazonaws.com" suffix and lowercase the result.
#
# PROCESS OVERVIEW
#     1. Confirm event_source ends with ".amazonaws.com"; return None if not.
#     2. Return the portion before the first "." in lowercase.
#
# IMPORTANT DETAILS
#     - This is a reasonable heuristic, not a guaranteed-correct mapping
#       for every AWS service; it matches the common case (most
#       EventSource values are exactly "<namespace>.amazonaws.com") and
#       is only ever used to merge CloudTrail evidence into an otherwise
#       conservative calculation, never as the sole basis for a
#       conclusion on its own.
#
# PARAMETERS
#     event_source (str)
#         A CloudTrail event's EventSource field.
#
# RETURNS
#     str or None
#         The lowercase service namespace, or None if event_source
#         doesn't look like a standard AWS service hostname.
#
# FAILURE CASES
#     - event_source doesn't end with ".amazonaws.com": returns None.
################################################################################
def service_namespace_from_event_source(event_source):
    """Converts a CloudTrail EventSource (e.g. "s3.amazonaws.com") into
    its lowercase service namespace ("s3"), or None if it doesn't look
    like a standard AWS service hostname."""
    if not event_source or not event_source.endswith(".amazonaws.com"):
        return None
    return event_source.split(".")[0].lower()


################################################################################
# FUNCTION: extract_role_name_from_cloudtrail_event
#
# PURPOSE
#     Identifies which role (if any) made a given CloudTrail event, by
#     parsing its embedded userIdentity, so collected events can be
#     attributed back to the scoped roles this run cares about.
#
# RESPONSIBILITIES
#     - Parse the event's CloudTrailEvent JSON string.
#     - Prefer the session issuer's ARN (the role that was assumed) over
#       the session's own ARN.
#
# PROCESS OVERVIEW
#     1. Parse the event's "CloudTrailEvent" field as JSON; return None
#        if it's missing or invalid.
#     2. Read userIdentity.sessionContext.sessionIssuer.arn if present
#        (an assumed-role session's issuing role).
#     3. Fall back to userIdentity.arn if there's no session issuer.
#     4. Extract a role name from whichever ARN was found via
#        extract_role_name_from_arn().
#
# IMPORTANT DETAILS
#     - An event made directly by an IAM user or the account root
#       correctly returns None here; those aren't roles this skill reviews.
#
# PARAMETERS
#     event (dict)
#         One entry from CloudTrail's lookup-events "Events" list.
#
# RETURNS
#     str or None
#         The role name that made this event, or None if it wasn't made
#         by a role, or the event couldn't be parsed.
#
# FAILURE CASES
#     - "CloudTrailEvent" missing or not valid JSON: returns None.
#     - Neither sessionIssuer.arn nor userIdentity.arn point at a role:
#       returns None.
################################################################################
def extract_role_name_from_cloudtrail_event(event):
    """Identifies the role name (if any) that made this CloudTrail
    event, preferring the assumed-role session's issuing role."""
    raw_event = event.get("CloudTrailEvent")
    if not raw_event:
        return None

    try:
        parsed_event = json.loads(raw_event)
    except ValueError:
        return None

    user_identity = parsed_event.get("userIdentity", {})
    session_issuer_arn = user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("arn")
    arn_to_check = session_issuer_arn or user_identity.get("arn")
    return extract_role_name_from_arn(arn_to_check)


################################################################################
# FUNCTION: match_cloudtrail_events_to_roles
#
# PURPOSE
#     Groups the account-wide CloudTrail event list by which scoped role
#     made each event and which service/action it called, the shape
#     compute_used_services_and_actions() needs per role.
#
# RESPONSIBILITIES
#     - Attribute each event to a role name, skipping events from roles
#       outside this run's scope.
#     - Derive each event's service namespace and build a
#       "service:action" string matching last-accessed's ActionName format.
#
# PROCESS OVERVIEW
#     1. For each event, extract its role name; skip if it's not one of
#        role_names.
#     2. Derive the event's service namespace from EventSource; skip if
#        that or EventName is missing.
#     3. Record "<service>:<EventName>" under that role and service.
#
# IMPORTANT DETAILS
#     - CloudTrail's EventName field matches IAM's action-name casing
#       convention directly (e.g. "GetObject" for s3:GetObject); this
#       function does not lowercase anything, callers that need
#       case-insensitive comparison (compute_excess(),
#       compute_unknown_usage()) handle that themselves.
#
# PARAMETERS
#     cloudtrail_events (dict)
#         {"Events": [...]} as collected by collect_cloudtrail_events().
#     role_names (list[str])
#         The scoped role names this run cares about; events from any
#         other principal are ignored.
#
# RETURNS
#     dict[str, dict[str, set]]
#         role_name -> service -> set of "service:action" strings.
#
# FAILURE CASES
#     - An event that can't be attributed to a scoped role, or has no
#       recognizable service/action, is simply skipped.
################################################################################
def match_cloudtrail_events_to_roles(cloudtrail_events, role_names):
    """Groups cloudtrail_events's Events by scoped role name and
    service, returning role_name -> service -> set of "service:action"
    strings."""
    role_name_set = set(role_names)
    result = {}

    for event in cloudtrail_events.get("Events", []):
        role_name = extract_role_name_from_cloudtrail_event(event)
        if role_name not in role_name_set:
            continue

        service = service_namespace_from_event_source(event.get("EventSource", ""))
        action_name = event.get("EventName")
        if not service or not action_name:
            continue

        result.setdefault(role_name, {}).setdefault(service, set()).add(f"{service}:{action_name}")

    return result


################################################################################
# FUNCTION: compute_used_services_and_actions
#
# PURPOSE
#     Computes the "USED" half of this skill's core calculation for one
#     role, merging IAM last-accessed data with CloudTrail-derived
#     action evidence for the same role.
#
# RESPONSIBILITIES
#     - Determine, per granted service, whether it was used at all, and
#       if so, at what granularity (action-level or service-level-only).
#     - Fold in CloudTrail-sourced actions, which can upgrade a
#       service's coverage even when last-accessed itself only tracked
#       that service at the service level.
#
# PROCESS OVERVIEW
#     1. For each service entry in the last-accessed report, read its
#        LastAuthenticated date and any TrackedActionsLastAccessed
#        entries that actually have a LastAccessedTime (meaning they
#        were tracked AND used, not just tracked).
#     2. Union in any CloudTrail-sourced actions for that same service.
#     3. Mark coverage "action_level" if either source provided
#        per-action evidence, "service_level_only" otherwise.
#     4. Mark used_at_all true if LastAuthenticated is set or any action
#       was found from either source.
#     5. Fold in any service CloudTrail saw that last-accessed's report
#       didn't mention at all (rare, but CloudTrail is still real evidence).
#
# IMPORTANT DETAILS
#     - A TrackedActionsLastAccessed entry with an ActionName but no
#       LastAccessedTime means that action is tracked for this service
#       but was never actually used, it is correctly excluded from
#       used_actions.
#
# PARAMETERS
#     last_accessed_report (dict)
#         A completed get-service-last-accessed-details response
#         ({"ServicesLastAccessed": [...]}).
#     cloudtrail_actions_by_service (dict[str, set])
#         This role's entry from match_cloudtrail_events_to_roles()'s result.
#
# RETURNS
#     dict[str, dict]
#         service (str) -> {"coverage": "action_level" or
#         "service_level_only", "used_actions": set, "used_at_all": bool,
#         "last_used": str or None}.
#
# FAILURE CASES
#     - A service with no last-accessed entry and no CloudTrail evidence
#       simply doesn't appear in the result; callers must treat an
#       absent service the same as used_at_all=False.
################################################################################
def compute_used_services_and_actions(last_accessed_report, cloudtrail_actions_by_service):
    """Merges IAM last-accessed data with CloudTrail-derived action
    evidence into one per-service usage picture for a role."""
    used_coverage = {}

    for entry in last_accessed_report.get("ServicesLastAccessed", []):
        service = entry.get("ServiceNamespace")
        if not service:
            continue

        last_authenticated = entry.get("LastAuthenticated")
        tracked_actions = entry.get("TrackedActionsLastAccessed") or []
        used_actions = {action["ActionName"] for action in tracked_actions if action.get("LastAccessedTime")}

        cloudtrail_actions = cloudtrail_actions_by_service.get(service, set())
        used_actions |= cloudtrail_actions

        coverage = "action_level" if (tracked_actions or cloudtrail_actions) else "service_level_only"
        used_at_all = bool(last_authenticated) or bool(used_actions)

        used_coverage[service] = {
            "coverage": coverage, "used_actions": used_actions,
            "used_at_all": used_at_all, "last_used": last_authenticated,
        }

    for service, actions in cloudtrail_actions_by_service.items():
        if service not in used_coverage:
            used_coverage[service] = {
                "coverage": "action_level", "used_actions": set(actions),
                "used_at_all": True, "last_used": None,
            }

    return used_coverage


################################################################################
# FUNCTION: compute_excess
#
# PURPOSE
#     Computes GRANTED minus USED, this skill's core calculation, for
#     one role. This is the one function in the whole pipeline that
#     decides what counts as removable excess, and it is deliberately
#     conservative: anything it can't verify goes to unknown_usage
#     instead (compute_unknown_usage()), never into excess.
#
# RESPONSIBILITIES
#     - A granted service never used at all is excess at the service level.
#     - A granted action never used, where action-level data exists and
#       the action isn't a quarantined data-plane action, is excess at
#       the action level.
#     - A full-service wildcard grant is never enumerated into excess
#       actions (there's no bounded universe to diff against).
#
# PROCESS OVERVIEW
#     1. For each granted service, check whether it was used at all; if
#        not, it's an excess service, nothing further to compute for it.
#     2. If the service was used but granted as "ALL", skip it, its risk
#        is surfaced via cloudsplaining's ServiceWildcard flag instead,
#        not enumerated here.
#     3. If the service was used but its usage coverage is
#        service_level_only, skip it, no action-level excess can be
#        computed (this is handled by compute_unknown_usage() instead).
#     4. Otherwise, for each granted action, mark it excess if it's
#        neither in the used-actions set nor in this service's
#        data-plane-only quarantine list.
#
# IMPORTANT DETAILS
#     - All comparisons are case-insensitive (both AWS's own action-name
#       casing in different data sources, and cloudsplaining's findings,
#       were found to disagree on casing in practice); the original
#       granted casing is preserved in the returned excess_actions for
#       display.
#
# PARAMETERS
#     granted (dict)
#         From compute_granted_services_and_actions().
#     used_coverage (dict)
#         From compute_used_services_and_actions().
#     data_plane_actions_by_service (dict[str, set])
#         DATA_PLANE_ACTIONS_BY_SERVICE, or an equivalent lowercase
#         action-name lookup.
#
# RETURNS
#     tuple[list[str], dict[str, list[str]]]
#         (excess_services, excess_actions). excess_actions only has
#         entries for services with action-level usage data.
#
# FAILURE CASES
#     - None; an empty result for a fully-used, fully-covered role is
#       the expected "nothing to flag" case, not a failure.
################################################################################
def compute_excess(granted, used_coverage, data_plane_actions_by_service):
    """Computes GRANTED minus USED for one role: (excess_services,
    excess_actions), conservative by design (see function docstring
    above for exactly what is and isn't counted as excess)."""
    excess_services = []
    excess_actions = {}

    for service, granted_value in granted.items():
        coverage_info = used_coverage.get(service)
        used_at_all = coverage_info["used_at_all"] if coverage_info else False

        if not used_at_all:
            excess_services.append(service)
            continue

        if granted_value == "ALL":
            continue

        if coverage_info["coverage"] != "action_level":
            continue

        used_actions_lower = {action.lower() for action in coverage_info["used_actions"]}
        data_plane_lower = data_plane_actions_by_service.get(service, set())

        candidate_excess = sorted(
            action for action in granted_value
            if action.lower() not in used_actions_lower and action.lower() not in data_plane_lower
        )
        if candidate_excess:
            excess_actions[service] = candidate_excess

    return sorted(excess_services), excess_actions


################################################################################
# FUNCTION: compute_unknown_usage
#
# PURPOSE
#     Quarantines everything compute_excess() could not safely classify,
#     so normalize's output never silently drops a granted permission:
#     it is either excess, unknown, or part of an already-excess whole
#     service, never simply absent.
#
# RESPONSIBILITIES
#     - For a service with no action-level usage data, quarantine its
#       entire granted action set as unknown (we know the service was
#       used, we don't know which actions).
#     - For a service with action-level data, quarantine only its
#       data-plane-only granted actions.
#
# PROCESS OVERVIEW
#     1. Skip any service already classified as a whole excess_services
#       entry, it's already accounted for, not unknown.
#     2. Skip any service granted as "ALL" (not enumerable, same
#        reasoning as compute_excess()).
#     3. For a service with no action-level coverage, quarantine its
#        full granted action set.
#     4. For a service with action-level coverage, quarantine only its
#        data-plane-only granted actions.
#
# IMPORTANT DETAILS
#     - This function and compute_excess() are deliberately kept as two
#       separate passes over the same granted dict, rather than one
#       combined function, so each one's responsibility (what's
#       removable vs. what's merely unverifiable) stays easy to read and
#       test in isolation.
#
# PARAMETERS
#     granted (dict)
#         From compute_granted_services_and_actions().
#     used_coverage (dict)
#         From compute_used_services_and_actions().
#     excess_services (list[str])
#         compute_excess()'s excess_services result for this role.
#     data_plane_actions_by_service (dict[str, set])
#         DATA_PLANE_ACTIONS_BY_SERVICE, or an equivalent lowercase
#         action-name lookup.
#
# RETURNS
#     dict[str, list[str]]
#         service -> sorted list of granted actions that can't be
#         verified as used or unused.
#
# FAILURE CASES
#     - None.
################################################################################
def compute_unknown_usage(granted, used_coverage, excess_services, data_plane_actions_by_service):
    """Quarantines granted actions compute_excess() couldn't safely
    classify as excess, returning service -> list of unverifiable
    actions."""
    excess_services_set = set(excess_services)
    unknown_usage = {}

    for service, granted_value in granted.items():
        if service in excess_services_set:
            continue

        if granted_value == "ALL":
            continue

        coverage_info = used_coverage.get(service)
        data_plane_lower = data_plane_actions_by_service.get(service, set())

        if coverage_info is None or coverage_info["coverage"] != "action_level":
            unknown_for_service = sorted(granted_value)
        else:
            unknown_for_service = sorted(action for action in granted_value if action.lower() in data_plane_lower)

        if unknown_for_service:
            unknown_usage[service] = unknown_for_service

    return unknown_usage


################################################################################
# FUNCTION: extract_account_id_from_principal
#
# PURPOSE
#     Pulls a 12-digit AWS account ID out of a trust policy Principal
#     value, which may be a bare account ID string or a full ARN
#     (root/user/role) containing one.
#
# RESPONSIBILITIES
#     - Search the principal string for a 12-digit account ID.
#
# PROCESS OVERVIEW
#     1. Search principal_value for BARE_ACCOUNT_ID_PATTERN.
#     2. Return the match, or None if there isn't one.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     principal_value (str)
#         One entry from a trust policy statement's Principal.AWS list.
#
# RETURNS
#     str or None
#         The 12-digit account ID, or None if none was found.
#
# FAILURE CASES
#     - principal_value contains no 12-digit sequence: returns None.
################################################################################
def extract_account_id_from_principal(principal_value):
    """Extracts a 12-digit account ID from a trust policy Principal.AWS
    value, or None if it has none."""
    match = BARE_ACCOUNT_ID_PATTERN.search(principal_value)
    return match.group(0) if match else None


################################################################################
# FUNCTION: statement_has_repo_scoped_condition
#
# PURPOSE
#     Decides whether a trust policy statement that federates via GitHub
#     OIDC actually scopes which repository can assume the role, the
#     difference between "any GitHub Actions workflow anywhere can
#     assume this" and "only this one repo can."
#
# RESPONSIBILITIES
#     - Look for a Condition targeting a ":sub" key whose value contains
#       a "repo:" scoping pattern.
#
# PROCESS OVERVIEW
#     1. Read the statement's Condition block; return False if absent.
#     2. For each condition operator's key/value pairs, check whether
#        the key ends in ":sub" (the convention GitHub's OIDC provider
#        uses, e.g. "token.actions.githubusercontent.com:sub").
#     3. If such a key's value (normalized to a list) contains a string
#        with "repo:" in it, return True.
#
# IMPORTANT DETAILS
#     - This checks for the presence of repo-scoping syntax, not that
#       the specific repo named is the "correct" one; judging whether
#       the named repo is appropriate is Step 4's job (an AI judgment
#       with context this script doesn't have), not this function's.
#
# PARAMETERS
#     statement (dict)
#         One trust policy statement.
#
# RETURNS
#     bool
#         True if a repo-scoped "sub" condition was found.
#
# FAILURE CASES
#     - No Condition block, or none of its keys end in ":sub": returns False.
################################################################################
def statement_has_repo_scoped_condition(statement):
    """Checks whether statement's Condition block scopes a federated
    OIDC principal to a specific repo via a ":sub" condition key."""
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return False

    for operator_block in condition.values():
        if not isinstance(operator_block, dict):
            continue
        for condition_key, condition_value in operator_block.items():
            if not condition_key.endswith(":sub"):
                continue
            if any("repo:" in value for value in coerce_value_to_list(condition_value)):
                return True

    return False


################################################################################
# FUNCTION: summarize_trust_policy
#
# PURPOSE
#     Reduces a role's raw trust policy document into the small set of
#     boolean/structural signals Step 4's risk rubric actually reasons
#     over, so neither the script nor the AI layer needs to re-parse raw
#     trust policy JSON for every risk judgment.
#
# RESPONSIBILITIES
#     - Detect cross-account, wildcard, and federated-OIDC assumability.
#     - Detect whether a federated OIDC trust is scoped to a specific repo.
#     - Collect which AWS service principals can assume the role.
#
# PROCESS OVERVIEW
#     1. Normalize Statement into a list.
#     2. Skip any non-Allow statement.
#     3. A bare "*" Principal sets the wildcard flag directly.
#     4. For a Principal.AWS entry: "*" sets the wildcard flag; a
#        resolvable account ID other than self_account_id sets the
#        cross-account flag and is recorded.
#     5. Record every Principal.Service entry.
#     6. For a Principal.Federated entry naming an "oidc-provider", set
#        the OIDC flag, and if statement_has_repo_scoped_condition()
#        is False, also set the missing-repo-condition flag.
#
# IMPORTANT DETAILS
#     - self_account_id is used only to distinguish "this account" from
#       "a different account"; an account ID matching self_account_id is
#       not reported as cross-account access.
#
# PARAMETERS
#     trust_policy_document (dict)
#         A role's AssumeRolePolicyDocument.
#     self_account_id (str or None)
#         This account's own ID, from extract_self_account_id().
#
# RETURNS
#     dict
#         {"assumable_by_other_account": bool,
#          "assumable_by_wildcard_principal": bool,
#          "assumable_by_federated_oidc": bool,
#          "oidc_missing_repo_condition": bool,
#          "assumable_service_principals": list[str],
#          "external_account_ids": list[str]}.
#
# FAILURE CASES
#     - trust_policy_document is empty or malformed: returns all-False/
#       all-empty defaults rather than raising.
################################################################################
def summarize_trust_policy(trust_policy_document, self_account_id):
    """Reduces a role's trust policy document into the boolean/
    structural signals this skill's risk rubric reasons over."""
    result = {
        "assumable_by_other_account": False,
        "assumable_by_wildcard_principal": False,
        "assumable_by_federated_oidc": False,
        "oidc_missing_repo_condition": False,
        "assumable_service_principals": [],
        "external_account_ids": [],
    }

    statements = (trust_policy_document or {}).get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    service_principals = set()
    external_account_ids = set()

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal", {})
        if principal == "*":
            result["assumable_by_wildcard_principal"] = True
            continue
        if not isinstance(principal, dict):
            continue

        for aws_principal in coerce_value_to_list(principal.get("AWS")):
            if aws_principal == "*":
                result["assumable_by_wildcard_principal"] = True
                continue
            account_id = extract_account_id_from_principal(aws_principal)
            if account_id and account_id != self_account_id:
                result["assumable_by_other_account"] = True
                external_account_ids.add(account_id)

        service_principals.update(coerce_value_to_list(principal.get("Service")))

        for federated_principal in coerce_value_to_list(principal.get("Federated")):
            if "oidc-provider" in federated_principal:
                result["assumable_by_federated_oidc"] = True
                if not statement_has_repo_scoped_condition(statement):
                    result["oidc_missing_repo_condition"] = True

    result["assumable_service_principals"] = sorted(service_principals)
    result["external_account_ids"] = sorted(external_account_ids)
    return result


################################################################################
# FUNCTION: extract_self_account_id
#
# PURPOSE
#     Determines this account's own account ID from the collected role
#     ARNs, without normalize ever needing to call sts:GetCallerIdentity
#     itself (normalize makes no AWS calls at all, by design).
#
# RESPONSIBILITIES
#     - Pull the account ID segment out of the first role ARN available.
#
# PROCESS OVERVIEW
#     1. For each role detail, try to match its Arn against
#        ACCOUNT_ID_IN_ARN_PATTERN.
#     2. Return the first match found.
#
# IMPORTANT DETAILS
#     - Every role in a single get-account-authorization-details export
#       belongs to the same account, so the first match is sufficient;
#       this function does not check for (and would not expect to find)
#       disagreement across roles.
#
# PARAMETERS
#     role_detail_list (list[dict])
#         get-account-authorization-details's RoleDetailList.
#
# RETURNS
#     str or None
#         The 12-digit account ID, or None if role_detail_list is empty
#         or no role's Arn matched.
#
# FAILURE CASES
#     - Empty role_detail_list, or no role's Arn matches the expected
#       shape: returns None.
################################################################################
def extract_self_account_id(role_detail_list):
    """Extracts this account's own account ID from the first role ARN
    found in role_detail_list."""
    for role_detail in role_detail_list:
        match = ACCOUNT_ID_IN_ARN_PATTERN.search(role_detail.get("Arn", ""))
        if match:
            return match.group(1)
    return None


################################################################################
# FUNCTION: load_cloudsplaining_output
#
# PURPOSE
#     Locates and reads cloudsplaining's results JSON from the run
#     directory `analyze` wrote it into, using the same filename
#     convention run_cloudsplaining() relied on to find it in the first place.
#
# RESPONSIBILITIES
#     - Derive the expected results filename and read it.
#
# PROCESS OVERVIEW
#     1. Derive the input file's basename the same way
#        run_cloudsplaining() did.
#     2. Build the expected results path.
#     3. Read and return it as JSON, or None if it's missing/invalid.
#
# IMPORTANT DETAILS
#     - Returning None here is the expected outcome when cloudsplaining
#       failed to run in `analyze`; map_cloudsplaining_risk_flags()
#       treats a None cloudsplaining_output as "no data available", not
#       as "nothing was flagged".
#
# PARAMETERS
#     run_directory (str)
#         The directory collect/analyze wrote their files into.
#
# RETURNS
#     dict or None
#         cloudsplaining's parsed results JSON, or None if not found.
#
# FAILURE CASES
#     - Results file missing or invalid JSON: returns None.
################################################################################
def load_cloudsplaining_output(run_directory):
    """Reads cloudsplaining's results JSON from run_directory, or
    returns None if it's missing or invalid."""
    output_dir = os.path.join(run_directory, "cloudsplaining_output")
    input_basename = os.path.splitext(os.path.basename("iam_authorization_details.json"))[0]
    results_path = os.path.join(output_dir, f"iam-results-{input_basename}.json")
    return read_json_file(results_path)


################################################################################
# FUNCTION: find_cloudsplaining_role_entry
#
# PURPOSE
#     Locates one role's entry inside cloudsplaining's results JSON,
#     which keys roles by an internal RoleId rather than by role name.
#
# RESPONSIBILITIES
#     - Search cloudsplaining_output's "roles" map for an entry whose
#       "name" matches role_name.
#
# PROCESS OVERVIEW
#     1. Iterate cloudsplaining_output["roles"]'s values.
#     2. Return the first entry whose "name" field equals role_name.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     cloudsplaining_output (dict)
#         cloudsplaining's parsed results JSON.
#     role_name (str)
#         The role name to find.
#
# RETURNS
#     dict or None
#         That role's entry, or None if cloudsplaining has no entry for
#         it (e.g. a role with no inline or managed policies at all).
#
# FAILURE CASES
#     - No matching entry found: returns None.
################################################################################
def find_cloudsplaining_role_entry(cloudsplaining_output, role_name):
    """Finds role_name's entry inside cloudsplaining_output's "roles"
    map, or None if there isn't one."""
    for role_entry in (cloudsplaining_output.get("roles") or {}).values():
        if role_entry.get("name") == role_name:
            return role_entry
    return None


################################################################################
# FUNCTION: extract_actions_from_category_findings
#
# PURPOSE
#     Normalizes cloudsplaining's two different "findings" shapes for a
#     risk category (a flat list of action-name strings for most
#     categories, a list of {"type", "actions"} dicts for
#     PrivilegeEscalation specifically, confirmed against a real scan's
#     output) into one lowercase action-name set.
#
# RESPONSIBILITIES
#     - Handle both finding shapes uniformly.
#
# PROCESS OVERVIEW
#     1. For each finding, if it's a dict, collect every string in its
#        "actions" list.
#     2. If it's a plain string, collect it directly.
#     3. Lowercase every collected action name.
#
# IMPORTANT DETAILS
#     - Lowercasing here is required, not just defensive:
#       cloudsplaining's own output was observed, in direct testing, to
#       mix casing between categories (PrivilegeEscalation's "actions"
#       lists are lowercase, e.g. "iam:createpolicyversion", while
#       ResourceExposure's are not, e.g. "iam:CreatePolicyVersion").
#
# PARAMETERS
#     findings_value (list)
#         A risk category's "findings" value.
#
# RETURNS
#     set[str]
#         Lowercase action names.
#
# FAILURE CASES
#     - None.
################################################################################
def extract_actions_from_category_findings(findings_value):
    """Normalizes a cloudsplaining risk category's "findings" value
    (either flat strings or {"type","actions"} dicts) into one lowercase
    action-name set."""
    actions = set()
    for finding in findings_value:
        if isinstance(finding, dict):
            actions.update(action.lower() for action in finding.get("actions", []))
        elif isinstance(finding, str):
            actions.add(finding.lower())
    return actions


################################################################################
# FUNCTION: map_cloudsplaining_risk_flags
#
# PURPOSE
#     Decides which of cloudsplaining's risk categories apply to this
#     role's verified excess permissions specifically, so Step 4's risk
#     ranking is grounded in "this dangerous pattern sits on a
#     permission that's provably unused" rather than "this role has a
#     dangerous pattern somewhere, possibly entirely within permissions
#     it actively uses".
#
# RESPONSIBILITIES
#     - Find this role's cloudsplaining entry.
#     - For each of its attached policies, check whether any risk
#       category's flagged actions/services intersect this role's
#       excess_actions/excess_services.
#
# PROCESS OVERVIEW
#     1. Return None immediately if cloudsplaining_output is falsy
#       (the tool didn't run or produced nothing readable).
#     2. Find this role's entry; return an empty list if cloudsplaining
#        ran but has no entry for this role at all.
#     3. Build a lowercase comparison set of every excess action: the
#        per-service entries in excess_actions, PLUS, for every service
#        in excess_services that was granted as a specific action set
#        (not a full "ALL" wildcard), every action granted under that
#        wholly-unused service too. Without this second part, a service
#        that's entirely unused would never surface a per-action risk
#        category (PrivilegeEscalation, ResourceExposure, etc.), since
#        compute_excess() never populates excess_actions for a service
#        that's already counted as wholly excess.
#     4. For every policy (inline, customer-managed, AWS-managed)
#        attached to this role, for every risk category: for
#        ServiceWildcard, check its flagged services against
#        excess_services; for every other category, check its flagged
#        actions (via extract_actions_from_category_findings()) against
#        that comparison set.
#     5. Return the sorted set of categories that intersected.
#
# IMPORTANT DETAILS
#     - A risk category that only touches permissions this role actually
#       uses is deliberately never reported here; cloudsplaining's own
#       full report still has that information for someone who wants it,
#       but this skill's framing is specifically about the excess.
#     - A service in excess_services granted as "ALL" (a full
#       service-wildcard grant that's wholly unused) is not enumerable
#       into individual actions; its risk is still caught, just via the
#       ServiceWildcard category's service-name check, not this
#       per-action one.
#
# PARAMETERS
#     role_name (str)
#         The role to check.
#     cloudsplaining_output (dict or None)
#         From load_cloudsplaining_output(), or None if cloudsplaining
#         didn't produce usable output this run.
#     granted (dict)
#         This role's granted services/actions from
#         compute_granted_services_and_actions(), needed to recover the
#         full action list for a wholly-unused service.
#     excess_services (list[str])
#         This role's excess_services from compute_excess().
#     excess_actions (dict[str, list[str]])
#         This role's excess_actions from compute_excess().
#
# RETURNS
#     list[str] or None
#         Sorted risk category names that intersect this role's excess,
#         an empty list if cloudsplaining ran but found nothing for this
#         role, or None if cloudsplaining's output isn't available at all
#         (a meaningfully different, less certain case than an empty list).
#
# FAILURE CASES
#     - cloudsplaining_output is None: returns None (unknown, not "clean").
#     - Role has no cloudsplaining entry: returns an empty list.
################################################################################
def map_cloudsplaining_risk_flags(role_name, cloudsplaining_output, granted, excess_services, excess_actions):
    """Intersects cloudsplaining's risk categories against role_name's
    verified excess permissions specifically, including every granted
    action under a wholly-unused service. Returns None if
    cloudsplaining_output isn't available, distinct from an empty list
    (available, nothing flagged)."""
    if not cloudsplaining_output:
        return None

    role_entry = find_cloudsplaining_role_entry(cloudsplaining_output, role_name)
    if role_entry is None:
        return []

    excess_actions_lower = {action.lower() for actions in excess_actions.values() for action in actions}
    for service in excess_services:
        granted_value = granted.get(service)
        if isinstance(granted_value, set):
            excess_actions_lower.update(action.lower() for action in granted_value)
    excess_services_set = set(excess_services)

    policy_category_lookup = {
        "inline_policies": cloudsplaining_output.get("inline_policies", {}),
        "customer_managed_policies": cloudsplaining_output.get("customer_managed_policies", {}),
        "aws_managed_policies": cloudsplaining_output.get("aws_managed_policies", {}),
    }

    flagged_categories = set()
    for policy_group, policy_table in policy_category_lookup.items():
        for policy_id in (role_entry.get(policy_group) or {}).keys():
            policy_detail = policy_table.get(policy_id)
            if not policy_detail:
                continue

            for category_name in RISK_CATEGORY_NAMES:
                category_data = policy_detail.get(category_name)
                if not category_data or not category_data.get("findings"):
                    continue

                if category_name == "ServiceWildcard":
                    flagged_services = {service.lower() for service in category_data["findings"]}
                    if flagged_services & excess_services_set:
                        flagged_categories.add(category_name)
                    continue

                category_actions = extract_actions_from_category_findings(category_data["findings"])
                if category_actions & excess_actions_lower:
                    flagged_categories.add(category_name)

    return sorted(flagged_categories)


################################################################################
# FUNCTION: build_role_record
#
# PURPOSE
#     Assembles one role's complete entry in findings.json from every
#     piece this script computed for it, the shape Step 4 reads field by
#     field when writing its report.
#
# RESPONSIBILITIES
#     - Combine role identity, metadata, trust summary, granted/excess/
#       unknown permissions, and risk flags into one dict.
#
# PROCESS OVERVIEW
#     1. Read tags and last_used_date from role_metadata_entry, treating
#        a missing entry as empty/unknown rather than raising.
#     2. Assemble and return the full record.
#
# IMPORTANT DETAILS
#     - Any field this script couldn't determine is left as Python None
#       (JSON null) by whatever upstream function computed it; this
#       function does not invent a default for a None it receives.
#
# PARAMETERS
#     role_detail (dict)
#         One entry from get-account-authorization-details's RoleDetailList.
#     role_metadata_entry (dict or None)
#         This role's entry from collect_role_metadata()'s output, or
#         None if metadata collection failed for this role.
#     granted (dict)
#         From compute_granted_services_and_actions().
#     excess_services (list[str])
#         From compute_excess().
#     excess_actions (dict[str, list[str]])
#         From compute_excess().
#     unknown_usage (dict[str, list[str]])
#         From compute_unknown_usage().
#     trust_summary (dict)
#         From summarize_trust_policy().
#     risk_flags (list[str] or None)
#         From map_cloudsplaining_risk_flags().
#
# RETURNS
#     dict
#         One complete role record for findings.json's "roles" list.
#
# FAILURE CASES
#     - None.
################################################################################
def build_role_record(
    role_detail, role_metadata_entry, granted, excess_services, excess_actions,
    unknown_usage, trust_summary, risk_flags,
):
    """Assembles one role's complete findings.json entry from every
    piece this script computed for it."""
    metadata_entry = role_metadata_entry or {}
    return {
        "role_name": role_detail["RoleName"],
        "role_arn": role_detail["Arn"],
        "tags": metadata_entry.get("tags") or {},
        "last_used_date": metadata_entry.get("role_last_used_date"),
        "trust_policy_summary": trust_summary,
        "compute_attachment": trust_summary.get("assumable_service_principals", []),
        "granted_services": sorted(granted.keys()),
        "excess_services": excess_services,
        "excess_actions": excess_actions,
        "unknown_usage": unknown_usage,
        "risk_flags": risk_flags,
    }


################################################################################
# FUNCTION: placeholder_token_for
#
# PURPOSE
#     Generates a stable, per-run placeholder token for a sensitive raw
#     value, so the same ARN or account ID always redacts to the same
#     token throughout one findings.json, letting a reader still see
#     "these three roles trust the same external account" without ever
#     learning which account that is.
#
# RESPONSIBILITIES
#     - Reuse an existing token for a value already seen this run.
#     - Otherwise mint a new, sequentially-numbered token under the
#       given prefix.
#
# PROCESS OVERVIEW
#     1. If raw_value is already in token_map, return its existing token.
#     2. Otherwise increment this prefix's counter and mint a new token.
#     3. Record it in token_map and return it.
#
# IMPORTANT DETAILS
#     - token_map and counters are mutated in place and must be shared
#       across every call within one redact_findings() invocation for
#       the "same value -> same token" guarantee to hold.
#
# PARAMETERS
#     raw_value (str)
#         The sensitive value being replaced.
#     prefix (str)
#         The token family, e.g. "ARN_EXTERNAL" or "ACCOUNT_EXTERNAL".
#     token_map (dict)
#         Mutated in place: raw_value -> token, shared across one run.
#     counters (dict)
#         Mutated in place: prefix -> count of tokens minted so far.
#
# RETURNS
#     str
#         The token for raw_value, e.g. "ARN_EXTERNAL_2".
#
# FAILURE CASES
#     - None.
################################################################################
def placeholder_token_for(raw_value, prefix, token_map, counters):
    """Returns a stable per-run placeholder token for raw_value under
    prefix, reusing an existing token if raw_value was already seen this
    run."""
    if raw_value in token_map:
        return token_map[raw_value]

    counters[prefix] = counters.get(prefix, 0) + 1
    token = f"{prefix}_{counters[prefix]}"
    token_map[raw_value] = token
    return token


################################################################################
# FUNCTION: redact_string_value
#
# PURPOSE
#     Redacts every ARN and every bare 12-digit account ID inside one
#     string value, the unit of work redact_value_recursive() applies to
#     every string anywhere in findings.json.
#
# RESPONSIBILITIES
#     - Replace every ARN substring with a stable placeholder,
#       distinguishing this account's own ARNs from external ones.
#     - Replace every bare account ID substring the same way.
#
# PROCESS OVERVIEW
#     1. Substitute every ARN_PATTERN match: if self_account_id appears
#        inside that specific ARN, token it under "ARN_SELF", otherwise
#        under "ARN_EXTERNAL".
#     2. Substitute every remaining BARE_ACCOUNT_ID_PATTERN match: the
#       literal self_account_id becomes "ACCOUNT_SELF", anything else
#       is tokened under "ACCOUNT_EXTERNAL".
#
# IMPORTANT DETAILS
#     - Runs the ARN substitution first, then the bare-account-ID
#       substitution, so an account ID embedded inside an ARN is already
#       gone (replaced as part of the ARN token) by the time the
#       bare-ID pass runs; the bare-ID pass only catches account IDs
#       that appear outside of any ARN.
#
# PARAMETERS
#     value (str)
#         The string to redact.
#     self_account_id (str or None)
#         This account's own ID, so it can be distinguished from an
#         external one.
#     token_map (dict)
#         Shared, mutated in place across the whole redact_findings() call.
#     counters (dict)
#         Shared, mutated in place across the whole redact_findings() call.
#
# RETURNS
#     str
#         value with every ARN/account ID replaced by a placeholder token.
#
# FAILURE CASES
#     - None.
################################################################################
def redact_string_value(value, self_account_id, token_map, counters):
    """Redacts every ARN and bare account ID inside value, replacing
    each with a stable per-run placeholder token."""
    def replace_arn(match):
        raw_arn = match.group(0)
        if self_account_id and f":{self_account_id}:" in raw_arn:
            return placeholder_token_for(raw_arn, "ARN_SELF", token_map, counters)
        return placeholder_token_for(raw_arn, "ARN_EXTERNAL", token_map, counters)

    redacted = ARN_PATTERN.sub(replace_arn, value)

    def replace_account_id(match):
        raw_id = match.group(0)
        if raw_id == self_account_id:
            return "ACCOUNT_SELF"
        return placeholder_token_for(raw_id, "ACCOUNT_EXTERNAL", token_map, counters)

    return BARE_ACCOUNT_ID_PATTERN.sub(replace_account_id, redacted)


################################################################################
# FUNCTION: redact_value_recursive
#
# PURPOSE
#     Applies redact_string_value() to every string anywhere in an
#     arbitrarily-nested JSON-shaped value, so redaction never depends on
#     knowing every specific field name that might carry an ARN or
#     account ID in advance.
#
# RESPONSIBILITIES
#     - Recurse through dicts and lists.
#     - Redact every string value encountered.
#     - Leave every non-string value (bool, int, float, None) untouched.
#
# PROCESS OVERVIEW
#     1. If value is a string, redact it directly.
#     2. If value is a list, recurse into each element.
#     3. If value is a dict, recurse into each value (keys are left as-is).
#     4. Otherwise, return value unchanged.
#
# IMPORTANT DETAILS
#     - Dict keys are never redacted, only values; nothing in
#       findings.json's shape uses an ARN or account ID as a dict key.
#     - This single recursive sweep is both the "structured" redaction
#       and the "defense in depth" sweep in one pass. There is
#       deliberately no separate first pass that redacts specific named
#       fields: every sensitive field in findings.json is a string value
#       somewhere in this structure, so one generic sweep catches all of
#       them without needing two logic paths that could drift out of
#       sync with each other.
#
# PARAMETERS
#     value (Any)
#         Any JSON-shaped Python value.
#     self_account_id (str or None)
#         Passed through to redact_string_value().
#     token_map (dict)
#         Shared, mutated in place across the whole redact_findings() call.
#     counters (dict)
#         Shared, mutated in place across the whole redact_findings() call.
#
# RETURNS
#     Any
#         value with every string redacted, same shape otherwise.
#
# FAILURE CASES
#     - None.
################################################################################
def redact_value_recursive(value, self_account_id, token_map, counters):
    """Recursively redacts every string value inside an arbitrarily-
    nested dict/list structure."""
    if isinstance(value, str):
        return redact_string_value(value, self_account_id, token_map, counters)
    if isinstance(value, list):
        return [redact_value_recursive(item, self_account_id, token_map, counters) for item in value]
    if isinstance(value, dict):
        return {key: redact_value_recursive(item, self_account_id, token_map, counters) for key, item in value.items()}
    return value


################################################################################
# FUNCTION: redact_findings
#
# PURPOSE
#     The single, unconditional redaction choke point for this entire
#     skill. Every byte of findings.json Claude ever reads has passed
#     through this function first whenever model_location resolves to
#     "hosted", with no code path that can skip it.
#
# RESPONSIBILITIES
#     - Decide, from model_location alone, whether to redact at all.
#     - If so, recursively redact every string in the document and mark
#       redaction_applied true; if not, mark it false and return
#       the document unchanged.
#
# PROCESS OVERVIEW
#     1. If model_location is "local", set redaction_applied False and
#        return findings_document as-is.
#     2. Otherwise, read self_account_id from the document.
#     3. Recursively redact the whole document.
#     4. Set redaction_applied True on the result and return it.
#
# IMPORTANT DETAILS
#     - This function is called exactly once, from run_normalize(), as
#       the last step before that function returns. normalize is the
#       only mode whose output Claude ever reads in full
#       (preflight/collect/analyze only print small manifests), so this
#       is the only place in the entire pipeline redaction needs to happen.
#
# PARAMETERS
#     findings_document (dict)
#         The fully-assembled, pre-redaction findings document.
#     model_location (str)
#         "local" or "hosted", from resolve_model_location().
#
# RETURNS
#     dict
#         findings_document, either unchanged (local) or fully redacted
#         (hosted), with redaction_applied set accordingly.
#
# FAILURE CASES
#     - None.
################################################################################
def redact_findings(findings_document, model_location):
    """Redacts every ARN/account ID in findings_document if
    model_location is "hosted"; returns it unchanged if "local". Sets
    redaction_applied accordingly either way."""
    if model_location == "local":
        findings_document["redaction_applied"] = False
        return findings_document

    self_account_id = findings_document.get("account_id")
    token_map = {}
    counters = {}

    redacted_document = redact_value_recursive(findings_document, self_account_id, token_map, counters)
    redacted_document["redaction_applied"] = True
    return redacted_document


################################################################################
# FUNCTION: build_findings_document
#
# PURPOSE
#     Wraps every role's record with the run-level context Step 4 needs
#     up front: the observation window, the fixed limitations list, and
#     account-wide (not per-role) parliament/pmapper results, so Step 4
#     never has to reconstruct this context from scratch or guess at it.
#
# RESPONSIBILITIES
#     - Assemble the full findings.json structure.
#
# PROCESS OVERVIEW
#     1. Assemble the dict from the given arguments and LIMITATIONS_TEXT.
#
# IMPORTANT DETAILS
#     - "redaction_applied" is set to None here deliberately;
#       redact_findings() is responsible for setting its real value, and
#       leaving it None until then makes it obvious if that call were
#       ever accidentally skipped.
#
# PARAMETERS
#     role_records (list[dict])
#         From build_role_record(), one per role.
#     config_dict (dict)
#         A config dict as returned by load_config().
#     self_account_id (str or None)
#         From extract_self_account_id().
#     parliament_findings_total (int or None)
#         Total parliament finding count for this run, or None if
#         parliament didn't run.
#     pmapper_raw_text (str or None)
#         PMapper's raw query output for this run, or None if it didn't run.
#
# RETURNS
#     dict
#         The full, pre-redaction findings.json structure.
#
# FAILURE CASES
#     - None.
################################################################################
def build_findings_document(role_records, config_dict, self_account_id, parliament_findings_total, pmapper_raw_text):
    """Assembles the full, pre-redaction findings.json structure."""
    return {
        "mode": "normalize",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "observation_window_days": config_dict.get("observation_window_days", DEFAULT_OBSERVATION_WINDOW_DAYS),
        "model_location": resolve_model_location(config_dict),
        "redaction_applied": None,
        "account_id": self_account_id,
        "parliament_findings_total": parliament_findings_total,
        "pmapper_escalation_paths_raw_text": pmapper_raw_text,
        "limitations": LIMITATIONS_TEXT,
        "roles": role_records,
    }


################################################################################
# FUNCTION: run_normalize
#
# PURPOSE
#     Orchestrates the full normalize mode: reads back everything
#     collect/analyze wrote, computes GRANTED - USED = EXCESS per role,
#     and redacts the result, so SKILL.md's Step 3 is a single script
#     invocation that produces exactly the findings.json Step 4 reads.
#
# RESPONSIBILITIES
#     - Read every raw/analyzed file back from the run directory.
#     - Compute each role's full record.
#     - Assemble and redact the final findings document.
#
# PROCESS OVERVIEW
#     1. Load config and every raw/analyzed file from run_directory,
#        tolerating any that are missing (optional tools, partial
#        collection) rather than failing the whole run.
#     2. Build the account-wide lookups this needs once: managed policy
#        documents by ARN, this account's own account ID, and CloudTrail
#        events grouped by role.
#     3. For each role: compute granted, used coverage, excess,
#        unknown usage, trust policy summary, and risk flags, then
#        assemble its record.
#     4. Assemble the full findings document and redact it.
#
# IMPORTANT DETAILS
#     - Makes no AWS calls and no network calls of any kind; everything
#       it needs was already written to run_directory by collect and analyze.
#
# PARAMETERS
#     run_directory (str)
#         The directory collect/analyze wrote their files into.
#     config_path (str)
#         Path to the JSON config file.
#
# RETURNS
#     dict
#         The final, redacted (if applicable) findings.json structure.
#
# FAILURE CASES
#     - A role's last-accessed file is missing: that role's
#       used_coverage is computed from an empty report, so every granted
#       service for it becomes excess_services, the honest consequence
#       of missing usage data rather than a silent skip.
################################################################################
def run_normalize(run_directory, config_path):
    """Orchestrates the full normalize mode and returns the final,
    redacted findings.json structure."""
    config_dict = load_config(config_path)

    authorization_details = read_json_file(os.path.join(run_directory, "iam_authorization_details.json")) or {}
    role_metadata = read_json_file(os.path.join(run_directory, "role_metadata.json")) or {}
    cloudtrail_events = read_json_file(os.path.join(run_directory, "cloudtrail_events.json")) or {"Events": []}
    cloudsplaining_output = load_cloudsplaining_output(run_directory)
    parliament_findings = read_json_file(os.path.join(run_directory, "parliament_output.json"))
    pmapper_output = read_json_file(os.path.join(run_directory, "pmapper_output.json"))

    role_detail_list = authorization_details.get("RoleDetailList", [])
    managed_policy_documents_by_arn = index_managed_policies_by_arn(authorization_details.get("Policies", []))
    self_account_id = extract_self_account_id(role_detail_list)

    role_names = [role_detail["RoleName"] for role_detail in role_detail_list]
    cloudtrail_actions_by_role = match_cloudtrail_events_to_roles(cloudtrail_events, role_names)

    role_records = []
    for role_detail in role_detail_list:
        role_name = role_detail["RoleName"]

        granted = compute_granted_services_and_actions(role_detail, managed_policy_documents_by_arn)
        last_accessed_report = read_json_file(os.path.join(run_directory, "last_accessed", f"{role_name}.json")) or {}
        used_coverage = compute_used_services_and_actions(last_accessed_report, cloudtrail_actions_by_role.get(role_name, {}))
        excess_services, excess_actions = compute_excess(granted, used_coverage, DATA_PLANE_ACTIONS_BY_SERVICE)
        unknown_usage = compute_unknown_usage(granted, used_coverage, excess_services, DATA_PLANE_ACTIONS_BY_SERVICE)
        trust_summary = summarize_trust_policy(role_detail.get("AssumeRolePolicyDocument", {}), self_account_id)
        risk_flags = map_cloudsplaining_risk_flags(role_name, cloudsplaining_output, granted, excess_services, excess_actions)

        role_records.append(build_role_record(
            role_detail, role_metadata.get(role_name), granted, excess_services,
            excess_actions, unknown_usage, trust_summary, risk_flags,
        ))

    parliament_findings_total = len(parliament_findings) if isinstance(parliament_findings, list) else None
    pmapper_raw_text = pmapper_output.get("raw_text") if pmapper_output else None

    findings_document = build_findings_document(
        role_records, config_dict, self_account_id, parliament_findings_total, pmapper_raw_text,
    )
    return redact_findings(findings_document, resolve_model_location(config_dict))


# ===== MAIN =====

################################################################################
# FUNCTION: main
#
# PURPOSE
#     CLI entry point: dispatches to one of the four modes based on
#     sys.argv[1], and prints exactly one JSON object to stdout, the
#     contract every SKILL.md step invocation of this script relies on.
#
# RESPONSIBILITIES
#     - Validate argument count per mode.
#     - Dispatch to the right run_<mode>() function.
#     - Print its result as indented JSON.
#
# PROCESS OVERVIEW
#     1. Require at least a mode argument; print USAGE_MESSAGE and exit
#        1 if missing.
#     2. For "preflight"/"collect": require a config_path argument.
#     3. For "analyze"/"normalize": require run_directory and
#        config_path arguments.
#     4. Dispatch to the matching run_<mode>() function and print its result.
#     5. For an unrecognized mode, print an error and exit 1.
#
# IMPORTANT DETAILS
#     - "analyze" loads config itself here (rather than inside
#       run_analyze()) so a missing/invalid config file is reported the
#       same way across every mode, before any work starts.
#
# PARAMETERS
#     None (reads sys.argv).
#
# RETURNS
#     None
#
# FAILURE CASES
#     - No mode given, missing required positional arguments, an
#       unrecognized mode, or (analyze only) an invalid config file:
#       prints a JSON error object and exits 1.
################################################################################
def main():
    """CLI entry point: dispatches to preflight/collect/analyze/normalize
    based on sys.argv[1], printing exactly one JSON object to stdout."""
    if len(sys.argv) < 2:
        print(json.dumps({"error": USAGE_MESSAGE}))
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "preflight":
        if len(sys.argv) < 3:
            print(json.dumps({"error": USAGE_MESSAGE}))
            sys.exit(1)
        print(json.dumps(run_preflight(sys.argv[2]), indent=2))

    elif mode == "collect":
        if len(sys.argv) < 3:
            print(json.dumps({"error": USAGE_MESSAGE}))
            sys.exit(1)
        print(json.dumps(run_collect(sys.argv[2]), indent=2))

    elif mode == "analyze":
        if len(sys.argv) < 4:
            print(json.dumps({"error": USAGE_MESSAGE}))
            sys.exit(1)
        run_directory = sys.argv[2]
        config_dict = load_config(sys.argv[3])
        if config_dict is None:
            print(json.dumps({"error": f"config file not found or not valid JSON: {sys.argv[3]}"}))
            sys.exit(1)
        print(json.dumps(run_analyze(run_directory, config_dict), indent=2))

    elif mode == "normalize":
        if len(sys.argv) < 4:
            print(json.dumps({"error": USAGE_MESSAGE}))
            sys.exit(1)
        print(json.dumps(run_normalize(sys.argv[2], sys.argv[3]), indent=2))

    else:
        print(json.dumps({"error": f"unknown mode {mode!r}, expected preflight, collect, analyze, or normalize"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
