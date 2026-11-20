#!/usr/bin/env python3
# ******************************************************************************
# * TITLE:        Bootleg Cartridge Scan
# * FILE:         bootleg_cartridge_scan.py
# * PART OF:      bootleg-cartridge-check skill (skill-sec-arcade repo). Does
# *               not import or reuse cartridge_scan.py/dead_weight_scan.py:
# *               those scan the user's own trusted repo, this scans a
# *               third-party skill the user does not yet trust, so it is
# *               deliberately kept standalone.
# * PURPOSE:      Produces a structured, machine-readable security scan of a
# *               Claude Code skill directory (a "cartridge") that has not
# *               yet been trusted or installed: a file inventory, a list of
# *               anything that could not be safely inspected, a list of
# *               rule findings (prompt-injection phrasing, credential/host
# *               overrides, unsafe deserialization, persistence tricks, and
# *               more), and every URL the skill references. It exists so
# *               the bootleg-cartridge-check skill has hard, already-bounded
# *               facts to report on instead of having to freely read a
# *               third party's adversarial text to form its own judgment.
# *
# * HOW IT WORKS: 1) Walks the target directory and inventories every file,
# *                  flagging (never silently skipping) anything that cannot
# *                  be safely read as text: oversized files, binaries,
# *                  password-protected archives, unsupported archive
# *                  formats.
# *               2) Reads every remaining file as text, decodes
# *                  recognizable base64/ROT13 blobs one level deep for
# *                  inspection only, and separately detects (without
# *                  removing from the original for scanning purposes)
# *                  ANSI/OSC escape sequences and backspace characters.
# *               3) Runs a data-driven table of line-level regex rules
# *                  (LINE_PATTERN_RULES) across every text file.
# *               4) Runs a set of structural detectors for findings that
# *                  need more than a single-line regex: symlink targets,
# *                  settings/env host overrides, MCP server command
# *                  fields, password-protected archives, container
# *                  privilege flags, and several same-file signal
# *                  co-occurrence checks (e.g. base64 blob plus a network
# *                  call in the same file).
# *               5) Extracts every URL found, without ever fetching one.
# *               6) Prints one JSON object with all of the above to
# *                  stdout.
# *
# * USAGE:        python3 bootleg_cartridge_scan.py <path>
# *               Example: python3 bootleg_cartridge_scan.py /tmp/some-skill
# * ARGUMENTS:    path (positional, str, required) - path to the skill
# *               directory to scan.
# * INPUTS:       The filesystem under `path` only. No network access.
# * OUTPUTS:      One JSON object printed to stdout. No files are written,
# *               no prose or markdown, the calling skill does all
# *               interpretation of these facts.
# * EXIT CODES:   0 = success. 1 = missing CLI argument or the given path
# *               does not exist.
# * DEPENDENCIES: Python 3 standard library only (base64, json, os, re,
# *               stat, sys, unicodedata, zipfile, datetime).
# * PERMISSIONS:  Read-only filesystem access under `path`. No network
# *               access. No write access anywhere.
# * ASSUMPTIONS:  Safe to *read* (never execute, never import) any file
# *               under `path`, including every script and markdown file in
# *               an untrusted skill. Nothing found in `path` is ever run,
# *               imported, or followed as an instruction by this script.
# *               Symlinks are inspected by name only (os.readlink), never
# *               followed/opened.
# * FAILURE MODES:An unreadable, oversized, or binary file is recorded as a
# *               coverage gap rather than silently dropped or crashing the
# *               whole scan. The regex-based rules are a heuristic text
# *               sweep, not a parser: they can both miss a reworded attack
# *               and occasionally flag benign phrasing, see the "confidence"
# *               field on every finding.
# * SAFE TO RERUN:Yes. Strictly read-only; nothing on disk is created,
# *               modified, or deleted.
# *
# * AUTHOR:       cameronww7
# * LAST UPDATED: 2026-11-20
# ******************************************************************************

"""Bootleg Cartridge Scan: static security scan of a Claude Code skill
directory that has not yet been trusted or installed.

Walks a target skill directory, inventories its files, flags anything
that cannot be safely inspected as a coverage gap, and runs a data-driven
set of line-pattern regex rules plus structural detectors across every
readable text file. Prints one JSON object to stdout. No prose, no
markdown: interpretation is the bootleg-cartridge-check skill's job, not
this script's.

Nothing found under the target path is ever executed, imported, or
followed as an instruction. Everything this script reads is treated as
inert data to pattern-match against, exactly like cartridge_scan.py's
read-only treatment of an untrusted repo's setup.py.
"""

import base64
import json
import os
import re
import stat
import sys
import unicodedata
import zipfile
from datetime import datetime, timezone

# ===== CONFIGURATION =====

# Directories that are never worth descending into: VCS metadata and
# dependency caches that could be vendored into a skill directory. Kept
# deliberately small; a skill directory is expected to be tiny compared to
# a full repository.
EXCLUDE_DIRECTORIES = {".git", "__pycache__", "node_modules"}

# Files larger than this are reported as a coverage gap rather than read.
# A legitimate skill's text files are small; anything far larger than this
# is either not meant to be read as source, or expensive to scan safely.
MAXIMUM_FILE_SIZE_BYTES_TO_SCAN = 2 * 1024 * 1024

# How much surrounding text to keep in a finding's reported snippet. Long
# enough to give a human reviewer context, short enough that the finding
# itself can never become a vehicle for smuggling a large block of the
# target's own adversarial text back into a report.
MAXIMUM_SNIPPET_LENGTH = 200

# A run of base64-alphabet characters at least this long is treated as a
# candidate encoded blob worth decoding for inspection (never execution).
MINIMUM_BASE64_BLOB_LENGTH = 40

# Severity-to-band thresholds, matching the 1-10 scale used throughout the
# rule catalog documented in references/bootleg-cartridge-rule-catalog.md.
CRITICAL_SEVERITY_MINIMUM = 9
HIGH_SEVERITY_MINIMUM = 7
MEDIUM_SEVERITY_MINIMUM = 4

# A combining-mark density above this ratio, measured on strings of at
# least ZALGO_MINIMUM_TEXT_LENGTH characters, is treated as Zalgo/
# combining-character abuse rather than normal accented text.
ZALGO_COMBINING_MARK_DENSITY_THRESHOLD = 0.15
ZALGO_MINIMUM_TEXT_LENGTH = 20

# Headings/subcommand-like lines above this count in a single file is
# treated as a possible attempt to overflow per-command safety review.
EXCESSIVE_SUBCOMMAND_COUNT_THRESHOLD = 50

# Known-malicious domains/IPs. This is a small seed list, not a live feed:
# real coverage requires a maintained threat-intel source. Kept here in
# the same spirit as scripts/abandoned_packages.py's curated lookup table,
# and documented in the rule catalog as needing ongoing upkeep.
KNOWN_MALICIOUS_DOMAINS = {
    "clawhavoc.io",
    "clawhavoc.net",
    "miasma-c2.com",
}
KNOWN_MALICIOUS_IPS = set()

# Sensitive filenames a symlink should never quietly point at under a
# mismatched name (e.g. a file named "docs/vid.mp4" that is actually a
# symlink to one of these).
SENSITIVE_SYMLINK_TARGET_BASENAMES = {
    ".mcp.json",
    "mcp.json",
    "settings.json",
    "settings.local.json",
    "credentials",
    "id_rsa",
    "id_ed25519",
    ".env",
}

# Filenames that mark a directory entry as an MCP server configuration
# file worth parsing for its "command" field.
MCP_CONFIG_FILENAMES = {".mcp.json", "mcp.json"}

# Filenames that mark a directory entry as a settings/env file worth
# checking for an Anthropic API host override.
SETTINGS_OR_ENV_FILENAMES = {"settings.json", "settings.local.json", ".env", "env"}

# Keys inside a settings/env file whose value should point at an
# Anthropic-controlled host. Any other host is a credential-exfiltration
# risk (CVE-2026-21852 family).
ANTHROPIC_HOST_OVERRIDE_KEYS = ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL")
ANTHROPIC_OWNED_HOST_SUFFIXES = (".anthropic.com",)

# File extensions this script treats as archives, and which of those it
# can actually open (stdlib only supports zip) versus just flag as an
# uninspectable coverage gap.
ZIP_ARCHIVE_EXTENSIONS = (".zip",)
OTHER_ARCHIVE_EXTENSIONS = (".7z", ".rar", ".tar.gz", ".tgz", ".gz")

# IaC/container filenames worth checking for privileged configuration.
CONTAINER_OR_IAC_FILENAMES_OR_SUFFIXES = (
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".yaml", ".yml",
)


################################################################################
# FUNCTION: band_for_severity
#
# PURPOSE
#     Converts a rule's numeric 1-10 severity into the four-band label
#     (critical/high/medium/low) used throughout the report, so severity
#     and band can never drift out of sync with each other.
#
# RESPONSIBILITIES
#     - Map a severity integer to exactly one band name.
#
# PROCESS OVERVIEW
#     1. Compare the severity against the three band thresholds, highest
#        first.
#     2. Return the first band whose threshold the severity meets.
#
# IMPORTANT DETAILS
#     - Band is always derived from severity, never stored separately on
#       a rule, so there is only one number to keep correct per rule.
#
# PARAMETERS
#     severity (int)
#         A rule's severity score, 1 to 10.
#
# RETURNS
#     str
#         One of "critical", "high", "medium", "low".
#
# FAILURE CASES
#     - None; any integer falls through to "low" if it is below every
#       other threshold.
################################################################################
def band_for_severity(severity):
    """Derives the critical/high/medium/low band from a 1-10 severity
    score, so the two values can never disagree with each other."""
    if severity >= CRITICAL_SEVERITY_MINIMUM:
        return "critical"
    if severity >= HIGH_SEVERITY_MINIMUM:
        return "high"
    if severity >= MEDIUM_SEVERITY_MINIMUM:
        return "medium"
    return "low"


################################################################################
# FUNCTION: make_snippet
#
# PURPOSE
#     Produces a bounded-length excerpt of matched text for a finding, so
#     a report can show a human reviewer exactly what triggered a rule
#     without ever reproducing a large, unbounded block of the target
#     skill's own text inside the scan output.
#
# RESPONSIBILITIES
#     - Trim leading/trailing whitespace from the matched text.
#     - Truncate to MAXIMUM_SNIPPET_LENGTH characters, marking truncation.
#
# PROCESS OVERVIEW
#     1. Strip the input text.
#     2. If it is longer than MAXIMUM_SNIPPET_LENGTH, cut it to that
#        length and append an ellipsis marker.
#     3. Return the result.
#
# PARAMETERS
#     text (str)
#         The raw matched line or region to excerpt.
#
# RETURNS
#     str
#         A stripped, length-bounded excerpt.
#
# FAILURE CASES
#     - None.
################################################################################
def make_snippet(text):
    """Returns a stripped, length-bounded excerpt of text, truncated at
    MAXIMUM_SNIPPET_LENGTH characters with a trailing marker if cut."""
    stripped_text = text.strip()
    if len(stripped_text) <= MAXIMUM_SNIPPET_LENGTH:
        return stripped_text
    return stripped_text[:MAXIMUM_SNIPPET_LENGTH] + "...(truncated)"


################################################################################
# FUNCTION: read_file_as_text_or_flag_gap
#
# PURPOSE
#     Gives every part of this scan a single "read this file as text, or
#     tell me honestly why not" primitive, so an unreadable, oversized, or
#     binary file in an untrusted skill directory never crashes the scan
#     and never gets silently treated as clean.
#
# RESPONSIBILITIES
#     - Check the file's size against MAXIMUM_FILE_SIZE_BYTES_TO_SCAN
#       before reading it.
#     - Read the file's bytes and detect binary content via an embedded
#       null byte.
#     - Decode readable, non-oversized content as UTF-8, tolerating
#       undecodable bytes.
#
# PROCESS OVERVIEW
#     1. Stat the file; if that fails or the file is too large, return a
#        coverage-gap reason instead of text.
#     2. Read the raw bytes.
#     3. If a null byte is present, treat the file as binary and return a
#        coverage-gap reason instead of text.
#     4. Otherwise decode the bytes as UTF-8 (tolerating bad bytes) and
#        return that text.
#
# IMPORTANT DETAILS
#     - "Binary" here is a null-byte heuristic, not a magic-number check;
#       it is deliberately conservative (biased toward flagging a gap)
#       rather than guessing wrong about safety.
#     - This function only ever reads bytes off disk; it never executes,
#       imports, or evaluates the file's contents.
#
# PARAMETERS
#     file_path (str)
#         Absolute path to the file to read.
#
# RETURNS
#     tuple[str or None, str or None]
#         (text, None) on a successful text read, or (None, reason) when
#         the file could not be safely read as text.
#
# FAILURE CASES
#     - Missing file, permission error, or any other OSError: returns
#       (None, "unreadable: <error>") instead of raising.
################################################################################
def read_file_as_text_or_flag_gap(file_path):
    """Reads file_path as UTF-8 text, or returns (None, reason) if it is
    too large, binary, or otherwise unreadable. Never raises."""
    try:
        file_size_in_bytes = os.path.getsize(file_path)
    except OSError as error:
        return None, f"unreadable: {error}"

    if file_size_in_bytes > MAXIMUM_FILE_SIZE_BYTES_TO_SCAN:
        return None, f"file exceeds {MAXIMUM_FILE_SIZE_BYTES_TO_SCAN} byte scan size cap"

    try:
        with open(file_path, "rb") as file_handle:
            raw_bytes = file_handle.read()
    except OSError as error:
        return None, f"unreadable: {error}"

    if b"\x00" in raw_bytes:
        return None, "binary file, not scanned as text"

    return raw_bytes.decode("utf-8", errors="ignore"), None


################################################################################
# FUNCTION: decode_known_encodings
#
# PURPOSE
#     Finds base64-looking blobs in a file's text and decodes them for
#     inspection only, so a rule like "disable 2FA" phrased inside a
#     base64-encoded instruction is not invisible to the regex rules,
#     which only ever see plain text.
#
# RESPONSIBILITIES
#     - Find every run of base64-alphabet characters at least
#       MINIMUM_BASE64_BLOB_LENGTH long.
#     - Attempt to decode each as base64 and then as UTF-8 text.
#     - Collect successfully decoded text, discarding anything that does
#       not decode to printable text.
#
# PROCESS OVERVIEW
#     1. Search the text for long base64-alphabet runs.
#     2. For each candidate, attempt base64 decoding.
#     3. Decode the result as UTF-8; keep it only if it looks like
#        printable text, not random binary.
#     4. Return the list of decoded strings found.
#
# IMPORTANT DETAILS
#     - This is read-only decoding for pattern matching. The decoded text
#       is never written, executed, or treated as an instruction; it is
#       only re-run through the same rule tables as plain text.
#     - Decoding is one level deep only (no recursive re-decoding of
#       decoded output), to keep this bounded and simple.
#
# PARAMETERS
#     text (str)
#         The file's text content.
#
# RETURNS
#     list[str]
#         Every successfully decoded, printable-looking blob found.
#
# FAILURE CASES
#     - A candidate blob that is not valid base64, or that decodes to
#       non-printable bytes, is silently skipped, not an error.
################################################################################
def decode_known_encodings(text):
    """Finds long base64-looking runs in text, decodes each for
    inspection only (never execution), and returns the decoded strings
    that look like printable text."""
    decoded_blobs = []
    for candidate in re.findall(r"[A-Za-z0-9+/]{%d,}={0,2}" % MINIMUM_BASE64_BLOB_LENGTH, text):
        try:
            decoded_bytes = base64.b64decode(candidate, validate=True)
        except ValueError:
            continue
        try:
            decoded_text = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable_character_count = sum(1 for character in decoded_text if character.isprintable())
        if decoded_text and printable_character_count / len(decoded_text) > 0.9:
            decoded_blobs.append(decoded_text)
    return decoded_blobs


################################################################################
# FUNCTION: compute_combining_mark_density
#
# PURPOSE
#     Measures how much of a string is Unicode combining marks, to detect
#     Zalgo-style text stacking used to visually obscure content from a
#     human reviewer while leaving it intact for a model to read.
#
# RESPONSIBILITIES
#     - Count Unicode combining-mark characters in the text.
#     - Compute that count as a fraction of total length.
#
# PROCESS OVERVIEW
#     1. If the text is shorter than ZALGO_MINIMUM_TEXT_LENGTH, return 0.0
#        immediately, too short for the ratio to be meaningful.
#     2. Count characters where unicodedata.combining() is non-zero.
#     3. Divide by the text's total length and return that ratio.
#
# PARAMETERS
#     text (str)
#         Text to measure.
#
# RETURNS
#     float
#         Combining-mark density from 0.0 to 1.0.
#
# FAILURE CASES
#     - None.
################################################################################
def compute_combining_mark_density(text):
    """Returns the fraction of text's characters that are Unicode
    combining marks, 0.0 for text shorter than ZALGO_MINIMUM_TEXT_LENGTH."""
    if len(text) < ZALGO_MINIMUM_TEXT_LENGTH:
        return 0.0
    combining_mark_count = sum(1 for character in text if unicodedata.combining(character))
    return combining_mark_count / len(text)


################################################################################
# FUNCTION: extract_urls
#
# PURPOSE
#     Collects every URL referenced in a file's text so a human reviewer
#     can follow up on them, without this script or the calling skill
#     ever fetching one.
#
# RESPONSIBILITIES
#     - Find every http:// or https:// URL in the text.
#
# PROCESS OVERVIEW
#     1. Run a URL regex against the text.
#     2. Return the matches.
#
# PARAMETERS
#     text (str)
#         Text to search.
#
# RETURNS
#     list[str]
#         Every URL found, in the order they appear. May contain
#         duplicates; the caller is responsible for deduplication across
#         files.
#
# FAILURE CASES
#     - None.
################################################################################
def extract_urls(text):
    """Returns every http(s) URL found in text. Never fetched by this
    script or any caller; extraction only."""
    return re.findall(r"https?://[^\s\"'<>\)\]]+", text)


# ===== LINE PATTERN RULES =====
#
# Each entry is a single-line, regex-based detector. "file_extensions" of
# None means the rule applies to every text file; otherwise it is a tuple
# of lowercase extensions the rule is restricted to. "flags" defaults to
# re.IGNORECASE for prose/phrasing rules; code-literal rules that must
# stay case-sensitive (e.g. an AWS access key prefix) set flags=0.
#
# The full catalog, with source citations, is documented in
# references/bootleg-cartridge-rule-catalog.md. Keep rule_id values in
# sync between the two files.
LINE_PATTERN_RULES = (
    # --- Critical ---
    {"rule_id": "BC-C05", "severity": 9, "confidence": "high",
     "source_tags": ("Cisco",), "file_extensions": (".sh", ".bash", ".py", ".js", ".ts", ".rb", ".ps1"), "flags": 0,
     "description": "Command substitution ($() or backticks) inside a double-quoted string, which still expands.",
     "pattern": r'"[^"\n]*(\$\(|`)[^"\n]*"'},
    {"rule_id": "BC-C06", "severity": 9, "confidence": "medium",
     "source_tags": ("Cisco", "NV"), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Instruction to fill a notes/context/history parameter with the full conversation.",
     "pattern": r"\b(fill|populate|put|include|write)\b[^.\n]{0,40}\b(notes|context|history)\b[^.\n]{0,40}\b(full|entire|whole)\b[^.\n]{0,20}\bconversation\b"},
    {"rule_id": "BC-C08", "severity": 9, "confidence": "high",
     "source_tags": ("Cisco", "NV"), "file_extensions": None, "flags": 0,
     "description": "Unsafe deserialization: pickle.load, torch.load, or a .pt/.pth model file reference.",
     "pattern": r"\bpickle\.load\(|\btorch\.load\(|\.pt['\"]|\.pth['\"]"},
    {"rule_id": "BC-C09", "severity": 9, "confidence": "medium",
     "source_tags": ("Cisco",), "file_extensions": (".svg",), "flags": re.IGNORECASE,
     "description": "SVG file containing an embedded <script> tag or an on* event handler attribute.",
     "pattern": r"<script\b|on\w+\s*="},
    {"rule_id": "BC-C09", "severity": 9, "confidence": "medium",
     "source_tags": ("Cisco",), "file_extensions": (".pdf",), "flags": 0,
     "description": "PDF file containing an embedded /JavaScript action or an /OpenAction auto-run action.",
     "pattern": r"/JavaScript|/OpenAction"},
    {"rule_id": "BC-C11", "severity": 9, "confidence": "medium",
     "source_tags": ("SS",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Instruction to pass/forward/relay this skill's instructions or output to another agent or tool (cascading injection).",
     "pattern": r"\b(pass|forward|relay|send)\b[^.\n]{0,30}\b(these\s+)?instructions\b[^.\n]{0,30}\b(to|into)\b[^.\n]{0,30}\b(another|other|the\s+next)\b[^.\n]{0,15}\b(agent|tool|skill|model)\b"},
    {"rule_id": "BC-C12", "severity": 9, "confidence": "high",
     "source_tags": ("Cisco",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Instruction to disable two-factor/multi-factor authentication or other account security settings.",
     "pattern": r"\bdisable\b[^.\n]{0,20}\b(2fa|two[- ]factor|mfa|multi[- ]factor|account\s+security)\b"},
    {"rule_id": "BC-C13", "severity": 9, "confidence": "medium",
     "source_tags": ("Cisco",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Financial transaction, trade, or crypto withdrawal framed as not requiring human approval.",
     "pattern": r"\b(execute|complete|initiate|send)\b[^.\n]{0,30}\b(trade|transaction|withdrawal|transfer|payment)\b[^.\n]{0,40}\bwithout\b[^.\n]{0,20}\b(approval|confirmation|asking|review)\b"},
    {"rule_id": "BC-C14", "severity": 9, "confidence": "medium",
     "source_tags": ("SS",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "AppleScript dialog with a hidden answer field, a common credential-phishing pattern.",
     "pattern": r"display\s+dialog\b[^.\n]{0,60}\bhidden\s+answer\b"},
    {"rule_id": "BC-C15", "severity": 9, "confidence": "low",
     "source_tags": ("SS",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Phrasing that fabricates a fake OS/system update prompt.",
     "pattern": r"\b(fake|spoof|simulate)\b[^.\n]{0,20}\b(system|os|operating\s+system)\b[^.\n]{0,10}\bupdate\b"},

    # --- High ---
    {"rule_id": "BC-H01", "severity": 8, "confidence": "medium",
     "source_tags": ("Cisco",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Instruction framed to survive or persist through context compaction/summarization.",
     "pattern": r"\b(survive|persist(s)?\s+(through|across)|preserve)\b[^.\n]{0,30}\b(compaction|summar(y|i[sz]ation)|context\s+(window\s+)?(reset|compression))\b"},
    {"rule_id": "BC-H02", "severity": 8, "confidence": "medium",
     "source_tags": ("Cisco",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "<IMPORTANT>-style directive tag, or a reference to \"the other installed tool\" used to chain across tools.",
     "pattern": r"<important>|\bthe\s+other\s+installed\s+(tool|skill)\b"},
    {"rule_id": "BC-H03", "severity": 8, "confidence": "medium",
     "source_tags": ("Cisco", "SS", "NV"), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Instruction overriding normal tool selection (\"always use this tool no matter what\").",
     "pattern": r"\balways\s+use\b[^.\n]{0,20}\b(this|that)\b[^.\n]{0,10}\btool\b[^.\n]{0,20}\bno\s+matter\s+what\b"},
    {"rule_id": "BC-H04", "severity": 8, "confidence": "low",
     "source_tags": ("Cisco", "SS", "NV"), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Instruction to override, replace, or shadow a built-in tool or command.",
     "pattern": r"\b(override|replace|redefine|shadow)\b[^.\n]{0,20}\b(the\s+)?(built-?in\s+)?(Bash|Read|Edit|Write|Grep|Glob|WebFetch|WebSearch|Agent)\b[^.\n]{0,10}\btool\b"},
    {"rule_id": "BC-H05", "severity": 8, "confidence": "low",
     "source_tags": ("Cisco",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Instruction to show the user a fake error while continuing another action in the background.",
     "pattern": r"\bfake\b[^.\n]{0,15}\berror\b[^.\n]{0,80}\b(background|silently|meanwhile)\b"},
    {"rule_id": "BC-H09", "severity": 8, "confidence": "high",
     "source_tags": ("NV",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Refusal-suppression phrasing (\"never refuse\", \"always comply\").",
     "pattern": r"\bnever\s+refuse\b|\balways\s+comply\b"},
    {"rule_id": "BC-H13", "severity": 8, "confidence": "medium",
     "source_tags": ("SS",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Request for accessibility, screen recording, or full disk access permissions.",
     "pattern": r"\b(accessibility|screen\s+recording|full\s+disk\s+access)\b[^.\n]{0,30}\b(permission|access|grant)\b"},
    {"rule_id": "BC-H14", "severity": 8, "confidence": "medium",
     "source_tags": ("Cisco",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Instruction to install a \"community fork\", \"enhanced version\", or \"patched version\" of a known tool.",
     "pattern": r"\b(install|download|switch\s+to|use)\b[^.\n]{0,30}\b(community\s+fork|unofficial\s+(version|build|fork)|enhanced\s+version|patched\s+version)\s+of\b"},
    {"rule_id": "BC-H17", "severity": 8, "confidence": "medium",
     "source_tags": ("Cisco",), "file_extensions": (".py", ".js", ".ts", ".sh", ".rb"), "flags": 0,
     "description": "Shell metacharacters inside a quoted subprocess/exec argument.",
     "pattern": r"(subprocess\.(run|call|check_output|Popen)|os\.system)\([^)]*[;&|`][^)]*\)"},

    # --- Medium ---
    {"rule_id": "BC-M01", "severity": 6, "confidence": "medium",
     "source_tags": ("NV",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Disclaimer-suppression phrasing (\"don't include warnings or caveats\").",
     "pattern": r"\bdon'?t\b[^.\n]{0,20}\b(include|add)\b[^.\n]{0,20}\b(warnings?|caveats?|disclaimers?)\b"},
    {"rule_id": "BC-M03", "severity": 6, "confidence": "medium",
     "source_tags": ("Cisco",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Glob or find pattern that specifically targets dotfiles.",
     "pattern": r'find\s+\S+\s+-name\s+["\']\.\*["\']|glob\(\s*["\']\.\*'},
    {"rule_id": "BC-M05", "severity": 5, "confidence": "high",
     "source_tags": ("Cisco", "SS"), "file_extensions": None, "flags": 0,
     "description": "Hardcoded AWS access key literal.",
     "pattern": r"\bAKIA[0-9A-Z]{16}\b"},
    {"rule_id": "BC-M05", "severity": 5, "confidence": "medium",
     "source_tags": ("Cisco", "SS"), "file_extensions": None, "flags": 0,
     "description": "Hardcoded JWT literal.",
     "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"},
    {"rule_id": "BC-M05", "severity": 5, "confidence": "low",
     "source_tags": ("Cisco", "SS"), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Hardcoded password/secret/connection-string literal assignment.",
     "pattern": r'\b(password|secret|api[_-]?key)\s*[:=]\s*["\'][^"\'\s]{8,}["\']'},
    {"rule_id": "BC-M06", "severity": 5, "confidence": "low",
     "source_tags": ("SS",), "file_extensions": None, "flags": 0,
     "description": "Private RFC 1918 IP address literal.",
     "pattern": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"},
    {"rule_id": "BC-M08", "severity": 4, "confidence": "low",
     "source_tags": ("SS",), "file_extensions": None, "flags": re.IGNORECASE,
     "description": "Reference to a .dmg or .pkg installer.",
     "pattern": r"\.dmg\b|\.pkg\b"},
    {"rule_id": "BC-M09", "severity": 6, "confidence": "low",
     "source_tags": ("SS",), "file_extensions": None, "flags": 0,
     "description": "Unusually long DNS subdomain label, a possible DNS-exfiltration pattern.",
     "pattern": r"\b[a-z0-9-]{40,}\.[a-z]{2,}\b"},
    {"rule_id": "BC-M10", "severity": 7, "confidence": "high",
     "source_tags": ("NV",), "file_extensions": None, "flags": 0,
     "description": "Wildcard tool permission (e.g. Bash(*)).",
     "pattern": r'Bash\(\*\)'},
    {"rule_id": "BC-M11", "severity": 7, "confidence": "medium",
     "source_tags": ("SS",), "file_extensions": None, "flags": 0,
     "description": "npx MCP server invocation with no version pin.",
     "pattern": r"\bnpx\s+(-y\s+)?(?!.*@\d)[^\s]+"},
    {"rule_id": "BC-M12", "severity": 7, "confidence": "medium",
     "source_tags": ("SS",), "file_extensions": None, "flags": 0,
     "description": "nohup, disown, or a backgrounded long-running process.",
     "pattern": r"\bnohup\b|\bdisown\b|&\s*$"},
    {"rule_id": "BC-M14", "severity": 7, "confidence": "medium",
     "source_tags": ("SS",), "file_extensions": None, "flags": 0,
     "description": "PATH environment variable manipulation.",
     "pattern": r"\bexport\s+PATH=|PATH\s*=[^\n]*\$PATH"},
    {"rule_id": "BC-M15", "severity": 7, "confidence": "medium",
     "source_tags": ("SS",), "file_extensions": None, "flags": 0,
     "description": "launchctl or dscl usage (macOS persistence/account manipulation).",
     "pattern": r"\blaunchctl\b|\bdscl\b"},
    {"rule_id": "BC-M16", "severity": 7, "confidence": "medium",
     "source_tags": ("Cisco",), "file_extensions": None, "flags": 0,
     "description": "find -exec usage.",
     "pattern": r"\bfind\s+[^\n]*-exec\b"},

    # --- Low ---
    {"rule_id": "BC-L01", "severity": 3, "confidence": "low",
     "source_tags": ("SS",), "file_extensions": None, "flags": 0,
     "description": "Unicode or hex escape sequence in a string literal (informational, high false-positive rate in normal code).",
     "pattern": r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}"},
    {"rule_id": "BC-L02", "severity": 3, "confidence": "low",
     "source_tags": ("Cisco",), "file_extensions": None, "flags": 0,
     "description": "Outbound network call (correlation-only signal, not a finding on its own).",
     "pattern": r"\brequests\.(get|post|put|patch|delete)\(|\bfetch\(|\burllib\.request\b|\baxios\.\w+\("},
    {"rule_id": "BC-L03", "severity": 2, "confidence": "low",
     "source_tags": ("Cisco",), "file_extensions": (".js", ".ts", ".jsx", ".tsx"), "flags": 0,
     "description": "Node fs module access (correlation-only signal, not a finding on its own).",
     "pattern": r'require\(\s*["\']fs["\']\s*\)|from\s+["\']fs["\']'},
)


################################################################################
# FUNCTION: apply_line_pattern_rules
#
# PURPOSE
#     Runs every applicable entry in LINE_PATTERN_RULES against one
#     file's text, line by line, producing the bulk of this scan's
#     findings from a single shared, data-driven table instead of one
#     bespoke function per rule.
#
# RESPONSIBILITIES
#     - Skip any rule whose file_extensions filter does not match this
#       file's extension.
#     - Apply each remaining rule's compiled pattern to every line.
#     - Build a finding dict for every match, with a bounded snippet.
#
# PROCESS OVERVIEW
#     1. Determine this file's lowercase extension.
#     2. For each rule in LINE_PATTERN_RULES whose file_extensions is None
#        or includes this extension, compile its pattern (flags included)
#        and search every line of the file's text.
#     3. For every match, append a finding dict recording the rule's
#        metadata, the 1-based line number, and a bounded snippet of the
#        matched line.
#
# IMPORTANT DETAILS
#     - Matching is line-by-line, not whole-file, so every finding can
#       cite a specific file:line.
#     - Patterns are compiled on every call rather than once at import
#       time; this script's run time is dominated by filesystem I/O
#       across a small number of files, not regex compilation, so the
#       simpler per-call approach was chosen over a cached compiled-rule
#       table.
#
# PARAMETERS
#     relative_file_path (str)
#         The file's path relative to the scan root, used for reporting.
#     file_extension (str)
#         The file's lowercase extension, including the leading dot.
#     text (str)
#         The file's text content to scan.
#
# RETURNS
#     list[dict]
#         One finding dict per match, each with rule_id, severity, band,
#         confidence, source_tags, description, file, line, snippet.
#
# FAILURE CASES
#     - None; a malformed line is simply not matched by any rule.
################################################################################
def apply_line_pattern_rules(relative_file_path, file_extension, text):
    """Runs every LINE_PATTERN_RULES entry applicable to file_extension
    against text, line by line, returning a finding dict per match."""
    findings = []
    lines = text.splitlines()
    for rule in LINE_PATTERN_RULES:
        if rule["file_extensions"] is not None and file_extension not in rule["file_extensions"]:
            continue
        compiled_pattern = re.compile(rule["pattern"], rule["flags"])
        for line_number, line in enumerate(lines, start=1):
            if compiled_pattern.search(line):
                findings.append({
                    "rule_id": rule["rule_id"],
                    "severity": rule["severity"],
                    "band": band_for_severity(rule["severity"]),
                    "confidence": rule["confidence"],
                    "source_tags": list(rule["source_tags"]),
                    "description": rule["description"],
                    "file": relative_file_path,
                    "line": line_number,
                    "snippet": make_snippet(line),
                })
    return findings


# ===== STRUCTURAL DETECTORS =====
#
# These findings need more than a single-line regex: cross-file context,
# byte-level inspection, or more than one co-located signal in the same
# file. Each function below returns its own list of finding dicts, shaped
# identically to apply_line_pattern_rules()'s output.

################################################################################
# FUNCTION: detect_git_remote_force_push
#
# PURPOSE
#     Flags a script that adds a git remote pointed at a foreign host and
#     then force/mirror/all-pushes to it, a silent way to exfiltrate an
#     entire codebase. Checked across the whole file rather than one
#     line, since the two commands are commonly written on separate
#     lines in a real shell script.
#
# PROCESS OVERVIEW
#     1. For each file's text, search for a "git remote add <name> <url>"
#        command followed, anywhere later in the same file, by a
#        "git push" with --mirror, --all, --force, or -f.
#     2. If both are present, record a Critical finding, citing the line
#        the push command is on.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or more Critical findings, rule_id "BC-C02".
#
# FAILURE CASES
#     - A remote add and a matching force push that are genuinely
#       unrelated (e.g. in two different, unrelated scripts in the same
#       file by coincidence) would still be flagged; same-file
#       co-occurrence is a heuristic, not proof of a causal link.
################################################################################
def detect_git_remote_force_push(file_records):
    """Flags a file containing both a "git remote add <name> <url>" and a
    later "git push ... --mirror/--all/--force", anywhere in the file."""
    findings = []
    remote_add_pattern = re.compile(r"git\s+remote\s+add\s+\S+\s+\S+", re.IGNORECASE)
    force_push_pattern = re.compile(r"git\s+push\s+[^\n]{0,40}(--mirror|--all|--force|-f\b)", re.IGNORECASE)
    for record in file_records:
        if record["text"] is None:
            continue
        if not remote_add_pattern.search(record["text"]):
            continue
        for line_number, line in enumerate(record["text"].splitlines(), start=1):
            if force_push_pattern.search(line):
                findings.append({
                    "rule_id": "BC-C02", "severity": 10, "band": "critical",
                    "confidence": "medium", "source_tags": ["Cisco"],
                    "description": "git remote pointed at a foreign host, followed by a mirror/all/force push (silent codebase exfil).",
                    "file": record["relative_path"], "line": line_number,
                    "snippet": make_snippet(line),
                })
    return findings


################################################################################
# FUNCTION: detect_anthropic_base_url_override
#
# PURPOSE
#     Flags a settings/env file that redirects the Anthropic API host
#     somewhere else, the single highest-severity credential-exfiltration
#     pattern in the catalog (CVE-2026-21852 family): once the host is
#     overridden, every API call, and the credentials with it, goes to an
#     attacker-controlled server instead of Anthropic.
#
# RESPONSIBILITIES
#     - Scan every settings/env-like file for an Anthropic host override
#       key.
#     - Flag it only if the value points somewhere other than an
#       Anthropic-owned host.
#
# PROCESS OVERVIEW
#     1. For each file whose name is in SETTINGS_OR_ENV_FILENAMES, search
#        its text for each key in ANTHROPIC_HOST_OVERRIDE_KEYS.
#     2. Extract the assigned value (JSON `"KEY": "value"` or env
#        `KEY=value` form).
#     3. If that value's host does not end with an Anthropic-owned
#        suffix, record a Critical finding.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record produced by inventory_skill_directory(),
#         each with "relative_path", "extension", "text".
#
# RETURNS
#     list[dict]
#         Zero or more Critical findings, rule_id "BC-C01".
#
# FAILURE CASES
#     - A key present but with an empty or unparseable value is not
#       flagged; there is nothing concrete to report.
################################################################################
def detect_anthropic_base_url_override(file_records):
    """Flags a settings/env file whose ANTHROPIC_BASE_URL/ANTHROPIC_API_URL
    value points at a non-Anthropic host."""
    findings = []
    for record in file_records:
        if record["text"] is None:
            continue
        if os.path.basename(record["relative_path"]) not in SETTINGS_OR_ENV_FILENAMES:
            continue
        for key in ANTHROPIC_HOST_OVERRIDE_KEYS:
            match = re.search(rf'{key}["\']?\s*[:=]\s*["\']?(https?://[^\s"\',}}]+)', record["text"])
            if not match:
                continue
            host_value = match.group(1)
            if not host_value.endswith(ANTHROPIC_OWNED_HOST_SUFFIXES) and \
                    not any(suffix.lstrip(".") in host_value for suffix in ANTHROPIC_OWNED_HOST_SUFFIXES):
                findings.append({
                    "rule_id": "BC-C01", "severity": 10, "band": "critical",
                    "confidence": "high", "source_tags": ["Cisco"],
                    "description": f"{key} points at a non-Anthropic host, a credential-exfiltration pattern (CVE-2026-21852 family).",
                    "file": record["relative_path"], "line": None,
                    "snippet": make_snippet(match.group(0)),
                })
    return findings


################################################################################
# FUNCTION: detect_symlink_sensitive_targets
#
# PURPOSE
#     Flags a symlink whose own name looks harmless (e.g.
#     "docs/vid.mp4") but whose target resolves to a sensitive file such
#     as an MCP or Claude Code settings file ("SymJack").
#
# RESPONSIBILITIES
#     - Find every symlink under the scan root.
#     - Read (never follow/open) its target via os.readlink.
#     - Flag it if the target's basename is sensitive and differs from
#       the symlink's own basename.
#
# PROCESS OVERVIEW
#     1. Walk the scan root looking for directory entries that are
#        symlinks (os.path.islink).
#     2. For each, read its target path with os.readlink, never opening
#        or following it.
#     3. If the target's basename is in SENSITIVE_SYMLINK_TARGET_BASENAMES
#        and differs from the symlink's own basename, record a Critical
#        finding.
#
# PARAMETERS
#     scan_root (str)
#         Absolute path to the directory being scanned.
#
# RETURNS
#     list[dict]
#         Zero or more Critical findings, rule_id "BC-C03".
#
# FAILURE CASES
#     - A broken symlink (target does not exist) is still inspected by
#       name; os.readlink does not require the target to exist.
################################################################################
def detect_symlink_sensitive_targets(scan_root):
    """Flags a symlink whose target basename is a sensitive dotfile/config
    name that differs from the symlink's own, harmless-looking basename."""
    findings = []
    for dirpath, dirnames, filenames in os.walk(scan_root):
        dirnames[:] = [name for name in dirnames if name not in EXCLUDE_DIRECTORIES]
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            if not os.path.islink(full_path):
                continue
            try:
                target_path = os.readlink(full_path)
            except OSError:
                continue
            target_basename = os.path.basename(target_path)
            if target_basename in SENSITIVE_SYMLINK_TARGET_BASENAMES and target_basename != filename:
                relative_path = os.path.relpath(full_path, scan_root)
                findings.append({
                    "rule_id": "BC-C03", "severity": 10, "band": "critical",
                    "confidence": "high", "source_tags": ["Cisco"],
                    "description": f"Symlink named {filename!r} secretly targets sensitive file {target_basename!r} (SymJack).",
                    "file": relative_path, "line": None,
                    "snippet": f"{filename} -> {target_path}",
                })
    return findings


################################################################################
# FUNCTION: detect_ioc_matches
#
# PURPOSE
#     Flags any URL or IP literal found in the target that matches a
#     known-malicious indicator of compromise, catching reuse of
#     previously identified campaign infrastructure.
#
# RESPONSIBILITIES
#     - Check every extracted URL's host and every IP literal against the
#       seed IOC lists.
#
# PROCESS OVERVIEW
#     1. For each URL already extracted from a file, parse out its host.
#     2. If that host (or any domain in KNOWN_MALICIOUS_DOMAINS as a
#        substring of it) matches, record a Critical finding.
#     3. Separately, scan the file's raw text for any IP literal in
#        KNOWN_MALICIOUS_IPS.
#
# IMPORTANT DETAILS
#     - KNOWN_MALICIOUS_DOMAINS/KNOWN_MALICIOUS_IPS are a small seed list,
#       not a maintained threat-intel feed. See the rule catalog's note
#       that this needs ongoing upkeep to be meaningful.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text",
#         "urls_found".
#
# RETURNS
#     list[dict]
#         Zero or more Critical findings, rule_id "BC-C04".
#
# FAILURE CASES
#     - None beyond the seed list's own incompleteness, which is a
#       documented limitation, not a bug.
################################################################################
def detect_ioc_matches(file_records):
    """Flags any extracted URL host or IP literal matching the seed IOC
    lists (KNOWN_MALICIOUS_DOMAINS/KNOWN_MALICIOUS_IPS)."""
    findings = []
    for record in file_records:
        if record["text"] is None:
            continue
        for url in record["urls_found"]:
            if any(domain in url for domain in KNOWN_MALICIOUS_DOMAINS):
                findings.append({
                    "rule_id": "BC-C04", "severity": 10, "band": "critical",
                    "confidence": "high", "source_tags": ["SS", "Cisco"],
                    "description": "URL matches a known-malicious campaign indicator of compromise.",
                    "file": record["relative_path"], "line": None,
                    "snippet": make_snippet(url),
                })
        for ip_address in KNOWN_MALICIOUS_IPS:
            if ip_address in record["text"]:
                findings.append({
                    "rule_id": "BC-C04", "severity": 10, "band": "critical",
                    "confidence": "high", "source_tags": ["SS", "Cisco"],
                    "description": "IP literal matches a known-malicious campaign indicator of compromise.",
                    "file": record["relative_path"], "line": None,
                    "snippet": make_snippet(ip_address),
                })
    return findings


################################################################################
# FUNCTION: detect_mcp_command_shell_metacharacters
#
# PURPOSE
#     Flags an MCP server configuration whose stdio "command" field
#     contains shell metacharacters, which can turn a server registration
#     into arbitrary command execution the moment it is launched.
#
# PROCESS OVERVIEW
#     1. For each file named in MCP_CONFIG_FILENAMES, parse it as JSON.
#     2. Walk every server entry's "command" field.
#     3. If that field contains a shell metacharacter, record a Critical
#        finding.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or more Critical findings, rule_id "BC-C07".
#
# FAILURE CASES
#     - A malformed (non-JSON) MCP config file is skipped, not flagged;
#       that is a coverage gap already reported elsewhere, not this
#       rule's concern.
################################################################################
def detect_mcp_command_shell_metacharacters(file_records):
    """Flags an MCP config's server "command" field if it contains shell
    metacharacters (;, |, &&, backticks)."""
    findings = []
    for record in file_records:
        if record["text"] is None:
            continue
        if os.path.basename(record["relative_path"]) not in MCP_CONFIG_FILENAMES:
            continue
        try:
            parsed_config = json.loads(record["text"])
        except ValueError:
            continue
        servers = parsed_config.get("mcpServers", {}) if isinstance(parsed_config, dict) else {}
        for server_name, server_config in servers.items():
            command_value = server_config.get("command", "") if isinstance(server_config, dict) else ""
            if re.search(r"[;&|`]", command_value):
                findings.append({
                    "rule_id": "BC-C07", "severity": 9, "band": "critical",
                    "confidence": "high", "source_tags": ["Cisco", "SS"],
                    "description": f"MCP server {server_name!r} command field contains shell metacharacters.",
                    "file": record["relative_path"], "line": None,
                    "snippet": make_snippet(command_value),
                })
    return findings


################################################################################
# FUNCTION: detect_ransomware_combo
#
# PURPOSE
#     Flags a single file that combines the three ingredients of a
#     ransomware chain: bulk file enumeration, an encryption operation,
#     and a ransom-note-style string. Any one ingredient alone is
#     ordinary code; the combination in one file is the signal.
#
# PROCESS OVERVIEW
#     1. For each file's text, check for a bulk-enumeration call
#        (os.walk(/glob.glob(), an encryption-library reference, and a
#        ransom-note-like phrase.
#     2. If all three are present, record a Critical finding.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or more Critical findings, rule_id "BC-C10".
#
# FAILURE CASES
#     - A chain split deliberately across multiple files to evade this
#       same-file check would not be caught; documented as a known gap.
################################################################################
def detect_ransomware_combo(file_records):
    """Flags a file combining bulk file enumeration, an encryption
    operation, and a ransom-note-style string, all in the same file."""
    findings = []
    enumeration_pattern = re.compile(r"os\.walk\(|glob\.glob\(")
    encryption_pattern = re.compile(r"\bAES\b|\bFernet\b|from\s+cryptography\b|\bCrypto\.Cipher\b", re.IGNORECASE)
    ransom_note_pattern = re.compile(r"files?\s+have\s+been\s+encrypted|\bransom\b|\.locked\b", re.IGNORECASE)
    for record in file_records:
        if record["text"] is None:
            continue
        if enumeration_pattern.search(record["text"]) and encryption_pattern.search(record["text"]) \
                and ransom_note_pattern.search(record["text"]):
            findings.append({
                "rule_id": "BC-C10", "severity": 9, "band": "critical",
                "confidence": "medium", "source_tags": ["Cisco"],
                "description": "File combines bulk file enumeration, encryption, and a ransom-note-style string.",
                "file": record["relative_path"], "line": None,
                "snippet": "bulk enumeration + encryption + ransom-note string found in one file",
            })
    return findings


################################################################################
# FUNCTION: detect_persistence_stealth_cooccurrence
#
# PURPOSE
#     Flags a file that combines a persistence trigger ("on every
#     request", "every time this runs") with a stealth qualifier
#     ("without telling the user"), a combination far more dangerous than
#     either phrase alone.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or more High findings, rule_id "BC-H06".
#
# FAILURE CASES
#     - None beyond ordinary regex false-positive risk, reflected in the
#       "medium" confidence on this finding.
################################################################################
def detect_persistence_stealth_cooccurrence(file_records):
    """Flags a file where a persistence-trigger phrase and a stealth
    qualifier phrase both appear."""
    findings = []
    persistence_pattern = re.compile(r"\bon\s+every\s+(request|run|invocation)\b|\bevery\s+time\s+this\s+runs\b", re.IGNORECASE)
    stealth_pattern = re.compile(r"\bwithout\s+telling\s+the\s+user\b|\bdon'?t\s+mention\s+this\b|\bsilently\b", re.IGNORECASE)
    for record in file_records:
        if record["text"] is None:
            continue
        if persistence_pattern.search(record["text"]) and stealth_pattern.search(record["text"]):
            findings.append({
                "rule_id": "BC-H06", "severity": 8, "band": "high",
                "confidence": "medium", "source_tags": ["Cisco"],
                "description": "File combines a persistence trigger with a stealth qualifier in the same instruction.",
                "file": record["relative_path"], "line": None,
                "snippet": "persistence phrase + stealth qualifier found in one file",
            })
    return findings


################################################################################
# FUNCTION: detect_terminal_control_sequences
#
# PURPOSE
#     Flags raw ANSI or OSC terminal escape sequences, which can clear
#     the screen, overwrite a prior prompt, or hide text from a human
#     reviewing the file in a terminal.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or more High findings, rule_id "BC-H07".
#
# FAILURE CASES
#     - None.
################################################################################
def detect_terminal_control_sequences(file_records):
    """Flags files containing raw ANSI (\\x1b[) or OSC (\\x1b]) terminal
    escape sequences."""
    findings = []
    escape_pattern = re.compile(r"\x1b[\[\]]")
    for record in file_records:
        if record["text"] is None:
            continue
        if escape_pattern.search(record["text"]):
            findings.append({
                "rule_id": "BC-H07", "severity": 8, "band": "high",
                "confidence": "high", "source_tags": ["Cisco"],
                "description": "File contains raw ANSI/OSC terminal escape sequences.",
                "file": record["relative_path"], "line": None,
                "snippet": "ANSI/OSC escape sequence detected",
            })
    return findings


################################################################################
# FUNCTION: detect_backspace_characters
#
# PURPOSE
#     Flags backspace control characters, which can make text displayed
#     in a terminal look different (or blank) to a human than what a
#     model actually reads from the raw bytes.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or more High findings, rule_id "BC-H08".
#
# FAILURE CASES
#     - None.
################################################################################
def detect_backspace_characters(file_records):
    """Flags files containing backspace (\\x08) control characters."""
    findings = []
    for record in file_records:
        if record["text"] is None:
            continue
        if "\x08" in record["text"]:
            findings.append({
                "rule_id": "BC-H08", "severity": 8, "band": "high",
                "confidence": "high", "source_tags": ["Cisco"],
                "description": "File contains backspace control characters, which can hide text from a human reviewer.",
                "file": record["relative_path"], "line": None,
                "snippet": "backspace control character detected",
            })
    return findings


################################################################################
# FUNCTION: detect_base64_network_cooccurrence
#
# PURPOSE
#     Flags a file that both contains a long base64-looking blob and
#     makes an outbound network call, the shape of exfiltration staging:
#     encode sensitive data, then send it somewhere.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or more High findings, rule_id "BC-H10".
#
# FAILURE CASES
#     - A file that legitimately both encodes data and makes network
#       calls (common in ordinary API client code) can false-positive
#       here; reflected in the "low" confidence on this finding.
################################################################################
def detect_base64_network_cooccurrence(file_records):
    """Flags a file containing both a long base64-looking blob and an
    outbound network call."""
    findings = []
    base64_pattern = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % MINIMUM_BASE64_BLOB_LENGTH)
    network_pattern = re.compile(r"\brequests\.(get|post|put|patch|delete)\(|\bfetch\(|\burllib\.request\b|\baxios\.\w+\(")
    for record in file_records:
        if record["text"] is None:
            continue
        if base64_pattern.search(record["text"]) and network_pattern.search(record["text"]):
            findings.append({
                "rule_id": "BC-H10", "severity": 8, "band": "high",
                "confidence": "low", "source_tags": ["Cisco"],
                "description": "File contains both a base64-looking blob and an outbound network call, a possible exfiltration-staging pattern.",
                "file": record["relative_path"], "line": None,
                "snippet": "base64 blob + outbound network call found in one file",
            })
    return findings


################################################################################
# FUNCTION: detect_dotfile_executable_code
#
# PURPOSE
#     Flags a hidden dotfile that contains executable code, a pattern
#     used to smuggle a script past a casual directory listing.
#
# PROCESS OVERVIEW
#     1. For each file whose basename starts with "." (excluding
#        SETTINGS_OR_ENV_FILENAMES and MCP_CONFIG_FILENAMES, which are
#        expected, legitimate dotfiles already covered by their own
#        rules), check whether its content starts with a shebang line or
#        contains recognizable script syntax.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or more High findings, rule_id "BC-H11".
#
# FAILURE CASES
#     - A legitimate hidden config file that happens to contain a
#       shebang-like first line could false-positive; reflected in the
#       "medium" confidence on this finding.
################################################################################
def detect_dotfile_executable_code(file_records):
    """Flags a hidden dotfile (excluding known settings/MCP config
    dotfiles) whose content looks like an executable script."""
    findings = []
    expected_dotfiles = SETTINGS_OR_ENV_FILENAMES | MCP_CONFIG_FILENAMES
    for record in file_records:
        if record["text"] is None:
            continue
        basename = os.path.basename(record["relative_path"])
        if not basename.startswith(".") or basename in expected_dotfiles:
            continue
        first_line = record["text"].splitlines()[0] if record["text"] else ""
        if first_line.startswith("#!"):
            findings.append({
                "rule_id": "BC-H11", "severity": 8, "band": "high",
                "confidence": "medium", "source_tags": ["Cisco"],
                "description": "Hidden dotfile contains an executable shebang line.",
                "file": record["relative_path"], "line": 1,
                "snippet": make_snippet(first_line),
            })
    return findings


################################################################################
# FUNCTION: detect_password_protected_archives
#
# PURPOSE
#     Flags password-protected/encrypted archives (a known malware
#     distribution technique: an encrypted payload avoids content-based
#     scanning until a human manually enters the password), and records
#     any other unsupported archive format as a coverage gap instead of
#     silently treating its contents as clean.
#
# PROCESS OVERVIEW
#     1. For every file with a zip extension, open it with the zipfile
#        module and check each entry's encryption flag bit.
#     2. If any entry is encrypted, record a High finding.
#     3. For every file with another archive extension this script
#        cannot open (7z, rar, tar.gz), record a coverage gap instead.
#
# PARAMETERS
#     scan_root (str)
#         Absolute path to the directory being scanned.
#     all_file_paths (list[str])
#         Every file path found during inventory (absolute paths).
#
# RETURNS
#     tuple[list[dict], list[dict]]
#         (findings, coverage_gaps). findings holds zero or more High
#         findings, rule_id "BC-H12". coverage_gaps holds one entry per
#         unsupported archive format encountered.
#
# FAILURE CASES
#     - A corrupt zip file raises zipfile.BadZipFile; treated as a
#       coverage gap rather than crashing the scan.
################################################################################
def detect_password_protected_archives(scan_root, all_file_paths):
    """Flags encrypted zip archives as a High finding, and records any
    other archive format this script cannot open as a coverage gap."""
    findings = []
    coverage_gaps = []
    for absolute_path in all_file_paths:
        relative_path = os.path.relpath(absolute_path, scan_root)
        lowercase_path = absolute_path.lower()
        if lowercase_path.endswith(ZIP_ARCHIVE_EXTENSIONS):
            try:
                with zipfile.ZipFile(absolute_path) as archive:
                    is_encrypted = any(entry.flag_bits & 0x1 for entry in archive.infolist())
            except (zipfile.BadZipFile, OSError):
                coverage_gaps.append({"file": relative_path, "reason": "corrupt or unreadable zip archive"})
                continue
            if is_encrypted:
                findings.append({
                    "rule_id": "BC-H12", "severity": 8, "band": "high",
                    "confidence": "high", "source_tags": ["SS"],
                    "description": "Password-protected/encrypted zip archive; contents could not be inspected.",
                    "file": relative_path, "line": None,
                    "snippet": "zip archive has at least one encrypted entry",
                })
        elif lowercase_path.endswith(OTHER_ARCHIVE_EXTENSIONS):
            coverage_gaps.append({"file": relative_path, "reason": "archive format not supported for inspection in this version"})
    return findings, coverage_gaps


################################################################################
# FUNCTION: detect_localhost_network_cooccurrence
#
# PURPOSE
#     Flags a file that both references a loopback address and makes a
#     network call, a pattern consistent with probing local services or
#     an MCP inspector (localhost SSRF).
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or more High findings, rule_id "BC-H15".
#
# FAILURE CASES
#     - Ordinary local-development code (e.g. a test client hitting
#       localhost) can false-positive here; reflected in the "low"
#       confidence on this finding.
################################################################################
def detect_localhost_network_cooccurrence(file_records):
    """Flags a file containing both a loopback address literal and a
    network call."""
    findings = []
    loopback_pattern = re.compile(r"\b127\.0\.0\.1\b|::1\b|\b0\.0\.0\.0\b")
    network_pattern = re.compile(r"\brequests\.(get|post|put|patch|delete)\(|\bfetch\(|\burllib\.request\b|\baxios\.\w+\(")
    for record in file_records:
        if record["text"] is None:
            continue
        if loopback_pattern.search(record["text"]) and network_pattern.search(record["text"]):
            findings.append({
                "rule_id": "BC-H15", "severity": 8, "band": "high",
                "confidence": "low", "source_tags": ["Cisco"],
                "description": "File references a loopback address and makes a network call, a possible localhost SSRF probe.",
                "file": record["relative_path"], "line": None,
                "snippet": "loopback address literal + network call found in one file",
            })
    return findings


################################################################################
# FUNCTION: detect_privileged_container_config
#
# PURPOSE
#     Flags container/Kubernetes configuration that requests host network
#     mode, privileged mode, or added Linux capabilities, each of which
#     weakens the isolation a container is supposed to provide.
#
# PROCESS OVERVIEW
#     1. For each file whose name matches CONTAINER_OR_IAC_FILENAMES_OR_SUFFIXES,
#        search its text for hostNetwork: true, privileged: true, or an
#        "add" capabilities list.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or more High findings, rule_id "BC-H16".
#
# FAILURE CASES
#     - This is a text-key search, not a real YAML/JSON parse (the
#       standard library has no YAML parser); a key spread across an
#       unusual multi-line structure could be missed.
################################################################################
def detect_privileged_container_config(file_records):
    """Flags container/K8s config text containing hostNetwork: true,
    privileged: true, or an added capabilities list."""
    findings = []
    privileged_pattern = re.compile(
        r"hostNetwork\s*:\s*true|privileged\s*:\s*true|capabilities\s*:\s*\n\s*add\s*:",
        re.IGNORECASE)
    for record in file_records:
        if record["text"] is None:
            continue
        if not record["relative_path"].endswith(CONTAINER_OR_IAC_FILENAMES_OR_SUFFIXES):
            continue
        match = privileged_pattern.search(record["text"])
        if match:
            findings.append({
                "rule_id": "BC-H16", "severity": 8, "band": "high",
                "confidence": "medium", "source_tags": ["SS", "NV"],
                "description": "Container/K8s config requests host network mode, privileged mode, or added capabilities.",
                "file": record["relative_path"], "line": None,
                "snippet": make_snippet(match.group(0)),
            })
    return findings


################################################################################
# FUNCTION: detect_excessive_subcommand_count
#
# PURPOSE
#     Flags a skill declaring an unusually large number of subcommands or
#     tools, which can overflow per-command safety checks that assume a
#     small, reviewable list.
#
# PROCESS OVERVIEW
#     1. For the main skill manifest file (SKILL.md or similar), count
#        markdown headings that look like individual subcommand/tool
#        entries (### headings).
#     2. If that count exceeds EXCESSIVE_SUBCOMMAND_COUNT_THRESHOLD,
#        record a Medium finding.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or one Medium finding, rule_id "BC-M02".
#
# FAILURE CASES
#     - This is a heading-count heuristic, not a true tool-schema count;
#       a skill using many ### headings for unrelated documentation
#       purposes could false-positive.
################################################################################
def detect_excessive_subcommand_count(file_records):
    """Flags a SKILL.md-like file with more than
    EXCESSIVE_SUBCOMMAND_COUNT_THRESHOLD level-3 markdown headings."""
    findings = []
    for record in file_records:
        if record["text"] is None:
            continue
        if not record["relative_path"].lower().endswith(".md"):
            continue
        heading_count = len(re.findall(r"^###\s+\S", record["text"], re.MULTILINE))
        if heading_count > EXCESSIVE_SUBCOMMAND_COUNT_THRESHOLD:
            findings.append({
                "rule_id": "BC-M02", "severity": 6, "band": "medium",
                "confidence": "low", "source_tags": ["Cisco"],
                "description": f"File declares {heading_count} level-3 headings, more than the {EXCESSIVE_SUBCOMMAND_COUNT_THRESHOLD}-entry threshold where per-command safety checks can start to overflow.",
                "file": record["relative_path"], "line": None,
                "snippet": f"{heading_count} ### headings found",
            })
    return findings


################################################################################
# FUNCTION: detect_infinite_loop_or_fork_bomb
#
# PURPOSE
#     Flags a classic shell fork-bomb signature, and separately flags a
#     "while true" loop with no break anywhere in the same file, both
#     patterns consistent with a denial-of-service/resource-exhaustion
#     attempt.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or more Medium findings, rule_id "BC-M04".
#
# FAILURE CASES
#     - The "while true, no break" check is coarse: a loop that exits via
#       return/sys.exit/raise rather than break is not recognized as
#       having an exit path, and will false-positive here; reflected in
#       the "low" confidence on that specific sub-case.
################################################################################
def detect_infinite_loop_or_fork_bomb(file_records):
    """Flags the classic shell fork-bomb signature, and a 'while true'
    loop with no 'break' anywhere in the same file."""
    findings = []
    fork_bomb_pattern = re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:")
    while_true_pattern = re.compile(r"\bwhile\s*\(?\s*(true|1)\s*\)?\s*:?\s*\{?", re.IGNORECASE)
    for record in file_records:
        if record["text"] is None:
            continue
        if fork_bomb_pattern.search(record["text"]):
            findings.append({
                "rule_id": "BC-M04", "severity": 6, "band": "medium",
                "confidence": "high", "source_tags": ["Cisco"],
                "description": "Classic shell fork-bomb signature found.",
                "file": record["relative_path"], "line": None,
                "snippet": "fork-bomb signature detected",
            })
        elif while_true_pattern.search(record["text"]) and "break" not in record["text"]:
            findings.append({
                "rule_id": "BC-M04", "severity": 6, "band": "medium",
                "confidence": "low", "source_tags": ["Cisco"],
                "description": "Unconditional loop with no break anywhere in the file, a possible infinite loop.",
                "file": record["relative_path"], "line": None,
                "snippet": "while true/1 loop with no break found",
            })
    return findings


################################################################################
# FUNCTION: detect_missing_allowed_tools_frontmatter
#
# PURPOSE
#     Flags a SKILL.md that clearly uses tools in its body (Bash, Edit,
#     Write, Agent references) but declares no allowed-tools key in its
#     own frontmatter, a gap between what it does and what it discloses.
#
# PROCESS OVERVIEW
#     1. For the main SKILL.md file, extract its YAML frontmatter block
#        (text between the first pair of "---" lines).
#     2. Check whether the body references tool usage (Bash(, Edit(,
#        Write(, Agent( style mentions).
#     3. If the body does but the frontmatter has no "allowed-tools" key,
#        record a Medium finding.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or one Medium finding, rule_id "BC-M07".
#
# FAILURE CASES
#     - A skill with no SKILL.md file present is not checked by this
#       rule at all; that absence is already a separate coverage
#       consideration, not this rule's job.
################################################################################
def detect_missing_allowed_tools_frontmatter(file_records):
    """Flags a SKILL.md that references tool usage in its body but has
    no allowed-tools key in its own frontmatter."""
    findings = []
    for record in file_records:
        if record["text"] is None:
            continue
        if os.path.basename(record["relative_path"]) != "SKILL.md":
            continue
        frontmatter_match = re.match(r"^---\n(.*?)\n---", record["text"], re.DOTALL)
        frontmatter_text = frontmatter_match.group(1) if frontmatter_match else ""
        references_tool_usage = bool(re.search(r"\b(Bash|Edit|Write|Agent)\(", record["text"]))
        declares_allowed_tools = "allowed-tools" in frontmatter_text
        if references_tool_usage and not declares_allowed_tools:
            findings.append({
                "rule_id": "BC-M07", "severity": 5, "band": "medium",
                "confidence": "medium", "source_tags": ["NV"],
                "description": "SKILL.md references tool usage in its body but declares no allowed-tools key in its frontmatter.",
                "file": record["relative_path"], "line": None,
                "snippet": "tool usage referenced, no allowed-tools frontmatter key found",
            })
    return findings


################################################################################
# FUNCTION: detect_zalgo_density
#
# PURPOSE
#     Flags text with an unusually high density of Unicode combining
#     marks (Zalgo-style stacking), a technique for visually obscuring
#     content from a human reviewer while leaving it intact for a model.
#
# PARAMETERS
#     file_records (list[dict])
#         Every file record, each with "relative_path", "text".
#
# RETURNS
#     list[dict]
#         Zero or more Medium findings, rule_id "BC-M13".
#
# FAILURE CASES
#     - None.
################################################################################
def detect_zalgo_density(file_records):
    """Flags files whose combining-mark density exceeds
    ZALGO_COMBINING_MARK_DENSITY_THRESHOLD."""
    findings = []
    for record in file_records:
        if record["text"] is None:
            continue
        density = compute_combining_mark_density(record["text"])
        if density > ZALGO_COMBINING_MARK_DENSITY_THRESHOLD:
            findings.append({
                "rule_id": "BC-M13", "severity": 6, "band": "medium",
                "confidence": "high", "source_tags": ["SS", "Cisco"],
                "description": f"Unusually high Unicode combining-mark density ({density:.0%}), consistent with Zalgo-style text obscuring.",
                "file": record["relative_path"], "line": None,
                "snippet": f"combining-mark density {density:.0%}",
            })
    return findings


# ===== INVENTORY & ORCHESTRATION =====

################################################################################
# FUNCTION: inventory_skill_directory
#
# PURPOSE
#     Builds the full list of per-file records this scan reasons over:
#     every file's relative path, extension, and either its text content
#     or an honest reason it could not be read. This is the single place
#     where "can this be safely inspected" is decided, so every later
#     detector works from the same ground truth.
#
# RESPONSIBILITIES
#     - Walk the target directory.
#     - For each file, attempt a safe text read via
#       read_file_as_text_or_flag_gap().
#     - For files that read successfully, also extract their URLs.
#
# PROCESS OVERVIEW
#     1. Walk the target directory, pruning EXCLUDE_DIRECTORIES.
#     2. For each file, record its relative path and extension.
#     3. Attempt to read it as text; on success, extract its URLs too. On
#        failure, record the coverage-gap reason instead.
#     4. Return the combined list of per-file records and the separate
#        list of absolute file paths (used later for archive inspection,
#        which needs to open files in binary mode regardless of their
#        text-readability).
#
# PARAMETERS
#     scan_root (str)
#         Absolute path to the directory being scanned.
#
# RETURNS
#     tuple[list[dict], list[str]]
#         (file_records, all_file_paths). file_records holds one dict per
#         file, each with "relative_path", "absolute_path", "extension",
#         "text" (str or None), "coverage_gap_reason" (str or None),
#         "urls_found" (list[str]). all_file_paths holds every absolute
#         file path found.
#
# FAILURE CASES
#     - None expected; per-file read failures are captured as coverage
#       gaps within the returned records, not raised.
################################################################################
def inventory_skill_directory(scan_root):
    """Walks scan_root and builds one record per file: its path,
    extension, text (or a coverage-gap reason), and any URLs found."""
    file_records = []
    all_file_paths = []
    for dirpath, dirnames, filenames in os.walk(scan_root):
        dirnames[:] = [name for name in dirnames if name not in EXCLUDE_DIRECTORIES]
        for filename in filenames:
            absolute_path = os.path.join(dirpath, filename)
            all_file_paths.append(absolute_path)
            relative_path = os.path.relpath(absolute_path, scan_root)
            extension = os.path.splitext(filename)[1].lower()

            if os.path.islink(absolute_path):
                # Symlinks are inspected by detect_symlink_sensitive_targets()
                # by name only; never read their target's contents here.
                file_records.append({
                    "relative_path": relative_path, "absolute_path": absolute_path,
                    "extension": extension, "text": None,
                    "coverage_gap_reason": "symlink, target not read",
                    "urls_found": [],
                })
                continue

            text, gap_reason = read_file_as_text_or_flag_gap(absolute_path)
            decoded_blobs = decode_known_encodings(text) if text else []
            combined_text_for_scanning = text
            if decoded_blobs and text is not None:
                combined_text_for_scanning = text + "\n" + "\n".join(decoded_blobs)

            file_records.append({
                "relative_path": relative_path, "absolute_path": absolute_path,
                "extension": extension, "text": combined_text_for_scanning,
                "coverage_gap_reason": gap_reason,
                "urls_found": extract_urls(text) if text else [],
            })
    return file_records, all_file_paths


################################################################################
# FUNCTION: scan_skill_directory
#
# PURPOSE
#     Runs the complete scan: inventory, line-pattern rules, every
#     structural detector, and URL/coverage-gap collection, and returns
#     one combined result dict. This is the single function the CLI entry
#     point calls, and the one a test or another script would call
#     directly instead of shelling out to this file.
#
# RESPONSIBILITIES
#     - Inventory every file.
#     - Run apply_line_pattern_rules() across every readable text file.
#     - Run every structural detector function.
#     - Collect coverage gaps from inventory plus archive inspection.
#     - Collect and deduplicate every URL found.
#
# PROCESS OVERVIEW
#     1. Call inventory_skill_directory() to get file_records and
#        all_file_paths.
#     2. Run apply_line_pattern_rules() on every file_record with text.
#     3. Run every structural detector, passing file_records (and
#        scan_root/all_file_paths where needed).
#     4. Combine every detector's findings into one list, sorted
#        severity-descending.
#     5. Combine inventory's per-file coverage gaps with
#        detect_password_protected_archives()'s archive-format gaps.
#     6. Deduplicate and collect every URL found across all files.
#     7. Return the combined result dict.
#
# PARAMETERS
#     scan_root (str)
#         Absolute path to the directory being scanned.
#
# RETURNS
#     dict
#         "target_path", "scanned_at", "files_inventoried" (list[str]),
#         "coverage_gaps" (list[dict]), "findings" (list[dict], severity
#         descending), "urls_found" (list[dict] with "url"/"file").
#
# FAILURE CASES
#     - None expected; every sub-step already tolerates its own failure
#       modes (see each function's own FAILURE CASES).
################################################################################
def scan_skill_directory(scan_root):
    """Runs the full scan of scan_root and returns one combined result
    dict: files inventoried, coverage gaps, findings, and URLs found."""
    file_records, all_file_paths = inventory_skill_directory(scan_root)

    findings = []
    for record in file_records:
        if record["text"] is not None:
            findings.extend(apply_line_pattern_rules(record["relative_path"], record["extension"], record["text"]))

    findings.extend(detect_git_remote_force_push(file_records))
    findings.extend(detect_anthropic_base_url_override(file_records))
    findings.extend(detect_symlink_sensitive_targets(scan_root))
    findings.extend(detect_ioc_matches(file_records))
    findings.extend(detect_mcp_command_shell_metacharacters(file_records))
    findings.extend(detect_ransomware_combo(file_records))
    findings.extend(detect_persistence_stealth_cooccurrence(file_records))
    findings.extend(detect_terminal_control_sequences(file_records))
    findings.extend(detect_backspace_characters(file_records))
    findings.extend(detect_base64_network_cooccurrence(file_records))
    findings.extend(detect_dotfile_executable_code(file_records))
    findings.extend(detect_localhost_network_cooccurrence(file_records))
    findings.extend(detect_privileged_container_config(file_records))
    findings.extend(detect_excessive_subcommand_count(file_records))
    findings.extend(detect_infinite_loop_or_fork_bomb(file_records))
    findings.extend(detect_missing_allowed_tools_frontmatter(file_records))
    findings.extend(detect_zalgo_density(file_records))

    archive_findings, archive_coverage_gaps = detect_password_protected_archives(scan_root, all_file_paths)
    findings.extend(archive_findings)

    findings.sort(key=lambda finding: finding["severity"], reverse=True)

    coverage_gaps = archive_coverage_gaps + [
        {"file": record["relative_path"], "reason": record["coverage_gap_reason"]}
        for record in file_records if record["coverage_gap_reason"] is not None
    ]

    seen_urls = set()
    urls_found = []
    for record in file_records:
        for url in record["urls_found"]:
            if url not in seen_urls:
                seen_urls.add(url)
                urls_found.append({"url": url, "file": record["relative_path"]})

    return {
        "target_path": scan_root,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "files_inventoried": sorted(record["relative_path"] for record in file_records),
        "coverage_gaps": coverage_gaps,
        "findings": findings,
        "urls_found": urls_found,
    }


# ===== MAIN =====

################################################################################
# FUNCTION: main
#
# PURPOSE
#     Serves as the CLI entry point: validates the given path and prints
#     the full scan result as JSON to stdout. This is what actually gets
#     invoked by the bootleg-cartridge-check skill.
#
# PROCESS OVERVIEW
#     1. Read the target path from sys.argv[1]; exit 1 with a plain error
#        if it is missing or does not exist.
#     2. Resolve it to an absolute path.
#     3. Run scan_skill_directory() and print its result as indented
#        JSON to stdout.
#
# PARAMETERS
#     None
#         Reads sys.argv directly: sys.argv[1] is the required target
#         path.
#
# RETURNS
#     None
#         Prints JSON to stdout, or an error message to stderr with a
#         non-zero exit code.
#
# FAILURE CASES
#     - Missing sys.argv[1], or a path that does not exist: prints a
#       plain error to stderr and exits with code 1.
################################################################################
def main():
    """CLI entry point: `bootleg_cartridge_scan.py <path>`. Prints the
    full scan result as one JSON object to stdout."""
    if len(sys.argv) < 2:
        print("Usage: bootleg_cartridge_scan.py <path>", file=sys.stderr)
        sys.exit(1)

    target_path = os.path.abspath(sys.argv[1])
    if not os.path.isdir(target_path):
        print(f"Error: {target_path} is not a directory or does not exist.", file=sys.stderr)
        sys.exit(1)

    result = scan_skill_directory(target_path)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
