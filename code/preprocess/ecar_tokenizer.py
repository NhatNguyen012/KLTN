#!/usr/bin/env python3
"""Compact, structure-aware semantic features for the OpTC Host ML branch.

This module is deliberately side-effect free: it never executes a command line and
never writes to the source dataset.  The returned tokens are suitable as columns of
a sparse binary/count matrix for tree models.
"""

from __future__ import annotations

import ast
import base64
import binascii
import ipaddress
import ntpath
import re
import unicodedata
from collections import Counter, defaultdict
from functools import lru_cache
from typing import Any, DefaultDict, Iterable, Mapping

from command_syntax import Lexeme, MAX_LEXEMES, MAX_NESTED_DEPTH, inline_remainder, lex


COMMAND_FAMILIES = (
    "cmd",
    "powershell",
    "python",
    "wscript",
    "cscript",
    "rundll32",
    "native",
)

GROUPS = (
    "action",
    "object",
    "principal",
    "property_key",
    "command_line",
    "property_value",
    "structure_semantic",
)

# An allowlist is intentional: a newly observed property must not silently
# become a model feature. Identifiers remain available in the unmodified record
# to the eCAR-Bro join stage, but never enter this vocabulary.
HOST_OBJECT_FIELDS = {
    "process": ("image_path", "parent_image_path", "command_line"),
    "file": ("image_path", "file_path", "new_path"),
    "module": ("image_path", "module_path"),
    "registry": ("image_path", "key", "registry_key", "registry_path"),
    "task": ("image_path", "path"),
    "shell": ("image_path", "payload"),
    "thread": ("image_path",),
    "user_session": (),
    "service": (),
    "host": (),
}
HOST_OBJECTS = tuple(HOST_OBJECT_FIELDS)
KNOWN_ACTIONS = frozenset({
    "add", "command", "create", "delete", "edit", "grant", "interactive",
    "load", "login", "logout", "message", "modify", "open", "rdp", "read",
    "remote", "remote_create", "remove", "rename", "start", "terminate",
    "unlock", "write",
})
MAX_COMMAND_CHARS = 32768
TOKENIZER_POLICY = {
    "name": "host_ml_structure_anchor_syntax",
    "revision": "v5_canonical_office_registry",
    "feature_contract": {
        "structure": "clause-local roles, directed pipeline and provenance relations",
        "anchor": "normalized launcher/command/module/API names observed in grammar roles",
        "syntax": "family-specific switches, operators, quote and bounded AST evidence",
        "semantic": "typed dynamic operands; known credential values suppressed before lexical emission",
        "lexical": "normalized fallback alongside the above layers",
    },
    "parser": {"maximum_lexemes": MAX_LEXEMES, "maximum_nested_depth": MAX_NESTED_DEPTH,
               "source_normalization": "parse original whitespace/case; normalize emitted features only",
               "unsupported_groups": "opaque, with parse-status tokens; no full shell emulation"},
    "objects": HOST_OBJECT_FIELDS,
    "excluded_objects": ["flow"],
    "unknown_or_missing_object": "exclude",
    "unknown_action": "action::unknown",
    "principals_and_accounts": "finite built-in/domain/absent buckets; no account literals",
    "property_key_inventory": "drop",
    "generic_property_values": "drop",
    "network_fields": "drop (including on retained objects)",
    "path_features": "finite location category/subcategory plus office_category; normalized system32/syswow64 stems; executable/module basenames; XSL and Office extensions",
    "registry_features": "root and overlapping finite persistence/security/Office categories; no key/value/data literals",
    "canonical_tokens": "one syntax switch and anchor launcher/DLL/entrypoint token; retain distinct command roles and field scopes",
    "dynamic_literals": "typed UUID/SID/numeric/hex placeholders; normalize Search gather pipe counters; no rarity-based deletion",
    "shell_features": "recognized CommandInvocation and ParameterBinding payload; no context_info",
    "relations": ["action->object", "parent executable->child executable", "switch->value role",
                  "command->switch", "pipeline source->destination", "launcher->inline payload"],
    "maximum_command_chars": MAX_COMMAND_CHARS,
    "cache": {"command_lines": 2048, "paths": 8192, "registry": 4096},
}

WORDPUNCT_RE = re.compile(r"\w+|[^\w\s]+", re.UNICODE)
UUID_RE = re.compile(
    r"(?i)(?<![a-z0-9])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![a-z0-9])"
)
SID_RE = re.compile(r"(?i)\bS-\d-(?:\d+-){1,14}\d+\b")
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
LONG_HEX_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{16,}(?![0-9a-f])")
LONG_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")
NUMBER_RE = re.compile(r"(?<![a-zA-Z0-9])\d+(?![a-zA-Z0-9])")
HOST_COUNTER_RE = re.compile(r"(?i)\bsysclient\d+\b")
HARDDISK_VOLUME_RE = re.compile(r"(?i)\bharddiskvolume\d+\b")
SEARCH_PIPE_COUNTER_RE = re.compile(r"(?i)\b(usgthr(?:ctrl)?fltpipemssgthrpipe)\d+(?=_|\b)")
HEX_ADDRESS_RE = re.compile(r"(?i)(?<![a-z0-9_])0x[0-9a-f]+(?![a-z0-9_])")
USER_PATH_RE = re.compile(r"(?i)([\\/](?:users|documents and settings)[\\/])[^\\/\s\"']+")
ENCODED_SWITCHES = {"-" + "encodedcommand"[:n] for n in range(1, 15)} | {"-ec"}
POWERSHELL_ENCODED_RE = re.compile(
    r"(?i)(?:^|\s)(?:" + "|".join(re.escape(flag) for flag in sorted(ENCODED_SWITCHES))
    + r''')\s+["']?([A-Za-z0-9+/]+={0,2})(?=["']?(?:\s|$))''' 
)
MAX_ENCODED_CHARS = 131072
MAX_DECODED_CHARS = 65536
KNOWN_EXTENSIONS = {
    ".exe", ".com", ".dll", ".sys", ".scr", ".msi", ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd", ".py", ".pyw", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".tmp", ".log", ".evtx", ".json", ".jsonlz4", ".xml", ".txt", ".csv",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".zip", ".7z",
    ".rar", ".lnk", ".dat", ".bin", ".db", ".ini", ".cfg", ".conf", ".manifest",
    ".cat", ".mui", ".cmdline", ".db-wal", ".db-shm", ".etl", ".pol", ".ttf", ".otf",
    ".xsl", ".xslt", ".docm", ".dot", ".dotx", ".dotm", ".xlsm", ".xlsb",
    ".xlt", ".xltx", ".xltm", ".xla", ".xlam", ".pptm", ".pot", ".potx",
    ".potm", ".ppa", ".ppam", ".dic",
}

SHELL_OPERATORS = (
    "2>&1",
    "1>&2",
    "2>>",
    "1>>",
    "&&",
    "||",
    ">>",
    "2>",
    "1>",
    "|",
    "&",
    ">",
    "<",
)

OPERATOR_NAMES = {
    "&&": "and",
    "||": "or",
    "|": "pipe",
    "&": "sequence",
    ">": "redirect_output",
    ">>": "append_output",
    "1>": "redirect_stdout",
    "1>>": "append_stdout",
    "2>": "redirect_stderr",
    "2>>": "append_stderr",
    "2>&1": "stderr_to_stdout",
    "1>&2": "stdout_to_stderr",
    "<": "redirect_input",
}

SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".py", ".pyw", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh"}
EXECUTABLE_EXTENSIONS = {".exe", ".com", ".scr", ".msi"}

# Options whose following item is semantically a value rather than another
# positional argument.  This deliberately small table can be extended without
# changing the vocabulary schema.
VALUE_SWITCHES = {
    "cmd": {"/c", "/k"},
    "powershell": {
        "-command",
        "-c",
        "-file",
        "-f",
        "-encodedcommand",
        "-enc",
        "-e",
        "-executionpolicy",
        "-ep",
        "-windowstyle",
        "-w",
        "-workingdirectory",
    },
    "python": {"-c", "-m", "-w", "-x"},
    "wscript": {"//e", "//t", "//job"},
    "cscript": {"//e", "//t", "//job"},
    "rundll32": set(),
    "native": {
        "/tn",
        "/tr",
        "/sc",
        "/mo",
        "/st",
        "/sd",
        "/s",
        "/u",
        "/p",
        "/fo",
        "/fi",
        "/d",
        "/t",
        "/v",
        "-d",
        "-f",
        "-m",
        "-o",
        "-p",
        "-u",
    },
}
VALUE_SWITCHES["powershell"].update(ENCODED_SWITCHES)


def _clean_text(value: Any) -> str:
    """Convert a scalar to normalized text without interpreting it."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = unicodedata.normalize("NFKC", str(value))
    return " ".join(text.replace("\x00", " ").split())


def _basename_windows(path: str) -> str:
    return ntpath.basename(path.strip().strip('"\''))


def _launcher_name(image_path: str, command_line: str) -> str:
    image = _basename_windows(image_path).casefold()
    if image:
        return image

    # This fallback intentionally does not try to reproduce CommandLineToArgvW;
    # it only needs the first executable-like item for family classification.
    items, _ = lex(command_line, "argv")
    first = items[0].value if items else ""
    if _split_switch(first)[0]:
        return ""
    return _basename_windows(first).casefold()


def classify_command_line(command_line: Any, image_path: Any = "") -> str:
    """Classify an OpTC command into one of seven launcher/grammar families."""
    command = command_line if isinstance(command_line, str) else ""
    image = image_path if isinstance(image_path, str) else ""
    launcher = _launcher_name(image, command)

    if launcher in {"cmd", "cmd.exe"}:
        return "cmd"
    if launcher in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        return "powershell"
    if re.fullmatch(r"python(?:w)?(?:\d+(?:\.\d+)*)?(?:\.exe)?", launcher):
        return "python"
    if launcher in {"wscript", "wscript.exe"}:
        return "wscript"
    if launcher in {"cscript", "cscript.exe"}:
        return "cscript"
    if launcher in {"rundll32", "rundll32.exe"}:
        return "rundll32"
    return "native"


def _replace_ipv4(match: re.Match[str]) -> str:
    raw = match.group(0)
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    return f"ip_{_ip_class(raw)}"


def normalize_literals(text: str, *, replace_base64: bool = True) -> str:
    """Normalize values that otherwise create near-singleton vocabulary entries."""
    text = _clean_text(text)
    text = USER_PATH_RE.sub(r"\1user_name", text)
    text = HOST_COUNTER_RE.sub("host_name", text)
    text = HARDDISK_VOLUME_RE.sub("harddiskvolume", text)
    text = SEARCH_PIPE_COUNTER_RE.sub(r"\1_number_value", text)
    text = HEX_ADDRESS_RE.sub("hex_value", text)
    text = UUID_RE.sub("uuid_value", text)
    text = SID_RE.sub("sid_value", text)
    text = IPV4_RE.sub(_replace_ipv4, text)
    text = LONG_HEX_RE.sub("hex_value", text)
    if replace_base64:
        text = LONG_BASE64_RE.sub("base64_blob", text)
    text = re.sub(r"(?i)(?<![a-z0-9.])v?\d+(?:\.\d+){1,4}(?![a-z0-9.])", "version_value", text)
    text = NUMBER_RE.sub("number_value", text)
    text = re.sub(r"(?<![A-Za-z0-9])[A-Za-z0-9]{6,}(?![A-Za-z0-9])", _normalize_identifier, text)
    return _clean_text(text).casefold()


def wordpunct(text: str) -> list[str]:
    """QuasarNix-style punctuation-aware lexical splitting."""
    return WORDPUNCT_RE.findall(text)


def _normalize_identifier(match: re.Match[str]) -> str:
    value = match.group(0)
    lower = value.casefold()
    # Technical names with conventional numeric suffixes remain useful words.
    if re.fullmatch(r"(?:[a-z]+)(?:32|64|86|\d{1,3})", lower) or re.fullmatch(
        r"(?:sha|md|ipv|tls|python|msvcp|vcruntime|win|kernel|system|framework)\d+", lower
    ):
        return value
    digits = sum(ch.isdigit() for ch in value)
    if digits >= 2 and any(ch.isalpha() for ch in value) and len(set(lower)) >= 5:
        return "identifier_value"
    return value


def lexical_parts(text: str) -> list[str]:
    """Keep words/placeholders; switches and operators have structured tokens."""
    return [part for part in wordpunct(normalize_literals(text))
            if 2 <= len(part) <= 64 and any(ch.isalnum() for ch in part)]


def _extension(value: str) -> str:
    extension = ntpath.splitext(value)[1].casefold()
    return extension if extension in KNOWN_EXTENSIONS else ("other" if extension else "")


def _bucket_count(value: int) -> str:
    if value <= 2:
        return str(value)
    if value <= 4:
        return "3-4"
    if value <= 8:
        return "5-8"
    if value <= 16:
        return "9-16"
    return "17+"


def _lex_command(command_line: str) -> list[tuple[str, str]]:
    """Compatibility view of the bounded CMD lexer; use lex() for source spans."""
    return [(item.kind, item.value) for item in lex(command_line, "cmd")[0]]


def _split_switch(argument: str) -> tuple[str | None, str | None]:
    """Return a normalized option name and optional attached value."""
    item = argument.strip()
    if not item:
        return None, None
    if item.startswith("//"):
        prefix_length = 2
    elif item.startswith(("-", "/")):
        prefix_length = 1
    else:
        return None, None

    # A slash-containing absolute/relative pathname is not an option.
    if prefix_length == 1 and item.startswith("/") and ("/" in item[1:] or "\\" in item[1:]):
        return None, None
    body = item[prefix_length:]
    if not body:
        return None, None
    for separator in (":", "="):
        if separator in body:
            name, attached = body.split(separator, 1)
            if not re.fullmatch(r"[\w?-]{1,32}", name):
                return None, None
            return (item[:prefix_length] + name).casefold(), attached or None
    if not re.fullmatch(r"[\w?-]{1,32}", body):
        return None, None
    return item.casefold(), None


def _argument_role(argument: str, *, position: int = -1) -> tuple[str, str | None]:
    """Assign a stable semantic role and optional low-cardinality subtype."""
    item = _clean_text(argument).strip('"\'')
    lower = item.casefold()
    if not item:
        return "empty", None
    if position == 0:
        return "launcher", _extension(_basename_windows(lower)) or None
    if re.fullmatch(r"(?i)[a-z][a-z0-9+.-]*://\S+", item):
        return "url", None
    try:
        address = ipaddress.ip_address(item.strip("[]"))
    except ValueError:
        address = None
    if address is not None:
        return "ip_address", f"ipv{address.version}"
    if re.match(r"(?i)^(?:hkey_|hk(?:lm|cu|cr|u|cc)\\)", item):
        return "registry_location", None
    if item.startswith("@") and len(item) > 1:
        return "response_file", _extension(item[1:]) or None
    switch, attached = _split_switch(item)
    if switch is not None:
        return "switch", "attached_value" if attached is not None else None
    if UUID_RE.fullmatch(item):
        return "identifier", "uuid"
    if SID_RE.fullmatch(item):
        return "identifier", "sid"
    if re.fullmatch(r"(?i)(?:0x)?[0-9a-f]{16,}", item):
        return "identifier", "hex"
    if LONG_BASE64_RE.fullmatch(item):
        return "encoded_data", "base64_like"
    if re.fullmatch(r"(?i)v?\d+(?:\.\d+){1,4}", item):
        return "version", None
    if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", item):
        return "number", "integer" if "." not in item else "decimal"
    if "=" in item and not item.startswith("="):
        return "assignment", None

    extension = ntpath.splitext(lower)[1]
    has_path_separator = "\\" in item or "/" in item
    if extension in SCRIPT_EXTENSIONS:
        return "script", extension
    if extension == ".dll":
        return "library", extension
    if extension in EXECUTABLE_EXTENSIONS:
        return "executable", extension
    if has_path_separator or re.match(r"^[A-Za-z]:", item):
        return "path", _extension(lower) or None
    if extension:
        return "file", _extension(lower)
    return "literal", None


def _semantic_category(role: str) -> str:
    """Map argument roles to the parameter taxonomy used in the report."""
    return {
        "launcher": "command",
        "switch": "command",
        "path": "location",
        "registry_location": "location",
        "url": "location",
        "ip_address": "location",
        "script": "object_name",
        "library": "object_name",
        "executable": "object_name",
        "file": "object_name",
        "response_file": "object_name",
        "number": "object_amount",
        "version": "version",
        "encoded_data": "data_content",
        "identifier": "object_id",
        "assignment": "data_content",
        "literal": "other_parameter",
    }.get(role, "other_parameter")


def _value_semantic_type(switch: str, role: str, raw_value: str,
                         family: str = "native", launcher: str = "") -> str:
    lower_switch = switch.casefold()
    utility = _basename_windows(launcher).casefold().removesuffix(".exe")
    native_role = NATIVE_VALUE_ROLES.get(utility, {}).get(lower_switch)
    if native_role:
        return native_role
    if family == "powershell" and lower_switch in ENCODED_SWITCHES:
        return "encoded_command"
    if ((family == "powershell" and lower_switch in {"-command", "-c"})
            or (family == "cmd" and lower_switch in {"/c", "/k"})
            or (family == "python" and switch == "-c")):
        return "command_fragment"
    if family == "powershell" and lower_switch in {"-file", "-f"}:
        return "file"
    if family == "python" and switch == "-m":
        return "module_or_mode"
    if family == "powershell" and lower_switch in {"-executionpolicy", "-ep"}:
        return "policy"
    if family == "powershell" and lower_switch == "-workingdirectory":
        return "location"
    if family == "powershell" and lower_switch in {"-w", "-windowstyle"}:
        return "status_or_mode"
    return _semantic_category(role)


def _python_ast_tokens(arguments: list[str]) -> list[str]:
    """Extract Python AST node/edge types from a -c payload without executing it."""
    mode, marker = _python_mode(arguments)
    if mode != "-c":
        return []
    if marker + 1 >= len(arguments):
        return ["command_line::python::ast=parse_missing"]
    source = arguments[marker + 1]
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
        return ["command_line::python::ast=parse_failed"]

    tokens = ["command_line::python::ast=parse_success"]
    seen_nodes = 0
    for parent in ast.walk(tree):
        parent_name = type(parent).__name__.casefold()
        tokens.append(f"command_line::python::ast_node={parent_name}")
        if isinstance(parent, (ast.Import, ast.ImportFrom)):
            modules = [alias.name for alias in parent.names] if isinstance(parent, ast.Import) else [parent.module or ""]
            for module in modules:
                if module.split(".")[0] in PYTHON_ANCHOR_MODULES:
                    tokens.append(f"command_line::anchor::module={normalize_literals(module)}")
        if isinstance(parent, ast.Call):
            names = []
            node = parent.func
            while isinstance(node, ast.Attribute) and len(names) < 8:
                names.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name) and node.id in PYTHON_ANCHOR_MODULES | PYTHON_ANCHOR_BUILTINS:
                names.append(node.id)
                tokens.append(f"command_line::anchor::api={normalize_literals('.'.join(reversed(names)))}")
        for child in ast.iter_child_nodes(parent):
            child_name = type(child).__name__.casefold()
            tokens.append(f"command_line::python::ast_edge={parent_name}->{child_name}")
        seen_nodes += 1
        if seen_nodes >= 256:
            tokens.append("command_line::python::ast=truncated")
            break
    return tokens


# Option meanings are utility-specific. Unknown utilities keep lexical/type
# evidence, without guessing that /p is a port or -e is an encoded command.
NATIVE_VALUE_ROLES = {
    "schtasks": {"/u": "username", "/ru": "username", "/p": "password", "/rp": "password",
                 "/s": "host_name", "/tn": "task_name", "/tr": "command_fragment",
                 "/sc": "schedule", "/mo": "schedule", "/fo": "format"},
    "net": {"/user": "username", "/u": "username"},
    "runas": {"/user": "username"},
    "wmic": {"/user": "username", "/password": "password", "/node": "host_name"},
    "psexec": {"-u": "username", "-p": "password"},
    "ssh": {"-p": "network_port", "-l": "username"},
}
PRIVATE_ROLES = {"username", "password", "host_name", "task_name", "encoded_command"}
PYTHON_ANCHOR_MODULES = {"os", "sys", "subprocess", "socket", "pathlib", "shutil", "base64",
                         "urllib", "http", "ctypes", "winreg", "json", "re", "time"}
PYTHON_ANCHOR_BUILTINS = {"print", "open", "exec", "eval", "compile", "__import__"}


def _anchor(value: str) -> str | None:
    name = normalize_literals(_basename_windows(value))
    return name if re.fullmatch(r"[a-z_][a-z0-9_.-]{0,95}", name) else None


def _has_launcher(arguments: list[str], launcher: str) -> bool:
    return bool(arguments and launcher and
                _basename_windows(arguments[0]).casefold().removesuffix(".exe") ==
                launcher.casefold().removesuffix(".exe"))


def _python_mode(arguments: list[str]) -> tuple[str, int]:
    """Locate the interpreter boundary. Python option names are case-sensitive."""
    i = 1 if arguments and re.fullmatch(r"python(?:w)?(?:\d+(?:\.\d+)*)?(?:\.exe)?",
                                      _basename_windows(arguments[0]), re.I) else 0
    while i < len(arguments):
        arg = arguments[i]
        if arg in {"-c", "-m"}:
            return arg, i
        if arg == "--":
            return "script", i + 1
        if arg in {"-W", "-X"}:
            i += 2
        elif arg == "-" or not arg.startswith("-"):
            return "script", i
        else:
            i += 1
    return "interactive", len(arguments)


def _parse_status_tokens(status: set[str]) -> list[str]:
    return [f"command_line::syntax::parse={value}" for value in sorted(status)]


def _arguments_tokens(items: list[Lexeme], family: str, launcher: str,
                      lexical_family: str, *, head: bool = True,
                      option_end: int | None = None) -> list[str]:
    """Emit one invocation segment; bindings never cross shell operators.

    Bound values are assigned semantic roles before any lexical token is emitted.
    A quoted payload placeholder is supplied by the wrapper parser, preventing
    duplicate lexical emission of code handled in a nested grammar.
    """
    tokens: list[str] = []
    roles: list[str] = []
    bound: dict[int, str] = {}
    attached_roles: dict[int, str] = {}
    utility = _basename_windows(launcher).casefold().removesuffix(".exe")
    value_switches = (set() if family == "native" else set(VALUE_SWITCHES[family]))
    value_switches.update(NATIVE_VALUE_ROLES.get(utility, {}))
    anchor = _anchor(launcher) if head else None
    if anchor:
        tokens.append(f"command_line::anchor::command={anchor}")
    for i, item in enumerate(items):
        if i in bound or (head and i == 0) or (option_end is not None and i >= option_end):
            continue
        switch, attached = _split_switch(item.value) if not item.quoted else (None, None)
        if not switch:
            continue
        stable = normalize_literals(switch)
        tokens.append(f"command_line::syntax::switch={stable}")
        if anchor:
            tokens.append(f"command_line::relation::command_switch={anchor}->{stable}")
        if attached is not None or (switch in value_switches and i + 1 < len(items)):
            value = attached if attached is not None else items[i + 1].value
            private = NATIVE_VALUE_ROLES.get(utility, {}).get(switch) in PRIVATE_ROLES
            if attached is None and not private and not items[i + 1].quoted and _split_switch(value)[0]:
                continue
            value_role, _ = _argument_role(value)
            semantic = _value_semantic_type(switch, value_role, value, family, launcher)
            if attached is not None:
                attached_roles[i] = semantic
            else:
                bound[i + 1] = semantic
            tokens.append(f"command_line::relation::switch_value={stable}->{semantic}")

    for i, item in enumerate(items):
        value = item.value
        role, subtype = _argument_role(value, position=0 if head and i == 0 else -1)
        if item.quoted and role == "switch":
            role, subtype = "literal", None
        if option_end is not None and i >= option_end and role == "switch":
            role, subtype = "script_argument", None
            switch, _ = _split_switch(value)
            tokens.append(f"command_line::syntax::script_argument_switch={normalize_literals(switch)}")
        if i in bound:
            if bound[i] in PRIVATE_ROLES:
                role, subtype = bound[i], None
                value = "base64_blob" if role == "encoded_command" else role + "_value"
            tokens.append(f"command_line::semantic::value_type={bound[i]}")
        if attached_roles.get(i) in PRIVATE_ROLES:
            switch, _ = _split_switch(value)
            value = f"{switch} {attached_roles[i]}_value"
            tokens.append(f"command_line::semantic::value_type={attached_roles[i]}")
        tokens.extend(f"command_line::{lexical_family}::{part}" for part in lexical_parts(value))
        roles.append(role)
        tokens.extend((f"command_line::semantic::role={role}",
                       f"command_line::semantic::category={_semantic_category(role)}"))
        if subtype:
            tokens.append(f"command_line::semantic::subtype={normalize_literals(subtype)}")
        if item.quoted:
            tokens.append("command_line::syntax::quoted_argument")
    tokens.extend(f"command_line::relation::role_transition={left}->{right}"
                  for left, right in zip(roles, roles[1:]))
    return tokens


def _shell_tokens(source: str, grammar: str, lexical_family: str,
                  depth: int = 1) -> list[str]:
    """Parse shallow shell clauses, retaining directed command-anchor relations."""
    if depth > MAX_NESTED_DEPTH:
        return ["command_line::syntax::parse=depth_limit"]
    items, status = lex(source, grammar)
    tokens = _parse_status_tokens(status)
    tokens.append(f"command_line::structure::nested_depth={depth}")
    operators = [item for item in items if item.kind == "operator"]
    tokens.append(f"command_line::structure::segment_count={_bucket_count(1 + sum(item.value in {'|', '&&', '||', ';', '&'} for item in operators))}")
    block: list[Lexeme] = []
    command_anchor: str | None = None
    at_head = True
    called = False
    pending: tuple[str, str | None] | None = None

    def flush() -> None:
        nonlocal command_anchor, at_head, pending, called
        if not block:
            return
        can_anchor = at_head and (grammar != "powershell" or not block[0].quoted or called)
        name = _anchor(block[0].value) if can_anchor else None
        if at_head:
            command_anchor = name
            if pending and pending[1] and name:
                relation, left = pending
                tokens.append(f"command_line::relation::{relation}={left}->{name}")
            pending = None
        invocation_family = classify_command_line("", block[0].value) if name else "native"
        # Wrapper commands in a clause can expose one more inline grammar.
        if name and invocation_family in {"cmd", "powershell", "python"}:
            child_source = source[block[0].start:block[-1].end]
            child, _ = _invocation_tokens(child_source, block[0].value, depth + 1)
            tokens.extend(child)
        else:
            tokens.extend(_arguments_tokens(block, "powershell" if grammar == "powershell" else invocation_family,
                                           name or "", lexical_family, head=bool(name)))
        at_head = False
        called = False
        block.clear()

    i = 0
    while i < len(items):
        item = items[i]
        if item.kind == "argument":
            # Dot-sourcing is syntax; its following path remains data.
            if grammar == "powershell" and at_head and not block and item.value == ".":
                tokens.append("command_line::syntax::operator=dot_source")
                called = True
            else:
                block.append(item)
            i += 1
            continue
        op = item.value
        name = "call" if grammar == "powershell" and op == "&" else "sequence" if op == ";" else OPERATOR_NAMES[op]
        tokens.extend((f"command_line::syntax::operator={name}",
                       f"command_line::structure::operator={name}"))
        if grammar == "cmd":
            tokens.append(f"command_line::structure::nested_operator={name}")
        if grammar == "powershell" and op == "&":
            if block:
                tokens.append("command_line::syntax::parse=ambiguous_call")
                flush()
            called = True
            i += 1
            continue
        flush()
        if op in {"|", "&&", "||", "&", ";"}:
            pending = ("pipeline" if op == "|" else name, command_anchor)
            command_anchor, at_head = None, True
        elif op not in {"2>&1", "1>&2"} and i + 1 < len(items) and items[i + 1].kind == "argument":
            target = items[i + 1]
            target_role, _ = _argument_role(target.value)
            tokens.append(f"command_line::relation::redirect_target={name}->{target_role}")
            tokens.extend(_arguments_tokens([target], "native", "", lexical_family, head=False))
            i += 1
        i += 1
    flush()
    return tokens


def _invocation_tokens(command_line: str, image_path: str,
                       depth: int = 0) -> tuple[list[str], dict[str, int]]:
    family = classify_command_line(command_line, image_path)
    launcher = _launcher_name(image_path, command_line)
    if depth > MAX_NESTED_DEPTH:
        return ["command_line::syntax::parse=depth_limit"], {}
    items, parse_status = lex(command_line, "argv")
    arguments = [item.value for item in items]
    has_launcher = _has_launcher(arguments, launcher)
    tokens = [f"command_line::family={family}", *_parse_status_tokens(parse_status)]
    tokens.append(f"command_line::structure::argument_count={_bucket_count(len(items))}")
    status: dict[str, int] = {}
    if launcher:
        normalized = normalize_literals(launcher)
        tokens.append(f"command_line::anchor::launcher={normalized}")
    else:
        tokens.append("command_line::syntax::parse=missing_launcher")

    marker: int | None = None
    payload_mode = ""
    option_end: int | None = None
    if family == "python":
        payload_mode, boundary = _python_mode(arguments)
        if payload_mode in {"-c", "-m"}:
            tokens.append(f"command_line::python::mode={payload_mode}")
            marker = boundary if payload_mode == "-c" else None
            option_end = boundary + 2
        elif payload_mode == "script":
            option_end = boundary
            if boundary < len(items):
                tokens.append("command_line::python::mode=script")
                tokens.append(f"command_line::semantic::role=script")
                extension = _extension(items[boundary].value)
                tokens.append(f"command_line::python::script_ext={extension or 'none'}")
        if payload_mode == "-m" and boundary + 1 < len(items):
            module = _anchor(items[boundary + 1].value)
            if module:
                tokens.append(f"command_line::anchor::module={module}")
    elif family in {"cmd", "powershell"}:
        for i in range(int(has_launcher), len(items)):
            value = items[i].value.casefold()
            if items[i].quoted:
                continue
            if (family == "cmd" and value in {"/c", "/k"}) or (family == "powershell" and value in {"-command", "-c", *ENCODED_SWITCHES}):
                marker, payload_mode = i, value
                break
            # -File terminates PowerShell host-option interpretation.
            if family == "powershell" and value in {"-file", "-f"}:
                option_end = i + 2
                break

    if family in {"wscript", "cscript"}:
        # WSH host options precede the script; subsequent switches belong to it.
        option_end = next((i for i in range(int(has_launcher), len(items))
                           if not items[i].value.startswith("//")), len(items))
        for item in items[int(has_launcher):option_end]:
            option = item.value.casefold()
            if option in {"//b", "//i", "//nologo", "//logo", "//s", "//h:cscript", "//h:wscript"}:
                tokens.append(f"command_line::syntax::wsh_option={option}")
            elif re.fullmatch(r"//t:[0-9]+", option):
                tokens.append("command_line::syntax::wsh_timeout=present")

    wrapper = list(items)
    if marker is not None:
        encoded = family == "powershell" and payload_mode in ENCODED_SWITCHES
        tokens.append(f"command_line::relation::launcher_payload={family}->{'encoded_command' if encoded else 'inline_command'}")
        if family == "cmd":
            tokens.append(f"command_line::cmd::mode={payload_mode}")
        if marker + 1 >= len(items):
            tokens.append("command_line::syntax::parse=missing_payload")
            if encoded:
                tokens.extend(("command_line::powershell::has_encoded_command", "command_line::powershell::encoded_not_decoded"))
                status["encoded_not_decoded"] = 1
            elif family == "python":
                tokens.append("command_line::python::ast=parse_missing")
        else:
            first = items[marker + 1]
            payload = first.value if encoded or family == "python" else inline_remainder(command_line, first)
            placeholder = "base64_blob" if encoded else "command_fragment"
            wrapper = items[:marker + 1] + [Lexeme("argument", placeholder, first.start, first.end, True)]
            if encoded or family == "python":
                wrapper += items[marker + 2:]
                option_end = marker + 2
            if encoded:
                tokens.append("command_line::powershell::has_encoded_command")
                result = decode_powershell_payload(payload)
                if result["text"] is None:
                    status["encoded_not_decoded"] = 1
                    tokens.append("command_line::powershell::encoded_not_decoded")
                else:
                    decoded, decode_depth = result["text"], result["depth"]
                    status[f"encoded_{result['status']}_depth_{decode_depth}"] = 1
                    if result["status"] == "partial":
                        tokens.append("command_line::powershell::decoded_partial")
                    tokens.extend((f"command_line::powershell::decoded_encoding={result['encoding']}",
                                   f"command_line::powershell::decoded_depth={decode_depth}"))
                    decoded_tokens = _shell_tokens(decoded, "powershell", "powershell", depth + 1)
                    tokens.extend(token.replace("command_line::powershell::", "command_line::", 1)
                                  .replace("command_line::", "command_line::powershell_decoded::", 1)
                                  for token in decoded_tokens)
            elif family == "python":
                tokens.extend(_python_ast_tokens(arguments))
                tokens.extend(f"command_line::python::{part}" for part in lexical_parts(payload))
            else:
                tokens.extend(_shell_tokens(payload, family, family, depth + 1))
    tokens.extend(_arguments_tokens(wrapper, family, launcher, family,
                                   head=has_launcher, option_end=option_end))
    if family in {"wscript", "cscript"}:
        for item in items[int(has_launcher):]:
            extension = _extension(item.value)
            if extension in SCRIPT_EXTENSIONS:
                tokens.extend((f"command_line::{family}::script_ext={extension}", f"command_line::anchor::script_ext={extension}"))
                break
    elif family == "rundll32":
        target = next((item.value for item in items[int(has_launcher):]
                       if not item.value.startswith("/")), "")
        if "," in target:
            dll, entry = target.split(",", 1)
            if dll and entry:
                dll_name = normalize_literals(_basename_windows(dll))
                entry_name = normalize_literals(entry)
                tokens.extend((f"command_line::anchor::dll={dll_name}",
                               f"command_line::anchor::entrypoint={entry_name}",
                               f"command_line::relation::dll_entry={dll_name}->{entry_name}"))
                # Finite review list from the approved plan; a context feature,
                # never a malicious label or an execution decision.
                if dll_name in {"comsvcs.dll", "advpack.dll", "ieadvpack.dll"}:
                    tokens.append(f"command_line::rundll32::review_dll={dll_name}")
                tokens.extend(("command_line::syntax::delimiter=dll_entry",
                               "command_line::relation::launcher_target=library->entry_point"))
    return tokens, status


def _command_structure_tokens(command_line: str, family: str) -> list[str]:
    """Compatibility helper for shallow inline shell structure inspection."""
    if family in {"cmd", "powershell"}:
        return _shell_tokens(command_line, family, family)
    items, status = lex(command_line, 'argv')
    return _parse_status_tokens(status) + _arguments_tokens(items, family, '', family, head=False)


@lru_cache(maxsize=2048)
def _command_tokens(command_line: str, image_path: str) -> tuple[str, tuple[str, ...], tuple[tuple[str, int], ...]]:
    tokens, status = _invocation_tokens(command_line, image_path)
    return classify_command_line(command_line, image_path), tuple(tokens), tuple(sorted(status.items()))


@lru_cache(maxsize=128)
def decode_powershell_payload(payload: str) -> dict[str, Any]:
    """Decode at most two layers, reporting partial UTF-16 and resource limits.

    A partial result contains only complete code points. It is never repaired
    into an assumed script and is never executed. Callers must not mutate the
    cached result.
    """
    current = payload.strip()
    for depth in (1, 2):
        if len(current) > MAX_ENCODED_CHARS:
            return {"status": "limit_exceeded", "text": None, "depth": 0}
        try:
            raw = base64.b64decode(current + "=" * (-len(current) % 4), validate=True)
        except (binascii.Error, ValueError):
            return {"status": "invalid", "text": None, "depth": 0}
        utf16 = raw.startswith(b"\xff\xfe") or bool(
            raw[1::2] and raw[1::2].count(0) / len(raw[1::2]) > 0.3
        )
        encodings = ("utf-16le", "utf-8") if utf16 else ("utf-8", "utf-16le")
        decoded = None
        partial = False
        for encoding in encodings:
            candidate_bytes = raw
            incomplete = utf16 and encoding == "utf-16le" and len(raw) % 2 == 1
            if incomplete:
                candidate_bytes = raw[:-1]
            try:
                candidate = candidate_bytes.decode(encoding).lstrip("\ufeff")
            except UnicodeError:
                continue
            if len(candidate) > MAX_DECODED_CHARS:
                return {"status": "limit_exceeded", "text": None, "depth": 0}
            if candidate and sum(ch.isprintable() or ch.isspace() for ch in candidate) / len(candidate) >= 0.95:
                decoded, partial = candidate, incomplete
                break
        if decoded is None:
            return {"status": "invalid", "text": None, "depth": 0}
        nested = re.fullmatch(r"\s*([A-Za-z0-9+/]{4,}={0,2})\s*", decoded)
        if nested and not ("=" in decoded or any(ch.isupper() for ch in decoded)):
            nested = None
        if nested and not partial:
            if depth == 1:
                current = nested.group(1)
                continue
            return {"status": "limit_exceeded", "text": None, "depth": depth}
        return {
            "status": "partial" if partial else "decoded",
            "text": decoded, "depth": depth, "encoding": encoding,
            "decoded_bytes": len(raw), "discarded_bytes": int(partial),
        }
    return {"status": "invalid", "text": None, "depth": 0}


def _decode_powershell_base64(payload: str) -> tuple[str | None, int]:
    result = decode_powershell_payload(payload)
    return result["text"], result["depth"]


def _ip_class(value: Any) -> str | None:
    try:
        address = ipaddress.ip_address(_clean_text(value))
    except ValueError:
        return None
    if address.is_loopback:
        return "loopback"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "unspecified"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    return "public"


def is_learned_token(token: str) -> bool:
    """Classify literal-derived tokens for diagnostics; selection remains corpus-based."""
    if "::anchor::" in token or any(marker in token for marker in ("::component=", "::basename=", "::prefix=", "::launcher=", "::executable=", "::script=", "::dll=", "::entry=", "::process_lineage=", "::parent_launch_family=", "::system_stem=", "shell::class_name=", "shell::class_namespace=")):
        return True
    tail = token.rsplit("::", 1)[-1]
    return "=" not in tail and not token.startswith(("action::", "object::", "property_key::"))


def token_layers(token: str) -> tuple[str, ...]:
    """Overlapping evidence tags for audit/ablation; never extra feature columns."""
    layers: set[str] = set()
    if "::anchor::" in token or any(x in token for x in ("::basename=", "::launcher=", "::dll=", "::entry=", "shell::invocation=", "::system_stem=", "shell::class_name=", "shell::class_namespace=")):
        layers.add("anchor")
    if "::syntax::" in token or "::ast" in token or "::switch=" in token or "::operator=" in token or "::mode=" in token:
        layers.add("syntax")
    if "::relation::" in token or token.startswith("structure::") or "::structure::" in token or "::ast_edge=" in token or "::syntax::switch=" in token:
        layers.add("structure")
    if token.startswith("principal::") or "::semantic::" in token or any(x in token for x in ("::category=", "::office_category=", "::extension=", "::root=", "::parameter_role=", "::subcategory=")):
        layers.add("semantic")
    if not layers:
        layers.add("context" if token.startswith(("action::", "object::", "command_line::family=")) else "lexical")
    return tuple(sorted(layers))


def token_rejection_reason(token: str) -> str | None:
    if len(token) > 160:
        return "overlong_token"
    if not any(ch.isalnum() for ch in token.rsplit("::", 1)[-1]):
        return "punctuation_only"
    return None


def tokenize_principal(value: Any) -> list[str]:
    """Bucket account context without emitting domain, username or SID values."""
    if not isinstance(value, str) or not value.strip():
        return ["principal::absent"]
    p = value.strip().casefold()
    if p == "nt authority\\system":
        return ["principal::nt_system"]
    if p.startswith("nt authority\\"):
        return ["principal::nt_authority"]
    if p.startswith("nt service\\"):
        return ["principal::nt_service"]
    if "\\" in p:
        user = p.split("\\", 1)[1].strip()
        return ["principal::domain_user"] + (["principal::admin_account"] if user in {"admin", "administrator", "sysadmin"} else [])
    return ["principal::local_or_unknown"]


def categorize_path(value: str) -> tuple[str, str | None]:
    path = value.strip().strip('"\'').replace("/", "\\").casefold()
    parts = [part for part in path.split("\\") if part]
    part_set = set(parts)
    if "startup" in part_set:
        category = "startup"
    elif part_set & {"temp", "tmp", "%temp%", "%tmp%"}:
        category = "temp"
    elif "appdata" in part_set or "%appdata%" in part_set or "%localappdata%" in part_set:
        category = "appdata"
    elif "programdata" in part_set or "%programdata%" in part_set:
        category = "programdata"
    elif any(a in {"windows", "%windir%", "%systemroot%"} and b in {"system32", "syswow64", "sysnative"}
             for a, b in zip(parts, parts[1:])):
        category = "system"
    elif part_set & {"windows", "%windir%", "%systemroot%"}:
        category = "windows"
    elif part_set & {"program files", "program files (x86)", "%programfiles%", "%programfiles(x86)%"}:
        category = "program_files"
    elif part_set & {"users", "documents and settings", "%userprofile%"}:
        category = "user_profile"
    elif path.startswith("\\\\"):
        category = "unc"
    elif len(parts) > 1 or re.match(r"^[a-z]:", path):
        category = "other_path"
    else:
        category = "relative"
    subcategory = None
    if category == "system":
        subcategory = next((p for p in ("system32", "syswow64", "sysnative") if p in part_set), None)
    elif category == "windows":
        subcategory = "windows_other"
    elif category == "temp":
        subcategory = "windows_temp" if part_set & {"windows", "%windir%", "%systemroot%"} else "user_temp"
    elif category == "appdata":
        subcategory = "roaming" if "roaming" in part_set or "%appdata%" in part_set else "local" if "local" in part_set or "%localappdata%" in part_set else None
    return category, subcategory


def _office_path_category(path: str, location: str) -> str | None:
    """Finite application roles, independent of location and private filenames."""
    normalized = "\\" + "\\".join(p for p in path.split("\\") if p)
    if location in {"program_files", "startup"} and re.search(
            r"\\(?:program files(?: \(x86\))?|%programfiles(?:\(x86\))?%)\\microsoft office(?:\\|$)", normalized):
        if re.search(r"\\(?:startup|xlstart)(?:\\|$)", normalized):
            return "startup"
        return "installation"
    if location not in {"appdata", "startup"}:
        return None
    rules = (
        (r"\\microsoft\\bibliography\\style(?:\\|$)", "bibliography_style"),
        (r"\\microsoft\\bibliography(?:\\|$)", "bibliography"),
        (r"\\microsoft\\(?:word\\startup|excel\\xlstart)(?:\\|$)", "startup"),
        (r"\\microsoft\\templates(?:\\|$)", "templates"),
        (r"\\microsoft\\proof(?:\\|$)", "proofing"),
        (r"\\microsoft\\office\\unsavedfiles(?:\\|$)", "recovery"),
        (r"\\microsoft\\(?:word|excel|powerpoint)(?:\\|$)", "application_data"),
        (r"\\microsoft\\office(?:\\|$)", "application_data"),
    )
    return next((name for pattern, name in rules if re.search(pattern, normalized)), None)


@lru_cache(maxsize=8192)
def _compact_path_tokens(key: str, value: str, keep_basename: bool = False) -> tuple[str, ...]:
    path = value.strip().strip('"\'').replace("/", "\\").casefold()
    category, subcategory = categorize_path(path)
    tokens = [f"{key}::category={category}"]
    if subcategory:
        tokens.append(f"{key}::subcategory={subcategory}")
    office = _office_path_category(path, category)
    if office:
        tokens.append(f"{key}::office_category={office}")
    if key in {"file_path", "module_path"} and category == "system" and subcategory in {"system32", "syswow64"}:
        stem = normalize_literals(ntpath.splitext(_basename_windows(path))[0])
        if re.fullmatch(r"[a-z_][a-z0-9_.-]{0,95}", stem):
            tokens.append(f"{key}::system_stem={stem}")
    if keep_basename:
        basename = normalize_literals(_basename_windows(path))
        if basename:
            tokens.append(f"{key}::basename={basename}")
    else:
        tokens.append(f"{key}::extension={_extension(path) or 'none'}")
    return tuple(tokens)


REGISTRY_CATEGORIES = (
    (re.compile(r"\\currentversion\\runonce(?:\\|$)"), "run_once"),
    (re.compile(r"\\currentversion\\run(?:\\|$)"), "run"),
    (re.compile(r"\\(?:currentcontrolset|controlset\d+)\\services(?:\\|$)"), "services"),
    (re.compile(r"\\winlogon(?:\\|$)"), "winlogon"),
    (re.compile(r"\\image file execution options(?:\\|$)"), "image_execution_options"),
    (re.compile(r"\\schedule\\taskcache(?:\\|$)"), "task_cache"),
    (re.compile(r"\\(?:policies|policy)(?:\\|$)"), "policies"),
    (re.compile(r"\\(?:powershell|windows powershell)(?:\\|$)"), "powershell"),
    (re.compile(r"\\windows defender(?:\\|$)"), "defender"),
    (re.compile(r"\\environment(?:\\|$)"), "environment"),
    # Overlapping categories preserve both the broad application and key role.
    # Match stable key components only; never emit account/SID/value/data text.
    (re.compile(r"\\microsoft\\office(?:\\|$)"), "office"),
    (re.compile(r"\\microsoft\\office\\(?:\d+\.\d+\\)?(?:word|excel|powerpoint|outlook|common)\\security(?:\\|$)"), "office_security"),
    (re.compile(r"\\microsoft\\office\\(?:\d+\.\d+\\)?(?:word|excel|powerpoint|outlook|common)\\security\\trusted locations(?:\\|$)"), "office_trusted_locations"),
    (re.compile(r"\\microsoft\\office\\(?:\d+\.\d+\\)?(?:word|excel|powerpoint|outlook|common)\\security\\trusted documents(?:\\|$)"), "office_trusted_documents"),
    (re.compile(r"\\microsoft\\office\\(?:\d+\.\d+\\)?(?:word|excel|powerpoint|outlook)\\addins(?:\\|$)"), "office_addins"),
    (re.compile(r"\\microsoft\\shared tools\\proofing tools(?:\\|$)"), "office_proofing"),
    (re.compile(r"\\microsoft\\shared tools\\proofing tools\\(?:\d+\.\d+\\)?custom dictionaries(?:\\|$)"), "office_custom_dictionaries"),
    (re.compile(r"\\microsoft\\windows\\currentversion\\(?:explorer\\)?(?:user shell folders|shell folders)(?:\\|$)"), "shell_folders"),
    (re.compile(r"\\microsoft\\windows\\currentversion\\explorer\\(?:runmru|typedpaths|recentdocs)(?:\\|$)"), "shell_history"),
    (re.compile(r"\\microsoft\\windows\\currentversion\\internet settings(?:\\|$)"), "internet_settings"),
    (re.compile(r"\\(?:currentcontrolset|controlset\d+)\\control\\lsa(?:\\|$)"), "lsa"),
    (re.compile(r"\\(?:currentcontrolset|controlset\d+)\\control\\securityproviders(?:\\|$)"), "security_providers"),
    (re.compile(r"\\(?:currentcontrolset|controlset\d+)\\control\\terminal server(?:\\|$)"), "remote_desktop"),
    (re.compile(r"\\(?:classes|hkcr|hkey_classes_root)\\(?:wow6432node\\)?clsid(?:\\|$)"), "com_class"),
    (re.compile(r"\\(?:classes|hkcr|hkey_classes_root)\\(?:wow6432node\\)?clsid\\[^\\]+\\(?:inprocserver32|localserver32)(?:\\|$)"), "com_server"),
)


@lru_cache(maxsize=4096)
def _registry_tokens(value: str) -> tuple[str, ...]:
    path = "\\".join(part for part in value.replace("/", "\\").casefold().split("\\") if part)
    first = path.split("\\", 1)[0]
    root = {"hkey_local_machine": "hklm", "hklm": "hklm", "hkey_current_user": "hkcu",
            "hkcu": "hkcu", "hkey_users": "hku", "hku": "hku", "hkey_classes_root": "hkcr",
            "hkcr": "hkcr", "hkey_current_config": "hkcc", "hkcc": "hkcc"}.get(first, "other")
    if path.startswith("registry\\machine\\") or path == "registry\\machine":
        root = "hklm"
    elif path.startswith("registry\\user\\") or path == "registry\\user":
        root = "hku"
    categories = [name for pattern, name in REGISTRY_CATEGORIES if pattern.search("\\" + path)]
    return tuple([f"registry::root={root}"] +
                 [f"registry::category={name}" for name in categories or ["other"]])


SHELL_INVOCATION_RE = re.compile(r"CommandInvocation\(([^)\r\n]{1,128})\):", re.IGNORECASE)
SHELL_PARAMETER_RE = re.compile(
    r'ParameterBinding\(([^)\r\n]{1,128})\):\s*name="([A-Za-z][A-Za-z0-9_-]{0,63})";\s*value="([^"\r\n]*)"',
    re.IGNORECASE,
)


def _shell_payload_tokens(payload: str) -> list[str]:
    """Parse the two known eCAR SHELL forms without tokenizing arbitrary dumps."""
    tokens: list[str] = []
    for match in SHELL_INVOCATION_RE.finditer(payload):
        command = normalize_literals(_basename_windows(match.group(1)))
        if re.fullmatch(r"[a-z_][a-z0-9_.-]{0,95}", command):
            tokens.append(f"shell::invocation={command}")
    for match in SHELL_PARAMETER_RE.finditer(payload):
        command = normalize_literals(_basename_windows(match.group(1)))
        if not re.fullmatch(r"[a-z_][a-z0-9_.-]{0,95}", command):
            continue
        parameter = normalize_literals(match.group(2))
        if parameter == "typename" and command == "new-object":
            name = match.group(3).casefold()
            if re.fullmatch(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*){1,15}", name) and len(name) <= 128:
                parts = normalize_literals(name).split(".")
                tokens.extend((f"shell::class_namespace={'.'.join(parts[:2])}", f"shell::class_name={parts[-1]}"))
        role, _ = _argument_role(match.group(3))
        tokens.extend((f"shell::parameter={parameter}", f"shell::parameter_role={parameter}->{role}"))
    if not tokens:
        tokens.append("shell::payload=unparsed")
    return tokens


def tokenize_record(record: Mapping[str, Any]) -> tuple[dict[str, list[str]], dict[str, Any]]:
    """Return compact Host ML tokens and an eligibility audit, without mutation.

    FLOW rows and unknown/missing object types produce no tokens. All other
    properties are selected explicitly by object type; nested property values
    are ignored instead of stringifying identities into lexical features.
    Repeated command words are retained so a builder can distinguish TF and DF.
    """
    grouped: dict[str, list[str]] = {group: [] for group in GROUPS}
    audit: dict[str, Any] = {
        "eligible": False, "excluded_reason": None, "command_family": None,
        "decode_status": {}, "parse_status": {}, "filtered_tokens": {},
    }
    raw_object = record.get("object")
    object_type = raw_object.strip().casefold() if isinstance(raw_object, str) else ""
    if object_type not in HOST_OBJECT_FIELDS:
        audit["excluded_reason"] = "network_flow" if object_type == "flow" else "unknown_or_missing_object"
        return grouped, audit
    audit["eligible"] = True
    raw_action = record.get("action")
    action = raw_action.strip().casefold() if isinstance(raw_action, str) else ""
    if action not in KNOWN_ACTIONS:
        action = "unknown"
    grouped["principal"].extend(tokenize_principal(record.get("principal")))
    grouped["action"].append(f"action::{action}")
    grouped["object"].append(f"object::{object_type}")
    grouped["structure_semantic"].append(f"structure::action_object={action}->{object_type}")

    raw_properties = record.get("properties")
    properties = raw_properties if isinstance(raw_properties, Mapping) else {}
    # Standard eCAR keys are lowercase; no iteration over unknown properties.
    values = {key: properties[key].strip() for key in HOST_OBJECT_FIELDS[object_type]
              if isinstance(properties.get(key), str) and properties[key].strip()}
    image_path = values.get("image_path", "")
    if image_path:
        grouped["property_value"].extend(_compact_path_tokens("image_path", image_path, True))
    if object_type == "process":
        parent_path = values.get("parent_image_path", "")
        if parent_path:
            grouped["property_value"].extend(_compact_path_tokens("parent_image_path", parent_path, True))
        if image_path and parent_path:
            parent = normalize_literals(_basename_windows(parent_path))
            image = normalize_literals(_basename_windows(image_path))
            if parent and image:
                grouped["structure_semantic"].append(f"structure::process_lineage={parent}->{image}")
                if parent == image == "cmd.exe":
                    grouped["command_line"].append("command_line::cmd::self_spawn=true")
                if parent in {"python.exe", "pythonw.exe", "python3.exe"} and image in {"ping.exe", "net.exe", "net1.exe", "ipconfig.exe"}:
                    grouped["command_line"].append("command_line::context::suspicious_parent=python->network_tool")
        command_line = values.get("command_line", "")
        if command_line:
            if len(command_line) > MAX_COMMAND_CHARS:
                command_line = command_line[:MAX_COMMAND_CHARS]
                grouped["command_line"].append("command_line::input=truncated")
            family, tokens, status = _command_tokens(command_line, image_path)
            grouped["command_line"].extend(tokens)
            audit["command_family"] = family
            audit["decode_status"] = dict(status)
            audit["parse_status"] = dict(Counter(token for token in tokens if '::syntax::parse=' in token or '::ast=' in token))
    elif object_type == "file":
        for key in ("file_path", "new_path"):
            if key in values:
                grouped["property_value"].extend(_compact_path_tokens(key, values[key]))
    elif object_type == "module" and "module_path" in values:
        grouped["property_value"].extend(_compact_path_tokens("module_path", values["module_path"], True))
    elif object_type == "registry":
        registry = next((values[key] for key in ("key", "registry_key", "registry_path") if key in values), "")
        if registry:
            grouped["property_value"].extend(_registry_tokens(registry))
    elif object_type == "task" and "path" in values:
        grouped["property_value"].extend(_compact_path_tokens("task_path", values["path"]))
    elif object_type == "shell" and "payload" in values:
        payload = values["payload"]
        if len(payload) > MAX_COMMAND_CHARS:
            payload = payload[:MAX_COMMAND_CHARS]
            grouped["command_line"].append("shell::payload=truncated")
        grouped["command_line"].extend(_shell_payload_tokens(payload))

    rejected: DefaultDict[str, int] = defaultdict(int)
    for group in GROUPS:
        accepted = []
        for token in grouped[group]:
            reason = token_rejection_reason(token)
            if reason:
                rejected[reason] += 1
            else:
                accepted.append(token)
        grouped[group] = accepted
    audit["filtered_tokens"] = dict(rejected)
    return grouped, audit


def flatten_tokens(grouped: Mapping[str, Iterable[str]]) -> list[str]:
    """Flatten token groups in a stable order."""
    return [token for group in GROUPS for token in grouped.get(group, ())]
