"""Bounded lexical spans for Windows argv, CMD clauses and PowerShell code.

This is a conservative lexer, not shell emulation. No values are expanded and no
referenced code is loaded. Source offsets/quotes are parsing evidence, never ML
identifiers. Unsupported grouping is kept opaque and reported in the audit.
"""
from __future__ import annotations

from dataclasses import dataclass

MAX_LEXEMES = 1024
MAX_NESTED_DEPTH = 4
OPERATORS = ("2>&1", "1>&2", "2>>", "1>>", "&&", "||", ">>", "2>", "1>", "|", "&", ">", "<")


@dataclass(frozen=True)
class Lexeme:
    kind: str
    value: str
    start: int
    end: int
    quoted: bool = False


def lex(source: str, grammar: str = "argv") -> tuple[list[Lexeme], set[str]]:
    """Retain bounded spans; only the selected shell grammar recognizes operators.

    argv handles double quotes/backslash escapes. CMD adds caret escapes and
    operators; PowerShell adds single quotes, backticks, comments, statement
    separators and opaque balanced groups. Newlines inside quotes survive.
    """
    if grammar not in {"argv", "cmd", "powershell"}:
        raise ValueError(f"unknown grammar: {grammar}")
    result: list[Lexeme] = []
    status: set[str] = set()
    buffer: list[str] = []
    start: int | None = None
    quote: str | None = None
    quoted = False
    groups: list[str] = []
    i = 0

    def flush(end: int) -> None:
        nonlocal start, quoted
        if start is not None:
            result.append(Lexeme("argument", "".join(buffer), start, end, quoted))
        buffer.clear()
        start, quoted = None, False

    while i < len(source):
        if len(result) >= MAX_LEXEMES:
            status.add("lexeme_limit")
            break
        ch = source[i]
        escape = "`" if grammar == "powershell" else "^" if grammar == "cmd" else None
        if escape and ch == escape and quote != "'" and (grammar != "cmd" or quote is None):
            if start is None:
                start = i
            if i + 1 < len(source):
                if source[i + 1] != "\n":
                    buffer.append(source[i + 1])
                i += 2
                status.add("escaped_character")
                continue
            status.add("trailing_escape")
        if ch == "\\" and grammar == "argv":
            j = i
            while j < len(source) and source[j] == "\\":
                j += 1
            if j < len(source) and source[j] == '"':
                if start is None:
                    start = i
                buffer.extend("\\" * ((j - i) // 2))
                if (j - i) % 2:
                    buffer.append('"')
                else:
                    quote = None if quote else '"'
                    quoted = True
                i = j + 1
                continue
        if ch == '"' or (grammar == "powershell" and ch == "'"):
            if start is None:
                start = i
            if quote == ch and grammar == "powershell" and ch == "'" and source[i:i + 2] == "''":
                buffer.append("'")
                i += 2
                continue
            if quote is None:
                quote, quoted = ch, True
                if groups:
                    buffer.append(ch)
            elif quote == ch:
                quote = None
                if groups:
                    buffer.append(ch)
            else:
                buffer.append(ch)
            i += 1
            continue
        if quote is None and grammar == "powershell":
            if ch == "#" and start is None and not groups:
                end = source.find("\n", i)
                i = len(source) if end < 0 else end
                status.add("comment")
                continue
            if ch in "({[":
                groups.append({"(": ")", "{": "}", "[": "]"}[ch])
                status.add("opaque_group")
            elif ch in ")}]":
                if groups and ch == groups[-1]:
                    groups.pop()
                else:
                    status.add("unbalanced_group")
            if groups or ch in ")}]":
                if start is None:
                    start = i
                buffer.append(ch)
                i += 1
                continue
        if quote is None:
            operator = None
            if grammar != "argv":
                if ch == "\n" or (grammar == "powershell" and ch == ";"):
                    operator = ";"
                else:
                    operator = next((op for op in OPERATORS if source.startswith(op, i)), None)
            if operator:
                flush(i)
                result.append(Lexeme("operator", operator, i, i + len(operator)))
                i += len(operator)
                continue
            if ch.isspace():
                flush(i)
                i += 1
                continue
        if start is None:
            start = i
        buffer.append(ch)
        i += 1
    if len(result) < MAX_LEXEMES:
        flush(i)
    if quote:
        status.add("unclosed_quote")
    if groups:
        status.add("unbalanced_group")
    return result, status


def inline_remainder(source: str, first: Lexeme) -> str:
    """Remove one whole outer payload quote, retaining the unquoted remainder."""
    raw = source[first.start:first.end]
    if first.quoted and raw.startswith('"') and raw.endswith('"'):
        return first.value + source[first.end:]
    return source[first.start:]
