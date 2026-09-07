"""Control-plane static raw-command validator (design.md Section 8.2).

Binary allowlist: ``cat grep egrep tail head ls ps df du free uptime
curl(GET only) jcmd jstack jmap(-histo)``. Rejects pipes to writes,
``; && || | > >>``, command substitution, and sudo. Probe re-validates
against its local allowlist before execution; this module is the control-
plane half of the gate.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

ALLOWED_BINARIES = frozenset(
    {
        "cat",
        "grep",
        "egrep",
        "tail",
        "head",
        "ls",
        "ps",
        "df",
        "du",
        "free",
        "uptime",
        "curl",
        "jcmd",
        "jstack",
        "jmap",
    }
)

_FORBIDDEN_RE = re.compile(
    r"""
    (?:
        ; | && | \|\| | \| | >{1,2} | < |
        ` | \$\( | \$\{ |
        \bsudo\b
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    reason: str = ""


def static_validate(command: str) -> ValidationResult:
    """Return whether ``command`` passes the Section 8.2 static validator."""
    if command is None or not str(command).strip():
        return ValidationResult(False, "empty command")
    text = str(command).strip()
    if _FORBIDDEN_RE.search(text):
        return ValidationResult(False, "forbidden shell metacharacter or sudo")

    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        return ValidationResult(False, f"unparseable command: {exc}")
    if not tokens:
        return ValidationResult(False, "empty command")

    binary = tokens[0]
    base = binary.rsplit("/", 1)[-1]
    if base not in ALLOWED_BINARIES:
        return ValidationResult(False, f"binary {base!r} not in allowlist")

    if base == "curl":
        curl_err = _validate_curl_get_only(tokens[1:])
        if curl_err:
            return ValidationResult(False, curl_err)

    if base == "jmap":
        rest = tokens[1:]
        if not rest or not any(t == "-histo" or t.startswith("-histo:") for t in rest):
            return ValidationResult(False, "jmap only allows -histo")

    return ValidationResult(True, "")


def _validate_curl_get_only(args: list[str]) -> str:
    """curl is GET-only (Section 8.2). Returns reason string or empty if ok."""
    i = 0
    while i < len(args):
        tok = args[i]
        low = tok.lower()
        if low in ("-x", "--request"):
            if i + 1 >= len(args):
                return "curl is GET-only"
            method = args[i + 1].upper()
            if method not in ("GET", "HEAD"):
                return "curl is GET-only"
            i += 2
            continue
        if low.startswith("-x") and len(tok) > 2 and not low.startswith("--"):
            # Combined form: -XPOST
            method = tok[2:].upper()
            if method not in ("GET", "HEAD"):
                return "curl is GET-only"
            i += 1
            continue
        if low in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"):
            return "curl is GET-only"
        if low.startswith("-d") and not low.startswith("--"):
            return "curl is GET-only"
        if low in ("-f",) and False:
            pass
        if tok == "-F" or low.startswith("--form"):
            return "curl is GET-only"
        i += 1
    return ""
