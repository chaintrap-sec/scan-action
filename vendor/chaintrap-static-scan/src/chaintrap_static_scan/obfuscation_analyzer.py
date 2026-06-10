"""File-level structural obfuscation heuristics for JavaScript payloads."""

from __future__ import annotations

import math
import re
from collections import Counter

_RE_STRING_ARRAY = re.compile(
    r"(?:const|let|var)\s+_0x[0-9a-f]{2,}\s*=\s*\[(?:.|\n){80,}?\]",
    re.IGNORECASE,
)
_RE_ACCESSOR = re.compile(
    r"function\s+_0x[0-9a-f]{2,}\s*\([^)]*\)\s*\{(?:.|\n){0,250}?"
    r"=\s*\w+\s*-\s*0x[0-9a-f]+(?:.|\n){0,250}?return\s+[^;]*\[[^;\]]+\]",
    re.IGNORECASE,
)
_RE_ROTATION = re.compile(
    r"\(\s*function\s*\([^)]*\)\s*\{(?:.|\n){0,700}?"
    r"(?:push|shift)\s*\((?:.|\n){0,700}?parseInt\s*\(",
    re.IGNORECASE,
)
_RE_DECODE_TO_EXEC = re.compile(
    r"(?:atob\s*\(|Buffer\.from\s*\([^)]*base64|String\.fromCharCode|unescape\s*\(|decodeURIComponent\s*\()"
    r"(?:.|\n){0,260}?"
    r"(?:eval\s*\(|new\s+Function\s*\(|Function\s*\(|setTimeout\s*\(|setInterval\s*\(|vm\.runInNewContext\s*\(|WebAssembly\.instantiate\s*\()",
    re.IGNORECASE,
)
_RE_CRYPTO_STAGE = re.compile(
    r"createDecipheriv\s*\(\s*['\"]aes-(?:128|256)-gcm['\"]|"
    r"pbkdf2(?:Sync)?\s*\([^)]{0,250}\b[1-9]\d{5,}\b|"
    r"Fisher[- ]Yates|for\s*\([^)]*;\s*[^)]*;\s*[^)]*\)\s*\{(?:.|\n){0,120}?\[\w+\]\s*=\s*\[\w+\]",
    re.IGNORECASE,
)
_RE_OX_IDENT = re.compile(r"\b_0x[0-9a-f]{3,}\b", re.IGNORECASE)


def _entropy(data: str) -> float:
    if not data:
        return 0.0
    raw = data.encode("utf-8", errors="ignore")
    if not raw:
        return 0.0
    counts = Counter(raw)
    total = len(raw)
    val = 0.0
    for c in counts.values():
        p = c / total
        val -= p * math.log2(p)
    return val


def _literal_entropy_hit(text: str) -> bool:
    for m in re.finditer(r"['\"]([A-Za-z0-9+/=\\x\\u\-_.]{180,})['\"]", text):
        if _entropy(m.group(1)) >= 4.7:
            return True
    return False


def analyze_js_structure(text: str) -> list[dict[str, str]]:
    """Return structural obfuscation findings as dict payloads."""
    hits: list[dict[str, str]] = []

    has_array = bool(_RE_STRING_ARRAY.search(text))
    has_accessor = bool(_RE_ACCESSOR.search(text))
    has_rotation = bool(_RE_ROTATION.search(text))
    if has_array and has_accessor and has_rotation:
        hits.append(
            {
                "rule_id": "CTC-OBF030",
                "severity": "CRITICAL",
                "category": "OBFUSCATION",
                "message": "Combines string-array indirection, accessor offset math, and rotation bootstrap to conceal runtime strings",
            }
        )

    if _RE_DECODE_TO_EXEC.search(text):
        hits.append(
            {
                "rule_id": "CTC-OBF031",
                "severity": "CRITICAL",
                "category": "OBFUSCATION",
                "message": "Decodes staged data and routes it into a dynamic execution sink",
            }
        )

    if _RE_CRYPTO_STAGE.search(text):
        hits.append(
            {
                "rule_id": "CTC-OBF032",
                "severity": "HIGH",
                "category": "OBFUSCATION",
                "message": "Uses heavy cryptographic staging to hide payload constants until runtime",
            }
        )

    ox_count = len(_RE_OX_IDENT.findall(text))
    max_line = max((len(line) for line in text.splitlines()), default=0)
    if (ox_count >= 25 and max_line >= 500) or (ox_count >= 12 and max_line >= 3000):
        hits.append(
            {
                "rule_id": "CTC-OBF033",
                "severity": "HIGH",
                "category": "OBFUSCATION",
                "message": "Uses dense generated identifier mangling with extreme line compaction to hide control flow",
            }
        )

    if _literal_entropy_hit(text):
        hits.append(
            {
                "rule_id": "CTC-OBF034",
                "severity": "HIGH",
                "category": "OBFUSCATION",
                "message": "Contains long high-entropy encoded literals consistent with staged encrypted payload blocks",
            }
        )

    return hits
