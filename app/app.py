from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import re

app = FastAPI(title="Rule 718 — Prefer IS INITIAL over LINES()", version="1.1")

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class Finding(BaseModel):
    pgm_name: Optional[str] = None
    inc_name: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None
    severity: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1

def snippet_at(text: str, start: int, end: int) -> str:
    s = max(0, start - 60)
    e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")

# Statement-scoped: grab a single IF/ELSEIF condition line ending in '.'
# Handles extra whitespace / newlines between tokens.
STMT_RE = re.compile(r"(?is)\b(?:IF|ELSEIF)\b[^.]*\.", re.DOTALL)

# Inside the condition, detect LINES(itab) <op> number
COND_RE = re.compile(
    r"""(?is)
    \bLINES\s*\(\s*(?P<itab>\w+)\s*\)\s*
    (?P<op>=|EQ|<>|NE|>|GT|>=|GE|<|LT|<=|LE)\s*
    (?P<num>\d+)
    """,
    re.DOTALL | re.VERBOSE,
)

# -----------------------------------------------------------------------------
# Rule logic
# -----------------------------------------------------------------------------
def classify(op: str, num: int) -> Optional[Dict[str, str]]:
    """
    Map common LINES( ) comparisons to preferred IS INITIAL / NOT ... IS INITIAL patterns.
    Returns dict with 'message' and 'suggestion' when we know the equivalence; None otherwise.
    """
    op_u = op.upper()
    # Empty table checks
    if num == 0 and op_u in ("=", "EQ", "<=", "LE"):
        return {
            "message": "Use IS INITIAL instead of LINES(itab) = 0 / <= 0.",
            "suggestion": "IF itab IS INITIAL.\n  \" ...\nENDIF.",
        }
    if num == 0 and op_u in (">", "GT", "<>", "NE"):
        return {
            "message": "Use NOT ... IS INITIAL instead of LINES(itab) > 0 / <> 0.",
            "suggestion": "IF NOT itab IS INITIAL.\n  \" ...\nENDIF.",
        }
    # Common positive checks written as >= 1 / GE 1
    if num == 1 and op_u in (">=", "GE"):
        return {
            "message": "Use NOT ... IS INITIAL instead of LINES(itab) >= 1.",
            "suggestion": "IF NOT itab IS INITIAL.\n  \" ...\nENDIF.",
        }
    # Other numeric patterns are harder to rewrite safely without semantic change
    return None

def scan_unit(unit: Unit) -> Dict[str, Any]:
    src = unit.code or ""
    findings: List[Dict[str, Any]] = []

    for m in STMT_RE.finditer(src):
        stmt = m.group(0)
        c = COND_RE.search(stmt)
        if not c:
            continue

        itab = c.group("itab")
        op = c.group("op")
        num = int(c.group("num"))

        start, end = m.start(), m.end()
        equivalence = classify(op, num)

        if equivalence:
            # Tailor the suggestion with actual itab name
            msg = equivalence["message"].replace("itab", itab)
            sug = equivalence["suggestion"].replace("itab", itab)
            issue = (
                "LinesEqualsZero" if num == 0 and op.upper() in ("=", "EQ", "<=", "LE")
                else "LinesGreaterZero"
            )
            findings.append({
                "pgm_name": unit.pgm_name,
                "inc_name": unit.inc_name,
                "type": unit.type,
                "name": unit.name,
                "start_line": unit.start_line,
                "end_line": unit.end_line,
                "issue_type": issue,
                "severity": "info",
                "line": line_of_offset(src, start),
                "message": msg,
                "suggestion": sug,
                "snippet": snippet_at(src, start, end),
            })
        else:
            # Non-standard numeric comparisons: still nudge toward size/is initial idioms
            findings.append({
                "pgm_name": unit.pgm_name,
                "inc_name": unit.inc_name,
                "type": unit.type,
                "name": unit.name,
                "start_line": unit.start_line,
                "end_line": unit.end_line,
                "issue_type": "LinesComparisonNonCanonical",
                "severity": "info",
                "line": line_of_offset(src, start),
                "message": f"Consider avoiding LINES({itab}) {op} {num}. Prefer IS INITIAL / NOT IS INITIAL or SIZE syntax.",
                "suggestion": (
                    f"* For emptiness: IF {itab} IS INITIAL. ... ENDIF.\n"
                    f"* For non-empty: IF NOT {itab} IS INITIAL. ... ENDIF." f"Consider avoiding LINES({itab}) {op} {num}. Prefer IS INITIAL / NOT IS INITIAL or SIZE syntax."
                ),
                "snippet": snippet_at(src, start, end),
            })

    obj = unit.model_dump()
    obj["rule718_findings"] = findings
    return obj

# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@app.post("/remediate-array")
async def scan_rule(units: List[Unit]):
    results = []
    for u in units:
        res = scan_unit(u)
        if res.get("rule718_findings"):
            results.append(res)
    return results

@app.get("/health")
async def health():
    return {"ok": True, "rule": 718}
