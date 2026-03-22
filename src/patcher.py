import ast
import os
import re
from groq import Groq
from src.config import GROQ_API_KEY, MODEL_NAME, MAX_TOKENS, TEMPERATURE
from src.rules import MISUSE_RULES

client = Groq(api_key=GROQ_API_KEY)

MAX_SOURCE_CHARS = 2000
MAX_MISUSES_PER_FILE = 6

PATCH_EXAMPLES = {
    "R1": {"before": "cipher = DES.new(key)", "after": "cipher = AES.new(key, AES.MODE_GCM)"},
    "R3": {"before": "hashlib.md5(data).hexdigest()", "after": "hashlib.sha256(data).hexdigest()"},
    "R4": {"before": "cipher = AES.new(key, AES.MODE_ECB)", "after": "iv = os.urandom(16)\ncipher = AES.new(key, AES.MODE_CBC, iv)"},
    "R5": {"before": "key = b'hardcoded_key_here'", "after": "key = os.urandom(32)"},
    "R8": {"before": "iv = b'0000000000000000'", "after": "iv = os.urandom(16)"},
    "R10": {"before": "hashlib.pbkdf2_hmac('sha256', password, salt, 1000)", "after": "hashlib.pbkdf2_hmac('sha256', password, salt, 600000)"}
}

def extract_relevant_chunk(source, misuses):
    if len(source) <= MAX_SOURCE_CHARS:
        return source, False
    lines = source.split('\n')
    total_lines = len(lines)
    misuse_lines = [m['lineno'] for m in misuses]
    relevant_lines = set()
    for lineno in misuse_lines:
        start = max(0, lineno - 30)
        end = min(total_lines, lineno + 30)
        for i in range(start, end):
            relevant_lines.add(i)
    for i in range(min(20, total_lines)):
        relevant_lines.add(i)
    chunk_lines = [lines[i] for i in sorted(relevant_lines)]
    return '\n'.join(chunk_lines), True

def build_prompt(misuse):
    rule = misuse["rule"]
    deps = misuse["dependencies"]
    dep_summary = []
    if deps["constants"]:
        dep_summary.append(f"Known constants/hardcoded values: {deps['constants']}")
    if deps["functions"]:
        dep_summary.append(f"Functions in scope: {deps['functions']}")
    if deps["assignments"]:
        dep_summary.append(f"Variable assignments: {dict(list(deps['assignments'].items())[:5])}")
    dep_text = "\n".join(dep_summary) if dep_summary else "No additional context"
    all_violations = misuse.get("all_violations", [f"Line {misuse['lineno']}: [{rule['id']}] {rule['description']}"])
    violations_text = "\n".join(f"  - {v}" for v in all_violations)
    fix_guidance = []
    seen_rules = set()
    for v in all_violations:
        for rule_id, r in MISUSE_RULES.items():
            if f"[{rule_id}]" in v and rule_id not in seen_rules:
                seen_rules.add(rule_id)
                ex = PATCH_EXAMPLES.get(rule_id, {})
                fix_guidance.append(f"  [{rule_id}] {r['description']}\n    Fix: {r['fix_hint']}\n    Before: {ex.get('before','N/A')}\n    After:  {ex.get('after','N/A')}")
    fix_text = "\n".join(fix_guidance)
    all_misuses = misuse.get("_all_misuses", [misuse])
    source_to_use, is_chunked = extract_relevant_chunk(misuse['source'], all_misuses)
    chunk_note = "NOTE: This is a relevant excerpt from a larger file. Fix only what is shown.\n" if is_chunked else ""
    return f"""You are a Python security expert specializing in cryptographic API misuse repair.

ALL SECURITY VIOLATIONS FOUND IN THIS FILE:
{violations_text}

FIX GUIDANCE FOR EACH VIOLATION:
{fix_text}

DEPENDENCY CONTEXT:
{dep_text}

{chunk_note}VULNERABLE CODE TO FIX:
{source_to_use}

INSTRUCTIONS:
1. Fix ALL violations listed above in one complete rewrite
2. Preserve all original function signatures and logic
3. Add necessary imports (os, secrets, hmac) at the top
4. Replace md5/sha1 with hashlib.sha256
5. Replace hardcoded keys with os.urandom(32)
6. Replace static IVs with os.urandom(16)
7. Replace MODE_ECB with MODE_CBC and random IV
8. Replace low iteration counts with 600000
9. Return ONLY the complete fixed Python code, no explanation, no markdown

FIXED CODE:"""

def generate_patch(misuse):
    prompt = build_prompt(misuse)
    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE
        )
        return clean_response(response.choices[0].message.content.strip())
    except Exception as e:
        print(f"    LLM error: {e}")
        return None

def clean_response(text):
    text = re.sub(r'^```python\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'^```\s*', '', text, flags=re.MULTILINE)
    return text.strip()

class PatchValidator:
    def validate_syntax(self, code):
        try:
            ast.parse(code)
            return True, None
        except SyntaxError as e:
            return False, str(e)

    def validate_security(self, code):
        from src.detector import MisuseDetector
        detector = MisuseDetector()
        result = detector.analyze_source(code)
        remaining = result["misuses"]
        if remaining:
            return False, f"Still contains misuses: {[m['rule_id'] for m in remaining]}"
        return True, None

    def validate(self, original_misuse, patched_code):
        syntax_ok, syntax_err = self.validate_syntax(patched_code)
        if not syntax_ok:
            return {"valid": False, "stage_failed": "syntax", "error": syntax_err}
        sec_ok, sec_err = self.validate_security(patched_code)
        if not sec_ok:
            return {"valid": False, "stage_failed": "security", "error": sec_err}
        return {"valid": True, "stage_failed": None, "error": None}

class PatchGenerator:
    def __init__(self):
        self.validator = PatchValidator()

    def generate_and_validate(self, misuse, max_retries=3):
        validation = {"valid": False, "error": "No attempts made"}
        for attempt in range(max_retries):
            patch = generate_patch(misuse)
            if patch is None:
                continue
            validation = self.validator.validate(misuse, patch)
            if validation["valid"]:
                return {"success": True, "patch": patch, "attempts": attempt + 1, "validation": validation}
        return {"success": False, "patch": None, "attempts": max_retries, "validation": validation}

    def process_file(self, misuse_result):
        if not misuse_result["misuses"]:
            return {"filepath": misuse_result["filepath"], "status": "no_misuses", "patches": []}
        seen = set()
        unique_misuses = []
        for m in misuse_result["misuses"]:
            key = (m["rule_id"], m["lineno"])
            if key not in seen:
                seen.add(key)
                unique_misuses.append(m)
        if len(unique_misuses) > MAX_MISUSES_PER_FILE:
            return {
                "filepath": misuse_result["filepath"],
                "status": "too_complex",
                "misuses_found": len(unique_misuses),
                "patches": [{"success": False, "patch": None, "attempts": 0, "validation": {"error": "Too many misuses"}}]
            }
        primary_misuse = unique_misuses[0]
        primary_misuse["all_violations"] = [
            f"Line {m['lineno']}: [{m['rule_id']}] {m['rule']['description']}"
            for m in unique_misuses
        ]
        primary_misuse["_all_misuses"] = unique_misuses
        result = self.generate_and_validate(primary_misuse)
        return {
            "filepath": misuse_result["filepath"],
            "status": "patched" if result["success"] else "failed",
            "misuses_found": len(unique_misuses),
            "patches": [result]
        }
