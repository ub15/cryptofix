import json
import time
from groq import Groq
from src.config import GROQ_API_KEY, MODEL_NAME, MAX_TOKENS, TEMPERATURE
from src.detector import MisuseDetector
from src.patcher import PatchValidator, clean_response, extract_relevant_chunk, MAX_SOURCE_CHARS
from src.rules import MISUSE_RULES
from src.patcher import PATCH_EXAMPLES

client = Groq(api_key=GROQ_API_KEY)

def build_prompt_A(misuse):
    """Condition A: Zero-shot - no rules, no dependency context"""
    source, _ = extract_relevant_chunk(misuse['source'], [misuse])
    return f"""You are a Python security expert.
The following Python code may contain cryptographic API misuses.
Fix any security issues you find.
Return ONLY the fixed Python code, no explanation, no markdown.

CODE:
{source}

FIXED CODE:"""

def build_prompt_B(misuse):
    """Condition B: Rules only - no dependency context"""
    all_violations = misuse.get("all_violations", [])
    violations_text = "\n".join(f"  - {v}" for v in all_violations)
    fix_guidance = []
    seen_rules = set()
    for v in all_violations:
        for rule_id, r in MISUSE_RULES.items():
            if f"[{rule_id}]" in v and rule_id not in seen_rules:
                seen_rules.add(rule_id)
                ex = PATCH_EXAMPLES.get(rule_id, {})
                fix_guidance.append(
                    f"  [{rule_id}] {r['description']}\n"
                    f"    Fix: {r['fix_hint']}\n"
                    f"    Before: {ex.get('before','N/A')}\n"
                    f"    After:  {ex.get('after','N/A')}"
                )
    fix_text = "\n".join(fix_guidance)
    source, _ = extract_relevant_chunk(misuse['source'], [misuse])
    return f"""You are a Python security expert specializing in cryptographic API misuse repair.

ALL SECURITY VIOLATIONS FOUND:
{violations_text}

FIX GUIDANCE:
{fix_text}

CODE TO FIX:
{source}

INSTRUCTIONS:
1. Fix ALL violations listed above
2. Preserve all original function signatures
3. Add necessary imports at the top
4. Return ONLY the fixed Python code, no explanation, no markdown

FIXED CODE:"""

def build_prompt_C(misuse):
    """Condition C: Full CryptoFix - rules + dependency context"""
    deps = misuse["dependencies"]
    dep_summary = []
    if deps["constants"]:
        dep_summary.append(f"Known constants/hardcoded values: {deps['constants']}")
    if deps["functions"]:
        dep_summary.append(f"Functions in scope: {deps['functions']}")
    if deps["assignments"]:
        dep_summary.append(f"Variable assignments: {dict(list(deps['assignments'].items())[:5])}")
    dep_text = "\n".join(dep_summary) if dep_summary else "No additional context"

    all_violations = misuse.get("all_violations", [])
    violations_text = "\n".join(f"  - {v}" for v in all_violations)
    fix_guidance = []
    seen_rules = set()
    for v in all_violations:
        for rule_id, r in MISUSE_RULES.items():
            if f"[{rule_id}]" in v and rule_id not in seen_rules:
                seen_rules.add(rule_id)
                ex = PATCH_EXAMPLES.get(rule_id, {})
                fix_guidance.append(
                    f"  [{rule_id}] {r['description']}\n"
                    f"    Fix: {r['fix_hint']}\n"
                    f"    Before: {ex.get('before','N/A')}\n"
                    f"    After:  {ex.get('after','N/A')}"
                )
    fix_text = "\n".join(fix_guidance)
    all_misuses = misuse.get("_all_misuses", [misuse])
    source, is_chunked = extract_relevant_chunk(misuse['source'], all_misuses)
    chunk_note = "NOTE: Relevant excerpt from larger file.\n" if is_chunked else ""

    return f"""You are a Python security expert specializing in cryptographic API misuse repair.

ALL SECURITY VIOLATIONS FOUND:
{violations_text}

FIX GUIDANCE:
{fix_text}

DEPENDENCY CONTEXT:
{dep_text}

{chunk_note}CODE TO FIX:
{source}

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

def call_llm(prompt):
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

def run_condition(condition, misuse):
    if condition == "A":
        prompt = build_prompt_A(misuse)
    elif condition == "B":
        prompt = build_prompt_B(misuse)
    else:
        prompt = build_prompt_C(misuse)

    validator = PatchValidator()
    for attempt in range(3):
        patch = call_llm(prompt)
        if patch is None:
            continue
        result = validator.validate(misuse, patch)
        if result["valid"]:
            return {"success": True, "attempts": attempt + 1}
    return {"success": False, "attempts": 3}

def run_ablation(data_dir, max_files=60, output_path="results/ablation.json"):
    import os
    detector = MisuseDetector()

    # Load files with misuses only
    all_files = []
    for root, dirs, files in os.walk(data_dir):
        for f in files:
            if f.endswith(".py") and not f.startswith("_"):
                all_files.append(os.path.join(root, f))

    results = []
    processed = 0

    for filepath in all_files:
        if processed >= max_files:
            break

        detection = detector.analyze_file(filepath)
        if detection.get("error") or detection["total"] == 0:
            continue

        # Deduplicate
        seen = set()
        unique = []
        for m in detection["misuses"]:
            key = (m["rule_id"], m["lineno"])
            if key not in seen:
                seen.add(key)
                unique.append(m)

        if len(unique) > 6:
            continue

        primary = unique[0]
        primary["all_violations"] = [
            f"Line {m['lineno']}: [{m['rule_id']}] {m['rule']['description']}"
            for m in unique
        ]
        primary["_all_misuses"] = unique

        filename = filepath.split("/")[-1]
        print(f"[{processed+1}] {filename} ({len(unique)} misuses)")

        file_result = {
            "filepath": filepath,
            "misuse_types": list(set(m["rule_id"] for m in unique)),
            "unique_misuses": len(unique),
            "conditions": {}
        }

        for condition in ["A", "B", "C"]:
            r = run_condition(condition, primary)
            file_result["conditions"][condition] = r
            icon = "✓" if r["success"] else "✗"
            print(f"  Condition {condition}: {icon} (attempts: {r['attempts']})")
            time.sleep(1)

        results.append(file_result)
        processed += 1

        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

    # Print summary
    print("\n" + "="*50)
    print("ABLATION STUDY RESULTS")
    print("="*50)
    for cond in ["A", "B", "C"]:
        label = {"A": "Zero-shot (no context)", "B": "Rules only", "C": "Full CryptoFix"}[cond]
        success = sum(1 for r in results if r["conditions"][cond]["success"])
        total = len(results)
        rate = success/total*100 if total > 0 else 0
        print(f"Condition {cond} - {label}: {success}/{total} = {rate:.1f}%")
    print("="*50)
    print(f"Results saved to {output_path}")
    return results

def run_ablation_on_filelist(filepaths, model_name, output_path, max_files=60):
    """Run ablation on a specific list of files with a specific model."""
    import os
    global client
    # Override model
    from src.config import GROQ_API_KEY
    client = Groq(api_key=GROQ_API_KEY)
    
    detector = MisuseDetector()
    results = []

    for i, filepath in enumerate(filepaths[:max_files]):
        if not os.path.exists(filepath):
            print(f"  MISSING: {filepath}")
            continue

        detection = detector.analyze_file(filepath)
        if detection.get("error") or detection["total"] == 0:
            continue

        seen = set()
        unique = []
        for m in detection["misuses"]:
            key = (m["rule_id"], m["lineno"])
            if key not in seen:
                seen.add(key)
                unique.append(m)

        if len(unique) > 6:
            continue

        primary = unique[0]
        primary["all_violations"] = [
            f"Line {m['lineno']}: [{m['rule_id']}] {m['rule']['description']}"
            for m in unique
        ]
        primary["_all_misuses"] = unique

        filename = filepath.split("/")[-1]
        print(f"[{i+1}/{len(filepaths)}] {filename} ({len(unique)} misuses)")

        file_result = {
            "filepath": filepath,
            "misuse_types": list(set(m["rule_id"] for m in unique)),
            "unique_misuses": len(unique),
            "model": model_name,
            "conditions": {}
        }

        for condition in ["A", "B", "C"]:
            # Temporarily override model in client calls
            r = _run_condition_with_model(condition, primary, model_name)
            file_result["conditions"][condition] = r
            icon = "✓" if r["success"] else "✗"
            print(f"  Condition {condition}: {icon} (attempts: {r['attempts']})")
            time.sleep(1)

        results.append(file_result)

        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

    print("\n" + "="*50)
    print(f"ABLATION RESULTS - {model_name}")
    print("="*50)
    for cond in ["A", "B", "C"]:
        label = {"A": "Zero-shot", "B": "Rules only", "C": "Full CryptoFix"}[cond]
        success = sum(1 for r in results if r["conditions"][cond]["success"])
        total = len(results)
        rate = success/total*100 if total > 0 else 0
        print(f"Condition {cond} - {label}: {success}/{total} = {rate:.1f}%")
    print("="*50)
    return results

def _run_condition_with_model(condition, misuse, model_name):
    from groq import Groq
    from src.config import GROQ_API_KEY, MAX_TOKENS, TEMPERATURE
    _client = Groq(api_key=GROQ_API_KEY)
    validator = PatchValidator()

    if condition == "A":
        prompt = build_prompt_A(misuse)
    elif condition == "B":
        prompt = build_prompt_B(misuse)
    else:
        prompt = build_prompt_C(misuse)

    for attempt in range(3):
        try:
            response = _client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=MAX_TOKENS,
                temperature=TEMPERATURE
            )
            patch = clean_response(response.choices[0].message.content.strip())
            result = validator.validate(misuse, patch)
            if result["valid"]:
                return {"success": True, "attempts": attempt + 1}
        except Exception as e:
            print(f"    LLM error: {e}")
            time.sleep(5)
    return {"success": False, "attempts": 3}

def run_ablation_openrouter(filepaths, output_path, max_files=60, model="meta-llama/llama-3.3-70b-instruct"):
    """Run 70b ablation using OpenRouter API."""
    import os
    import requests
    from src.config import OPENROUTER_API_KEY
    from src.detector import MisuseDetector

    def call_openrouter(prompt):
        try:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 2048,
                    "temperature": 0.1
                },
                timeout=60
            )
            data = response.json()
            if "choices" in data:
                return clean_response(data["choices"][0]["message"]["content"].strip())
            else:
                print(f"    API error: {data}")
                return None
        except Exception as e:
            print(f"    Request error: {e}")
            return None

    def run_condition_or(condition, misuse):
        if condition == "A":
            prompt = build_prompt_A(misuse)
        elif condition == "B":
            prompt = build_prompt_B(misuse)
        else:
            prompt = build_prompt_C(misuse)

        validator = PatchValidator()
        for attempt in range(3):
            patch = call_openrouter(prompt)
            if patch is None:
                continue
            result = validator.validate(misuse, patch)
            if result["valid"]:
                return {"success": True, "attempts": attempt + 1}
        return {"success": False, "attempts": 3}

    detector = MisuseDetector()
    results = []

    for i, filepath in enumerate(filepaths[:max_files]):
        if not os.path.exists(filepath):
            continue

        detection = detector.analyze_file(filepath)
        if detection.get("error") or detection["total"] == 0:
            continue

        seen = set()
        unique = []
        for m in detection["misuses"]:
            key = (m["rule_id"], m["lineno"])
            if key not in seen:
                seen.add(key)
                unique.append(m)

        if len(unique) > 6:
            continue

        primary = unique[0]
        primary["all_violations"] = [
            f"Line {m['lineno']}: [{m['rule_id']}] {m['rule']['description']}"
            for m in unique
        ]
        primary["_all_misuses"] = unique

        filename = filepath.split("/")[-1]
        print(f"[{i+1}/{len(filepaths)}] {filename} ({len(unique)} misuses)")

        file_result = {
            "filepath": filepath,
            "misuse_types": list(set(m["rule_id"] for m in unique)),
            "unique_misuses": len(unique),
            "model": "llama-3.3-70b",
            "conditions": {}
        }

        for condition in ["A", "B", "C"]:
            r = run_condition_or(condition, primary)
            file_result["conditions"][condition] = r
            icon = "✓" if r["success"] else "✗"
            print(f"  Condition {condition}: {icon} (attempts: {r['attempts']})")
            time.sleep(2)

        results.append(file_result)

        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)

    print("\n" + "="*50)
    print("ABLATION RESULTS - llama-3.3-70b (OpenRouter)")
    print("="*50)
    for cond in ["A", "B", "C"]:
        label = {"A": "Zero-shot", "B": "Rules only", "C": "Full CryptoFix"}[cond]
        success = sum(1 for r in results if r["conditions"][cond]["success"])
        total = len(results)
        rate = success/total*100 if total > 0 else 0
        print(f"Condition {cond} - {label}: {success}/{total} = {rate:.1f}%")
    print("="*50)
    return results
