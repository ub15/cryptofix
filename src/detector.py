import ast
from src.rules import MISUSE_RULES

class DependencyExtractor(ast.NodeVisitor):
    def __init__(self):
        self.crypto_calls = []
        self.assignments = {}
        self.function_defs = {}
        self.constants = {}

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, bytes):
                    val = node.value.s if isinstance(node.value, ast.Str) else node.value.value
                    self.assignments[target.id] = val
                    self.constants[target.id] = val
                elif isinstance(node.value, ast.Call):
                    self.assignments[target.id] = ast.unparse(node.value)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.function_defs[node.name] = {"args": [a.arg for a in node.args.args], "lineno": node.lineno}
        self.generic_visit(node)

    def visit_Call(self, node):
        call_str = ast.unparse(node)
        keywords = {kw.arg: ast.unparse(kw.value) for kw in node.keywords}
        args = [ast.unparse(a) for a in node.args]
        for rule_id, rule in MISUSE_RULES.items():
            for pattern in rule["patterns"]:
                if pattern in call_str:
                    if rule_id == "R3":
                        if not any(x in call_str for x in ["hashlib.", "SHA1.", "SHA256.", "MD5.", "hmac."]):
                            continue
                    self.crypto_calls.append({"rule_id": rule_id, "call": call_str, "args": args, "keywords": keywords, "lineno": getattr(node, "lineno", 0), "pattern": pattern})
        self.generic_visit(node)

class MisuseDetector:
    def analyze_file(self, filepath):
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        return self.analyze_source(source, filepath)

    def analyze_source(self, source, filepath="<string>"):
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            return {"error": str(e), "filepath": filepath, "misuses": [], "total": 0}
        extractor = DependencyExtractor()
        extractor.visit(tree)
        misuses = []
        for call in extractor.crypto_calls:
            misuses.append({"rule_id": call["rule_id"], "rule": MISUSE_RULES[call["rule_id"]], "call": call["call"], "args": call["args"], "keywords": call["keywords"], "lineno": call["lineno"], "pattern": call["pattern"], "source": source, "filepath": filepath, "dependencies": {"assignments": extractor.assignments, "constants": extractor.constants, "functions": list(extractor.function_defs.keys())}})
        misuses += self._detect_hardcoded_keys(source, filepath, extractor)
        misuses += self._detect_static_iv(source, filepath, extractor)
        misuses += self._detect_low_iterations(source, filepath, extractor)
        seen = set()
        unique_misuses = []
        for m in misuses:
            key = (m["rule_id"], m["lineno"])
            if key not in seen:
                seen.add(key)
                unique_misuses.append(m)
        return {"filepath": filepath, "misuses": unique_misuses, "total": len(unique_misuses)}

    def _detect_hardcoded_keys(self, source, filepath, extractor):
        misuses = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return misuses
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        if any(name == k or name.startswith(k+"_") or name.endswith("_"+k) for k in ["key","secret","apikey","api_key","secretkey"]):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, bytes):
                                val = node.value.s if isinstance(node.value, ast.Str) else node.value.value
                                if isinstance(val, (str, bytes)) and len(str(val)) >= 8:
                                    misuses.append({"rule_id": "R5", "rule": MISUSE_RULES["R5"], "call": ast.unparse(node), "args": [str(val)], "keywords": {}, "lineno": node.lineno, "pattern": "hardcoded_key", "source": source, "filepath": filepath, "dependencies": {"assignments": extractor.assignments, "constants": extractor.constants, "functions": list(extractor.function_defs.keys())}})
        return misuses

    def _detect_static_iv(self, source, filepath, extractor):
        misuses = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return misuses
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        if any(k in name for k in ["iv","nonce","vector"]):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, bytes):
                                misuses.append({"rule_id": "R8", "rule": MISUSE_RULES["R8"], "call": ast.unparse(node), "args": [], "keywords": {}, "lineno": node.lineno, "pattern": "static_iv", "source": source, "filepath": filepath, "dependencies": {"assignments": extractor.assignments, "constants": extractor.constants, "functions": list(extractor.function_defs.keys())}})
        return misuses

    def _detect_low_iterations(self, source, filepath, extractor):
        misuses = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return misuses
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_str = ast.unparse(node)
                if "pbkdf2" in call_str.lower():
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and arg.value < 600000:
                            misuses.append({"rule_id": "R10", "rule": MISUSE_RULES["R10"], "call": call_str, "args": [str(arg.value)], "keywords": {}, "lineno": node.lineno, "pattern": "low_iterations", "source": source, "filepath": filepath, "dependencies": {"assignments": extractor.assignments, "constants": extractor.constants, "functions": list(extractor.function_defs.keys())}})
                    for kw in node.keywords:
                        if kw.arg == "iterations" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int) and kw.value.value < 600000:
                            misuses.append({"rule_id": "R10", "rule": MISUSE_RULES["R10"], "call": call_str, "args": [str(kw.value.value)], "keywords": {}, "lineno": node.lineno, "pattern": "low_iterations", "source": source, "filepath": filepath, "dependencies": {"assignments": extractor.assignments, "constants": extractor.constants, "functions": list(extractor.function_defs.keys())}})
        return misuses
