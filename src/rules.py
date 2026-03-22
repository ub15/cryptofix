MISUSE_RULES = {
    "R1": {
        "id": "R1",
        "category": "Symmetric encryption",
        "description": "Use secure and modern symmetric ciphers",
        "patterns": ["DES", "3DES", "RC4", "Blowfish"],
        "fix_hint": "Replace with AES using GCM or CBC mode"
    },
    "R3": {
        "id": "R3",
        "category": "Hash function",
        "description": "Avoid weak hash functions",
        "patterns": ["md5", "sha1", "MD5", "SHA1"],
        "fix_hint": "Replace with SHA-256 or SHA-3"
    },
    "R4": {
        "id": "R4",
        "category": "Mode of operation",
        "description": "Avoid insecure block cipher modes",
        "patterns": ["MODE_ECB"],
        "fix_hint": "Replace with AES.MODE_GCM or AES.MODE_CBC with random IV"
    },
    "R5": {
        "id": "R5",
        "category": "Key management",
        "description": "Avoid hardcoded or static keys",
        "patterns": [],
        "fix_hint": "Replace with os.urandom(32) or secrets module"
    },
    "R8": {
        "id": "R8",
        "category": "IV management",
        "description": "Avoid static IVs",
        "patterns": [],
        "fix_hint": "Replace with os.urandom(16)"
    },
    "R10": {
        "id": "R10",
        "category": "PBE iteration count",
        "description": "Use sufficient iteration count for PBKDF2",
        "patterns": [],
        "fix_hint": "Use at least 600000 iterations"
    }
}
