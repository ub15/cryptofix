import os
import time
import requests
import json

SEARCH_QUERIES = [
    "AES.MODE_ECB language:Python",
    "hashlib.md5 password language:Python",
    "pbkdf2_hmac iterations language:Python",
    "AES.new hardcoded key language:Python",
    "hashlib.sha1 language:Python",
    "random.random secret language:Python",
    "DES.new language:Python",
    "AES.MODE_CBC iv hardcoded language:Python",
    "hashlib.md5 token language:Python",
    "hashlib.sha1 signature language:Python",
    "pbkdf2_hmac 1000 language:Python",
    "pbkdf2_hmac 10000 language:Python",
    "AES.new key b language:Python",
    "Crypto.Cipher import AES language:Python",
    "from Crypto.Hash import MD5 language:Python",
    "from Crypto.Hash import SHA language:Python",
    "random.seed secret language:Python",
    "iv = b language:Python",
    "key = b language:Python",
    "salt = b language:Python",
]

HEADERS = {
    "Accept": "application/vnd.github.v3.text-match+json"
}

def search_github(query, max_results=10, token=None):
    if token:
        HEADERS["Authorization"] = f"token {token}"
    url = "https://api.github.com/search/code"
    params = {"q": query, "per_page": max_results}
    try:
        response = requests.get(url, headers=HEADERS, params=params, timeout=10)
        if response.status_code == 200:
            return response.json().get("items", [])
        elif response.status_code == 403:
            reset_time = int(response.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait = max(reset_time - int(time.time()), 10)
            print(f"  Rate limited, waiting {wait}s...")
            time.sleep(wait)
            return []
        else:
            print(f"  Error {response.status_code}")
            return []
    except Exception as e:
        print(f"  Request error: {e}")
        return []

def download_file(raw_url, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        r = requests.get(raw_url, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.text
        return None
    except:
        return None

def collect_vulnerable_files(output_dir, token=None, max_per_query=8):
    os.makedirs(output_dir, exist_ok=True)
    collected = []
    seen_urls = set()
    manifest = []

    for i, query in enumerate(SEARCH_QUERIES):
        print(f"\n[{i+1}/{len(SEARCH_QUERIES)}] Searching: {query}")
        items = search_github(query, max_results=max_per_query, token=token)
        print(f"  Found {len(items)} results")

        for item in items:
            html_url = item.get("html_url", "")
            raw_url = html_url.replace(
                "github.com", "raw.githubusercontent.com"
            ).replace("/blob/", "/")

            if raw_url in seen_urls:
                continue
            seen_urls.add(raw_url)

            repo = item.get("repository", {}).get("full_name", "unknown")
            filename = item.get("name", "unknown.py")
            if not filename.endswith(".py"):
                continue

            # Get commit SHA for reproducibility
            sha = item.get("sha", "unknown")

            print(f"  Downloading: {repo}/{filename}")
            content = download_file(raw_url, token)

            if content and len(content) > 50:
                safe_name = f"{repo.replace('/', '_')}_{filename}"
                save_path = os.path.join(output_dir, safe_name)
                with open(save_path, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(content)

                record = {
                    "repo": repo,
                    "filename": filename,
                    "raw_url": raw_url,
                    "html_url": html_url,
                    "sha": sha,
                    "saved_as": save_path,
                    "size_chars": len(content)
                }
                collected.append(record)
                manifest.append(record)
                print(f"  Saved ({len(content)} chars)")

            time.sleep(2)

        time.sleep(8)

    # Save manifest for reproducibility
    manifest_path = os.path.join(output_dir, "_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\nManifest saved to {manifest_path}")
    print(f"Total collected: {len(collected)} files")
    return collected
