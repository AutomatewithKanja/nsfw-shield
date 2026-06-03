import json
import hashlib
import hmac
import ipaddress
import requests
import time
import os
import sys

# Configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HMAC_SECRET = os.environ.get("NSFW_SHIELD_HMAC_SECRET")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "blocklist.json")
VERSION_FILE = os.path.join(SCRIPT_DIR, "version.txt")
HISTORY_FILE = os.path.join(SCRIPT_DIR, "history.log")
MAX_DOMAINS_PER_CATEGORY = 30
MIN_TOTAL_DOMAINS = 20
MAX_SHRINK_RATIO = 0.5  # Abort if total domains drop below 50% of previous

# Trusted sources (example URLs - you can add more)
SOURCES = {
    "adult": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
    ],
    "gambling": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
    ],
    "drugs": [
        "https://blocklistproject.github.io/Lists/drugs.txt",
    ],
    "gore": [
        "https://raw.githubusercontent.com/ShadowWhisperer/BlockLists/master/Lists/Shock",
    ],
    "self_harm": [],
    "hate_speech": []
}

def _is_ip(token):
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False

def get_hmac_secret():
    """Load the HMAC signing secret from an environment variable."""
    if not HMAC_SECRET:
        print("Missing required environment variable: NSFW_SHIELD_HMAC_SECRET")
        print("Set it locally or add it as a GitHub Actions secret before generating the blocklist.")
        sys.exit(1)
    return HMAC_SECRET

def fetch_domains(url):
    """Simple parser for host-style files."""
    try:
        print(f"Fetching {url}...")
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        
        domains = set()
        for line in response.text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            
            parts = line.split()
            if not parts:
                continue

            # Accept both host-file format ("0.0.0.0 domain.com") and domain-only lists.
            if len(parts) == 1:
                domain = parts[0].lower()
            else:
                domain = parts[1].lower() if _is_ip(parts[0]) else parts[0].lower()

            # Clean up known non-domain entries and obvious junk.
            if domain and domain not in ["localhost", "broadcasthost"] and "://" not in domain:
                domains.add(domain)
        return list(domains), None
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return [], str(e)

def generate():
    signing_secret = get_hmac_secret()

    # 1. Load current version and old domains for comparison
    version = 1
    old_domains = set()
    old_total = 0
    old_data = {}
    old_by_category = {}
    
    print(f"Checking for existing blocklist at: {OUTPUT_FILE}")
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r") as f:
            try:
                old_data = json.load(f)
                version = old_data.get("version", 0)
                print(f"Found existing blocklist v{version}")
                # Collect all old domains across all categories
                for cat, domains in old_data.get("domains", {}).items():
                    cat_set = {d.lower() for d in domains}
                    old_by_category[cat] = cat_set
                    old_domains.update(cat_set)
                old_total = sum(len(v) for v in old_data.get("domains", {}).values())
            except Exception as e:
                print(f"Error loading existing blocklist: {e}")
    
    print(f"Checking for version file at: {VERSION_FILE}")
    if os.path.exists(VERSION_FILE):
        with open(VERSION_FILE, "r") as f:
            try:
                content = f.read().strip()
                if content:
                    version = max(version, int(content))
                    print(f"Found version file with v{version}")
            except Exception as e:
                print(f"Error loading version file: {e}")

    # 2. Fetch and categorize domains
    data = {
        "adult": [],
        "gambling": [],
        "drugs": [],
        "gore": [],
        "self_harm": [],
        "hate_speech": []
    }

    fetch_errors = []
    for category, urls in SOURCES.items():
        all_for_cat = set()
        for url in urls:
            domains, err = fetch_domains(url)
            if err:
                fetch_errors.append(f"{url} -> {err}")
            all_for_cat.update(domains)
        
        # Prioritize newly discovered domains, then fill with existing ones.
        # This increases the chance of legitimate daily updates while keeping stability.
        prev_set = old_by_category.get(category, set())
        new_domains = sorted([d for d in all_for_cat if d not in prev_set])
        old_domains_still = sorted([d for d in all_for_cat if d in prev_set])
        combined = new_domains + old_domains_still
        data[category] = combined[:MAX_DOMAINS_PER_CATEGORY]

    # 3a. Fail fast if any source failed to fetch
    if fetch_errors:
        print("One or more sources failed to fetch:")
        for err in fetch_errors:
            print(f"  - {err}")
        print("Aborting update to avoid publishing an incomplete blocklist.")
        sys.exit(1)

    # 3b. Sanity checks to avoid catastrophic shrink
    new_total = sum(len(v) for v in data.values())
    if new_total < MIN_TOTAL_DOMAINS:
        print(f"Aborting update: only {new_total} total domains (min {MIN_TOTAL_DOMAINS}).")
        sys.exit(1)
    if old_total > 0 and new_total < int(old_total * MAX_SHRINK_RATIO):
        print(f"Aborting update: total domains dropped from {old_total} to {new_total}.")
        sys.exit(1)

    # 3c. If domains are unchanged, skip version bump and exit cleanly
    if old_data.get("domains") == data:
        print("No domain changes detected; leaving blocklist unchanged.")
        return

    # Increment for this run only when domains changed
    version += 1
    print(f"Next version will be v{version}")

    # 3. Create a canonical domains string for signing (stable key order, no spaces).
    domains_json_str = json.dumps(data, separators=(',', ':'), sort_keys=True)

    # 4. Generate HMAC Signature
    signature = hmac.new(
        signing_secret.encode(),
        domains_json_str.encode(),
        hashlib.sha256
    ).hexdigest()

    # 5. Build final object
    final_output = {
        "version": version,
        "signature": signature,
        "domains": data
    }

    # 6. Save files
    with open(OUTPUT_FILE, "w") as f:
        json.dump(final_output, f, indent=2, sort_keys=True)
    
    with open(VERSION_FILE, "w") as f:
        f.write(str(version))

    # 7. Update history log with new additions
    all_new_domains = []
    for cat_list in data.values():
        for domain in cat_list:
            if domain not in old_domains:
                all_new_domains.append(domain)
    
    if all_new_domains:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        log_entry = f"[{timestamp}] v{version}: Added {len(all_new_domains)} domains: {', '.join(all_new_domains)}\n"
        with open(HISTORY_FILE, "a") as f:
            f.write(log_entry)
        print(f"Logged {len(all_new_domains)} new domains to {HISTORY_FILE}")

    print(f"Successfully generated {OUTPUT_FILE} (v{version}) with {sum(len(v) for v in data.values())} domains.")

if __name__ == "__main__":
    generate()
