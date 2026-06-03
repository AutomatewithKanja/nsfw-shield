# nsfw-shield

A lightweight, auto-updating domain blocklist generator for NSFW and high-risk content categories.

This project aggregates domains from trusted public sources, validates update safety, signs the output for integrity verification, and publishes a versioned JSON blocklist.

## Features

- **Automated daily updates** via GitHub Actions
- **Manual on-demand refresh** with `workflow_dispatch`
- **Category-based domain lists**:
  - `adult`
  - `gambling`
  - `drugs`
  - `gore`
  - `self_harm` *(currently empty source list)*
  - `hate_speech` *(currently empty source list)*
- **Safety checks** to prevent broken or catastrophic list shrinkage
- **Deterministic JSON signing** using HMAC-SHA256
- **Signing key loaded from an environment variable or GitHub Actions secret**
- **Version tracking** with `scripts/version.txt`
- **Change logging** in `scripts/history.log`

## Repository Structure

```text
.
├── .github/
│   └── workflows/
│       └── update_blocklist.yml
└── scripts/
    ├── blocklist.json
    ├── generate_blocklist.py
    ├── history.log
    ├── requirements.txt
    └── version.txt
```

## How It Works

The generator script (`scripts/generate_blocklist.py`) performs the following:

1. Loads the HMAC signing secret from `NSFW_SHIELD_HMAC_SECRET`
2. Loads previous blocklist/version if available
3. Fetches domains from configured source URLs
4. Parses host-style and domain-only formats
5. Limits domains per category (`MAX_DOMAINS_PER_CATEGORY`)
6. Aborts if:
   - the signing secret is missing
   - any source fetch fails
   - total domains fall below the minimum threshold
   - total domains shrink too aggressively compared to the previous version
7. Skips version bump if there are no domain changes
8. Signs canonicalized domain payload with HMAC-SHA256
9. Writes:
   - `scripts/blocklist.json`
   - `scripts/version.txt`
   - `scripts/history.log` (newly added domains only)

## Output Format

Generated file: `scripts/blocklist.json`

```json
{
  "version": 36,
  "signature": "<hmac_sha256>",
  "domains": {
    "adult": ["..."],
    "gambling": ["..."],
    "drugs": ["..."],
    "gore": ["..."],
    "self_harm": [],
    "hate_speech": []
  }
}
```

## Local Development

### Requirements

- Python 3.x
- pip

Install dependencies:

```bash
pip install -r scripts/requirements.txt
```

### Set the Signing Secret

The generator requires an HMAC signing secret. Set it as an environment variable before running the script.

Linux/macOS:

```bash
export NSFW_SHIELD_HMAC_SECRET="your-local-development-secret"
```

Windows PowerShell:

```powershell
$env:NSFW_SHIELD_HMAC_SECRET="your-local-development-secret"
```

Use a private value that is not committed to the repository.

### Generate Blocklist Locally

```bash
python scripts/generate_blocklist.py
```

Artifacts updated in `scripts/`:

- `blocklist.json`
- `version.txt`
- `history.log` (if new domains were added)

## CI/CD Automation

Workflow file: `.github/workflows/update_blocklist.yml`

- Runs **daily at `21:00 UTC`** (`cron: 0 21 * * *`)
- Can also be run manually from the Actions tab
- Reads the signing key from the `NSFW_SHIELD_HMAC_SECRET` GitHub Actions secret
- Commits and pushes updates only when `scripts/` has changes
- Commit message format:
  - `Auto-update blocklist (v<version>)`

## GitHub Actions Secret Setup

Before the scheduled workflow can generate signed blocklists, add this repository secret:

```text
NSFW_SHIELD_HMAC_SECRET
```

In GitHub, go to:

```text
Repository Settings → Secrets and variables → Actions → New repository secret
```

Set the secret name to `NSFW_SHIELD_HMAC_SECRET` and use a strong private value.

## Data Sources

Current upstream feeds include:

- StevenBlack hosts (porn, gambling alternates)
- BlocklistProject drugs list
- ShadowWhisperer shock list

> Source URLs are configured directly in `scripts/generate_blocklist.py`.

## Security Note

The generated file includes an HMAC signature for tamper detection. If you consume this list in production, verify the signature before applying updates.

The signing key is not stored in the source code. It should be provided through an environment variable locally and through a GitHub Actions secret in CI.

## Known Limitations

- `self_harm` and `hate_speech` source arrays are currently empty
- Category overlap can exist across external source lists
- Domain-only filtering does not yet include advanced normalization/dedup across punycode variants

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This blocklist is provided as-is. Upstream sources may change quality, accuracy, and coverage over time. Always test and validate before deploying to production environments.
