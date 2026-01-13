# Trustify CLI

A command-line interface for interacting with the [Trustify](https://github.com/guacsec/trustify) API.

## Features

- 🔐 OAuth2 authentication (client credentials) with token retrieval
- 📦 SBOM management (list, get, delete)
- 🔍 Duplicate detection and cleanup
- ⚡ Concurrent operations with automatic retry and token refresh

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/ruromero/trustify-cli.git
cd trustify-cli

# Build
cargo build --release

# The binary will be at ./target/release/trustify
```

### Using Docker

Pull and run the pre-built image:

```bash
# Run with environment variables
docker run --rm \
  -e TRUSTIFY_URL=https://trustify.example.com \
  -e TRUSTIFY_SSO_URL=https://sso.example.com/realms/trustify \
  -e TRUSTIFY_CLIENT_ID=my-client \
  -e TRUSTIFY_CLIENT_SECRET=my-secret \
  ghcr.io/ruromero/trustify-cli sbom list

# Or use an env file
docker run --rm --env-file .env ghcr.io/ruromero/trustify-cli sbom list

# Mount a volume to save/load files (e.g., duplicates.json)
docker run --rm --env-file .env \
  -v $(pwd):/data \
  ghcr.io/ruromero/trustify-cli sbom duplicates find --output /data/duplicates.json
```

### Build Docker Image Locally

```bash
# Clone and build
git clone https://github.com/ruromero/trustify-cli.git
cd trustify-cli

docker build -t trustify-cli .

# Run
docker run --rm --env-file .env trustify-cli sbom list
```

## Configuration

The CLI can be configured using command-line arguments, environment variables, or a `.env` file.

### Configuration Options

| CLI Argument | Environment Variable | Required | Description |
|--------------|---------------------|----------|-------------|
| `-u, --url` | `TRUSTIFY_URL` | ✅ Yes | Trustify API URL |
| `--sso-url` | `TRUSTIFY_SSO_URL` | No | SSO/Keycloak URL for authentication |
| `--client-id` | `TRUSTIFY_CLIENT_ID` | No | OAuth2 Client ID |
| `--client-secret` | `TRUSTIFY_CLIENT_SECRET` | No | OAuth2 Client Secret |

### Using Environment Variables

```bash
export TRUSTIFY_URL=http://localhost:8080
export TRUSTIFY_SSO_URL=http://sso.example.com/realms/trustify
export TRUSTIFY_CLIENT_ID=my-client
export TRUSTIFY_CLIENT_SECRET=my-secret

trustify sbom list
```

### Using a `.env` File

Create a `.env` file in your working directory:

```env
TRUSTIFY_URL=http://localhost:8080
TRUSTIFY_SSO_URL=http://sso.example.com/realms/trustify
TRUSTIFY_CLIENT_ID=my-client
TRUSTIFY_CLIENT_SECRET=my-secret
```

Then simply run:

```bash
trustify sbom list
```

### Configuration Priority

1. **CLI arguments** (highest priority)
2. **Shell environment variables**
3. **`.env` file** (lowest priority)

## Authentication

When `--sso-url`, `--client-id`, and `--client-secret` are all provided, the CLI automatically obtains an OAuth2 token using the client credentials grant before making API requests.

The SSO URL should point to your Keycloak realm. The CLI automatically appends `/protocol/openid-connect/token` if needed.

```bash
# Full authentication example
trustify -u http://localhost:8080 \
  --sso-url http://sso.example.com/realms/trustify \
  --client-id my-client \
  --client-secret my-secret \
  sbom list
```

## Commands

### Global Options

```
-u, --url <URL>                      Trustify API URL (required)
    --sso-url <SSO_URL>              SSO URL for authentication
    --client-id <CLIENT_ID>          OAuth2 Client ID
    --client-secret <CLIENT_SECRET>  OAuth2 Client Secret
-h, --help                           Print help
-V, --version                        Print version
```

---

### `auth token`

Retrieve an OAuth2 access token using the configured credentials. Useful for debugging authentication or using the token with other tools.

```bash
trustify -u http://localhost:8080 \
  --sso-url http://sso.example.com/realms/trustify \
  --client-id my-client \
  --client-secret my-secret \
  auth token
```

**Output:** The access token string (can be used as a Bearer token)

**Example with curl:**

```bash
# Get token and use with curl
TOKEN=$(trustify auth token)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v2/sbom
```

---

### `sbom get <ID>`

Get an SBOM by its ID. Returns the full JSON document.

```bash
trustify -u http://localhost:8080 sbom get abc123
```

**Output:** Raw JSON of the SBOM

---

### `sbom list`

List SBOMs with optional filtering, pagination, and output formatting.

```bash
trustify -u http://localhost:8080 sbom list [OPTIONS]
```

**Options:**

| Option | Description |
|--------|-------------|
| `--query <QUERY>` | Query filter (e.g., `name=my-app`) |
| `--limit <LIMIT>` | Maximum number of results |
| `--offset <OFFSET>` | Skip first N results |
| `--sort <SORT>` | Sort order (e.g., `name:asc`, `published:desc`) |
| `--format <FORMAT>` | Output format: `id`, `name`, `short`, `full` (default: `full`) |

**Format Options:**

| Format | Fields Included |
|--------|-----------------|
| `id` | Just the ID (one per line) |
| `name` | `id`, `name`, `document_id` |
| `short` | `id`, `name`, `document_id`, `ingested`, `published`, `size` |
| `full` | Complete JSON document |

**Examples:**

```bash
# List all SBOMs (full JSON)
trustify -u http://localhost:8080 sbom list

# List with query filter
trustify -u http://localhost:8080 sbom list --query "name=my-app"

# List only IDs
trustify -u http://localhost:8080 sbom list --format id

# Paginated results
trustify -u http://localhost:8080 sbom list --limit 10 --offset 20

# Sorted results
trustify -u http://localhost:8080 sbom list --sort "published:desc"
```

---

### `sbom delete`

Delete an SBOM (placeholder - not fully implemented).

```bash
trustify -u http://localhost:8080 sbom delete --id <ID> [--dry-run]
```

---

### `sbom duplicates find`

Find duplicate SBOMs by `document_id`. Groups SBOMs with the same `document_id` and identifies the most recent (by `published` date) as the primary, with others marked as duplicates.

```bash
trustify -u http://localhost:8080 sbom duplicates find [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-b, --batch-size` | 100 | Number of SBOMs to fetch per request |
| `-j, --concurrency` | 4 | Number of concurrent fetch requests |
| `--output` | `duplicates.json` | Output file path |

**Examples:**

```bash
# Default settings
trustify -u http://localhost:8080 sbom duplicates find

# Faster with more concurrency
trustify -u http://localhost:8080 sbom duplicates find -j 8

# Larger batches
trustify -u http://localhost:8080 sbom duplicates find -b 500 -j 8

# Custom output file
trustify -u http://localhost:8080 sbom duplicates find --output my-duplicates.json
```

**Output Format (`duplicates.json`):**

```json
[
  {
    "document_id": "urn:example:sbom-1.0",
    "published": "2025-01-10T12:00:00Z",
    "id": "abc123",
    "duplicates": ["def456", "ghi789"]
  }
]
```

Where:
- `id` = The most recent SBOM (keep this one)
- `duplicates` = Older versions that can be deleted

---

### `sbom duplicates delete`

Delete duplicate SBOMs identified by the `duplicates find` command.

```bash
trustify -u http://localhost:8080 sbom duplicates delete [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--input` | `duplicates.json` | Input file from `duplicates find` |
| `-j, --concurrency` | 8 | Number of concurrent delete requests |
| `--dry-run` | false | Preview deletions without executing |

**Examples:**

```bash
# Dry run first (recommended)
trustify -u http://localhost:8080 sbom duplicates delete --dry-run

# Actually delete
trustify -u http://localhost:8080 sbom duplicates delete

# With higher concurrency
trustify -u http://localhost:8080 sbom duplicates delete -j 16

# From a specific file
trustify -u http://localhost:8080 sbom duplicates delete --input my-duplicates.json
```

**Output:**

```
Deleting 150 duplicates with 8 concurrent requests...
Deleted: abc123 (document_id: urn:example:sbom-1.0)
Deleted: def456 (document_id: urn:example:sbom-1.0)
...
Deleted 150 duplicate(s), 0 failed out of 150 total
```

---

## Complete Workflow Example

```bash
# 1. Configure authentication
export TRUSTIFY_URL=http://localhost:8080
export TRUSTIFY_SSO_URL=http://sso.example.com/realms/trustify
export TRUSTIFY_CLIENT_ID=my-client
export TRUSTIFY_CLIENT_SECRET=my-secret

# 2. Find duplicates
trustify sbom duplicates find -j 8
# Output: Found 150 document(s) with duplicates. Saved to duplicates.json

# 3. Review the duplicates file
cat duplicates.json | jq '.[0]'

# 4. Dry run to see what would be deleted
trustify sbom duplicates delete --dry-run

# 5. Delete duplicates
trustify sbom duplicates delete -j 16
# Output: Deleted 300 duplicate(s), 0 failed out of 300 total
```

## API Reference

This CLI interacts with the Trustify API. See the [OpenAPI specification](https://raw.githubusercontent.com/guacsec/trustify/refs/heads/main/openapi.yaml) for full API documentation.

## License

Apache License, Version 2.0
