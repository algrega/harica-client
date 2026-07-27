# harica-client

**English** | [Italiano](README.it.md)

[![CI](https://github.com/algrega/harica-client/actions/workflows/ci.yml/badge.svg)](https://github.com/algrega/harica-client/actions/workflows/ci.yml)

Synchronous Python client and CLI for querying certificates through the official
HARICA Certificate Manager API keys.

This is an independent, unofficial project. It is not affiliated with, endorsed by,
or supported by HARICA.

> **Author's note:** I am not a professional programmer. This project grew out of a
> real need, plenty of curiosity, and a very generous amount of help from OpenAI Codex.
> In addition to running the automated tests, I have personally verified every
> feature, and all of them work as expected. Expert eyes, reports, and contributions
> are always welcome—please be kind, I am learning!

The project is deliberately small and cautious: it can store the API key in a protected
local file, never accepts the key as a CLI argument, and explicitly handles HTTP 429
rate limiting.

## Features

- authentication through the `X-API-Key` header;
- separate credentials for each environment, suitable for manual and cron execution;
- `production`, `staging`, and `development` environments;
- listing `valid`, `revoked`, `expired`, or all certificates;
- certificate lookup by serial number;
- download of the final certificate to an automatic CN-based PEM filename;
- local filtering by FQDN, `friendlyName`, and email address;
- optional local JSON cache for repeated offline filtering;
- cache-only summaries, expiration reports, owner breakdowns, and data-quality checks;
- retries for `429`, `502`, `503`, and `504` with exponential backoff and jitter;
- HTTPS enforcement and fail-closed handling of authenticated redirects;
- support for `Retry-After` as seconds or an HTTP date;
- distinct errors for authentication, rate limiting, networking, HTTP, and non-JSON responses;
- neutralization of terminal control sequences in human-readable output;
- table or JSON output and CSV export;
- a `CN` field derived from `dN` when necessary;
- Italian and English CLI messages;
- no external runtime dependencies.

## Requirements and installation

- Python 3.11 or later;
- a HARICA account with 2FA;
- the Enterprise Admin role for the implemented endpoints;
- [an API key created in the HARICA profile](https://guides.harica.gr/docs/Guides/Developer/5.-API-Keys/).

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

## Interface language

Italian is the initial default language. Save your preferred language once with:

```bash
harica-client language set en
harica-client language status
```

The preference is stored in `${XDG_CONFIG_HOME}/harica-client/language`, or in
`~/.config/harica-client/language` when `XDG_CONFIG_HOME` is unset. To remove it:

```bash
harica-client language reset
```

Use `--language` only for an occasional override; the option may be placed before or
after a command:

```bash
harica-client --language en list --status valid
harica-client list --status valid --language en
```

For cron jobs and servers, set `HARICA_CLIENT_LANGUAGE`:

```bash
HARICA_CLIENT_LANGUAGE=en harica-client list --status valid
```

Precedence is `--language`, `HARICA_CLIENT_LANGUAGE`, the saved preference, then `it`.
Only `it` and `en` are accepted. Language selection changes help, prompts, messages,
and errors; it does not change command names, option names, or JSON/CSV data.

## Secure API key configuration

Save the key once using hidden input and double confirmation:

```bash
harica-client auth set --environment production
harica-client auth status --environment production
```

The default path is:

```text
${XDG_CONFIG_HOME}/harica-client/credentials/{environment}.key
```

If `XDG_CONFIG_HOME` is unset, the client uses:

```text
~/.config/harica-client/credentials/{environment}.key
```

The directory is created with mode `0700` and the file with mode `0600`. Reading rejects
shared directories, symbolic links, non-regular files, files owned by another user,
group/other permissions, and empty files.

A separate key can be stored for each environment:

```bash
harica-client auth set --environment production
harica-client auth set --environment staging
harica-client auth set --environment development
```

To use an explicitly managed path:

```bash
harica-client auth set \
  --environment production \
  --api-key-file /home/harica/secrets/production.key
```

The explicit path can also be supplied through `HARICA_API_KEY_FILE`, which contains
only a path and not the secret. Credential precedence is:

1. `--api-key-file`;
2. `HARICA_API_KEY`, retained for compatibility and CI;
3. `HARICA_API_KEY_FILE`;
4. the environment's default file.

### Rotation and deletion

Run `auth set` again to rotate a key. The new file is written atomically:

```bash
harica-client auth set --environment production
```

Remove the local copy interactively or non-interactively:

```bash
harica-client auth delete --environment production
harica-client auth delete --environment production --yes
```

Deleting the local copy does not revoke the key in HARICA Certificate Manager. Revoke
the key in the portal if it may have been compromised.

### Cron execution

Use a dedicated, unprivileged service account. Example crontab:

```cron
PATH=/opt/harica-client/.venv/bin:/usr/bin:/bin
HOME=/home/harica
HARICA_API_KEY_FILE=/home/harica/.config/harica-client/credentials/production.key
HARICA_CLIENT_LANGUAGE=en

0 6 * * * /bin/sh -c 'umask 077; exec harica-client list --environment production --status valid --csv /home/harica/exports/valid-certificates.csv --force' >> /home/harica/log/harica-client.log 2>&1
```

The crontab contains no secret. An explicit `HOME` makes configuration deterministic in
cron's minimal environment. Create output and log directories in advance with permissions
appropriate for the service account.

To refresh once and perform later exports without more API calls, use two jobs:

```cron
HARICA_CLIENT_CACHE_FILE=/home/harica/.cache/harica-client/certificates/production.json

30 5 * * * /bin/sh -c 'umask 077; exec harica-client cache refresh --environment production' >> /home/harica/log/harica-client.log 2>&1
0 6 * * * /bin/sh -c 'umask 077; exec harica-client list --from-cache --max-cache-age 24 --status valid --csv /home/harica/exports/valid-certificates.csv --force' >> /home/harica/log/harica-client.log 2>&1
15 6 * * * /bin/sh -c 'umask 077; exec harica-client stats expirations --max-cache-age 24 --within 30 --csv /home/harica/exports/upcoming-expirations.csv --force' >> /home/harica/log/harica-client.log 2>&1
```

If the refresh fails, the previous valid snapshot remains. The export job fails instead
of silently contacting HARICA when the cache is missing, invalid, or too old.

Do not store the key in `.zshrc`, `.profile`, crontab, CLI arguments, or repository files.
`HARICA_API_KEY` remains useful for ephemeral CI execution but is not recommended for
persistent server configuration.

## Usage

```bash
harica-client version
harica-client auth status --environment production
harica-client list --status valid
harica-client list --status all
harica-client list --status valid --fqdn auth.wifi.example.org
harica-client list --status valid --friendly-name wifi
harica-client list --status valid --email pki@example.org
harica-client list --status revoked --json
harica-client list --status valid --csv valid-certificates.csv
harica-client list --status all --csv all-certificates.csv
harica-client list --status expired --environment staging
harica-client serial 'SERIAL-NUMBER' --json
harica-client serial 'SERIAL-NUMBER' --csv certificate.csv
harica-client download 'SERIAL-NUMBER'
harica-client download 'SERIAL-NUMBER' --output certificate.pem
harica-client stats summary
harica-client stats expirations --within 30
harica-client stats owners
harica-client stats quality
```

### Listing every status

Use `all` to combine valid, revoked, and expired certificates:

```bash
harica-client list --status all
harica-client list --status all --json
harica-client list --status all --csv all-certificates.csv --force
```

HARICA exposes one endpoint per status, so `--status all` makes three sequential requests.
Retry and rate-limit handling apply independently to each request. Responses are merged,
and a missing `status` field is added from the source endpoint.

### Optional local cache

The default `list` behavior does not use a cache. Create or refresh a complete snapshot
explicitly when repeated searches should avoid further HARICA requests:

```bash
harica-client cache refresh --environment production
harica-client cache status --environment production
```

`cache refresh` queries `valid`, `revoked`, and `expired` once and stores a versioned JSON
snapshot. Subsequent reads are completely local and do not require an API key:

```bash
harica-client list --from-cache --status valid
harica-client list --from-cache --fqdn example.org
harica-client list --from-cache --friendly-name portal --email pki@example.org
harica-client list --from-cache --status all --json
harica-client list --from-cache --status all --csv cached-certificates.csv
```

The cache does not expire automatically. To reject a snapshot older than 24 hours without
falling back to the network, use:

```bash
harica-client list --from-cache --max-cache-age 24 --status valid
```

Default locations are
`${XDG_CACHE_HOME}/harica-client/certificates/{environment}.json` or
`~/.cache/harica-client/certificates/{environment}.json`. Override the path with
`--cache-file PATH` or `HARICA_CLIENT_CACHE_FILE`; the flag has precedence. A custom
`--base-url` on `cache refresh` requires an explicit `--cache-file`.

Cache directories are created with mode `0700` and files with mode `0600`. Symlinks,
wrong ownership, and group/other access are rejected. Writes are atomic, so a failed
refresh preserves the previous snapshot. The API key and the potentially large
`certificate` field are never stored, but the cache can contain sensitive hostnames and
email addresses. Keep it outside repositories and shared directories.

Remove it explicitly with:

```bash
harica-client cache delete --environment production
harica-client cache delete --environment production --yes
```

### Cache-based statistics

The `stats` command analyzes only the selected local cache. It never loads an API key,
creates an HTTP client, contacts HARICA, or falls back to the network. A missing, unsafe,
invalid, incompatible, wrong-environment, or over-age cache causes the command to fail.
Refresh the snapshot separately whenever current data is required:

```bash
harica-client cache refresh --environment production
harica-client stats summary
```

The available reports are:

```bash
# Overall counts, expiration bands, recent revocations, and missing fields
harica-client stats summary

# Valid certificates expiring in the next 30 days; the default is 30
harica-client stats expirations --within 30

# Counts grouped by userEmail, with user as descriptive information
harica-client stats owners

# One row for every certificate/data-quality anomaly
harica-client stats quality
```

`summary` includes cache date and age, status totals, exclusive expiration bands
(`0–7`, `8–30`, `31–60`, `61–90`, and over 90 days), revocations during the previous
30 days, and records missing owner, email, CN, or usable validity dates.
`expirations` considers only `valid` certificates, sorts them by expiration and CN, and
reports how many otherwise valid records were excluded because `validTo` was missing or
invalid. `owners` uses a separate group for a missing email/owner. `quality` reports
stable machine-readable issue codes for missing or invalid fields, reversed validity
ranges, revocation inconsistencies, duplicate serials, missing CNs, and unknown statuses.

Every report supports the same cache selection and age controls:

```bash
harica-client stats summary --environment staging
harica-client stats summary --cache-file /srv/harica/cache.json
harica-client stats summary --max-cache-age 24
```

The path precedence remains `--cache-file`, `HARICA_CLIENT_CACHE_FILE`, then the
environment-specific default path. Output is a localized table by default. JSON keys,
CSV headers, and quality issue codes are stable and identical in Italian and English:

```bash
harica-client stats summary --json
harica-client stats expirations --within 60 --json
harica-client stats owners --csv certificate-owners.csv
harica-client stats quality --csv certificate-quality.csv --force
```

Statistics describe only the selected snapshot and are not authoritative real-time
HARICA data. No history or comparison between refreshes is retained. JSON and CSV
exports may contain sensitive hostnames, personal names, and email addresses; protect
them like the cache and keep them out of repositories and shared directories.

### Filtering by FQDN, friendlyName, and email

`list` performs local, case-insensitive partial matching. The FQDN filter considers FQDN,
CN, SAN, DN, and `friendlyName` as a fallback:

```bash
harica-client list --status valid --fqdn auth.wifi.example.org
harica-client list --status valid --friendly-name wifi
harica-client list --status valid --email pki@example.org
```

`--friendlyName` is retained as an alias. Filters can be combined and use AND logic:

```bash
harica-client list \
  --status valid \
  --fqdn example.org \
  --friendly-name wifi \
  --email pki@example.org
```

JSON and CSV export use the same filtered results. Live filtering happens after the
HARICA response and does not create one request per certificate; with `--from-cache`,
all status selection and filtering happen locally without any HARICA request.

In every output format, `CN` remains separate from `friendlyName`. If HARICA does not
provide a separate `commonName`, the client extracts CN from `dN`. All other field names
and values remain exactly as returned by the API.

### CSV export

`--csv FILE` exports all returned fields using UTF-8 with BOM for Excel compatibility:

```bash
harica-client list --status valid --csv export/valid-certificates.csv
```

Lists and nested objects are stored as compact JSON in one cell. To reduce CSV injection
risk, text beginning with `=`, `+`, `-`, `@`, tab, or carriage return receives a leading
apostrophe. Use `--json` when completely raw values are required.

The potentially large `certificate` field is removed from every CLI format. Informational
fields such as `certificateType` and `certificateValidTo` remain. Library users still
receive the complete HARICA response.

Existing files are not overwritten unless `--force` is supplied. `--json` and `--csv`
are mutually exclusive.

### Certificate download

Download the final X.509 certificate returned by the serial lookup:

```bash
harica-client download 'SERIAL-NUMBER'
# saves ./portal.example.org.pem

harica-client download 'SERIAL-NUMBER' --output custom-name.pem
```

After saving the file, the command always prints a human-readable summary:

```text
Path: /absolute/path/certificate.pem
Serial: 1234AB
Subject: C=IT, O=Example, CN=portal.example.org
Issuer: C=GR, O=HARICA, CN=...
Valid from: 2026-07-23T08:26:40Z
Valid until: 2027-07-23T08:26:39Z
```

The summary is extracted internally with the Python standard library. Dates are
normalized to ISO 8601 UTC and distinguished names use a compact deterministic format.
It confirms that the file is a readable X.509 certificate, but does not verify its
trust chain, revocation status, hostname, or current temporal validity.
The summary is human-readable output and is not a stable machine-data format.

Without `--output`, the filename is built from the certificate subject CN and saved in
the current directory. Wildcard CNs such as `*.example.org` become
`wildcard.example.org.pem`; unsafe filesystem characters are replaced. If there is no
usable CN, the certificate serial number is used. Multiple different CN values require
an explicit `--output`.

`download` always performs a live, point lookup and therefore requires an API key. It
does not use the local cache, which deliberately excludes certificate contents. The
command accepts the same connection options as `serial`, including `--environment`,
`--base-url`, `--timeout`, `--max-attempts`, and `--api-key-file`.

Only one final certificate is written: chains, PKCS#7/PKCS#12 data, private keys,
concatenated certificates, and malformed values are rejected. HARICA may return PEM or
base64-encoded DER; the saved file is normalized to PEM with LF line endings, a final
newline, and mode `0644`.

Use `--output` to choose a different name or directory. An existing regular file is
preserved unless `--force` is supplied; symbolic links and non-regular destinations are
rejected even with `--force`. Writes use a temporary file in the destination directory
followed by an atomic replacement. The PEM contents are never printed to the terminal
or logs.

For an independent, optional check on a system that provides OpenSSL:

```bash
openssl x509 -in certificate.pem -noout -serial -subject -issuer -dates
```

Default environments are:

| Environment | Base URL |
| --- | --- |
| production | `https://cm.harica.gr` |
| staging | `https://cm-stg.harica.gr` |
| development | `https://cm-dev.harica.gr` |

`--base-url` is available for controlled tests. HTTPS is mandatory except for loopback
addresses (`localhost`, `127.0.0.0/8`, and `::1`). Authenticated redirects are never
followed. Do not use a custom HTTPS destination without verifying it, because the API
key is sent to that host.

Control characters received from remote data or included in errors are neutralized in
human-readable terminal output, with unsafe controls shown as visible escape sequences.
This terminal sanitization is not applied to JSON or CSV; those formats retain their
existing export semantics, including CSV formula-prefix protection.

## Library usage

```python
import os

from harica_client import HaricaClient, RetryPolicy

client = HaricaClient(
    os.environ["HARICA_API_KEY"],
    retry_policy=RetryPolicy(max_attempts=4, base_delay=1, max_delay=60),
)

valid = client.list_certificates("valid")
certificate = client.certificate_by_serial("SERIAL-NUMBER")
```

The return value is decoded HARICA JSON without a local schema that could quickly become
outdated.

## Rate-limit behavior

On HTTP 429 the client:

1. honors a valid `Retry-After` value;
2. otherwise uses exponential backoff with jitter;
3. caps each wait at `max_delay`;
4. raises `HaricaRateLimitError` after the final attempt.

The CLI exits with code `75` while the rate limit remains active. Ordinary errors return
`1`; usage and configuration errors return `2`.

## Tests

Tests use a simulated HTTP transport and never contact HARICA:

```bash
python -m unittest discover -s tests -v
```

## Contributing

Contributions are welcome. Read the [contribution guidelines](CONTRIBUTING.md) and
[Code of Conduct](CODE_OF_CONDUCT.md), then use the appropriate
[issue form](https://github.com/algrega/harica-client/issues/new/choose) or open a pull
request. Report suspected vulnerabilities only through GitHub's private
[Report a vulnerability](https://github.com/algrega/harica-client/security/advisories/new)
form.

## Implemented endpoints

```text
GET /cm/v1/admin/certificates/list/valid
GET /cm/v1/admin/certificates/list/revoked
GET /cm/v1/admin/certificates/list/expired
GET /cm/v1/admin/certificates/serial/{serialNumber}
```

Official references consulted on July 17, 2026:

- https://guides.harica.gr/docs/Guides/Developer/5.-API-Keys/
- https://developer.harica.gr/

## Limitations

The project does not implement certificate issuance, approval, or revocation.
Those operations mutate state and require specific request models; they should only be
added after reviewing the current HARICA Swagger documentation and adding dedicated tests.
