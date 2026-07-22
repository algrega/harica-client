# harica-client

**English** | [Italiano](README.it.md)

Synchronous Python client and CLI for querying certificates through the official
HARICA Certificate Manager API keys.

This is an independent, unofficial project. It is not affiliated with, endorsed by,
or supported by HARICA.

> **Author's note:** I am not a professional programmer. This project grew out of a
> real need, plenty of curiosity, and a very generous amount of help from OpenAI Codex.
> I have verified the result with automated tests, but expert eyes, reports, and
> contributions are always welcome—please be kind, I am learning!

The project is deliberately small and cautious: it can store the API key in a protected
local file, never accepts the key as a CLI argument, and explicitly handles HTTP 429
rate limiting.

## Features

- authentication through the `X-API-Key` header;
- separate credentials for each environment, suitable for manual and cron execution;
- `production`, `staging`, and `development` environments;
- listing `valid`, `revoked`, `expired`, or all certificates;
- certificate lookup by serial number;
- local filtering by FQDN, `friendlyName`, and email address;
- retries for `429`, `502`, `503`, and `504` with exponential backoff and jitter;
- HTTPS enforcement and fail-closed handling of authenticated redirects;
- support for `Retry-After` as seconds or an HTTP date;
- distinct errors for authentication, rate limiting, networking, HTTP, and non-JSON responses;
- table or JSON output and CSV export;
- a `CN` field derived from `dN` when necessary;
- Italian and English CLI messages;
- no external runtime dependencies.

## Requirements and installation

- Python 3.10 or later;
- a HARICA account with 2FA;
- the Enterprise Admin role for the implemented endpoints;
- an API key created in the HARICA profile.

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

JSON and CSV export use the same filtered results. Filtering happens after the single
HARICA response and does not create one request per certificate.

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

The project does not implement certificate issuance, approval, revocation, or download.
Those operations mutate state and require specific request models; they should only be
added after reviewing the current HARICA Swagger documentation and adding dedicated tests.
