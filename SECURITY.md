# Security policy

[English](#english) | [Italiano](#italiano)

## English

### Supported versions

Until a formal public release policy is established, only the latest code on the
`main` branch is supported.

The supported platforms are Linux, macOS, other POSIX-compatible systems, and
supported x64 editions of Windows 10, Windows 11, and Windows Server with Python
3.11–3.14. Windows ARM64 is not currently supported.

On Windows, API keys and caches are protected with user-scoped DPAPI. This does not
make them portable: protected files are intended for the same user on the same
computer. Report any plaintext disclosure, integrity bypass, reparse-point bypass,
or cross-user/cross-machine access as a vulnerability.

### Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
[Report a vulnerability](https://github.com/algrega/harica-client/security/advisories/new)
form instead.

Never include API keys, credentials, certificate contents, private hostnames, email
addresses, cache files, exports, or other personal or operational data in a public
issue, discussion, pull request, or log.

Please include the affected version or commit, Python version, operating system,
reproduction steps, expected impact, and sanitized logs when available.

If a HARICA API key may have been exposed, revoke or rotate it immediately in HARICA
Certificate Manager. Do not wait for the report to be reviewed.

## Italiano

### Versioni supportate

Fino alla definizione di una politica formale per le release pubbliche, è supportato
soltanto il codice più recente del branch `main`.

Le piattaforme supportate sono Linux, macOS, gli altri sistemi compatibili POSIX e
le edizioni x64 supportate di Windows 10, Windows 11 e Windows Server con Python
3.11–3.14. Windows ARM64 non è attualmente supportato.

Su Windows API key e cache sono protette con DPAPI in ambito utente. I file protetti
non sono portabili: sono destinati allo stesso utente sullo stesso computer. Segnala
come vulnerabilità qualsiasi esposizione in chiaro, aggiramento dell'integrità o dei
controlli sui reparse point, oppure accesso tra utenti o computer diversi.

### Segnalazione di una vulnerabilità

Non aprire una issue pubblica per una possibile vulnerabilità. Usa invece il modulo
GitHub privato
[Report a vulnerability](https://github.com/algrega/harica-client/security/advisories/new).

Non inserire mai API key, credenziali, contenuti di certificati, hostname privati,
indirizzi email, file di cache, esportazioni o altri dati personali od operativi in
issue, discussioni, pull request o log pubblici.

Includi, quando disponibili, la versione o il commit interessato, la versione Python,
il sistema operativo, i passaggi per riprodurre il problema, l'impatto previsto e log
opportunamente ripuliti.

Se un'API key HARICA potrebbe essere stata esposta, revocala o ruotala immediatamente
in HARICA Certificate Manager. Non attendere la revisione della segnalazione.
