# Contributing to harica-client / Contribuire a harica-client

[English](#english) | [Italiano](#italiano)

Thank you for helping improve this independent project. Contributions of code,
tests, documentation, and careful bug reports are welcome.

Grazie per contribuire a questo progetto indipendente. Sono benvenuti codice,
test, documentazione e segnalazioni di bug accurate.

## English

### Before opening an issue

- Search existing issues first.
- Use the appropriate issue form for bugs, improvements, or questions.
- Do not open a public issue for a suspected vulnerability. Use GitHub's private
  [Report a vulnerability](https://github.com/algrega/harica-client/security/advisories/new)
  form.
- Never publish API keys, credentials, certificate contents, private hostnames,
  email addresses, cache files, exports, or unsanitized logs.
- Report conduct concerns through the same private form and prefix the title
  with `[Conduct]`.

For a substantial behavioral change, open an issue before implementation so the
approach can be discussed. Small fixes and documentation corrections may go
directly to a pull request.

### Development setup

Python 3.11 or later is required. CI tests Linux and Windows with Python 3.11–3.14
and macOS with Python 3.14. Initial Windows support is x64 only. The project
deliberately has no external runtime dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install ruff==0.15.22
```

PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install ruff==0.15.22
```

Create a focused branch from the current `main`. Keep unrelated changes out of
the same pull request.

### Required checks

Before opening a pull request, run:

```bash
python -W error::ResourceWarning -m unittest discover -s tests -v
ruff check .
python -m pip wheel . --no-deps --wheel-dir dist
```

Tests must not contact HARICA or require a real API key. Add or update tests for
behavioral changes, and update both README variants when user-facing behavior or
requirements change. POSIX permission tests must stay on POSIX runners; Windows
storage tests must exercise APPDATA/LOCALAPPDATA, DPAPI, and reparse-point validation
without requiring elevated privileges.

### Pull requests

Describe the problem, the chosen solution, compatibility implications, and the
checks you ran. Link a related issue when one exists. Keep the CLI and Python API
stable unless the change explicitly requires a documented compatibility break.

All contributions must follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Signed commits, DCO sign-off, and mandatory review approvals are not required.

## Italiano

### Prima di aprire una issue

- Cerca prima tra le issue esistenti.
- Usa il modulo adatto per bug, miglioramenti o domande.
- Non aprire una issue pubblica per una possibile vulnerabilità: usa il modulo
  GitHub privato
  [Report a vulnerability](https://github.com/algrega/harica-client/security/advisories/new).
- Non pubblicare mai API key, credenziali, contenuti di certificati, hostname
  privati, indirizzi email, cache, esportazioni o log non ripuliti.
- Per problemi di condotta usa lo stesso modulo privato e anteponi `[Conduct]`
  al titolo.

Per modifiche sostanziali al comportamento, apri prima una issue per concordare
l'approccio. Correzioni piccole e modifiche documentali possono essere proposte
direttamente con una pull request.

### Ambiente di sviluppo

È richiesto Python 3.11 o successivo. La CI verifica Linux e Windows con Python
3.11–3.14 e macOS con Python 3.14. Il supporto Windows iniziale è limitato a x64.
Il progetto non ha dipendenze runtime esterne.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install ruff==0.15.22
```

PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install ruff==0.15.22
```

Crea un branch dedicato a partire dal `main` aggiornato e non includere nella
stessa pull request modifiche non correlate.

### Controlli richiesti

Prima di aprire una pull request esegui:

```bash
python -W error::ResourceWarning -m unittest discover -s tests -v
ruff check .
python -m pip wheel . --no-deps --wheel-dir dist
```

I test non devono contattare HARICA né richiedere API key reali. Aggiungi o
aggiorna i test per le modifiche di comportamento e modifica entrambi i README
quando cambiano comportamento o requisiti visibili agli utenti. I test dei permessi
POSIX devono restare sui runner POSIX; i test dello storage Windows devono coprire
APPDATA/LOCALAPPDATA, DPAPI e la validazione dei reparse point senza richiedere
privilegi elevati.

### Pull request

Descrivi il problema, la soluzione scelta, le implicazioni di compatibilità e i
controlli eseguiti. Collega una issue quando esiste. Mantieni stabili CLI e API
Python, salvo modifiche che richiedano esplicitamente una rottura documentata
della compatibilità.

Tutti i contributi devono rispettare il
[Codice di condotta](CODE_OF_CONDUCT.md). Non sono richiesti commit firmati,
firma DCO o approvazioni obbligatorie.
