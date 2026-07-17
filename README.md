# harica-client

Client Python sincrono e CLI per consultare i certificati tramite le API key ufficiali
di HARICA Certificate Manager.

Questo è un progetto indipendente e non ufficiale. Non è affiliato, approvato o
supportato da HARICA.

Il progetto è intenzionalmente piccolo e prudente: può conservare l'API key in un file
locale protetto, non la accetta come argomento della CLI e gestisce esplicitamente il
rate limit HTTP 429.

## Funzionalità

- autenticazione tramite header `X-API-Key`;
- credenziali separate per ambiente, adatte a esecuzioni manuali e cron;
- ambienti `production`, `staging` e `development`;
- elenco certificati `valid`, `revoked`, `expired` oppure di tutti gli stati;
- ricerca di un certificato per numero seriale;
- ricerca locale per FQDN, `friendlyName` e indirizzo email;
- retry di `429`, `502`, `503` e `504` con backoff esponenziale e jitter;
- supporto a `Retry-After` sia in secondi sia come data HTTP;
- errori distinti per autenticazione, rate limit, rete, HTTP e risposta non JSON;
- output tabellare o JSON ed esportazione CSV;
- colonna `CN` nell'output tabellare, ricavata anche dal campo `dN`;
- nessuna dipendenza runtime esterna.

## Requisiti e installazione

- Python 3.10 o successivo;
- account HARICA con 2FA;
- ruolo Enterprise Admin per gli endpoint implementati;
- API key creata nel profilo HARICA.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

## Configurazione sicura della chiave

Salva la chiave una sola volta con input nascosto e doppia conferma:

```bash
harica-client auth set --environment production
harica-client auth status --environment production
```

Il percorso predefinito è:

```text
${XDG_CONFIG_HOME}/harica-client/credentials/{environment}.key
```

Se `XDG_CONFIG_HOME` non è definita viene usato:

```text
~/.config/harica-client/credentials/{environment}.key
```

La directory viene creata con permessi `0700` e il file con `0600`. La lettura rifiuta
directory condivise, link simbolici, file non regolari, proprietario diverso dall'utente
corrente, permessi per gruppo/altri e file vuoti.

È possibile mantenere una chiave distinta per ciascun ambiente:

```bash
harica-client auth set --environment production
harica-client auth set --environment staging
harica-client auth set --environment development
```

Per usare un percorso amministrato esplicitamente:

```bash
harica-client auth set \
  --environment production \
  --api-key-file /home/harica/secrets/production.key
```

La directory specificata deve già essere sicura oppure deve poter essere creata dal
client. Un percorso esplicito può essere utilizzato anche tramite
`HARICA_API_KEY_FILE`; la variabile contiene solo il percorso, non la chiave.

La precedenza è:

1. `--api-key-file`;
2. `HARICA_API_KEY`, mantenuta per compatibilità e CI;
3. `HARICA_API_KEY_FILE`;
4. file predefinito dell'ambiente.

### Rotazione e cancellazione

Se la chiave era stata configurata con una versione `harica-safe`, può essere migrata
senza reinserirla e senza mostrarla:

```bash
harica-client auth migrate --environment production
```

In assenza della migrazione, `harica-client` continua temporaneamente a leggere il vecchio
percorso come fallback. Ogni nuovo `auth set` scrive esclusivamente nel percorso
`harica-client`.

Per sostituire la chiave, ripeti `auth set`: il nuovo file viene scritto atomicamente.

```bash
harica-client auth set --environment production
```

Per rimuovere la copia locale:

```bash
harica-client auth delete --environment production
```

In uno script non interattivo la conferma può essere esplicita:

```bash
harica-client auth delete --environment production --yes
```

La cancellazione locale non revoca la chiave sul portale HARICA; in caso di compromissione
occorre revocarla anche nel Certificate Manager.

### Esecuzione tramite cron

Usa un account di sistema dedicato e non privilegiato. Esempio di crontab:

```cron
PATH=/opt/harica-client/.venv/bin:/usr/bin:/bin
HOME=/home/harica
HARICA_API_KEY_FILE=/home/harica/.config/harica-client/credentials/production.key

0 6 * * * /bin/sh -c 'umask 077; exec harica-client list --environment production --status valid --csv /home/harica/exports/certificati-validi.csv --force' >> /home/harica/log/harica-client.log 2>&1
```

Il crontab non contiene la chiave. `HOME` viene dichiarata esplicitamente per rendere
deterministica la configurazione anche nell'ambiente minimale di cron. Crea in anticipo
le directory di output e log con permessi adatti all'utente del job.

Non inserire la chiave in `.zshrc`, `.profile`, crontab, argomenti della CLI o file nel
repository. `HARICA_API_KEY` resta utile per esecuzioni effimere, ma non è il metodo
raccomandato per la persistenza su server.

## Utilizzo

```bash
harica-client version
harica-client auth status --environment production
harica-client list --status valid
harica-client list --status all
harica-client list --status valid --fqdn auth.wifi.example.org
harica-client list --status valid --friendly-name wifi
harica-client list --status valid --email pki@example.org
harica-client list --status revoked --json
harica-client list --status valid --csv certificati-validi.csv
harica-client list --status all --csv tutti-i-certificati.csv
harica-client list --status expired --environment staging
harica-client serial 'NUMERO-SERIALE' --json
harica-client serial 'NUMERO-SERIALE' --csv certificato.csv
```

### Elenco completo di tutti gli stati

Per unire certificati validi, revocati e scaduti in un unico risultato:

```bash
harica-client list --status all
harica-client list --status all --json
harica-client list --status all --csv tutti-i-certificati.csv --force
```

HARICA espone un endpoint distinto per ciascuno stato. Di conseguenza, `--status all`
esegue in sequenza tre richieste: `valid`, `revoked` ed `expired`. Il retry e la gestione
del rate limit si applicano separatamente a ogni richiesta. Le risposte vengono unite in
un solo elenco e, quando assente, viene aggiunto a ogni certificato il campo `status`
corrispondente all'endpoint di origine.

### Ricerca per FQDN, friendlyName ed email

Il comando `list` può filtrare localmente i certificati tramite una ricerca parziale e
case-insensitive. Il filtro FQDN considera i campi FQDN, CN, SAN, DN e, come fallback,
`friendlyName`:

```bash
harica-client list --status valid --fqdn auth.wifi.example.org
```

Per cercare esclusivamente nel campo `friendlyName`:

```bash
harica-client list --status valid --friendly-name wifi
```

Per cercare nei campi email restituiti da HARICA, incluso `userEmail`:

```bash
harica-client list --status valid --email pki@example.org
```

È supportato anche l'alias `--friendlyName`. I filtri possono essere combinati e in tal
caso devono risultare tutti veri:

```bash
harica-client list \
  --status valid \
  --fqdn example.org \
  --friendly-name wifi \
  --email pki@example.org
```

L'esportazione CSV e JSON utilizza gli stessi risultati filtrati:

```bash
harica-client list \
  --status valid \
  --fqdn example.org \
  --csv certificati-example.csv
```

Il filtraggio avviene dopo la singola risposta HARICA e non genera richieste aggiuntive
per ciascun certificato.

In ogni formato di output la colonna o proprietà `CN` è sempre distinta da `friendlyName`.
Se HARICA non restituisce un campo `commonName` separato, il client estrae il CN dal
distinguished name contenuto in `dN`. Il campo derivato `CN` viene aggiunto alla tabella,
al JSON e al CSV; tutti gli altri nomi e valori restano quelli originali restituiti
dall'API.

### Esportazione CSV

L'opzione `--csv FILE` esporta tutti i campi restituiti da HARICA:

```bash
harica-client list --status valid --csv export/certificati-validi.csv
```

Il file usa UTF-8 con BOM, così da essere riconosciuto correttamente anche da Excel.
Liste e oggetti annidati vengono salvati nella singola cella come JSON compatto. Per
ridurre il rischio di CSV injection, i testi che iniziano con `=`, `+`, `-`, `@`, tab o
carriage return ricevono un apostrofo iniziale; per ottenere i valori integralmente grezzi
resta disponibile `--json`.

Il campo `certificate`, che può contenere l'intero certificato e rendere l'output molto
pesante, viene escluso da tutti gli output della CLI (tabella, JSON e CSV). Il confronto
del nome non distingue tra maiuscole e minuscole. Campi informativi come
`certificateType` e `certificateValidTo` restano presenti. Questa esclusione riguarda
solo la CLI: usando `HaricaClient` come libreria si continua a ricevere la risposta
HARICA completa.

Per sicurezza un file esistente non viene sovrascritto. La sovrascrittura deve essere
richiesta esplicitamente:

```bash
harica-client list --status valid --csv certificati-validi.csv --force
```

`--json` e `--csv` sono mutuamente esclusivi.

Gli ambienti predefiniti sono:

| Ambiente | Base URL |
| --- | --- |
| production | `https://cm.harica.gr` |
| staging | `https://cm-stg.harica.gr` |
| development | `https://cm-dev.harica.gr` |

Per test controllati è disponibile `--base-url`; non usarla in produzione senza aver
verificato attentamente la destinazione, perché l'API key viene inviata a tale host.

## Uso come libreria

```python
import os

from harica_client import HaricaClient, RetryPolicy

client = HaricaClient(
    os.environ["HARICA_API_KEY"],
    retry_policy=RetryPolicy(max_attempts=4, base_delay=1, max_delay=60),
)

validi = client.list_certificates("valid")
certificato = client.certificate_by_serial("NUMERO-SERIALE")
```

Il valore restituito è il JSON HARICA decodificato, senza imporre uno schema locale che
potrebbe diventare rapidamente obsoleto.

## Comportamento sul rate limit

Su HTTP 429 il client:

1. rispetta `Retry-After`, se presente e valido;
2. altrimenti calcola un backoff esponenziale con jitter;
3. limita ogni attesa a `max_delay`;
4. dopo l'ultimo tentativo solleva `HaricaRateLimitError`.

La CLI restituisce exit code `75` quando il rate limit resta attivo. Gli errori ordinari
restituiscono `1`, mentre gli errori di uso/configurazione restituiscono `2`.

## Test

I test usano un server HTTP locale e non contattano HARICA:

```bash
python -m unittest discover -s tests -v
```

## Endpoint implementati

```text
GET /cm/v1/admin/certificates/list/valid
GET /cm/v1/admin/certificates/list/revoked
GET /cm/v1/admin/certificates/list/expired
GET /cm/v1/admin/certificates/serial/{serialNumber}
```

Riferimenti ufficiali consultati il 17 luglio 2026:

- https://guides.harica.gr/docs/Guides/Developer/5.-API-Keys/
- https://developer.harica.gr/

## Limiti

Il progetto non implementa emissione, approvazione, revoca o download di certificati.
Queste operazioni modificano stato e richiedono modelli di richiesta specifici: vanno
aggiunte solo dopo una verifica puntuale dello Swagger HARICA e con test dedicati.
