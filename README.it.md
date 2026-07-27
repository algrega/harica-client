# harica-client

[English](README.md) | **Italiano**

[![CI](https://github.com/algrega/harica-client/actions/workflows/ci.yml/badge.svg)](https://github.com/algrega/harica-client/actions/workflows/ci.yml)

Client Python sincrono e CLI per consultare i certificati tramite le API key ufficiali
di HARICA Certificate Manager.

Questo è un progetto indipendente e non ufficiale. Non è affiliato, approvato o
supportato da HARICA.

> **Nota dell'autore:** non sono un programmatore di professione. Questo progetto è
> nato da una necessità concreta, molta curiosità e un aiuto decisamente generoso di
> OpenAI Codex. Ho verificato il risultato con test automatici, ma occhi esperti,
> segnalazioni e contributi sono sempre benvenuti: siate gentili, sto imparando!

Il progetto è intenzionalmente piccolo e prudente: può conservare l'API key in un file
locale protetto, non la accetta come argomento della CLI e gestisce esplicitamente il
rate limit HTTP 429.

## Funzionalità

- autenticazione tramite header `X-API-Key`;
- credenziali separate per ambiente, adatte a esecuzioni manuali e cron;
- ambienti `production`, `staging` e `development`;
- elenco certificati `valid`, `revoked`, `expired` oppure di tutti gli stati;
- ricerca di un certificato per numero seriale;
- download del certificato finale con nome PEM automatico derivato dal CN;
- ricerca locale per FQDN, `friendlyName` e indirizzo email;
- cache JSON locale opzionale per filtri offline ripetuti;
- riepiloghi, scadenze, raggruppamenti e controlli qualità basati solo sulla cache;
- retry di `429`, `502`, `503` e `504` con backoff esponenziale e jitter;
- HTTPS obbligatorio e gestione fail-closed dei redirect autenticati;
- supporto a `Retry-After` sia in secondi sia come data HTTP;
- errori distinti per autenticazione, rate limit, rete, HTTP e risposta non JSON;
- neutralizzazione delle sequenze di controllo nell'output leggibile a terminale;
- output tabellare o JSON ed esportazione CSV;
- colonna `CN` nell'output tabellare, ricavata anche dal campo `dN`;
- interfaccia CLI in italiano e inglese;
- nessuna dipendenza runtime esterna.

## Lingua dell'interfaccia

L'italiano è la lingua predefinita iniziale. Salva una volta la lingua preferita con:

```bash
harica-client language set en
harica-client language status
```

La preferenza viene memorizzata in `${XDG_CONFIG_HOME}/harica-client/language` oppure,
se `XDG_CONFIG_HOME` non è definita, in `~/.config/harica-client/language`. Per
rimuoverla:

```bash
harica-client language reset
```

Usa `--language` soltanto come eccezione occasionale, posizionandolo prima o dopo il
comando:

```bash
harica-client --language en list --status valid
harica-client list --status valid --language en
```

Per cron e server usa `HARICA_CLIENT_LANGUAGE`:

```bash
HARICA_CLIENT_LANGUAGE=en harica-client list --status valid
```

La precedenza è `--language`, `HARICA_CLIENT_LANGUAGE`, preferenza salvata, quindi `it`.
Sono ammessi esclusivamente `it` ed `en`. La lingua modifica help, prompt, messaggi ed
errori, ma non cambia comandi, opzioni o struttura degli export JSON e CSV.

## Requisiti e installazione

- Python 3.11 o successivo;
- account HARICA con 2FA;
- ruolo Enterprise Admin per gli endpoint implementati;
- [API key creata nel profilo HARICA](https://guides.harica.gr/docs/Guides/Developer/5.-API-Keys/).

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
HARICA_CLIENT_LANGUAGE=it

0 6 * * * /bin/sh -c 'umask 077; exec harica-client list --environment production --status valid --csv /home/harica/exports/certificati-validi.csv --force' >> /home/harica/log/harica-client.log 2>&1
```

Il crontab non contiene la chiave. `HOME` viene dichiarata esplicitamente per rendere
deterministica la configurazione anche nell'ambiente minimale di cron. Crea in anticipo
le directory di output e log con permessi adatti all'utente del job.

Per aggiornare una sola volta e svolgere poi gli export senza ulteriori chiamate API,
usa due job:

```cron
HARICA_CLIENT_CACHE_FILE=/home/harica/.cache/harica-client/certificates/production.json

30 5 * * * /bin/sh -c 'umask 077; exec harica-client cache refresh --environment production' >> /home/harica/log/harica-client.log 2>&1
0 6 * * * /bin/sh -c 'umask 077; exec harica-client list --from-cache --max-cache-age 24 --status valid --csv /home/harica/exports/certificati-validi.csv --force' >> /home/harica/log/harica-client.log 2>&1
15 6 * * * /bin/sh -c 'umask 077; exec harica-client stats expirations --max-cache-age 24 --within 30 --csv /home/harica/exports/prossime-scadenze.csv --force' >> /home/harica/log/harica-client.log 2>&1
```

Se l'aggiornamento fallisce, la fotografia precedente resta integra. Il job di export
fallisce senza contattare silenziosamente HARICA se la cache manca, non è valida o è
troppo vecchia.

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
harica-client download 'NUMERO-SERIALE'
harica-client download 'NUMERO-SERIALE' --output certificato.pem
harica-client stats summary
harica-client stats expirations --within 30
harica-client stats owners
harica-client stats quality
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

### Cache locale opzionale

Il comportamento predefinito di `list` non usa alcuna cache. Per evitare richieste
ripetute a HARICA, crea o aggiorna esplicitamente una fotografia completa:

```bash
harica-client cache refresh --environment production
harica-client cache status --environment production
```

`cache refresh` interroga una volta gli stati `valid`, `revoked` ed `expired` e salva una
cache JSON versionata. Le letture successive sono completamente locali e non richiedono
la API key:

```bash
harica-client list --from-cache --status valid
harica-client list --from-cache --fqdn example.org
harica-client list --from-cache --friendly-name portale --email pki@example.org
harica-client list --from-cache --status all --json
harica-client list --from-cache --status all --csv certificati-cache.csv
```

La cache non scade automaticamente. Per rifiutare una fotografia più vecchia di 24 ore,
senza effettuare fallback verso la rete:

```bash
harica-client list --from-cache --max-cache-age 24 --status valid
```

I percorsi predefiniti sono
`${XDG_CACHE_HOME}/harica-client/certificates/{environment}.json` oppure
`~/.cache/harica-client/certificates/{environment}.json`. È possibile usare
`--cache-file PATH` o `HARICA_CLIENT_CACHE_FILE`; il flag ha la precedenza. Una
`--base-url` personalizzata con `cache refresh` richiede un `--cache-file` esplicito.

Le directory vengono create con permessi `0700` e i file con `0600`. Link simbolici,
proprietario errato e accesso da parte di gruppo o altri vengono rifiutati. La scrittura
è atomica, quindi un aggiornamento fallito conserva la cache precedente. La API key e il
campo potenzialmente pesante `certificate` non vengono mai salvati, ma la cache può
contenere hostname e indirizzi email sensibili: va tenuta fuori da repository e directory
condivise.

Per eliminarla esplicitamente:

```bash
harica-client cache delete --environment production
harica-client cache delete --environment production --yes
```

### Statistiche basate sulla cache

Il comando `stats` analizza esclusivamente la cache locale selezionata. Non carica la
API key, non crea il client HTTP, non contatta HARICA e non esegue fallback verso la
rete. Una cache assente, non sicura, non valida, incompatibile, appartenente a un altro
ambiente o troppo vecchia causa un errore. Quando servono dati aggiornati, aggiorna
separatamente la fotografia:

```bash
harica-client cache refresh --environment production
harica-client stats summary
```

I report disponibili sono:

```bash
# Conteggi generali, fasce di scadenza, revoche recenti e campi mancanti
harica-client stats summary

# Certificati validi in scadenza entro 30 giorni; il default è 30
harica-client stats expirations --within 30

# Conteggi raggruppati per userEmail, con user come informazione descrittiva
harica-client stats owners

# Una riga per ogni certificato e anomalia dei dati
harica-client stats quality
```

`summary` include data ed età della cache, totali per stato, fasce di scadenza esclusive
(`0–7`, `8–30`, `31–60`, `61–90` e oltre 90 giorni), revoche negli ultimi 30 giorni e
record privi di responsabile, email, CN o date di validità utilizzabili.
`expirations` considera solo i certificati `valid`, li ordina per scadenza e CN e segnala
quanti record validi sono stati esclusi perché `validTo` è assente o non valida.
`owners` usa un gruppo separato quando email o responsabile mancano. `quality` espone
codici stabili per campi mancanti o non validi, intervalli temporali invertiti,
incoerenze di revoca, seriali duplicati, CN mancanti e stati sconosciuti.

Ogni report supporta la selezione e il limite di età della cache:

```bash
harica-client stats summary --environment staging
harica-client stats summary --cache-file /srv/harica/cache.json
harica-client stats summary --max-cache-age 24
```

La precedenza del percorso resta `--cache-file`, `HARICA_CLIENT_CACHE_FILE`, quindi il
percorso predefinito dell'ambiente. L'output predefinito è una tabella localizzata.
Chiavi JSON, intestazioni CSV e codici delle anomalie restano stabili e identici tra
italiano e inglese:

```bash
harica-client stats summary --json
harica-client stats expirations --within 60 --json
harica-client stats owners --csv responsabili-certificati.csv
harica-client stats quality --csv qualita-certificati.csv --force
```

Le statistiche descrivono soltanto la fotografia selezionata e non sono dati HARICA
autoritativi in tempo reale. Non vengono conservati storico o confronti tra refresh.
Gli export JSON e CSV possono contenere hostname, nomi personali e indirizzi email
sensibili: proteggili come la cache e non salvarli in repository o directory condivise.

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

In modalità live il filtraggio avviene dopo la risposta HARICA e non genera richieste
aggiuntive per ciascun certificato. Con `--from-cache`, sia lo stato sia gli altri filtri
vengono applicati localmente senza alcuna richiesta a HARICA.

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

### Download del certificato

Per scaricare il certificato X.509 finale restituito dalla ricerca per seriale:

```bash
harica-client download 'NUMERO-SERIALE'
# salva ./portal.example.org.pem

harica-client download 'NUMERO-SERIALE' --output nome-personalizzato.pem
```

Dopo il salvataggio, il comando mostra sempre un riepilogo leggibile:

```text
Percorso: /percorso/assoluto/certificato.pem
Seriale: 1234AB
Soggetto: C=IT, O=Example, CN=portal.example.org
Emittente: C=GR, O=HARICA, CN=...
Valido dal: 2026-07-23T08:26:40Z
Valido fino al: 2027-07-23T08:26:39Z
```

Il riepilogo viene estratto internamente usando soltanto la libreria standard Python.
Le date sono normalizzate in ISO 8601 UTC e i distinguished name usano un formato
compatto e deterministico. Il controllo conferma che il file sia un certificato X.509
leggibile, ma non verifica chain di fiducia, revoca, hostname o validità temporale
corrente.
Il riepilogo è destinato alla lettura umana e non è un formato dati stabile per script.

Senza `--output`, il nome viene costruito dal CN del subject e il file viene salvato
nella directory corrente. I CN wildcard come `*.example.org` diventano
`wildcard.example.org.pem`; i caratteri non sicuri per il filesystem vengono
sostituiti. Se manca un CN utilizzabile viene usato il seriale del certificato. Più CN
differenti richiedono un `--output` esplicito.

`download` esegue sempre una ricerca puntuale in rete e richiede quindi la API key. Non
usa la cache locale, che esclude intenzionalmente il contenuto dei certificati. Il
comando accetta le stesse opzioni di connessione di `serial`, incluse `--environment`,
`--base-url`, `--timeout`, `--max-attempts` e `--api-key-file`.

Viene scritto un solo certificato finale: chain, dati PKCS#7/PKCS#12, chiavi private,
certificati concatenati e valori malformati vengono rifiutati. HARICA può restituire un
PEM o un DER codificato in base64; il file salvato viene normalizzato in PEM con
terminatori LF, newline finale e permessi `0644`.

Usa `--output` per scegliere un nome o una directory differenti. Un file regolare
esistente resta intatto salvo l'uso di `--force`; link simbolici e destinazioni non
regolari vengono rifiutati anche con `--force`. La scrittura usa un file temporaneo
nella directory di destinazione seguito da sostituzione atomica. Il contenuto PEM non
viene mai stampato nel terminale o nei log.

Per una verifica indipendente e facoltativa sui sistemi che dispongono di OpenSSL:

```bash
openssl x509 -in certificato.pem -noout -serial -subject -issuer -dates
```

Gli ambienti predefiniti sono:

| Ambiente | Base URL |
| --- | --- |
| production | `https://cm.harica.gr` |
| staging | `https://cm-stg.harica.gr` |
| development | `https://cm-dev.harica.gr` |

Per test controllati è disponibile `--base-url`. HTTPS è obbligatorio salvo indirizzi
loopback (`localhost`, `127.0.0.0/8` e `::1`) e i redirect autenticati non vengono mai
seguiti. Non usare una destinazione HTTPS personalizzata senza averla verificata,
perché l'API key viene inviata a tale host.

I caratteri di controllo ricevuti nei dati remoti o inclusi negli errori vengono
neutralizzati nell'output leggibile a terminale; quelli non sicuri sono mostrati come
sequenze di escape visibili. Questa sanitizzazione non viene applicata a JSON e CSV,
che mantengono le regole di export esistenti, inclusa la protezione dalle formule CSV.

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

## Contribuire

I contributi sono benvenuti. Leggi le [linee guida](CONTRIBUTING.md) e il
[Codice di condotta](CODE_OF_CONDUCT.md), quindi usa il
[modulo appropriato](https://github.com/algrega/harica-client/issues/new/choose) oppure
apri una pull request. Segnala le possibili vulnerabilità esclusivamente tramite il
modulo GitHub privato
[Report a vulnerability](https://github.com/algrega/harica-client/security/advisories/new).

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

Il progetto non implementa emissione, approvazione o revoca di certificati.
Queste operazioni modificano stato e richiedono modelli di richiesta specifici: vanno
aggiunte solo dopo una verifica puntuale dello Swagger HARICA e con test dedicati.
