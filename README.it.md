# harica-client

[English](https://github.com/algrega/harica-client/blob/main/README.md) | **Italiano**

[![CI](https://github.com/algrega/harica-client/actions/workflows/ci.yml/badge.svg)](https://github.com/algrega/harica-client/actions/workflows/ci.yml)

Client Python sincrono e CLI non ufficiali, in sola lettura, per consultare i certificati
tramite l'API HARICA Certificate Manager. Non emette, approva, annulla o revoca
certificati e non modifica richieste o altri dati remoti HARICA.

Questo progetto indipendente non è affiliato, approvato o supportato da HARICA.

> **Nota dell'autore:** non sono un programmatore di professione. Questo progetto è
> nato da una necessità concreta, molta curiosità e un aiuto decisamente generoso di
> OpenAI Codex. Oltre a eseguire i test automatici, ho verificato personalmente tutte
> le funzionalità e sono tutte operative. Occhi esperti, segnalazioni e contributi
> sono sempre benvenuti: siate gentili, sto imparando!

Il progetto è intenzionalmente piccolo e prudente: ogni operazione remota usa HTTP
`GET`. I comandi per credenziali, preferenza linguistica, cache, esportazione CSV e
download scrivono soltanto nel filesystem locale. Il client può conservare l'API key in
un file locale protetto, non la accetta come argomento della CLI e gestisce
esplicitamente il rate limit HTTP 429.

## Funzionalità

- accesso remoto in sola lettura tramite HTTP `GET`;
- autenticazione tramite header `X-API-Key`;
- credenziali separate per ambiente, adatte a esecuzioni manuali e pianificate;
- ambienti `production`, `staging` e `development`;
- elenco certificati `valid`, `revoked`, `expired` oppure di tutti gli stati;
- ricerca di un certificato per numero seriale;
- download del certificato finale con nome PEM automatico derivato dal CN;
- ricerca locale per FQDN, `friendlyName` e indirizzo email;
- cache locale protetta opzionale per filtri offline ripetuti;
- riepiloghi, scadenze, raggruppamenti e controlli qualità basati solo sulla cache;
- retry di `429`, `502`, `503` e `504` con backoff esponenziale e jitter;
- HTTPS obbligatorio e gestione fail-closed dei redirect autenticati;
- supporto a `Retry-After` sia in secondi sia come data HTTP;
- errori distinti per autenticazione, rate limit, rete, HTTP e risposta non JSON;
- neutralizzazione delle sequenze di controllo nell'output leggibile a terminale;
- output tabellare o JSON ed esportazione CSV;
- campo `CN` in tutti gli output della CLI, ricavato anche dal campo `dN`;
- interfaccia CLI in italiano e inglese;
- nessuna dipendenza runtime esterna.

## Requisiti e installazione

- Python 3.11 o successivo;
- Linux, macOS, un altro sistema operativo compatibile POSIX oppure un'edizione x64
  supportata di Windows 10, Windows 11 o Windows Server;
- account HARICA con 2FA;
- ruolo Enterprise Admin per gli endpoint implementati;
- [API key creata nel profilo HARICA](https://guides.harica.gr/docs/Guides/Developer/5.-API-Keys/).

Su Linux, macOS e gli altri sistemi POSIX, clona il repository ed esegui
l'installazione dalla sua directory principale:

```bash
git clone https://github.com/algrega/harica-client.git
cd harica-client
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

Su Windows usa PowerShell con un'installazione x64 di Python 3.11–3.14:

```powershell
git clone https://github.com/algrega/harica-client.git
Set-Location harica-client
py --list
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\harica-client.exe version
```

Prima di creare l'ambiente, verifica che la versione indicata come predefinita da
`py --list` sia Python x64 dalla 3.11 alla 3.14. Se sono installate più versioni
supportate, selezionane una esplicitamente, per esempio con
`py -3.14 -m venv .venv`. L'attivazione è facoltativa: richiamare direttamente gli
eseguibili dell'ambiente, come sopra, evita anche le restrizioni dell'execution policy
di PowerShell. Se preferisci attivarlo e le regole locali lo consentono, esegui:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\.venv\Scripts\Activate.ps1
```

La modifica della policy vale soltanto per il processo PowerShell corrente. Gli esempi
seguenti usano il comando più breve `harica-client`; senza attivazione, usa invece
`.\.venv\Scripts\harica-client.exe`. Windows ARM64 non rientra nel supporto iniziale.

Per un'installazione modificabile destinata allo sviluppo, segui le
[linee guida per contribuire](https://github.com/algrega/harica-client/blob/main/CONTRIBUTING.md).

## Lingua dell'interfaccia

L'italiano è la lingua predefinita iniziale. Salva una volta la lingua preferita con:

```bash
harica-client language set en
harica-client language status
```

Su POSIX la preferenza viene memorizzata in
`${XDG_CONFIG_HOME}/harica-client/language` oppure, se `XDG_CONFIG_HOME` non è definita,
in `~/.config/harica-client/language`. Su Windows viene salvata in
`%APPDATA%\harica-client\language`, con fallback ad `AppData\Roaming` nel profilo
dell'utente corrente. Per rimuoverla:

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

## Configurazione sicura della chiave

Salva la chiave una sola volta con input nascosto e doppia conferma:

```bash
harica-client auth set --environment production
harica-client auth status --environment production
```

`auth set` salva la chiave localmente. `auth status` indica la sorgente selezionata e
valida il file secondo le regole di sicurezza della piattaforma. Nessuno dei due comandi
contatta HARICA o verifica che la chiave sia attualmente valida.

Su POSIX il percorso predefinito è:

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

Su Windows il percorso predefinito è:

```text
%APPDATA%\harica-client\credentials\{environment}.key.dpapi
```

Se `APPDATA` non è disponibile, il client usa `AppData\Roaming` nel profilo dell'utente
corrente. `auth set` scrive sempre un contenitore DPAPI versionato, cifrato e autenticato
per l'utente Windows corrente sul computer corrente. Un file testuale creato manualmente
viene rifiutato: importa la chiave con `auth set` oppure usa `HARICA_API_KEY` soltanto
per un ambiente di automazione effimero. Per i file protetti vengono rifiutati percorsi
relativi, UNC/device path, alternate data stream, link simbolici, junction e altri
reparse point.

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

Equivalente PowerShell:

```powershell
harica-client auth set `
  --environment production `
  --api-key-file "$env:APPDATA\harica-client\credentials\production.key.dpapi"
```

La directory specificata deve già essere sicura oppure deve poter essere creata dal
client. Un percorso esplicito può essere utilizzato anche tramite
`HARICA_API_KEY_FILE`; la variabile contiene solo il percorso, non la chiave.

Per i comandi che leggono una chiave, inclusi `list`, `serial`, `download`,
`cache refresh` e `auth status`, la precedenza è:

1. `--api-key-file`;
2. `HARICA_API_KEY`, mantenuta per automazioni effimere;
3. `HARICA_API_KEY_FILE`;
4. file predefinito dell'ambiente.

Per `auth set` e `auth delete`, la precedenza della destinazione è `--api-key-file`,
`HARICA_API_KEY_FILE`, quindi il file predefinito dell'ambiente. `HARICA_API_KEY` viene
ignorata nella scelta del file da scrivere o eliminare.

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

### Esecuzione pianificata su POSIX (cron)

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
aggiungi al medesimo crontab la variabile e i job seguenti:

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
repository. `HARICA_API_KEY` resta utile per automazioni effimere, come un job CI
temporaneo, ma non è il metodo raccomandato per la persistenza su server.

### Esecuzione pianificata su Windows (Utilità di pianificazione)

Esegui prima `auth set` in modo interattivo con lo stesso account Windows che sarà
associato all'attività:

```powershell
harica-client auth set --environment production
harica-client auth status --environment production
```

Nell'Utilità di pianificazione usa quell'account anche se l'attività viene eseguita senza
sessione interattiva. Imposta **Programma/script** sull'eseguibile dell'ambiente virtuale,
per esempio `C:\Tools\harica-client\.venv\Scripts\harica-client.exe`, e
**Aggiungi argomenti** su:

```text
cache refresh --environment production
```

Imposta **Avvia in** sulla directory di installazione o del repository. Crea un'azione o
un'attività separata per un export basato sulla cache, per esempio:

```text
list --from-cache --max-cache-age 24 --status valid --csv C:\Harica\Export\certificati-validi.csv --force
```

Non inserire l'API key negli argomenti, negli script PowerShell o batch, né nella
definizione dell'attività. DPAPI lega intenzionalmente chiave e cache protette allo
stesso utente e computer: un'attività eseguita con un altro account non può decifrarle.
Verifica che l'account possa scrivere nelle directory di export e log scelte.

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
harica-client cache refresh --environment production
harica-client cache status --environment production
harica-client list --from-cache --status valid
harica-client list --from-cache --max-cache-age 24 --status all --json
harica-client stats summary
harica-client stats expirations --within 30
harica-client stats owners
harica-client stats quality
harica-client cache delete --environment production
```

### Opzioni di connessione

I comandi live `list`, `serial` e `download` e il comando `cache refresh` accettano le
stesse opzioni di connessione:

| Opzione | Valore predefinito | Funzione |
| --- | --- | --- |
| `--environment` | `production` | Seleziona `production`, `staging` o `development`. |
| `--base-url` | URL dell'ambiente | Sostituisce l'ambiente selezionato per test controllati. |
| `--timeout` | `30` secondi | Imposta il timeout HTTP positivo per ogni richiesta. |
| `--max-attempts` | `4` | Imposta il numero totale di tentativi, almeno uno. |
| `--api-key-file` | risoluzione automatica | Usa un file protetto esplicito con la precedenza più alta. |

Con `list --from-cache` non viene eseguita alcuna richiesta di rete: `--environment`
seleziona l'ambiente atteso della cache, mentre `--base-url`, `--timeout`,
`--max-attempts` e `--api-key-file` non vengono utilizzate.

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
fotografia JSON con schema logico versione 1. Su Windows, prima della scrittura il JSON
viene inserito in un contenitore DPAPI versionato. Le letture successive sono
completamente locali e non richiedono l'API key:

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

I percorsi POSIX predefiniti sono
`${XDG_CACHE_HOME}/harica-client/certificates/{environment}.json` oppure
`~/.cache/harica-client/certificates/{environment}.json`. Su Windows il percorso
predefinito è
`%LOCALAPPDATA%\harica-client\certificates\{environment}.json.dpapi`, con fallback ad
`AppData\Local` nel profilo dell'utente corrente. È possibile usare `--cache-file PATH`
o `HARICA_CLIENT_CACHE_FILE`; il flag ha la precedenza. Su Windows gli override devono
essere percorsi locali assoluti e restano protetti con DPAPI. Una `--base-url`
personalizzata con `cache refresh` richiede un `--cache-file` esplicito.

Su POSIX le directory vengono create con permessi `0700` e i file con `0600`; link
simbolici, proprietario errato e accesso da parte di gruppo o altri vengono rifiutati.
Su Windows la cache è cifrata e autenticata con DPAPI in ambito utente; vengono rifiutati
link, junction, reparse point, percorsi relativi, UNC/device path e alternate data
stream. La scrittura è atomica su ogni piattaforma, quindi un aggiornamento fallito
conserva la cache precedente. La API key e il campo potenzialmente pesante `certificate`
non vengono mai salvati, ma la cache decifrata può contenere hostname e indirizzi email
sensibili: mantieni gli export fuori da repository e directory condivise.

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
distinguished name contenuto in `dN`. La CLI aggiunge `CN` e rimuove ogni campo
`certificate`. Quando un filtro locale viene applicato a una risposta contenitore, un
campo intero `total`, `count` o `totalCount` viene aggiornato al numero di righe
filtrate. Gli altri nomi e valori restano quelli restituiti dall'API.

### Esportazione CSV

L'opzione `--csv FILE` esporta i campi elaborati dalla CLI:

```bash
harica-client list --status valid --csv export/certificati-validi.csv
```

Il file usa UTF-8 con BOM, così da essere riconosciuto correttamente anche da Excel.
Liste e oggetti annidati vengono salvati nella singola cella come JSON compatto. Per
ridurre il rischio di CSV injection, i testi che iniziano con `=`, `+`, `-`, `@`, tab o
carriage return ricevono un apostrofo iniziale. Usa `--json` per conservare questi valori
senza il prefisso specifico del CSV; anche il JSON segue comunque le regole di
elaborazione della CLI descritte di seguito.

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

La tabella predefinita è una vista compatta per la lettura umana: seleziona alcune
colonne scalari utili e tronca le celle lunghe a 48 caratteri. Usa JSON o CSV quando
servono tutti i campi elaborati disponibili nella CLI.

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
sostituiti. I nomi riservati Windows (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9` e
`LPT1`–`LPT9`) ricevono un prefisso e i nomi automatici non terminano mai con punto o
spazio. Se manca un CN utilizzabile viene usato il seriale del certificato. Più CN
differenti richiedono un `--output` esplicito.

`download` esegue sempre una ricerca puntuale in rete e richiede quindi l'API key. Non
usa la cache locale, che esclude intenzionalmente il contenuto dei certificati. Usa le
opzioni di connessione documentate sopra.

Viene scritto un solo certificato finale: chain, dati PKCS#7/PKCS#12, chiavi private,
certificati concatenati e valori malformati vengono rifiutati. HARICA può restituire un
PEM o un DER codificato in base64; il file salvato viene normalizzato in PEM con
terminatori LF, newline finale e permessi `0644` su POSIX.

Usa `--output` per scegliere un nome o una directory differenti. Un file regolare
esistente resta intatto salvo l'uso di `--force`; link simbolici e destinazioni non
regolari vengono rifiutati anche con `--force`. La scrittura usa un file temporaneo
nella directory di destinazione seguito da sostituzione atomica. Il contenuto PEM non
viene mai stampato nel terminale o nei log, anche se HARICA restituisce un blocco PEM
dove era atteso JSON.

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

from harica_client import Environment, HaricaClient, RetryPolicy

client = HaricaClient(
    os.environ["HARICA_API_KEY"],
    environment=Environment.PRODUCTION,
    timeout=30,
    retry_policy=RetryPolicy(max_attempts=4, base_delay=1, max_delay=60),
)

validi = client.list_certificates("valid")
certificato = client.certificate_by_serial("NUMERO-SERIALE")
```

`environment` seleziona una base URL HARICA documentata. `base_url` può sovrascriverla
per test controllati, mentre `timeout` è il timeout HTTP in secondi. `query` aggiunge
alla richiesta di elenco i parametri diversi da `None`. Entrambi i metodi pubblici
restituiscono il JSON HARICA decodificato come `Any`, senza imporre uno schema locale che
potrebbe diventare rapidamente obsoleto.

Gli errori operativi sollevati da `HaricaClient` derivano da `HaricaError`:
`HaricaConfigurationError`, `HaricaNetworkError`, `HaricaHTTPError`,
`HaricaAuthError`, `HaricaRateLimitError` e `HaricaResponseError`. Importa da
`harica_client` l'eccezione specifica necessaria. La creazione di una `RetryPolicy` con
`max_attempts` minore di uno oppure con ritardi o jitter negativi solleva `ValueError`.

## Comportamento sul rate limit

Su HTTP 429 il client:

1. rispetta `Retry-After`, se presente e valido;
2. altrimenti calcola un backoff esponenziale con jitter;
3. limita ogni attesa a `max_delay`;
4. dopo l'ultimo tentativo solleva `HaricaRateLimitError`.

La CLI restituisce exit code `75` quando il rate limit resta attivo. Gli errori ordinari
restituiscono `1`, mentre gli errori di uso/configurazione restituiscono `2`.

## Test

I test usano trasporti HTTP simulati e un server HTTP loopback temporaneo. Non
contattano mai HARICA. La CI esegue la suite trattando i `ResourceWarning` come errori
su Python 3.11–3.14 in Linux e Windows, oltre a Python 3.14 su macOS:

```bash
python -m unittest discover -s tests -v
```

## Contribuire

I contributi sono benvenuti. Leggi le
[linee guida](https://github.com/algrega/harica-client/blob/main/CONTRIBUTING.md) e il
[Codice di condotta](https://github.com/algrega/harica-client/blob/main/CODE_OF_CONDUCT.md),
quindi usa il
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

Riferimenti ufficiali:

- [Manuale HARICA per l'integrazione tramite API key](https://guides.harica.gr/docs/Guides/Developer/5.-API-Keys/)
- [Documentazione API HARICA Certificate Manager](https://developer.harica.gr/)

## Limiti

Il progetto implementa esclusivamente i quattro endpoint `GET` elencati sopra. Non
implementa emissione di certificati, approvazione o cancellazione di richieste, revoca
di certificati o altre operazioni remote in scrittura. Il supporto Windows iniziale è
limitato a x64; Windows ARM64, la condivisione di file protetti DPAPI tra utenti o
computer e la migrazione automatica di file Windows sperimentali restano fuori ambito.

## Licenza

Distribuito con
[licenza MIT](https://github.com/algrega/harica-client/blob/main/LICENSE).
