RENTRI Manager - Complete Edition 📊
====================================

Un'applicazione desktop moderna e completa per la gestione automatizzata della vidimazione FIR (Formulari di Identificazione Rifiuti) attraverso le API RENTRI del governo italiano.

🚀 Panoramica
-------------

RENTRI Manager è un'applicazione Python sviluppata con CustomTkinter che fornisce un'interfaccia grafica moderna per:

-   Gestione fornitori con certificati digitali P12

-   Vidimazione automatizzata dei FIR

-   Dashboard completo con statistiche in tempo reale

-   PDF Tools integrati per la gestione documentale

-   Gestione certificati con controllo scadenze

-   Interfaccia moderna con tema scuro/chiaro

🏗️ Architettura del Codice
---------------------------

Core Components
---------------

1\. SettingsManager
-------------------

python

`class  SettingsManager:    def  __init__(self, path: Path):   self.path = path  self.settings = self.load_settings()  `

-   Gestisce le impostazioni dell'applicazione (tema, logo, preferenze)

-   Salvataggio automatico in formato JSON

-   Caricamento con fallback ai valori predefiniti

2\. FornitoriDB
---------------

python

`class  FornitoriDB:    def  __init__(self, path: Path):   self.path = path  self.data =  {}   self.load_data()  `

-   Database JSON per la gestione fornitori

-   Funzioni CRUD complete (Create, Read, Update, Delete)

-   Ricerca avanzata per ragione sociale e codice fiscale

-   Aggiornamento certificati con validazione

3\. RentriREST
--------------

python

`class  RentriREST:    def  __init__(self, cfg:  dict):   self.p12 = cfg["p12"]   self.pwd = cfg["pwd"]   self._load_p12()  `

-   Client REST per le API RENTRI

-   Autenticazione JWT con certificati digitali

-   Rate limiting (90 richieste per 5 secondi)

-   Supporto algoritmi RS256 (RSA) ed ES256 (EC)

-   Gestione automatica retry per HTTP 429

API Integration
---------------

Autenticazione JWT
------------------

python

`def  _jwt_auth(self):   now = datetime.now(timezone.utc)   hdr =  {"alg": self.jwt_alg,  "typ":  "JWT",    "x5c":  [base64.b64encode(self.cert.public_bytes(Encoding.DER)).decode()]}   pay =  {"aud": AUDIENCE,  "iss": self.cf,  "sub": self.cf,    "iat":  int(now.timestamp()),  "nbf":  int(now.timestamp()),    "exp":  int((now+timedelta(minutes=5)).timestamp()),    "jti":  f"auth-{int(now.timestamp()*1000)}"}  `

Firma Digitale
--------------

python

`def  _jwt_sig(self, body:  bytes, ctype:  str):   dig = base64.b64encode(hashlib.sha256(body).digest()).decode()    # ... JWT payload con digest SHA-256  `

Threading & Workers
-------------------

1\. Worker (Vidimazione)
------------------------

-   Thread separato per operazioni lunghe

-   Comunicazione via `queue.Queue`

-   Progress tracking in tempo reale

-   Gestione errori robusta

2\. PDFDeliveryWorker
---------------------

-   Generazione stringhe serie per lettere di consegna

-   Estrazione automatica nomi file PDF

3\. PDFMergeWorker
------------------

-   Processamento e unione PDF

-   Duplicazione pagine (primi 2 fogli × 2)

-   Ordinamento automatico per numero progressivo

-   Cleanup file temporanei

UI Components
-------------

Modern Dashboard
----------------

python

`class  DashboardCard:    def  __init__(self, parent, title, value, color=None):   self.frame = ctk.CTkFrame(parent, height=120, fg_color=color or COLORS["card"])  `

Certificate Management
----------------------

python

`class  CertificateCard:    """Card speciale per mostrare informazioni del certificato"""    def  __init__(self, parent, title, cert_info, update_callback):    # Visualizzazione date emissione/scadenza    # Pulsante aggiornamento certificato    # Indicatore visuale scadenza  `

Progress Window
---------------

python

`class  ModernProgressWindow:    def  __init__(self, parent, title, fornitore_info):    # Finestra sempre in primo piano (topmost)    # Progress bar separate per vidimazioni e PDF    # Real-time status updates  `

🔧 Funzionalità Principali
--------------------------

📊 Dashboard
------------

-   Cards statistiche con contatori in tempo reale

-   Informazioni certificato con date di scadenza

-   Quick actions per operazioni comuni

-   Stato sistema con indicatori visivi

🏢 Gestione Fornitori
---------------------

-   Importazione automatica da certificati P12

-   Estrazione dati (ragione sociale, codice fiscale)

-   Ricerca in tempo reale con filtri avanzati

-   Aggiornamento certificati con validazione

✅ Vidimazione Automatizzata
---------------------------

1.  Selezione blocco FIR dalla lista disponibili

2.  Configurazione quantità da vidimare

3.  Scelta cartella destinazione PDF

4.  Processo automatico:

    -   Snapshot iniziale formulari

    -   POST vidimazioni multiple

    -   Attesa registrazione (8 secondi)

    -   Download PDF automatico

    -   Ordinamento per progressivo

🛠️ PDF Tools
-------------

Crea Lettera di Consegna
------------------------

python

`class  PDFDeliveryWorker:    def  run(self):   names =  [Path(p).stem for p in self.paths]   result =  "|".join(names)  `

-   Selezione multipla PDF

-   Generazione stringa serie separata da `|`

-   Output in textbox copiabile

Unisci FIR per Stampa
---------------------

python

`def  estrai_numero(self, filename):    """Estrae il numero dal nome del file con regex migliorata"""    match  = re.search(r'\b(\d{6})\b', filename)    if  match:    return  int(match.group(1))  `

-   Processamento batch PDF

-   Duplicazione pagine (per stampa fronte/retro)

-   Ordinamento numerico intelligente

-   Merge in singolo documento

⚙️ Impostazioni
---------------

-   Logo personalizzabile (testo + immagine)

-   Tema scuro/chiaro/sistema

-   Persistenza configurazioni

-   Reset impostazioni

🔐 Sicurezza
------------

Certificati Digitali
--------------------

-   Supporto P12/PKCS#12 con password

-   Algoritmi crittografici: RSA-2048+ e ECDSA

-   Validazione automatica certificati

-   Controllo scadenze con alerting visivo

API Security
------------

-   JWT Authentication conforme standard

-   Firma digitale richieste critiche

-   Rate limiting per compliance

-   Timeout configurabili (30s default)

💻 Tecnologie Utilizzate
------------------------

Core Libraries
--------------

-   CustomTkinter - UI moderna e responsive

-   cryptography - Gestione certificati e crittografia

-   PyJWT - Autenticazione JWT

-   requests - Client HTTP/REST

-   PyPDF2 - Manipolazione documenti PDF

-   Pillow (PIL) - Elaborazione immagini

Sistema Features
----------------

-   Threading per operazioni asincrone

-   Queue-based communication

-   JSON persistence per dati/settings

-   Cross-platform compatibility

🚀 Caratteristiche Avanzate
---------------------------

UI/UX Moderne
-------------

-   Avvio a schermo intero automatico

-   Finestre progress sempre in primo piano

-   Responsive design con grid layout

-   Color palette professionale

-   Hover effects e transizioni

Performance
-----------

-   Worker threads per UI non-bloccante

-   Progress tracking granulare

-   Memory efficient PDF processing

-   Automatic cleanup file temporanei

Robustezza
----------

-   Error handling completo su tutti i livelli

-   Retry logic per chiamate API

-   Input validation estensiva

-   Graceful degradation per errori non critici

📁 Struttura File
-----------------

text

`RENTRI_Manager/ ├── main.py              # Applicazione principale ├── fornitori.json       # Database fornitori ├── settings.json        # Impostazioni app ├── .pdfmerger/         # Cache PDF tools └── certificates/        # Certificati P12 (opzionale) `

🎯 Casi d'Uso Principali
------------------------

1.  Azienda di smaltimento rifiuti - Vidimazione automatizzata di centinaia di FIR

2.  Studio commercialista - Gestione multi-cliente con certificati separati

3.  Ente pubblico - Monitoraggio compliance e generazione reportistica

4.  Consulente ambientale - Supporto pratiche per più aziende clienti

* * * * *

RENTRI Manager rappresenta una soluzione completa, moderna e professionale per l'automazione dei processi RENTRI, progettata con focus su usabilità, sicurezza e performance.
