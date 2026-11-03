# MASTER TECHNICAL SPECIFICATION & PROJECT AGGREGATE
## Local VS Code Code Agent Security Architecture
### Declarative Packages (.agentpkg), Realms, Net-Rings & Cryptographic Gatekeeper

> **DOCUMENT STATUS**: ACTIVE LIVING SPECIFICATION  
> **CURRENT REVISION**: v1.2.0  
> **CLASSIFICATION**: System Architecture & Engineering Blueprint  
> **TARGET RUNTIME**: VS Code Extension (TypeScript / Node.js) & Gatekeeper Daemons (Python 3)

---

## 0. Regola Fondamentale di Manutenzione e Aggiornamento Continuo

> [!IMPORTANT]
> ### REGOLA AUREA DI GOVERNANCE (MANDATORY UPDATE RULE)
> Questo documento costituisce l'**unica fonte di verità tecnica aggregata** per l'intero progetto.
> In ogni iterazione, modifica, aggiunta di feature, refactoring o estensione dell'architettura:
> 
> 1. **Aggiornamento Contestuale Obbligatorio**: Ogni modifica al codice sorgente (TypeScript, Python, YAML, configurazioni) DEVE riflettersi immediatamente e nel minimo dettaglio all'interno di questo file.
> 2. **Nessuna Modifica Silenziosa**: È severamente vietato introdurre nuovi Tool, modificare i confini dei Realm, alterare le regole dei Net-Ring o cambiare gli algoritmi crittografici senza documentare la motivazione, la specifica tecnica e il codice d'esempio in questa specifica aggregata.
> 3. **Registro delle Modifiche**: Ogni iterazione deve incrementare il numero di versione e registrare la cronologia nella sezione *9. Changelog & Registro delle Revisioni*.
> 4. **Ispezionabilità nel Workbench**: Il contenuto di questa specifica deve rimanere sempre sincronizzato e accessibile sia a livello di filesystem che all'interno dell'interfaccia interattiva del workbench per la consultazione e il download immediato.

---

## 1. Executive Architectural Blueprint & Threat Model

### 1.1 Il Problema e il Threat Model
Gli agenti di codice locali eseguiti all'interno degli IDE (come le estensioni VS Code) possiedono privilegi operativi straordinariamente ampi:
- Accesso in lettura e scrittura all'intero albero di file dello workspace.
- Capacità di invocare comandi shell, build script e package manager.
- Accesso a socket di rete e connessioni verso API remote per l'inferenza dei modelli di fondazione.

Senza un'architettura di isolamento a compartimenti stagni, uno sviluppatore o un repository aperto può subire:
1. **Prompt Injection Egress Attacks**: comandi o commenti nel codice manipolano l'agente inducendolo a leggere file come `.env`, chiavi private SSH/TLS o token cloud e a trasmetterli via HTTP ad endpoint malevoli (C2).
2. **Untrusted Agent Extensions**: moduli di terze parti o estensioni non firmate che eseguono codice arbitrario simulando di essere strumenti di refactoring.
3. **Lateral Privilege Escalation nello Workspace**: un agente autorizzato a modificare componenti UI che riscrive file di infrastruttura critica (`Dockerfile`, pipeline CI/CD, script Terraform) alterando la security posture del cluster.

### 1.2 I 4 Pilastri di Difesa in Profondità (Defense-in-Depth)
La soluzione adotta una separazione rigorosa dei privilegi basata su 4 strati invalicabili:
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       STRATO 1: CODE SIGNING & GATEKEEPER                  │
│  - Verifica della firma crittografica asimmetrica Ed25519 (RFC 8032).       │
│  - Calcolo del digest SHA-256 del manifesto canonico.                       │
│  - Rifiuto immediato e blocco dell'agente se il pacchetto è manomesso.      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       STRATO 2: WORKSPACE REALM PARTITIONING                │
│  - Mappatura deterministica del percorso del file attivo tramite globbing.  │
│  - Assegnazione del file a un Realm di sicurezza (es. secrets vs domain).    │
│  - Context Scrubbing automatico per mascherare credenziali e token.         │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       STRATO 3: TOOL CAPABILITY MATRIX                      │
│  - Matrice rigorosa dei tool ammessi per ciascun Realm.                      │
│  - Privilegio minimo: nel Realm secrets zero tool; in infra solo format/lint│
│  - Rilevamento e blocco istantaneo di tool distruttivi non autorizzati.     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       STRATO 4: TIERED NET-RING FIREWALL PROXY              │
│  - Isolamento della rete a 4 anelli concentrici (Ring 0 -> Ring 3).          │
│  - Ring 0: Air-Gapped (zero rete, zero socket, blocco loopback).             │
│  - Ring 1: Local IPC (esclusivamente localhost:8000 / 127.0.0.1 / socket).  │
│  - Ring 2: Whitelisted Model APIs (esclusivamente OpenAI, Anthropic, Gemini) │
│  - Ring 3: Open Egress con tracciamento obbligatorio degli audit log.        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Specifica Dichiarativa del Pacchetto (`agent-package.yaml`)

Il pacchetto dell'agente (distribuibile come archivio `.agentpkg` o cartella manifest) contiene al suo interno il file `agent-package.yaml` e la firma distaccata `agent-package.sig`.

### 2.1 Struttura del Manifesto Canonico
```yaml
name: "com.acme.secure-coder"
version: "1.2.0"
author: "Acme Security Engineering <security@acme.corp>"
description: "Declarative security specification for local VS Code coding agent with Realm and Net-Ring isolation"
signature_algorithm: "Ed25519"
public_key_fingerprint: "SHA256:7e98bf02419a4d85eec5b9aa4f02888cf3bfcf9b71f9a15233ea19f074dcb54a"

net_rings:
  ring_0:
    name: "Ring 0 (Isolated / Air-Gapped)"
    tier: 0
    description: "Strict isolation. Zero network calls, zero sockets, no DNS lookups, no loopback."
    allowed_hosts: []
    allow_loopback: false
    tls_required: true
    max_payload_bytes: 0

  ring_1:
    name: "Ring 1 (Local IPC / Loopback)"
    tier: 1
    description: "Permits communication exclusively with local development daemons and test servers."
    allowed_hosts:
      - "localhost"
      - "127.0.0.1"
      - "::1"
      - "unix://*"
    allow_loopback: true
    tls_required: false
    max_payload_bytes: 10485760 # 10MB

  ring_2:
    name: "Ring 2 (Whitelisted Model & API Egress)"
    tier: 2
    description: "Strictly pinned egress to authorized foundation model APIs and verified package indexes."
    allowed_hosts:
      - "api.openai.com"
      - "api.anthropic.com"
      - "generativelanguage.googleapis.com"
      - "registry.npmjs.org"
      - "ai-gateway.acme-corp.internal"
    allow_loopback: false
    tls_required: true
    max_payload_bytes: 5242880 # 5MB
    rate_limit_per_minute: 120

  ring_3:
    name: "Ring 3 (Unrestricted Egress)"
    tier: 3
    description: "Full outbound network access. Requires mandatory audit logging and human supervisor notice."
    allowed_hosts:
      - "*"
    allow_loopback: true
    tls_required: true
    max_payload_bytes: 52428800 # 50MB
    requires_audit_trail: true

realms:
  secrets:
    id: "realm-secrets"
    name: "Restricted Secrets & Credentials"
    description: "Air-gapped realm. Contains sensitive tokens, env files, and private keys. All agent tools are disabled."
    paths:
      - "**/.env*"
      - "**/secrets/**"
      - "**/certs/**"
      - "**/*.pem"
      - "**/*.key"
      - "**/*.pfx"
    net_ring: "ring_0"
    allowed_tools: []
    blocked_tools:
      - "*"
    require_user_confirmation: true
    context_scrubbing:
      enabled: true
      mask_pattern: "REDACTED_SECRET"

  infrastructure:
    id: "realm-infra"
    name: "Infrastructure & Orchestration"
    description: "Container, CI/CD, and Cloud deployment configurations. Read-only inspection allowed; writes require approval."
    paths:
      - "**/docker-compose*.yml"
      - "**/Dockerfile*"
      - "**/infra/**"
      - "**/terraform/**"
      - "**/k8s/**"
      - "**/.github/workflows/**"
    net_ring: "ring_1"
    allowed_tools:
      - "fs_read"
      - "terraform_fmt"
      - "docker_lint"
      - "security_audit"
    blocked_tools:
      - "fs_write_destructive"
      - "shell_exec_root"
    require_user_confirmation: true
    context_scrubbing:
      enabled: false

  business_logic:
    id: "realm-business-logic"
    name: "Core Business & Domain Logic"
    description: "Application source code. Permits AI code refactoring and test generation via whitelisted Model APIs."
    paths:
      - "src/domain/**"
      - "src/services/**"
      - "src/models/**"
      - "src/core/**"
      - "lib/**"
    net_ring: "ring_2"
    allowed_tools:
      - "fs_read"
      - "fs_write"
      - "code_refactor"
      - "ast_analyze"
      - "unit_test_gen"
      - "llm_generate"
      - "lint"
    blocked_tools:
      - "shell_exec"
      - "network_raw_socket"
    require_user_confirmation: false
    context_scrubbing:
      enabled: false

  presentation_and_api:
    id: "realm-presentation"
    name: "Presentation & Public API"
    description: "Controllers, routes, and UI components. Full interactive editing and formatting allowed."
    paths:
      - "src/controllers/**"
      - "src/routes/**"
      - "src/views/**"
      - "src/components/**"
      - "src/pages/**"
    net_ring: "ring_2"
    allowed_tools:
      - "fs_read"
      - "fs_write"
      - "lint"
      - "prettier_format"
      - "api_doc_gen"
      - "llm_generate"
    blocked_tools:
      - "shell_exec_privileged"
    require_user_confirmation: false
    context_scrubbing:
      enabled: false

  test_sandbox:
    id: "realm-test"
    name: "Test Suite & Sandbox"
    description: "Integration and unit test suites. Local loopback permitted for running test fixtures."
    paths:
      - "tests/**"
      - "**/*.spec.ts"
      - "**/*.test.ts"
      - "**/__tests__/**"
    net_ring: "ring_1"
    allowed_tools:
      - "fs_read"
      - "fs_write"
      - "test_runner"
      - "coverage_reporter"
      - "llm_generate"
    blocked_tools:
      - "network_raw_socket"
    require_user_confirmation: false
    context_scrubbing:
      enabled: false

tools:
  - name: "fs_read"
    description: "Reads file content within workspace boundaries"
    risk_level: "low"
    requires_ring: "ring_0"

  - name: "fs_write"
    description: "Writes or patches an existing file within authorized Realm"
    risk_level: "medium"
    requires_ring: "ring_0"

  - name: "code_refactor"
    description: "AST-based semantic code restructuring"
    risk_level: "low"
    requires_ring: "ring_0"

  - name: "llm_generate"
    description: "Dispatches inference request to Foundation Model API"
    risk_level: "high"
    requires_ring: "ring_2"

  - name: "test_runner"
    description: "Executes test runner against local test harness"
    risk_level: "medium"
    requires_ring: "ring_1"

  - name: "shell_exec"
    description: "Spawns terminal shell command in workspace root"
    risk_level: "critical"
    requires_ring: "ring_3"
```

---

## 3. Sottosistema Gatekeeper Crittografico & Code Signing (Ed25519)

### 3.1 Algoritmo e Specifiche Crittografiche
- **Algoritmo di Firma**: Ed25519 conforme a **RFC 8032** su curva Edwards `Curve25519` ($p = 2^{255} - 19$).
- **Digest Canonico**: SHA-256 calcolato sui byte esatti UTF-8 del file `agent-package.yaml`.
- **Firma Distaccata**: 64 byte crittografici rappresentati in 128 caratteri esadecimali (`agent-package.sig`).
- **Chiavi Asimmetriche**: 
  - Chiave Privata (32 byte seed / PEM formattato PKCS#8).
  - Chiave Pubblica (32 byte compressi / PEM formattato SubjectPublicKeyInfo).

### 3.2 Modulo Python `python-gatekeeper/gatekeeper.py`
Questo modulo agisce da guardiano pre-caricamento:
- Carica la chiave pubblica PEM fidata.
- Calcola l'hash SHA-256 dei byte ricevuti.
- Esegue la verifica crittografica su curva ellittica tramite `ed25519_pure.py` o la libreria C `cryptography`.
- Se la firma non corrisponde (anche per la modifica di un singolo spazio o commento), genera un verdetto `BLOCKED` con codice di uscita `2`, impedendo all'orchestrator di caricare il pacchetto.

### 3.3 Utility di Generazione e Firma `python-gatekeeper/keygen.py`
Fornisce il comando di packaging:
```bash
python3 python-gatekeeper/keygen.py
```
1. Genera un seed crittografico casuale sicuro (`os.urandom(32)`).
2. Deriva la chiave pubblica Ed25519 punto su curva $A = s \cdot B$.
3. Firma il manifesto calcolando lo scalare effimero deterministico $r = H(h_b \dots h_{2b-1} \parallel M)$ e $S = (r + H(R \parallel A \parallel M) \cdot s) \pmod l$.
4. Scrive su disco `public_key.pem`, `private_key.pem` e `agent-package.sig`.

### 3.4 Modulo TypeScript Browser-Compatible `src/security/crypto-verifier.ts`
Implementa la medesima verifica tramite la **Web Crypto API** nativa (`crypto.subtle.verify('Ed25519', ...)`), permettendo al workbench di eseguire audit e simulare tentativi di manomissione interattivi in tempo reale senza dipendenze backend.

---

## 4. Sottosistema Realm: Partizione dei File & Risoluzione Tool

### 4.1 Logica di Glob Matching (`src/security/realm-engine.ts`)
Il motore accetta in input l'URI relativo o assoluto del documento aperto in VS Code e lo normalizza (gestione barre Unix/Windows):
1. Itera su ciascun Realm configurato nel manifesto.
2. Esegue il confronto tramite espressione regolare derivata da glob patterns (`**`, `*`, `?`).
3. Appena riscontra un match univoco, restituisce l'oggetto `RealmConfig`.
4. **Fallback Isolato (Fail-Secure)**: Se un file non corrisponde a nessun pattern (ad esempio un file arbitrario appena creato), il motore non consente privilegi predefiniti, ma lo assegna a `realm-unmapped-isolated` (bloccato in Ring 0 senza tool).

### 4.2 Tabella Matrice delle Autorizzazioni
| Realm ID | Nome Descrizione | Net-Ring | Tool Ammessi | Tool Bloccati | Approvazione Umana |
|---|---|:---:|---|---|:---:|
| `secrets` | Restricted Secrets & Credentials | **Ring 0** | *Nessuno (0)* | `*` (Tutti) | **Sì (Blocco)** |
| `infrastructure` | Infrastructure & Orchestration | **Ring 1** | `fs_read`, `terraform_fmt`, `docker_lint`, `security_audit` | `fs_write_destructive`, `shell_exec_root` | **Sì** |
| `business_logic` | Core Domain Logic | **Ring 2** | `fs_read`, `fs_write`, `code_refactor`, `unit_test_gen`, `llm_generate`, `lint` | `shell_exec`, `network_raw_socket` | **No** |
| `presentation` | Presentation & Public API | **Ring 2** | `fs_read`, `fs_write`, `lint`, `prettier_format`, `api_doc_gen`, `llm_generate` | `shell_exec_privileged` | **No** |
| `test_sandbox` | Test Suite & Sandbox | **Ring 1** | `fs_read`, `fs_write`, `test_runner`, `coverage_reporter`, `llm_generate` | `network_raw_socket` | **No** |
| *unmapped* | Fallback non classificato | **Ring 0** | `fs_read` | `*` | **Sì** |

### 4.3 Context Scrubbing (Sanificazione delle Credenziali)
Nel Realm `secrets`, la funzione `scrubContent(realm, text)` intercetta sia i file sia i prompt dello sviluppatore prima di inoltrarli al motore di inferenza, sostituendo chiavi API, token JWT, password e blocchi PEM con token di redazione `[REDACTED_SECRET]`.

---

## 5. Sottosistema Net-Ring: Firewall di Rete & Proxy Mock

### 5.1 Definizione dei Livelli di Rete (Rings 0 - 3)
```
     [ Ring 3: Unrestricted Egress (*.internet.org) ]
             ▲
             │
     [ Ring 2: Whitelisted Model APIs (api.openai.com, etc.) ]
             ▲
             │
     [ Ring 1: Localhost / IPC Loopback (127.0.0.1:8000) ]
             ▲
             │
     [ Ring 0: Air-Gapped / Isolated (Zero Network, Zero Sockets) ]
```

### 5.2 Algoritmo di Decisione del Proxy (`net_ring_proxy.py` & `net-ring-guard.ts`)
Quando un agente o un tool tenta di effettuare una richiesta verso un endpoint (`target_url`):
1. **Verifica della Firma**: Se `is_signed == False`, il proxy risponde con HTTP 403 `ERR_UNSIGNED_MODULE`.
2. **Controllo Ring 0**: Se `tier == 0`, il proxy risponde immediatamente con HTTP 403 `ERR_RING0_AIRGAP_VIOLATION`. Nessun socket può essere aperto.
3. **Controllo Loopback**: Se l'host di destinazione è `localhost`, `127.0.0.1` o `::1`:
   - Se `ring.allow_loopback == True` $\rightarrow$ Consentito (HTTP 200).
   - Altrimenti $\rightarrow$ HTTP 403 `ERR_LOOPBACK_PROHIBITED`.
4. **Controllo Ring 3**: Se `tier >= 3` o `allowed_hosts` include `*` $\rightarrow$ Consentito (HTTP 200) con audit log.
5. **Controllo Whitelist Ring 2**: Confronta l'host con la lista degli host esatti o dei pattern wildcard (`*.dominio.com`):
   - Se corrisponde $\rightarrow$ Consentito (HTTP 200).
   - Se non corrisponde $\rightarrow$ Bloccato con HTTP 403 `ERR_HOST_NOT_WHITELISTED`.

---

## 6. Runtime Engine per Estensione VS Code (`orchestrator.ts`)

L'orchestrator è il componente software principale residente nel processo dell'estensione VS Code. Intercetta ogni prompt dell'utente o richiesta di azione dell'agente tramite l'interfaccia:
```typescript
interface InterceptRequest {
  fileUri: string;
  prompt: string;
  requestedTool: string;
  egressUrl?: string;
  packageSigned?: boolean;
}
```

### 6.1 Pipeline di Intercettazione a 4 Fasi
```
Richiesta Intercettata
       │
       ▼
[FASE 1: Gatekeeper Check] ──(Firma Non Valida?)──> BLOCKED (ERR_UNSIGNED_MODULE)
       │ Passa
       ▼
[FASE 2: Risoluzione Realm] ──> Match Glob Path & Context Scrubbing
       │ Passa
       ▼
[FASE 3: Tool Capability Check] ──(Tool Non Ammesso?)──> BLOCKED (ERR_TOOL_DENIED)
       │ Passa
       ▼
[FASE 4: Net-Ring Egress Guard] ──(Host Fuori Whitelist?)──> BLOCKED (ERR_RING_VIOLATION)
       │ Passa
       ▼
[Verifica Approvazione Umana] ──(Richiede Conferma?)──> REQUIRES_USER_APPROVAL
       │ No
       ▼
VERDETTO: ALLOWED (Esecuzione autorizzata)
```

Ogni verdetto include:
- `verdict`: `ALLOWED` | `BLOCKED` | `REQUIRES_USER_APPROVAL`.
- `primaryReason`: spiegazione testuale chiara del motivo decisionale.
- `steps`: array sequenziale delle 4 verifiche con esito booleano (`PASS`/`FAIL`) e dettagli diagnostici.
- `scrubbedPrompt`: versione sanificata del prompt priva di credenziali.

---

## 7. Suite di Verifica, Test Automatizzati e Guida Locale

### 7.1 Esecuzione della Suite di Test Python
Il file `python-gatekeeper/test_gatekeeper.py` implementa 7 test unitari esaustivi che verificano l'intera pipeline di sicurezza crittografica e di rete:
```bash
python3 python-gatekeeper/test_gatekeeper.py
```
Output atteso:
```
.......
----------------------------------------------------------------------
Ran 7 tests in 4.233s

OK
```

Casi di test coperti:
1. `test_01_valid_manifest_signature`: Attesta che la firma autentica Ed25519 è valida e restituisce `PERMITTED`.
2. `test_02_tampered_manifest_rejection`: Attesta che alterare anche un solo byte del file `.yaml` genera `BLOCKED`.
3. `test_03_invalid_signature_hex`: Gestione sicura di stringhe firma esadecimali corrotte o malformate.
4. `test_04_ring_0_airgap_blocks_network`: Verifica il blocco di qualsiasi socket nel Realm `secrets`.
5. `test_05_ring_1_permits_localhost_blocks_public`: Verifica che Ring 1 accetti `localhost` e rifiuti `api.github.com`.
6. `test_06_ring_2_permits_whitelisted_apis`: Verifica che Ring 2 consenta OpenAI e Gemini ma blocchi domini non in whitelist.
7. `test_07_unsigned_module_is_blocked_immediately`: Verifica il blocco immediato di qualsiasi modulo privo di firma valida.

### 7.2 CLI del Gatekeeper e del Proxy
```bash
# Esecuzione verifica del pacchetto
python3 python-gatekeeper/gatekeeper.py

# Esecuzione simulazione del proxy di rete
python3 python-gatekeeper/net_ring_proxy.py
```

### 7.3 Suite di Audit Interattiva nel Workbench Web
All'interno del browser è integrato un pulsante **"Run All Tests"** che riesegue i 6 scenari di attacco e conformità in memoria, verificando in tempo reale la risposta dell'Orchestrator TypeScript su file di esempio.

---

## 8. Inventario Completo dei Componenti e File

| Percorso File | Linguaggio | Scopo e Responsabilità Architetturale |
|---|:---:|---|
| `/PROJECT_MASTER_DOCUMENT.md` | Markdown | **Living Document**: Specifica tecnica aggregata e regola aurea di manutenzione del progetto. |
| `/agent-spec/agent-package.yaml` | YAML | Manifesto dichiarativo del pacchetto dell'agente (Realms, Net-Rings, Tools). |
| `/agent-spec/agent-package.sig` | Esadecimale | Firma digitale distaccata Ed25519 (64 byte) calcolata sul manifesto. |
| `/agent-spec/public_key.pem` | PEM | Chiave pubblica Ed25519 per verificare l'autenticità del pacchetto. |
| `/agent-spec/private_key.pem` | PEM | Chiave privata Ed25519 per il firmatario autorizzato del pacchetto. |
| `/python-gatekeeper/gatekeeper.py` | Python 3 | Modulo per verifica integrità del pacchetto e firma Ed25519. |
| `/python-gatekeeper/net_ring_proxy.py` | Python 3 | Proxy mock per filtro traffico in uscita ed esecuzione dei Net-Rings 0-3. |
| `/python-gatekeeper/keygen.py` | Python 3 | Script per generare nuove coppie di chiavi Ed25519 e firmare il manifesto. |
| `/python-gatekeeper/ed25519_pure.py` | Python 3 | Implementazione autonoma Ed25519 RFC 8032 a zero dipendenze C. |
| `/python-gatekeeper/test_gatekeeper.py` | Python 3 | Test runner per l'esecuzione dei 7 test unitari del gatekeeper e del proxy. |
| `/src/security/types.ts` | TypeScript | Definizioni dei tipi per Manifest, NetRing, Realm, Tool e Verdetto Orchestrator. |
| `/src/security/manifest-parser.ts` | TypeScript | Parser YAML per caricare e validare strutturalmente `agent-package.yaml`. |
| `/src/security/realm-engine.ts` | TypeScript | Risolutore Realm basato su globbing dei percorsi e sanificazione dei dati. |
| `/src/security/net-ring-guard.ts` | TypeScript | Valutatore regole firewall di rete per i Net-Rings da 0 a 3. |
| `/src/security/crypto-verifier.ts` | TypeScript | Modulo di verifica crittografica Web Crypto e calcolo hash SHA-256 in browser. |
| `/src/security/default-data.ts` | TypeScript | Costanti incorporate con i dati del manifesto canonico e chiavi Ed25519. |
| `/src/extension/orchestrator.ts` | TypeScript | Orchestrator dell'estensione VS Code per intercettazione richieste a 4 fasi. |
| `/src/extension/sample-workspace.ts` | TypeScript | Workspace virtuale contenente file tipici (`.env`, `payment.ts`, `main.tf`, `certs`). |
| `/src/components/TopBar.tsx` | React / TSX | Barra superiore a 3 zone conforme alla disciplina architetturale Top Bar Contract. |
| `/src/components/IdeSimulator.tsx` | React / TSX | Simulatore visivo dell'IDE VS Code con file tree, editor e telemetria live. |
| `/src/components/PolicyMatrix.tsx` | React / TSX | Mappa visiva dei 4 Ring e 5 Realm con tester di policy interattivo. |
| `/src/components/GatekeeperLab.tsx` | React / TSX | Laboratorio crittografico con simulazione manomissione e calcolo hash real-time. |
| `/src/components/SourceCodeViewer.tsx`| React / TSX | Esploratore codice sorgente con visualizzazione documentazione e download. |
| `/src/App.tsx` | React / TSX | Root component con navigazione a schede e modale per la suite di audit. |

---

## 9. Changelog & Registro delle Revisioni

### Versione 1.2.0 (Baseline Aggregata Ufficiale)
- **Creazione Living Document**: Istituita la regola di governance per la documentazione tecnica obbligatoria e continua del progetto in `/PROJECT_MASTER_DOCUMENT.md`.
- **Implementazione Motore Crittografico Ed25519**: Sviluppati moduli `keygen.py`, `gatekeeper.py`, e `ed25519_pure.py` RFC 8032 nativi Python a zero dipendenze esterne.
- **Implementazione Proxy Mock Net-Ring**: Sviluppato `net_ring_proxy.py` con 4 livelli di isolamento (Ring 0 Airgap, Ring 1 Loopback, Ring 2 Whitelist, Ring 3 Unrestricted).
- **Suite di Test Python**: Creata suite con 7/7 casi di test unitari con esito superato.
- **Estensione VS Code Orchestrator (TypeScript)**: Sviluppati `orchestrator.ts`, `realm-engine.ts`, `net-ring-guard.ts`, `manifest-parser.ts`, e `crypto-verifier.ts`.
- **Workbench Grafico Completo**: Integrati simulatore VS Code, matrice visiva delle policy, laboratorio crittografico interattivo e visualizzatore sorgenti con download.
