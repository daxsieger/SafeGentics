/**
 * Master Technical Specification Document Content.
 * Sourced from PROJECT_MASTER_DOCUMENT.md.
 */

export const PROJECT_MASTER_DOCUMENT_CONTENT = `# MASTER TECHNICAL SPECIFICATION & PROJECT AGGREGATE
## Local VS Code Code Agent Security Architecture
### Declarative Packages (.agentpkg), Realms, Net-Rings & Cryptographic Gatekeeper

> **DOCUMENT STATUS**: ACTIVE LIVING SPECIFICATION  
> **CURRENT REVISION**: v1.2.0  
> **CLASSIFICATION**: System Architecture & Engineering Blueprint  
> **TARGET RUNTIME**: VS Code Extension (TypeScript / Node.js) & Gatekeeper Daemons (Python 3)

---

## 0. Regola Fondamentale di Manutenzione e Aggiornamento Continuo

### REGOLA AUREA DI GOVERNANCE (MANDATORY UPDATE RULE)
Questo documento costituisce l'unica fonte di verità tecnica aggregata per l'intero progetto.
In ogni iterazione, modifica, aggiunta di feature, refactoring o estensione dell'architettura:

1. **Aggiornamento Contestuale Obbligatorio**: Ogni modifica al codice sorgente (TypeScript, Python, YAML, configurazioni) DEVE riflettersi immediatamente e nel minimo dettaglio all'interno di questo file.
2. **Nessuna Modifica Silenziosa**: È severamente vietato introdurre nuovi Tool, modificare i confini dei Realm, alterare le regole dei Net-Ring o cambiare gli algoritmi crittografici senza documentare la motivazione, la specifica tecnica e il codice d'esempio in questa specifica aggregata.
3. **Registro delle Modifiche**: Ogni iterazione deve incrementare il numero di versione e registrare la cronologia nella sezione 9. Changelog & Registro delle Revisioni.
4. **Ispezionabilità nel Workbench**: Il contenuto di questa specifica deve rimanere sempre sincronizzato e accessibile sia a livello di filesystem che all'interno dell'interfaccia interattiva del workbench per la consultazione e il download immediato.

---

## 1. Executive Architectural Blueprint & Threat Model

### 1.1 Il Problema e il Threat Model
Gli agenti di codice locali eseguiti all'interno degli IDE (come le estensioni VS Code) possiedono privilegi operativi straordinariamente ampi:
- Accesso in lettura e scrittura all'intero albero di file dello workspace.
- Capacità di invocare comandi shell, build script e package manager.
- Accesso a socket di rete e connessioni verso API remote per l'inferenza dei modelli di fondazione.

Senza un'architettura di isolamento a compartimenti stagni, uno sviluppatore o un repository aperto può subire:
1. **Prompt Injection Egress Attacks**: comandi o commenti nel codice manipolano l'agente inducendolo a leggere file come .env, chiavi private SSH/TLS o token cloud e a trasmetterli via HTTP ad endpoint malevoli (C2).
2. **Untrusted Agent Extensions**: moduli di terze parti o estensioni non firmate che eseguono codice arbitrario simulando di essere strumenti di refactoring.
3. **Lateral Privilege Escalation nello Workspace**: un agente autorizzato a modificare componenti UI che riscrive file di infrastruttura critica (Dockerfile, pipeline CI/CD, script Terraform) alterando la security posture del cluster.

### 1.2 I 4 Pilastri di Difesa in Profondità (Defense-in-Depth)
1. **Strato 1: Code Signing & Gatekeeper**: Verifica della firma crittografica asimmetrica Ed25519 (RFC 8032) e digest SHA-256 del manifesto canonico. Rifiuto immediato se il pacchetto è manomesso.
2. **Strato 2: Workspace Realm Partitioning**: Mappatura deterministica del percorso del file attivo tramite globbing a un Realm di sicurezza (es. secrets vs domain). Context Scrubbing automatico per mascherare credenziali.
3. **Strato 3: Tool Capability Matrix**: Matrice rigorosa dei tool ammessi per ciascun Realm. Nel Realm secrets zero tool; in infra solo format/lint.
4. **Strato 4: Tiered Net-Ring Firewall Proxy**: Isolamento della rete a 4 anelli concentrici (Ring 0 -> Ring 3).

---

## 2. Specifica Dichiarativa del Pacchetto (agent-package.yaml)
- **ID Pacchetto**: com.acme.secure-coder
- **Versione**: 1.2.0
- **Algoritmo di Firma**: Ed25519
- **Net-Rings Definiti**:
  - Ring 0: Isolated / Air-Gapped (zero network, zero socket, blocco loopback)
  - Ring 1: Local IPC / Loopback (localhost, 127.0.0.1, ::1, unix://*)
  - Ring 2: Whitelisted Model & API Egress (api.openai.com, api.anthropic.com, generativelanguage.googleapis.com, registry.npmjs.org)
  - Ring 3: Unrestricted Egress (* con audit trail obbligatorio)
- **Realms Definiti**:
  - secrets (**/.env*, **/secrets/**, **/certs/**) -> Ring 0, zero tools, Context Scrubbing abilitato
  - infrastructure (**/docker-compose*.yml, **/Dockerfile*, **/infra/**, **/terraform/**) -> Ring 1, tools: fs_read, terraform_fmt, docker_lint
  - business_logic (src/domain/**, src/services/**, src/models/**) -> Ring 2, tools: fs_read, fs_write, code_refactor, ast_analyze, unit_test_gen, llm_generate, lint
  - presentation_and_api (src/controllers/**, src/routes/**, src/views/**) -> Ring 2, tools: fs_read, fs_write, lint, prettier_format, api_doc_gen, llm_generate
  - test_sandbox (tests/**, **/*.spec.ts, **/*.test.ts) -> Ring 1, tools: fs_read, fs_write, test_runner, coverage_reporter, llm_generate
  - unmapped_isolated (fallback predefinito per qualsiasi file non riconosciuto) -> Ring 0

---

## 3. Sottosistema Gatekeeper Crittografico (Ed25519)
- **Firma Asimmetrica**: 64 byte (128 caratteri esadecimali) calcolati con Ed25519 (RFC 8032).
- **Verifica Byte-by-Byte**: Il Gatekeeper (gatekeeper.py in Python e crypto-verifier.ts nel browser) calcola il digest SHA-256 canonico e verifica la firma prima che qualsiasi tool o file venga elaborato.
- **Rilevamento Manomissioni**: Qualsiasi modifica anche di un singolo byte provoca un errore crittografico immediato che blocca l'esecuzione dell'agente.

---

## 4. Sottosistema Proxy Mock di Rete Net-Ring (net_ring_proxy.py)
- Intercetta le richieste di uscita HTTP/HTTPS dell'agente.
- Estrae il Realm chiamante e determina il Ring attivo (0, 1, 2, 3).
- Blocca istantaneamente le chiamate di rete nel Ring 0 con HTTP 403 ERR_RING0_AIRGAP_VIOLATION.
- Blocca gli host non inclusi nella whitelist nel Ring 2 con HTTP 403 ERR_HOST_NOT_WHITELISTED.

---

## 5. VS Code Extension Orchestrator (orchestrator.ts)
Esegue la pipeline di valutazione sequenziale a 4 stadi:
1. Verifica Gatekeeper (Firma Ed25519 valida?)
2. Risoluzione Realm tramite Glob matching sul percorso del file attivo
3. Controllo autorizzazione Tool rispetto al Realm
4. Controllo firewall Net-Ring rispetto alla destinazione di rete
Emesso verdetto: ALLOWED, BLOCKED, o REQUIRES_USER_APPROVAL.

---

## 6. Test Suite e Risultati Esecuzione Locale
I 7 casi di test automatizzati eseguiti in python-gatekeeper/test_gatekeeper.py:
- test_01_valid_manifest_signature: PASSED
- test_02_tampered_manifest_rejection: PASSED
- test_03_invalid_signature_hex: PASSED
- test_04_ring_0_airgap_blocks_network: PASSED
- test_05_ring_1_permits_localhost_blocks_public: PASSED
- test_06_ring_2_permits_whitelisted_apis: PASSED
- test_07_unsigned_module_is_blocked_immediately: PASSED
Tutti i 7 test superati con successo in 4.23s.
`;
