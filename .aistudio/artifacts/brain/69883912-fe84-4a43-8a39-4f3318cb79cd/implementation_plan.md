# Local VS Code Code Agent Security Architecture
## Declarative Packages (.agentpkg), Realms, Net-Rings & Cryptographic Gatekeeper

This architecture delivers a local, secure-by-design coding agent framework for VS Code. It enforces strict privilege separation through declarative agent manifest specifications, workspace Realm boundary isolation, tiered Net-Ring network controls, and Ed25519 cryptographic code signing with a dedicated verification gatekeeper and network proxy.

---

### User Review & Critical Decisions

> [!IMPORTANT]
> The following architectural parameters have been confirmed based on the initial interview and are established as the foundational specifications:

- **Delivery & Verification Mode**: Interactive visual workbench featuring a live VS Code-style extension simulator, interactive policy auditor/tester, real-time request interceptor, and a code & file-tree viewer with direct file export.
- **Cryptographic Signing Protocol**: Asymmetric Ed25519 digital signatures with detached signature verification (`manifest.sig`), SHA-256 digest validation over the canonical manifest, and tamper detection.
- **Net-Ring Hierarchy**: Flexible, user-definable rings defaulting to a standard 4-tier model:
  - **Ring 0 (Isolated / Air-Gapped)**: Purely local computation, zero network I/O, no socket or loopback access.
  - **Ring 1 (Local IPC / Loopback)**: Local daemon/debug server communication (e.g. `localhost:8000`, Unix domain sockets).
  - **Ring 2 (Whitelisted Model & API Egress)**: Explicitly pinned egress endpoints (e.g. OpenAI/Anthropic/Gemini endpoints or private corporate AI gateways) with host and TLS validation.
  - **Ring 3 (Unrestricted Egress)**: Full network access, strictly reserved for vetted public package management or documentation scrapers.
- **Workspace Realms**: Fine-grained path globbing that partitions projects into security domains (e.g., `CoreBusinessLogic`, `Infrastructure`, `PublicPresentation`, `RestrictedSecrets`), binding specific tools and Net-Rings per realm.

---

### 1. Overview & Core Concept

Local AI coding agents in IDEs possess extensive file system and shell execution privileges. Without strict structural boundaries, a prompt injection or untrusted agent module can read private environment variables, leak source code over network sockets, or modify infrastructure configs.

This solution introduces four defensive pillars:
1. **Declarative Package Specification (`agent-package.yaml` / `manifest.yaml`)**: An immutable, structured contract defining agent identity, declared capabilities, assigned Realms, allowed Tools per Realm, and required Net-Ring levels.
2. **Cryptographic Gatekeeper (Python Service / Daemon)**: Verifies the integrity and authenticity of the `.agentpkg` before loading. Any unsigned package or modified manifest is blocked before execution.
3. **Realm Isolation Engine (TypeScript VS Code Orchestrator)**: Maps every active file and user request to its authorized Realm. If an agent tries to apply a file modification or invoke a tool outside the file's Realm boundary, the runtime aborts the operation.
4. **Net-Ring Network Guard & Egress Proxy (Python Mock Server)**: Intercepts all outgoing model API calls and tool network requests, validating that the target endpoint complies with the Realm's active Net-Ring rule.

---

### 2. System Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            VS Code Host Environment                         │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                     User / Developer Interaction                    │   │
│   │        (Chat Prompt, Inline Completion, Quick Fix, File Edit)       │   │
│   └──────────────────────────────────┬──────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │          Runtime Engine & Orchestrator (TypeScript / VS Code)       │   │
│   │                                                                     │   │
│   │  1. Parse Active Document URI & Context                             │   │
│   │  2. Map File Path -> Realm Registry                                 │   │
│   │  3. Lookup Realm Policy (Allowed Tools, Required Net-Ring)          │   │
│   │  4. Evaluate Proposed Agent Action (Read/Write/Exec/Egress)         │   │
│   └───────────────┬─────────────────────────────────┬───────────────────┘   │
└───────────────────┼─────────────────────────────────┼───────────────────────┘
                    │                                 │
                    ▼                                 ▼
┌───────────────────────────────────────┐ ┌───────────────────────────────────┐
│     Manifest & Package Engine (TS)    │ │   Gatekeeper & Proxy Daemon (PY)  │
│                                       │ │                                   │
│  - Reads `agent-package.yaml`         │ │  1. Cryptographic Gatekeeper      │
│  - Validates Schema & Ring Levels     │ │     - Ed25519 Signature Checker   │
│  - Computes Manifest Digest           │ │     - Digest & Tamper Detection   │
│  - Builds Runtime Policy Cache        │ │  2. Net-Ring Proxy & Egress Guard │
│  - Exports `.agentpkg` Archive Specs  │ │     - Ring 0-3 Rule Verification  │
│                                       │ │     - Block unauthorized sockets  │
└───────────────────────────────────────┘ └───────────────────────────────────┘
```

---

### 3. File & Directory Layout

The codebase will provide a clean, production-grade layout separating the TypeScript extension runtime, the Python cryptographic gatekeeper & proxy, and the interactive visual workbench:

```
├── agent-spec/
│   ├── agent-package.yaml            # Complete declarative package manifest
│   ├── agent-package.sig             # Detached Ed25519 signature
│   └── public_key.pem                # Public key for package signature verification
│
├── src/
│   ├── security/
│   │   ├── manifest-parser.ts        # Parser & validator for manifest.yaml / .agentpkg
│   │   ├── realm-engine.ts           # Realm matcher, path globbing & boundary enforcement
│   │   ├── net-ring-guard.ts         # Net-Ring policy evaluator & permission resolver
│   │   └── types.ts                  # Shared TypeScript types for manifests, realms & rings
│   │
│   ├── extension/
│   │   ├── orchestrator.ts           # VS Code extension orchestrator intercepting requests
│   │   ├── tool-executor.ts          # Guarded tool dispatch with capability check
│   │   └── context-interceptor.ts    # File path mapper & prompt context scrubber
│   │
│   ├── components/                   # Interactive Visual Workbench (Tailwind v4)
│   │   ├── WorkbenchView.tsx         # Main unified workbench container
│   │   ├── IdeSimulator.tsx          # Interactive VS Code file tree & prompt tester
│   │   ├── PolicyAuditPanel.tsx      # Real-time policy visualizer (Realms, Rings, Tools)
│   │   ├── GatekeeperConsole.tsx     # Cryptographic signature verifier & tamper tester
│   │   └── CodeViewer.tsx            # Clean syntax-highlighted inspector for all TS & PY code
│   │
│   ├── App.tsx                       # Root React application
│   ├── index.css                     # Design tokens & Tailwind v4 config
│   └── main.tsx                      # Web entry point
│
├── python-gatekeeper/
│   ├── gatekeeper.py                 # Ed25519 verification & package integrity gatekeeper
│   ├── net_ring_proxy.py             # Mock egress proxy enforcing Net-Ring 0-3 firewall rules
│   ├── keygen.py                     # Key generator & manifest signer utility
│   └── test_gatekeeper.py            # Automated test suite for signature & ring enforcement
│
└── package.json                      # Dependencies & runtime scripts
```

---

### 4. Technical Specifications & Components

#### A. Declarative Package Manifest (`agent-package.yaml`)
- **Metadata**: Identifier (`com.acme.secure-coder`), version, author, cryptographic fingerprint.
- **Rings Specification**: Dynamic definitions of Ring 0 (Isolated), Ring 1 (Local), Ring 2 (Whitelisted APIs), and Ring 3 (Unrestricted) with explicit allowed endpoints and protocol constraints.
- **Realms**:
  - `secrets`: Target pattern `**/.env*`, `**/certs/**` $\rightarrow$ Ring 0, zero tool access, air-gapped.
  - `infrastructure`: Target pattern `**/infra/**`, `**/terraform/**` $\rightarrow$ Ring 1, Read-only tool, require approval.
  - `business-logic`: Target pattern `src/domain/**` $\rightarrow$ Ring 2 (LLM query allowed), tool: `code_refactor`, `unit_test_gen`.
  - `public-api`: Target pattern `src/controllers/**` $\rightarrow$ Ring 2, tools: `lint`, `format`, `api_doc`.
- **Tool Policies**: Explicit declarations of which tools can execute under which conditions (e.g., `fs_read`, `fs_write`, `shell_exec`, `http_fetch`).

#### B. TypeScript Runtime Engine (`src/security/` and `src/extension/`)
- **`manifest-parser.ts`**: Validates YAML schemas, verifies internal ring references, and ensures no orphan tool policies exist.
- **`realm-engine.ts`**: Uses deterministic path glob matching (`minimatch` pattern matching) to map an active file to its most specific Realm.
- **`orchestrator.ts`**: Intercepts requests, evaluates `(TargetFile, RequestedTool, EgressDestination)` against `(Realm, NetRing, SigningStatus)`, returning either `ALLOWED` or `SECURITY_VIOLATION` with descriptive audit logging.

#### C. Python Cryptographic Gatekeeper & Proxy (`python-gatekeeper/`)
- **`gatekeeper.py`**:
  - Verifies Ed25519 signatures over SHA-256 manifest digests using `cryptography` / raw elliptic curve math.
  - Detects payload tampering or signature mismatches.
- **`net_ring_proxy.py`**:
  - Simulates a forward proxy / local gateway.
  - Inspects incoming requests: extracts `agent_token`, determines caller Realm and active Ring.
  - Enforces:
    - Ring 0: Drop all network attempts immediately with code `403 FORBIDDEN_AIRGAP`.
    - Ring 1: Allow only `localhost` / `127.0.0.1`.
    - Ring 2: Allow only exact domain whitelist from the manifest.
    - Ring 3: Allow with full audit logging.

#### D. Interactive Visual Workbench UI
- **VS Code Extension Simulation**: Allows the developer to pick files from a simulated repository, choose an agent prompt or tool action, and watch the Orchestrator evaluate the boundary in real time.
- **Tamper & Verification Playground**: Lets users toggle signature validity, edit the manifest live, test tamper detection, and inspect cryptographically verified status.
- **Policy Inspector & Matrix**: Visual interactive matrix mapping files $\rightarrow$ Realms $\rightarrow$ Tools $\rightarrow$ Allowed Net-Rings.
- **Source Code & Exporter**: Direct visual access to the clean, production-ready TypeScript and Python source files with one-click copy or file download.

---

### 5. Verification & Testing Strategy

- **Parser Validation**: Test parsing valid vs malformed `agent-package.yaml` manifests.
- **Realm Boundary Tests**: Test files in `src/domain/user.ts` (allowed) vs `.env.production` (blocked).
- **Net-Ring Guard Tests**: Test LLM API call from Ring 0 (fails) vs Ring 2 (succeeds).
- **Signature Integrity Tests**: Test genuine Ed25519 signature (valid) vs altered manifest bytes (rejected with checksum error).
- **Applet Compilation**: Run `compile_applet` to ensure zero TypeScript errors and flawless browser execution.
