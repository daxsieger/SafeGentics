/**
 * Canonical default manifest and cryptographic keys for the Local VS Code Agent.
 */

export const DEFAULT_MANIFEST_YAML = `name: "com.acme.secure-coder"
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
    max_payload_bytes: 10485760

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
    max_payload_bytes: 5242880
    rate_limit_per_minute: 120

  ring_3:
    name: "Ring 3 (Unrestricted Egress)"
    tier: 3
    description: "Full outbound network access. Requires mandatory audit logging and human supervisor notice."
    allowed_hosts:
      - "*"
    allow_loopback: true
    tls_required: true
    max_payload_bytes: 52428800
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
    requires_ring: "ring_3"`;

export const DEFAULT_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
e433d4fd5ad8e1a4e56997c498af16378d48cd57db590c255d57e39c44e48b8c
-----END PUBLIC KEY-----`;

export const DEFAULT_DETACHED_SIG_HEX = `6f31f652eeae05cc77f5439c12e7a6224ad77842f9231ae1ee46750cdc76aed55d117dfecd94516d10ad66d90e292b7eba63e55ffb1bfd8236706755a1ff9c05`;
