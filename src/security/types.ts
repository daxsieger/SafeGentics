/**
 * Types and interfaces for the Local VS Code Agent Security Architecture.
 * Covers Declarative Manifests, Realms, Net-Rings, Tools, and Orchestrator Interceptions.
 */

export type NetRingId = 'ring_0' | 'ring_1' | 'ring_2' | 'ring_3';

export interface NetRingConfig {
  name: string;
  tier: number;
  description: string;
  allowed_hosts: string[];
  allow_loopback: boolean;
  tls_required?: boolean;
  max_payload_bytes?: number;
  rate_limit_per_minute?: number;
  requires_audit_trail?: boolean;
}

export interface ContextScrubbingConfig {
  enabled: boolean;
  mask_pattern?: string;
}

export interface RealmConfig {
  id: string;
  name: string;
  description: string;
  paths: string[];
  net_ring: NetRingId;
  allowed_tools: string[];
  blocked_tools?: string[];
  require_user_confirmation: boolean;
  context_scrubbing?: ContextScrubbingConfig;
}

export interface ToolDefinition {
  name: string;
  description: string;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  requires_ring: NetRingId;
}

export interface AgentPackageManifest {
  name: string;
  version: string;
  author: string;
  description: string;
  signature_algorithm: string;
  public_key_fingerprint: string;
  net_rings: Record<string, NetRingConfig>;
  realms: Record<string, RealmConfig>;
  tools: ToolDefinition[];
}

export type VerdictStatus = 'ALLOWED' | 'BLOCKED' | 'REQUIRES_USER_APPROVAL';

export interface InterceptorCheckStep {
  step: 'SIGNATURE_GATEKEEPER' | 'REALM_MAPPING' | 'TOOL_AUTHORIZATION' | 'NET_RING_FIREWALL';
  title: string;
  passed: boolean;
  details: string;
  meta?: Record<string, unknown>;
}

export interface OrchestrationVerdict {
  verdict: VerdictStatus;
  primaryReason: string;
  targetFile: string;
  matchedRealm: RealmConfig | null;
  activeRing: NetRingConfig | null;
  requestedTool: string;
  egressUrl?: string;
  timestamp: string;
  steps: InterceptorCheckStep[];
  scrubbedPrompt?: string;
}

export interface InterceptRequest {
  fileUri: string;
  prompt: string;
  requestedTool: string;
  egressUrl?: string;
  packageSigned?: boolean;
}
