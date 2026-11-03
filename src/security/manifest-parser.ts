/**
 * Manifest Parser and Policy Validator for .agentpkg and manifest.yaml.
 * Reads declarative manifests, checks structural constraints, validates Ring references,
 * and builds the runtime policy cache.
 */

import { load } from 'js-yaml';
import { AgentPackageManifest, NetRingConfig, RealmConfig } from './types.ts';

export interface ParseResult {
  success: boolean;
  manifest: AgentPackageManifest | null;
  errors: string[];
  warnings: string[];
}

export function parseManifest(yamlContent: string): ParseResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  let rawData: unknown;
  try {
    rawData = load(yamlContent);
  } catch (err) {
    return {
      success: false,
      manifest: null,
      errors: [`YAML Syntax Error: ${(err as Error).message}`],
      warnings: [],
    };
  }

  if (!rawData || typeof rawData !== 'object') {
    return {
      success: false,
      manifest: null,
      errors: ['Manifest content is empty or not an object.'],
      warnings: [],
    };
  }

  const data = rawData as Record<string, unknown>;

  // Check required metadata
  if (!data.name || typeof data.name !== 'string') {
    errors.push("Missing required field: 'name' (string)");
  }
  if (!data.version || typeof data.version !== 'string') {
    errors.push("Missing required field: 'version' (string)");
  }

  // Validate Net-Rings
  const netRings = (data.net_rings as Record<string, NetRingConfig>) || {};
  if (Object.keys(netRings).length === 0) {
    errors.push("Manifest must define at least one entry in 'net_rings'.");
  } else {
    for (const [ringId, ring] of Object.entries(netRings)) {
      if (typeof ring.tier !== 'number') {
        errors.push(`Net-Ring '${ringId}' must define a numeric 'tier'.`);
      }
      if (!Array.isArray(ring.allowed_hosts)) {
        errors.push(`Net-Ring '${ringId}' must define 'allowed_hosts' as an array.`);
      }
    }
  }

  // Validate Realms
  const realms = (data.realms as Record<string, RealmConfig>) || {};
  if (Object.keys(realms).length === 0) {
    errors.push("Manifest must define at least one Realm in 'realms'.");
  } else {
    for (const [realmId, realm] of Object.entries(realms)) {
      if (!Array.isArray(realm.paths) || realm.paths.length === 0) {
        errors.push(`Realm '${realmId}' must specify at least one path pattern in 'paths'.`);
      }
      if (!realm.net_ring || !netRings[realm.net_ring]) {
        errors.push(`Realm '${realmId}' references unknown Net-Ring: '${realm.net_ring}'. Available rings: ${Object.keys(netRings).join(', ')}`);
      }
      if (!Array.isArray(realm.allowed_tools)) {
        errors.push(`Realm '${realmId}' must define 'allowed_tools' as an array.`);
      }
    }
  }

  if (errors.length > 0) {
    return {
      success: false,
      manifest: null,
      errors,
      warnings,
    };
  }

  const manifest: AgentPackageManifest = {
    name: String(data.name || ''),
    version: String(data.version || ''),
    author: String(data.author || 'Unknown'),
    description: String(data.description || ''),
    signature_algorithm: String(data.signature_algorithm || 'Ed25519'),
    public_key_fingerprint: String(data.public_key_fingerprint || ''),
    net_rings: netRings,
    realms: realms,
    tools: Array.isArray(data.tools) ? (data.tools as AgentPackageManifest['tools']) : [],
  };

  return {
    success: true,
    manifest,
    errors: [],
    warnings,
  };
}
