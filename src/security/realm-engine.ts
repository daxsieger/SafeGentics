/**
 * Realm Engine: Path-based Workspace Partitioning & Capability Resolution.
 * Maps active document paths to their authorized security Realm using glob pattern matching.
 */

import { RealmConfig } from './types.ts';

export class RealmEngine {
  private realms: RealmConfig[];

  constructor(realmsRecord: Record<string, RealmConfig>) {
    this.realms = Object.entries(realmsRecord).map(([key, r]) => ({
      ...r,
      id: r.id || key,
    }));
  }

  /**
   * Finds the best matching Realm for a given workspace file URI or path.
   */
  public resolveRealm(filePath: string): RealmConfig {
    const normalized = this.normalizePath(filePath);

    for (const realm of this.realms) {
      for (const pattern of realm.paths) {
        if (this.matchGlob(pattern, normalized)) {
          return realm;
        }
      }
    }

    // Default Fallback: Isolated Air-Gapped Realm (Ring 0)
    return {
      id: 'realm-unmapped-isolated',
      name: 'Unmapped File (Default Isolation)',
      description: 'Files not matched by any explicit realm default to Ring 0 air-gapped isolation with zero agent tool capabilities.',
      paths: ['**/*'],
      net_ring: 'ring_0',
      allowed_tools: ['fs_read'],
      blocked_tools: ['*'],
      require_user_confirmation: true,
      context_scrubbing: { enabled: true, mask_pattern: 'REDACTED' },
    };
  }

  /**
   * Tests whether a specific tool is authorized within the resolved Realm.
   */
  public isToolAllowed(realm: RealmConfig, toolName: string): { allowed: boolean; reason: string } {
    if (realm.blocked_tools?.includes('*') || realm.blocked_tools?.includes(toolName)) {
      return {
        allowed: false,
        reason: `Tool '${toolName}' is explicitly blocked in Realm '${realm.name}' (${realm.id}).`,
      };
    }

    if (realm.allowed_tools.includes('*') || realm.allowed_tools.includes(toolName)) {
      return {
        allowed: true,
        reason: `Tool '${toolName}' is explicitly granted in Realm '${realm.name}'.`,
      };
    }

    return {
      allowed: false,
      reason: `Tool '${toolName}' is not listed in allowed_tools for Realm '${realm.name}'.`,
    };
  }

  /**
   * Applies context scrubbing if enabled for the Realm.
   */
  public scrubContent(realm: RealmConfig, text: string): string {
    if (!realm.context_scrubbing?.enabled) {
      return text;
    }
    const mask = realm.context_scrubbing.mask_pattern || 'REDACTED_SECRET';

    // Scrub API keys, tokens, passwords, and private key blocks
    return text
      .replace(/(?:api[_-]?key|secret|token|password|auth)[\s:=]+['"][A-Za-z0-9_-]{8,}['"]/gi, `[${mask}]`)
      .replace(/-----BEGIN [A-Z ]+-----[^-]+-----END [A-Z ]+-----/g, `[${mask}_KEY_BLOCK]`);
  }

  private normalizePath(p: string): string {
    let clean = p.replace(/\\/g, '/');
    if (clean.startsWith('./')) clean = clean.slice(2);
    if (clean.startsWith('/')) clean = clean.slice(1);
    return clean;
  }

  /**
   * Lightweight, robust glob matching supporting **, *, and file extensions.
   */
  private matchGlob(pattern: string, path: string): boolean {
    const cleanPattern = this.normalizePath(pattern);
    const cleanPath = this.normalizePath(path);

    // Exact match
    if (cleanPattern === cleanPath) return true;

    // Convert glob pattern to regular expression
    // Escape regex special chars except * and ?
    let regexStr = cleanPattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*\//g, '(?:.*/)?')
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '.');

    const regex = new RegExp(`^${regexStr}$`, 'i');
    return regex.test(cleanPath);
  }
}
