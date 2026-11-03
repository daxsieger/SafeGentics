/**
 * Net-Ring Guard: Network Egress Firewall & Policy Enforcement.
 * Validates outgoing network endpoints and foundation model API calls against the active Net-Ring tier.
 */

import { NetRingConfig } from './types.ts';

export interface NetRingEvaluation {
  allowed: boolean;
  activeRing: NetRingConfig;
  targetHost: string;
  statusCode: number;
  reason: string;
  matchedRule?: string;
  errorCode?: string;
}

export class NetRingGuard {
  private rings: Record<string, NetRingConfig>;

  constructor(ringsRecord: Record<string, NetRingConfig>) {
    this.rings = ringsRecord;
  }

  /**
   * Evaluates an egress URL against the active Net-Ring configuration.
   */
  public evaluateEgress(ringId: string, targetUrl: string): NetRingEvaluation {
    const ring = this.rings[ringId] || this.rings['ring_0'] || {
      name: 'Ring 0 (Fallback Air-Gap)',
      tier: 0,
      description: 'Air-gapped fallback',
      allowed_hosts: [],
      allow_loopback: false,
    };

    let targetHost = targetUrl;
    try {
      const parsed = new URL(targetUrl.includes('://') ? targetUrl : `https://${targetUrl}`);
      targetHost = parsed.hostname;
    } catch {
      targetHost = targetUrl.split('/')[0].split(':')[0];
    }

    // Ring 0: Air-Gapped Isolation
    if (ring.tier === 0) {
      return {
        allowed: false,
        activeRing: ring,
        targetHost,
        statusCode: 403,
        errorCode: 'ERR_RING0_AIRGAP_VIOLATION',
        reason: `Active Net-Ring '${ring.name}' (Tier 0) is strictly air-gapped. Network egress, model API queries, and sockets are forbidden.`,
      };
    }

    const isLoopback = ['localhost', '127.0.0.1', '::1'].includes(targetHost);
    if (isLoopback) {
      if (ring.allow_loopback) {
        return {
          allowed: true,
          activeRing: ring,
          targetHost,
          statusCode: 200,
          reason: `Loopback endpoint '${targetHost}' permitted by ${ring.name}.`,
          matchedRule: 'loopback_allowed',
        };
      } else {
        return {
          allowed: false,
          activeRing: ring,
          targetHost,
          statusCode: 403,
          errorCode: 'ERR_LOOPBACK_PROHIBITED',
          reason: `Active Net-Ring '${ring.name}' explicitly disables local loopback IPC.`,
        };
      }
    }

    // Ring 3: Unrestricted
    if (ring.allowed_hosts.includes('*') || ring.tier >= 3) {
      return {
        allowed: true,
        activeRing: ring,
        targetHost,
        statusCode: 200,
        reason: `Destination '${targetHost}' permitted under ${ring.name} (Egress open with audit logging).`,
        matchedRule: 'unrestricted_egress',
      };
    }

    // Ring 2: Whitelisted Host Matching
    for (const hostPattern of ring.allowed_hosts) {
      if (hostPattern.startsWith('*.')) {
        const domainSuffix = hostPattern.slice(2);
        if (targetHost === domainSuffix || targetHost.endsWith('.' + domainSuffix)) {
          return {
            allowed: true,
            activeRing: ring,
            targetHost,
            statusCode: 200,
            reason: `Destination '${targetHost}' matches whitelisted wildcard pattern '${hostPattern}'.`,
            matchedRule: hostPattern,
          };
        }
      } else if (targetHost.toLowerCase() === hostPattern.toLowerCase()) {
        return {
          allowed: true,
          activeRing: ring,
          targetHost,
          statusCode: 200,
          reason: `Destination '${targetHost}' is explicitly whitelisted in ${ring.name}.`,
          matchedRule: hostPattern,
        };
      }
    }

    return {
      allowed: false,
      activeRing: ring,
      targetHost,
      statusCode: 403,
      errorCode: 'ERR_HOST_NOT_WHITELISTED',
      reason: `Target host '${targetHost}' is not in the allowed egress whitelist for ${ring.name}. Allowed: [${ring.allowed_hosts.join(', ') || 'None'}].`,
    };
  }
}
