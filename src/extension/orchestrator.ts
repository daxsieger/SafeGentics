/**
 * VS Code Extension Runtime Engine & Orchestrator.
 * Intercepts user requests and agent actions, coordinates Gatekeeper verification,
 * maps active files to security Realms, and enforces Net-Ring egress boundaries.
 */

import { RealmEngine } from '../security/realm-engine.ts';
import { NetRingGuard } from '../security/net-ring-guard.ts';
import {
  AgentPackageManifest,
  InterceptRequest,
  OrchestrationVerdict,
  InterceptorCheckStep,
} from '../security/types.ts';

export class ExtensionOrchestrator {
  private realmEngine: RealmEngine;
  private netRingGuard: NetRingGuard;
  private manifest: AgentPackageManifest;
  private isPackageCryptographicallyVerified: boolean;

  constructor(
    manifest: AgentPackageManifest,
    isPackageCryptographicallyVerified: boolean = true
  ) {
    this.manifest = manifest;
    this.isPackageCryptographicallyVerified = isPackageCryptographicallyVerified;
    this.realmEngine = new RealmEngine(manifest.realms);
    this.netRingGuard = new NetRingGuard(manifest.net_rings);
  }

  public updateManifest(manifest: AgentPackageManifest, isVerified: boolean) {
    this.manifest = manifest;
    this.isPackageCryptographicallyVerified = isVerified;
    this.realmEngine = new RealmEngine(manifest.realms);
    this.netRingGuard = new NetRingGuard(manifest.net_rings);
  }

  /**
   * Intercepts an agent action or developer prompt.
   * Runs the 4-step security pipeline.
   */
  public intercept(req: InterceptRequest): OrchestrationVerdict {
    const steps: InterceptorCheckStep[] = [];
    const now = new Date().toISOString();
    const isSigned = req.packageSigned !== undefined ? req.packageSigned : this.isPackageCryptographicallyVerified;

    // STEP 1: Cryptographic Gatekeeper Verification
    if (!isSigned) {
      steps.push({
        step: 'SIGNATURE_GATEKEEPER',
        title: 'Cryptographic Gatekeeper Verification',
        passed: false,
        details: 'Package Ed25519 signature missing, untrusted, or manifest integrity check failed.',
      });

      return {
        verdict: 'BLOCKED',
        primaryReason: 'Agent package failed Ed25519 signature verification. Execution is completely halted by Gatekeeper.',
        targetFile: req.fileUri,
        matchedRealm: null,
        activeRing: null,
        requestedTool: req.requestedTool,
        egressUrl: req.egressUrl,
        timestamp: now,
        steps,
      };
    }

    steps.push({
      step: 'SIGNATURE_GATEKEEPER',
      title: 'Cryptographic Gatekeeper Verification',
      passed: true,
      details: 'Package signature verified via Ed25519. Manifest authenticity and byte integrity confirmed.',
    });

    // STEP 2: Realm Mapping & Context Scrubber
    const realm = this.realmEngine.resolveRealm(req.fileUri);
    const scrubbedPrompt = this.realmEngine.scrubContent(realm, req.prompt);

    steps.push({
      step: 'REALM_MAPPING',
      title: `Realm Resolution: ${realm.name}`,
      passed: true,
      details: `Target path '${req.fileUri}' mapped to Realm '${realm.id}' (${realm.name}). Bound to Net-Ring '${realm.net_ring}'.`,
      meta: { realmId: realm.id, netRing: realm.net_ring, scrubbed: scrubbedPrompt !== req.prompt },
    });

    // STEP 3: Tool Capability Authorization
    const toolCheck = this.realmEngine.isToolAllowed(realm, req.requestedTool);
    if (!toolCheck.allowed) {
      steps.push({
        step: 'TOOL_AUTHORIZATION',
        title: `Tool Authorization: ${req.requestedTool}`,
        passed: false,
        details: toolCheck.reason,
      });

      return {
        verdict: 'BLOCKED',
        primaryReason: toolCheck.reason,
        targetFile: req.fileUri,
        matchedRealm: realm,
        activeRing: this.manifest.net_rings[realm.net_ring] || null,
        requestedTool: req.requestedTool,
        egressUrl: req.egressUrl,
        timestamp: now,
        steps,
        scrubbedPrompt,
      };
    }

    steps.push({
      step: 'TOOL_AUTHORIZATION',
      title: `Tool Authorization: ${req.requestedTool}`,
      passed: true,
      details: toolCheck.reason,
    });

    // STEP 4: Net-Ring Egress Firewall Evaluation
    const ringConfig = this.manifest.net_rings[realm.net_ring];
    let ringEvaluation = null;

    if (req.egressUrl) {
      ringEvaluation = this.netRingGuard.evaluateEgress(realm.net_ring, req.egressUrl);

      if (!ringEvaluation.allowed) {
        steps.push({
          step: 'NET_RING_FIREWALL',
          title: `Net-Ring Guard: ${realm.net_ring.toUpperCase()}`,
          passed: false,
          details: ringEvaluation.reason,
          meta: { targetHost: ringEvaluation.targetHost, statusCode: ringEvaluation.statusCode },
        });

        return {
          verdict: 'BLOCKED',
          primaryReason: ringEvaluation.reason,
          targetFile: req.fileUri,
          matchedRealm: realm,
          activeRing: ringConfig,
          requestedTool: req.requestedTool,
          egressUrl: req.egressUrl,
          timestamp: now,
          steps,
          scrubbedPrompt,
        };
      }

      steps.push({
        step: 'NET_RING_FIREWALL',
        title: `Net-Ring Guard: ${realm.net_ring.toUpperCase()}`,
        passed: true,
        details: ringEvaluation.reason,
        meta: { targetHost: ringEvaluation.targetHost, matchedRule: ringEvaluation.matchedRule },
      });
    } else {
      steps.push({
        step: 'NET_RING_FIREWALL',
        title: `Net-Ring Guard: ${realm.net_ring.toUpperCase()}`,
        passed: true,
        details: `No outbound network destination requested. Local tool execution permitted in ${realm.net_ring}.`,
      });
    }

    // User Confirmation Gate Check
    if (realm.require_user_confirmation) {
      return {
        verdict: 'REQUIRES_USER_APPROVAL',
        primaryReason: `Action is technically compliant but Realm '${realm.name}' mandates human supervisor approval prior to execution.`,
        targetFile: req.fileUri,
        matchedRealm: realm,
        activeRing: ringConfig,
        requestedTool: req.requestedTool,
        egressUrl: req.egressUrl,
        timestamp: now,
        steps,
        scrubbedPrompt,
      };
    }

    return {
      verdict: 'ALLOWED',
      primaryReason: `All security invariants satisfied. Tool '${req.requestedTool}' permitted within Realm '${realm.name}' under Net-Ring '${realm.net_ring}'.`,
      targetFile: req.fileUri,
      matchedRealm: realm,
      activeRing: ringConfig,
      requestedTool: req.requestedTool,
      egressUrl: req.egressUrl,
      timestamp: now,
      steps,
      scrubbedPrompt,
    };
  }
}
