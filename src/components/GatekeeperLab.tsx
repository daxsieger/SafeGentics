import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Key,
  Hash,
  Terminal,
  RefreshCw,
  FileSignature,
  AlertOctagon,
  CheckCircle2,
  Copy,
  Check,
  Play,
} from 'lucide-react';
import {
  computeSha256,
  verifyManifestSignature,
  simulateSignManifest,
  VerificationResult,
} from '../security/crypto-verifier.ts';
import { DEFAULT_PUBLIC_KEY_PEM } from '../security/default-data.ts';

interface GatekeeperLabProps {
  manifestYaml: string;
  signatureHex: string;
  onUpdateManifestYaml: (newYaml: string) => void;
  onUpdateSignatureHex: (newSig: string) => void;
  onResetToCanonical: () => void;
}

export const GatekeeperLab: React.FC<GatekeeperLabProps> = ({
  manifestYaml,
  signatureHex,
  onUpdateManifestYaml,
  onUpdateSignatureHex,
  onResetToCanonical,
}) => {
  const [verification, setVerification] = useState<VerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [copiedSig, setCopiedSig] = useState<boolean>(false);
  const [pythonTerminalOutput, setPythonTerminalOutput] = useState<string>('');

  // Re-verify whenever manifest or signature changes
  useEffect(() => {
    let isMounted = true;
    setIsVerifying(true);
    verifyManifestSignature(manifestYaml, signatureHex, DEFAULT_PUBLIC_KEY_PEM).then((res) => {
      if (isMounted) {
        setVerification(res);
        setIsVerifying(false);
      }
    });
    return () => {
      isMounted = false;
    };
  }, [manifestYaml, signatureHex]);

  const handleTamperInject = () => {
    const tampered = manifestYaml + '\n# MALICIOUS INJECTION: bypass_ring_0=true\n  evil_tool:\n    risk_level: critical\n';
    onUpdateManifestYaml(tampered);
  };

  const handleReSign = async () => {
    const newSig = await simulateSignManifest(manifestYaml);
    onUpdateSignatureHex(newSig);
  };

  const handleRunPythonSimulation = () => {
    const sha = verification?.sha256Hex || 'computing...';
    const isValid = verification?.valid;

    if (isValid) {
      setPythonTerminalOutput(
`$ python3 python-gatekeeper/gatekeeper.py
=================================================================
         VS CODE LOCAL AGENT CRYPTOGRAPHIC GATEKEEPER            
=================================================================
Manifest Path : /app/applet/agent-spec/agent-package.yaml
Digest SHA256 : ${sha}
Algorithm     : Ed25519 (RFC 8032)
Verdict       : ✓ PASS (SIGNED & VALID)
Action        : PERMITTED
[SUCCESS] Package signature verified. Agent module authorization granted.

$ python3 python-gatekeeper/net_ring_proxy.py
[ALLOW] Target: api.openai.com:443 | Realm: business_logic (Ring 2) -> Whitelisted
[BLOCK] Target: attacker-c2.org:443 | Realm: secrets (Ring 0) -> Airgap Violation (403)`
      );
    } else {
      setPythonTerminalOutput(
`$ python3 python-gatekeeper/gatekeeper.py
=================================================================
         VS CODE LOCAL AGENT CRYPTOGRAPHIC GATEKEEPER            
=================================================================
Manifest Path : /app/applet/agent-spec/agent-package.yaml
Digest SHA256 : ${sha}
Algorithm     : Ed25519 (RFC 8032)
Verdict       : ✗ FAIL (UNTRUSTED / TAMPERED)
Action        : BLOCKED
Reason        : Cryptographic signature mismatch: Package has been modified or signed with untrusted key.
[HALT] Agent execution aborted. Gatekeeper blocked code loading.`
      );
    }
  };

  return (
    <div className="flex-1 p-6 bg-slate-950 text-slate-200 overflow-y-auto space-y-6 font-sans">
      {/* Header */}
      <div className="space-y-1">
        <h2 className="text-xl font-bold tracking-tight text-slate-100">
          Cryptographic Gatekeeper & Code Signing Lab
        </h2>
        <p className="text-xs text-slate-400">
          Simulates the Ed25519 signature verification and manifest digest validation.
          Any unauthorized modification in <span className="font-mono text-indigo-400">agent-package.yaml</span>{' '}
          is caught before loading.
        </p>
      </div>

      {/* Verification Status Banner */}
      {verification && (
        <div
          className={`p-4 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
            verification.valid
              ? 'bg-emerald-950/20 border-emerald-500/40'
              : 'bg-rose-950/20 border-rose-500/40'
          }`}
        >
          <div className="flex items-center gap-3">
            <div
              className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${
                verification.valid
                  ? 'bg-emerald-600/20 text-emerald-400 border border-emerald-500/30'
                  : 'bg-rose-600/20 text-rose-400 border border-rose-500/30'
              }`}
            >
              {verification.valid ? (
                <ShieldCheck className="w-5 h-5" />
              ) : (
                <ShieldAlert className="w-5 h-5" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-slate-100">
                  Gatekeeper Status:{' '}
                  <span className={verification.valid ? 'text-emerald-400' : 'text-rose-400'}>
                    {verification.gatekeeperAction}
                  </span>
                </span>
                <span className="text-xs font-mono text-slate-400">
                  ({verification.algorithm})
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {verification.valid
                  ? 'Manifest is cryptographically authentic. All byte invariants and cryptographic signatures match.'
                  : verification.error || 'Signature check failed. Package is considered untrusted.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleTamperInject}
              className="px-3 py-1.5 text-xs font-medium text-rose-300 bg-rose-950/60 hover:bg-rose-900/60 border border-rose-800/80 rounded-lg transition-colors flex items-center gap-1.5"
            >
              <AlertOctagon className="w-3.5 h-3.5" />
              <span>Simulate Tampering</span>
            </button>

            <button
              onClick={handleReSign}
              className="px-3 py-1.5 text-xs font-medium text-indigo-300 bg-indigo-950/60 hover:bg-indigo-900/60 border border-indigo-800/80 rounded-lg transition-colors flex items-center gap-1.5"
            >
              <FileSignature className="w-3.5 h-3.5" />
              <span>Re-Sign Package</span>
            </button>

            <button
              onClick={onResetToCanonical}
              className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Reset Canonical</span>
            </button>
          </div>
        </div>
      )}

      {/* Cryptographic Parameters Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
        {/* SHA-256 Digest Card */}
        <div className="p-4 bg-slate-900/50 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <div className="flex items-center gap-1.5">
              <Hash className="w-3.5 h-3.5 text-indigo-400" />
              <span className="font-sans font-semibold uppercase text-[11px] text-slate-300">
                Live SHA-256 Manifest Digest
              </span>
            </div>
            <span className="text-[10px] text-slate-400">Canonical Checksum</span>
          </div>
          <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 text-[11px] text-indigo-300 break-all select-all">
            {verification?.sha256Hex || 'Computing SHA-256...'}
          </div>
          <p className="text-[11px] font-sans text-slate-400">
            Recalculated in real time across the canonical UTF-8 bytes of <span className="font-mono text-slate-300">agent-package.yaml</span>.
          </p>
        </div>

        {/* Detached Signature Card */}
        <div className="p-4 bg-slate-900/50 border border-slate-800 rounded-xl space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <div className="flex items-center gap-1.5">
              <Key className="w-3.5 h-3.5 text-indigo-400" />
              <span className="font-sans font-semibold uppercase text-[11px] text-slate-300">
                Detached Ed25519 Signature (.sig)
              </span>
            </div>
            <button
              onClick={() => {
                navigator.clipboard.writeText(signatureHex);
                setCopiedSig(true);
                setTimeout(() => setCopiedSig(false), 2000);
              }}
              className="text-[10px] text-slate-400 hover:text-slate-200 flex items-center gap-1"
            >
              {copiedSig ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              <span>{copiedSig ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800 text-[11px] text-slate-300 break-all select-all max-h-14 overflow-y-auto">
            {signatureHex}
          </div>
          <p className="text-[11px] font-sans text-slate-400">
            64-byte detached cryptographic signature (128 hex chars) verified against the public key.
          </p>
        </div>
      </div>

      {/* Split View: Live YAML Editor & Python Terminal Simulation */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Manifest Editor (Col 7) */}
        <div className="lg:col-span-7 bg-slate-900/50 border border-slate-800 rounded-xl flex flex-col overflow-hidden">
          <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-sans">
              Manifest YAML Content (Editable)
            </span>
            <span className="text-[11px] font-mono text-slate-400">
              agent-package.yaml
            </span>
          </div>
          <textarea
            value={manifestYaml}
            onChange={(e) => onUpdateManifestYaml(e.target.value)}
            rows={16}
            className="w-full p-4 bg-slate-950 text-xs font-mono text-slate-300 focus:outline-none border-none resize-none leading-relaxed"
            placeholder="Edit manifest YAML..."
          />
        </div>

        {/* Right: Python Gatekeeper & Proxy Output (Col 5) */}
        <div className="lg:col-span-5 bg-slate-900/50 border border-slate-800 rounded-xl flex flex-col overflow-hidden">
          <div className="px-4 py-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-indigo-400" />
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-sans">
                Python Gatekeeper CLI
              </span>
            </div>
            <button
              onClick={handleRunPythonSimulation}
              className="px-2.5 py-1 text-[11px] font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded transition-colors flex items-center gap-1"
            >
              <Play className="w-3 h-3 fill-current" />
              <span>Execute Verification</span>
            </button>
          </div>

          <div className="p-4 bg-slate-950 font-mono text-[11px] text-slate-300 flex-1 overflow-y-auto leading-relaxed whitespace-pre-wrap">
            {pythonTerminalOutput || (
              <span className="text-slate-400">
                Click "Execute Verification" above to simulate running the Python gatekeeper CLI (`python3 python-gatekeeper/gatekeeper.py`) against this manifest state.
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
