import React, { useState, useMemo, useEffect } from 'react';
import { TopBar, ActiveTab } from './components/TopBar.tsx';
import { IdeSimulator } from './components/IdeSimulator.tsx';
import { PolicyMatrix } from './components/PolicyMatrix.tsx';
import { GatekeeperLab } from './components/GatekeeperLab.tsx';
import { SourceCodeViewer } from './components/SourceCodeViewer.tsx';
import { parseManifest } from './security/manifest-parser.ts';
import { ExtensionOrchestrator } from './extension/orchestrator.ts';
import {
  DEFAULT_MANIFEST_YAML,
  DEFAULT_DETACHED_SIG_HEX,
  DEFAULT_PUBLIC_KEY_PEM,
} from './security/default-data.ts';
import { verifyManifestSignature } from './security/crypto-verifier.ts';
import { CheckCircle2, XCircle, ShieldCheck, Play, X } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('ide');
  const [manifestYaml, setManifestYaml] = useState<string>(DEFAULT_MANIFEST_YAML);
  const [signatureHex, setSignatureHex] = useState<string>(DEFAULT_DETACHED_SIG_HEX);
  const [isSignedAndValid, setIsSignedAndValid] = useState<boolean>(true);
  const [showAuditModal, setShowAuditModal] = useState<boolean>(false);

  // Parse YAML to manifest object
  const parseResult = useMemo(() => {
    return parseManifest(manifestYaml);
  }, [manifestYaml]);

  // Check signature on manifest change
  useEffect(() => {
    let isMounted = true;
    verifyManifestSignature(manifestYaml, signatureHex, DEFAULT_PUBLIC_KEY_PEM).then((res) => {
      if (isMounted) {
        setIsSignedAndValid(res.valid);
      }
    });
    return () => {
      isMounted = false;
    };
  }, [manifestYaml, signatureHex]);

  // Extension Orchestrator instance
  const orchestrator = useMemo(() => {
    if (!parseResult.manifest) {
      const fallback = parseManifest(DEFAULT_MANIFEST_YAML).manifest!;
      return new ExtensionOrchestrator(fallback, isSignedAndValid);
    }
    return new ExtensionOrchestrator(parseResult.manifest, isSignedAndValid);
  }, [parseResult.manifest, isSignedAndValid]);

  const activeManifest = parseResult.manifest || parseManifest(DEFAULT_MANIFEST_YAML).manifest!;

  // Automated Audit Test Scenarios
  const testScenarios = useMemo(() => {
    return [
      {
        id: 1,
        title: 'Ring 0 Airgap Violation',
        file: '.env.production',
        tool: 'llm_generate',
        url: 'https://api.openai.com/v1/chat',
        expected: 'BLOCKED',
        desc: 'Secrets realm must prohibit all network egress.',
      },
      {
        id: 2,
        title: 'Ring 1 Localhost IPC',
        file: 'tests/payment.spec.ts',
        tool: 'test_runner',
        url: 'http://localhost:3000/api',
        expected: 'ALLOWED',
        desc: 'Test sandbox permits local loopback calls.',
      },
      {
        id: 3,
        title: 'Ring 1 Public Egress Leak',
        file: 'infra/terraform/main.tf',
        tool: 'terraform_fmt',
        url: 'https://malicious-exfil.org/data',
        expected: 'BLOCKED',
        desc: 'Infrastructure realm rejects non-localhost egress.',
      },
      {
        id: 4,
        title: 'Ring 2 Whitelisted Model API',
        file: 'src/domain/payment.ts',
        tool: 'code_refactor',
        url: 'https://api.openai.com/v1/chat/completions',
        expected: 'ALLOWED',
        desc: 'Domain logic permits whitelisted OpenAI model egress.',
      },
      {
        id: 5,
        title: 'Ring 2 Non-Whitelisted Host',
        file: 'src/domain/payment.ts',
        tool: 'code_refactor',
        url: 'https://untrusted-c2.net/exfil',
        expected: 'BLOCKED',
        desc: 'Domain logic rejects unapproved egress targets.',
      },
      {
        id: 6,
        title: 'Secrets Realm Tool Lockdown',
        file: 'certs/private.key',
        tool: 'fs_read',
        url: '',
        expected: 'BLOCKED',
        desc: 'Secrets realm locks all agent tools.',
      },
    ];
  }, []);

  return (
    <div className="flex flex-col h-screen w-screen bg-slate-950 text-slate-100 overflow-hidden">
      {/* Top Navigation */}
      <TopBar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        isSignedAndValid={isSignedAndValid}
        onRunAudit={() => setShowAuditModal(true)}
      />

      {/* Main Tab Viewports */}
      <main className="flex-1 overflow-hidden flex flex-col">
        {activeTab === 'ide' && (
          <IdeSimulator
            manifest={activeManifest}
            isPackageValid={isSignedAndValid}
            orchestrator={orchestrator}
          />
        )}

        {activeTab === 'policy' && (
          <PolicyMatrix manifest={activeManifest} />
        )}

        {activeTab === 'gatekeeper' && (
          <GatekeeperLab
            manifestYaml={manifestYaml}
            signatureHex={signatureHex}
            onUpdateManifestYaml={setManifestYaml}
            onUpdateSignatureHex={setSignatureHex}
            onResetToCanonical={() => {
              setManifestYaml(DEFAULT_MANIFEST_YAML);
              setSignatureHex(DEFAULT_DETACHED_SIG_HEX);
            }}
          />
        )}

        {activeTab === 'source' && (
          <SourceCodeViewer />
        )}
      </main>

      {/* Comprehensive Audit Test Modal */}
      {showAuditModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-indigo-400" />
                <h3 className="text-base font-bold text-slate-100">
                  Full Boundary Invariant Verification Suite
                </h3>
              </div>
              <button
                onClick={() => setShowAuditModal(false)}
                className="text-slate-400 hover:text-slate-200 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Evaluates the current orchestrator and active Net-Ring policies against standard security invariant tests:
            </p>

            <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
              {testScenarios.map((sc) => {
                const result = orchestrator.intercept({
                  fileUri: sc.file,
                  prompt: 'Automated test suite evaluation',
                  requestedTool: sc.tool,
                  egressUrl: sc.url || undefined,
                  packageSigned: isSignedAndValid,
                });
                const passed = result.verdict === sc.expected;

                return (
                  <div
                    key={sc.id}
                    className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-between text-xs font-mono"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 font-sans font-semibold text-slate-200">
                        {passed ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                        ) : (
                          <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                        )}
                        <span>{sc.title}</span>
                      </div>
                      <div className="text-[11px] text-slate-400">
                        {sc.desc}
                      </div>
                      <div className="text-[10px] text-slate-400">
                        File: {sc.file} · Tool: {sc.tool} {sc.url ? `· Egress: ${sc.url}` : ''}
                      </div>
                    </div>

                    <div className="flex flex-col items-end gap-1 shrink-0 ml-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          passed
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/30'
                            : 'bg-rose-950 text-rose-300 border border-rose-500/30'
                        }`}
                      >
                        {result.verdict}
                      </span>
                      <span className="text-[10px] text-slate-400 font-sans">
                        Expected: {sc.expected}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="flex items-center justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setShowAuditModal(false)}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-lg transition-colors shadow"
              >
                Close Audit Suite
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
