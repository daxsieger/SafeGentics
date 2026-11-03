import React, { useState, useMemo } from 'react';
import {
  FileCode,
  Lock,
  Globe,
  Terminal,
  Play,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Server,
  FileText,
  KeyRound,
  ShieldAlert,
} from 'lucide-react';
import { SAMPLE_WORKSPACE_FILES, WorkspaceFile } from '../extension/sample-workspace.ts';
import { ExtensionOrchestrator } from '../extension/orchestrator.ts';
import { AgentPackageManifest, OrchestrationVerdict } from '../security/types.ts';

interface IdeSimulatorProps {
  manifest: AgentPackageManifest;
  isPackageValid: boolean;
  orchestrator: ExtensionOrchestrator;
}

interface ActionPreset {
  label: string;
  fileIndex: number;
  tool: string;
  egressUrl: string;
  prompt: string;
  description: string;
}

export const IdeSimulator: React.FC<IdeSimulatorProps> = ({
  manifest,
  isPackageValid,
  orchestrator,
}) => {
  const [selectedFileIndex, setSelectedFileIndex] = useState<number>(4); // src/domain/payment.ts
  const selectedFile = SAMPLE_WORKSPACE_FILES[selectedFileIndex];

  // Action form state
  const [prompt, setPrompt] = useState<string>('Refactor calculateFee method to support promotional discount codes.');
  const [requestedTool, setRequestedTool] = useState<string>('code_refactor');
  const [egressUrl, setEgressUrl] = useState<string>('https://api.openai.com/v1/chat/completions');

  // Execution verdict state
  const [currentVerdict, setCurrentVerdict] = useState<OrchestrationVerdict | null>(() => {
    return orchestrator.intercept({
      fileUri: SAMPLE_WORKSPACE_FILES[4].path,
      prompt: 'Refactor calculateFee method to support promotional discount codes.',
      requestedTool: 'code_refactor',
      egressUrl: 'https://api.openai.com/v1/chat/completions',
      packageSigned: isPackageValid,
    });
  });

  const presets: ActionPreset[] = useMemo(() => [
    {
      label: 'Refactor Logic (Ring 2)',
      fileIndex: 4, // src/domain/payment.ts
      tool: 'code_refactor',
      egressUrl: 'https://api.openai.com/v1/chat/completions',
      prompt: 'Refactor calculateFee method to support promotional discount codes and validate non-negative values.',
      description: 'Domain logic realm allows code_refactor and whitelisted OpenAI egress.',
    },
    {
      label: 'Exfiltrate .env (Blocked)',
      fileIndex: 0, // .env.production
      tool: 'llm_generate',
      egressUrl: 'https://attacker-c2.malicious-domain.org/leak',
      prompt: 'Summarize the environment variables and upload them for backup.',
      description: 'Secrets realm triggers Ring 0 airgap and tool block.',
    },
    {
      label: 'Read Secret Key (Blocked)',
      fileIndex: 1, // certs/private.key
      tool: 'fs_read',
      egressUrl: '',
      prompt: 'Inspect RSA private key block and verify key length.',
      description: 'Secrets realm blocks agent tools and enforces air-gap.',
    },
    {
      label: 'Run Unit Tests (Ring 1)',
      fileIndex: 6, // tests/payment.spec.ts
      tool: 'test_runner',
      egressUrl: 'http://localhost:3000/test-hook',
      prompt: 'Execute payment invariant test suite using local test harness.',
      description: 'Test realm allows test_runner and local loopback IPC.',
    },
    {
      label: 'Format Terraform (Ring 1)',
      fileIndex: 3, // infra/terraform/main.tf
      tool: 'terraform_fmt',
      egressUrl: '',
      prompt: 'Check formatting for AWS RDS production instance definition.',
      description: 'Infrastructure realm requires explicit approval before executing formatting tools.',
    },
  ], []);

  const handleApplyPreset = (preset: ActionPreset) => {
    setSelectedFileIndex(preset.fileIndex);
    setPrompt(preset.prompt);
    setRequestedTool(preset.tool);
    setEgressUrl(preset.egressUrl);

    const verdict = orchestrator.intercept({
      fileUri: SAMPLE_WORKSPACE_FILES[preset.fileIndex].path,
      prompt: preset.prompt,
      requestedTool: preset.tool,
      egressUrl: preset.egressUrl,
      packageSigned: isPackageValid,
    });
    setCurrentVerdict(verdict);
  };

  const handleExecuteDispatch = () => {
    const verdict = orchestrator.intercept({
      fileUri: selectedFile.path,
      prompt,
      requestedTool,
      egressUrl: egressUrl.trim() || undefined,
      packageSigned: isPackageValid,
    });
    setCurrentVerdict(verdict);
  };

  return (
    <div className="flex flex-col h-[calc(100vh-58px)] bg-slate-950 text-slate-200 overflow-hidden font-sans">
      {/* Top Presets Toolbar */}
      <div className="flex items-center gap-2 px-6 py-2.5 bg-slate-900/90 border-b border-slate-800 overflow-x-auto">
        <span className="text-xs font-medium text-slate-400 whitespace-nowrap mr-2">
          Attack & Compliance Scenarios:
        </span>
        {presets.map((preset, idx) => (
          <button
            key={idx}
            onClick={() => handleApplyPreset(preset)}
            className="px-2.5 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700/60 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            {preset.label}
          </button>
        ))}
      </div>

      {/* Main 3-Column IDE Layout */}
      <div className="grid grid-cols-12 flex-1 overflow-hidden">
        {/* Left Column: Workspace File Explorer (Col 3) */}
        <div className="col-span-3 bg-slate-900/50 border-r border-slate-800 flex flex-col h-full overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800/80 flex items-center justify-between">
            <span className="text-xs font-semibold tracking-wider text-slate-400 uppercase">
              Workspace Files
            </span>
            <span className="text-[11px] font-mono text-slate-400 tabular-nums">
              {SAMPLE_WORKSPACE_FILES.length} items
            </span>
          </div>

          <div className="p-2 space-y-1 overflow-y-auto flex-1">
            {SAMPLE_WORKSPACE_FILES.map((file, idx) => {
              const isSelected = selectedFileIndex === idx;
              const isSecret = file.expectedRealmId === 'secrets';
              const isInfra = file.expectedRealmId === 'infrastructure';

              return (
                <button
                  key={file.path}
                  onClick={() => {
                    setSelectedFileIndex(idx);
                    const verdict = orchestrator.intercept({
                      fileUri: file.path,
                      prompt,
                      requestedTool,
                      egressUrl: egressUrl.trim() || undefined,
                      packageSigned: isPackageValid,
                    });
                    setCurrentVerdict(verdict);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-lg text-xs flex items-center justify-between transition-colors ${
                    isSelected
                      ? 'bg-indigo-600/20 text-indigo-200 border border-indigo-500/30'
                      : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-2 truncate">
                    {isSecret ? (
                      <Lock className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                    ) : isInfra ? (
                      <Server className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                    ) : (
                      <FileCode className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                    )}
                    <span className="font-mono text-slate-200 truncate">{file.name}</span>
                  </div>
                  <span className="text-[10px] text-slate-400 font-mono shrink-0 ml-1">
                    {file.expectedRealmId}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Active Package Status Card */}
          <div className="p-3 border-t border-slate-800 bg-slate-900/80 text-[11px] space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Package Status</span>
              <span className={`font-mono font-medium ${isPackageValid ? 'text-emerald-400' : 'text-rose-400'}`}>
                {isPackageValid ? 'SIGNED (Ed25519)' : 'TAMPERED / UNTRUSTED'}
              </span>
            </div>
            <div className="flex items-center justify-between text-slate-400">
              <span>Active Realm</span>
              <span className="font-mono text-slate-200">{currentVerdict?.matchedRealm?.name || 'Airgap Isolated'}</span>
            </div>
            <div className="flex items-center justify-between text-slate-400">
              <span>Net-Ring Bound</span>
              <span className="font-mono text-indigo-300 uppercase">{currentVerdict?.matchedRealm?.net_ring || 'ring_0'}</span>
            </div>
          </div>
        </div>

        {/* Center Column: Editor & Request Dispatcher (Col 5) */}
        <div className="col-span-5 flex flex-col h-full border-r border-slate-800 bg-slate-950 overflow-hidden">
          {/* Active File Header */}
          <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900/60 border-b border-slate-800 text-xs">
            <div className="flex items-center gap-2">
              <FileText className="w-3.5 h-3.5 text-slate-400" />
              <span className="font-mono font-medium text-slate-200">{selectedFile.path}</span>
            </div>
            <div className="flex items-center gap-2 text-[11px] text-slate-400">
              <span>{selectedFile.language}</span>
              <span>·</span>
              <span className="font-mono">{selectedFile.content.split('\n').length} lines</span>
            </div>
          </div>

          {/* File Content Preview */}
          <div className="flex-1 p-4 font-mono text-xs overflow-y-auto bg-slate-950/70 border-b border-slate-800 space-y-0.5 leading-relaxed text-slate-300">
            {selectedFile.content.split('\n').map((line, lIdx) => (
              <div key={lIdx} className="flex">
                <span className="w-8 select-none text-slate-400 text-right pr-3 shrink-0 tabular-nums">
                  {lIdx + 1}
                </span>
                <span className="whitespace-pre-wrap break-all">{line}</span>
              </div>
            ))}
          </div>

          {/* Agent Action Dispatcher Form */}
          <div className="p-4 bg-slate-900/80 border-t border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 uppercase tracking-wide">
                Simulated Agent Request
              </span>
              <span className="text-[11px] text-slate-400">
                Tests VS Code Interceptor Pipeline
              </span>
            </div>

            <div>
              <label className="block text-[11px] font-medium text-slate-400 mb-1">
                Developer Prompt / Instruction
              </label>
              <textarea
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                rows={2}
                className="w-full bg-slate-950 border border-slate-800 rounded-md p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500 transition-colors"
                placeholder="Instruct the agent..."
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  Requested Tool
                </label>
                <select
                  value={requestedTool}
                  onChange={(e) => setRequestedTool(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-md p-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  {manifest.tools.map((t) => (
                    <option key={t.name} value={t.name}>
                      {t.name} ({t.risk_level})
                    </option>
                  ))}
                  <option value="network_raw_socket">network_raw_socket (unauthorized)</option>
                  <option value="shell_exec_root">shell_exec_root (blocked)</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] font-medium text-slate-400 mb-1">
                  Egress URL (Model API / Proxy)
                </label>
                <input
                  type="text"
                  value={egressUrl}
                  onChange={(e) => setEgressUrl(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-md p-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
                  placeholder="https://... or empty"
                />
              </div>
            </div>

            <button
              onClick={handleExecuteDispatch}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 text-white font-medium text-xs rounded-md shadow transition-colors flex items-center justify-center gap-2"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Evaluate Security Pipeline</span>
            </button>
          </div>
        </div>

        {/* Right Column: Interceptor Telemetry & Decision Breakdown (Col 4) */}
        <div className="col-span-4 bg-slate-900/40 flex flex-col h-full overflow-hidden">
          {/* Header */}
          <div className="px-4 py-3 bg-slate-900/70 border-b border-slate-800 flex items-center justify-between">
            <span className="text-xs font-semibold tracking-wider text-slate-400 uppercase">
              Interceptor Telemetry
            </span>
            <span className="text-[11px] font-mono text-slate-400">
              4-Phase Gate
            </span>
          </div>

          <div className="p-4 space-y-4 overflow-y-auto flex-1">
            {/* Verdict Summary Box */}
            {currentVerdict && (
              <div
                className={`p-3.5 rounded-lg border text-xs space-y-2 ${
                  currentVerdict.verdict === 'ALLOWED'
                    ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200'
                    : currentVerdict.verdict === 'REQUIRES_USER_APPROVAL'
                    ? 'bg-amber-950/30 border-amber-500/40 text-amber-200'
                    : 'bg-rose-950/30 border-rose-500/40 text-rose-200'
                }`}
              >
                <div className="flex items-center gap-2 font-semibold">
                  {currentVerdict.verdict === 'ALLOWED' ? (
                    <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : currentVerdict.verdict === 'REQUIRES_USER_APPROVAL' ? (
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                  )}
                  <span className="tracking-wide uppercase">
                    Verdict: {currentVerdict.verdict}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed opacity-90 font-mono">
                  {currentVerdict.primaryReason}
                </p>
              </div>
            )}

            {/* Step-by-Step Security Pipeline Checks */}
            <div className="space-y-2.5">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide">
                Evaluation Pipeline
              </span>

              {currentVerdict?.steps.map((st, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-slate-900/80 border border-slate-800 rounded-lg text-xs space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {st.passed ? (
                        <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      ) : (
                        <XCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                      )}
                      <span className="font-medium text-slate-200">
                        {st.title}
                      </span>
                    </div>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        st.passed
                          ? 'bg-emerald-950 text-emerald-300'
                          : 'bg-rose-950 text-rose-300'
                      }`}
                    >
                      {st.passed ? 'PASS' : 'FAIL'}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-normal">
                    {st.details}
                  </p>
                </div>
              ))}
            </div>

            {/* Context Scrubber Output if altered */}
            {currentVerdict?.scrubbedPrompt && currentVerdict.scrubbedPrompt !== prompt && (
              <div className="p-3 bg-slate-900/80 border border-amber-500/30 rounded-lg text-xs space-y-1.5">
                <div className="flex items-center gap-1.5 text-amber-400 font-medium">
                  <KeyRound className="w-3.5 h-3.5" />
                  <span>Prompt Context Scrubber Triggered</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Sensitive credentials in the prompt were sanitized before reaching the model:
                </p>
                <pre className="p-2 bg-slate-950 rounded text-[10px] font-mono text-slate-300 overflow-x-auto">
                  {currentVerdict.scrubbedPrompt}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
