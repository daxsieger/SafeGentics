import React, { useState } from 'react';
import {
  Shield,
  Layers,
  Globe,
  Lock,
  Server,
  Code2,
  TestTube,
  Check,
  X,
  FileCode,
  ArrowRight,
} from 'lucide-react';
import { AgentPackageManifest } from '../security/types.ts';
import { RealmEngine } from '../security/realm-engine.ts';
import { NetRingGuard } from '../security/net-ring-guard.ts';

interface PolicyMatrixProps {
  manifest: AgentPackageManifest;
}

export const PolicyMatrix: React.FC<PolicyMatrixProps> = ({ manifest }) => {
  const [testPath, setTestPath] = useState<string>('src/services/billing.ts');
  const [testTool, setTestTool] = useState<string>('code_refactor');
  const [testUrl, setTestUrl] = useState<string>('https://api.openai.com/v1/chat');

  const realmEngine = new RealmEngine(manifest.realms);
  const netRingGuard = new NetRingGuard(manifest.net_rings);

  const resolvedRealm = realmEngine.resolveRealm(testPath);
  const toolCheck = realmEngine.isToolAllowed(resolvedRealm, testTool);
  const egressCheck = testUrl ? netRingGuard.evaluateEgress(resolvedRealm.net_ring, testUrl) : null;

  return (
    <div className="flex-1 p-6 bg-slate-950 text-slate-200 overflow-y-auto space-y-8 font-sans">
      {/* Header Overview */}
      <div className="space-y-1">
        <h2 className="text-xl font-bold tracking-tight text-slate-100">
          Policy Specification & Ring Isolation Matrix
        </h2>
        <p className="text-xs text-slate-400">
          Declarative privileges loaded from <span className="font-mono text-indigo-400">agent-package.yaml</span>.
          Enforces the principle of least privilege across workspace directories and network sockets.
        </p>
      </div>

      {/* Net-Ring Tier Cards */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-indigo-400" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Net-Ring Network Egress Tiers
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {Object.entries(manifest.net_rings).map(([ringId, ring]) => {
            const isRing0 = ring.tier === 0;
            const isRing1 = ring.tier === 1;
            const isRing2 = ring.tier === 2;

            return (
              <div
                key={ringId}
                className={`p-4 rounded-xl border flex flex-col justify-between ${
                  isRing0
                    ? 'bg-rose-950/20 border-rose-500/30'
                    : isRing1
                    ? 'bg-amber-950/20 border-amber-500/30'
                    : isRing2
                    ? 'bg-blue-950/20 border-blue-500/30'
                    : 'bg-emerald-950/20 border-emerald-500/30'
                }`}
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold uppercase text-slate-200">
                      Tier {ring.tier}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                        isRing0
                          ? 'bg-rose-900/40 text-rose-300'
                          : isRing1
                          ? 'bg-amber-900/40 text-amber-300'
                          : isRing2
                          ? 'bg-blue-900/40 text-blue-300'
                          : 'bg-emerald-900/40 text-emerald-300'
                      }`}
                    >
                      {ringId}
                    </span>
                  </div>

                  <h4 className="text-sm font-semibold text-slate-100">{ring.name}</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">{ring.description}</p>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-1.5 text-[11px]">
                  <div className="text-slate-400 font-medium">Permitted Destinations:</div>
                  {ring.allowed_hosts.length === 0 ? (
                    <div className="text-rose-400 font-mono">None (Air-Gapped)</div>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {ring.allowed_hosts.map((h, i) => (
                        <span key={i} className="font-mono bg-slate-900 text-slate-300 px-1.5 py-0.5 rounded border border-slate-800">
                          {h}
                        </span>
                      ))}
                    </div>
                  )}
                  <div className="flex items-center justify-between text-slate-400 pt-1">
                    <span>Loopback IPC:</span>
                    <span className="font-mono text-slate-200">
                      {ring.allow_loopback ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Realms Table */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-indigo-400" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
            Workspace Realms & Path Capabilities
          </h3>
        </div>

        <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/40">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold text-[11px]">
                <tr>
                  <th className="py-3 px-4">Realm Domain</th>
                  <th className="py-3 px-4">Bound Ring</th>
                  <th className="py-3 px-4">Path Glob Patterns</th>
                  <th className="py-3 px-4">Allowed Tools</th>
                  <th className="py-3 px-4">Approval Required</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                {Object.entries(manifest.realms).map(([key, realm]) => {
                  return (
                    <tr key={key} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-sans">
                        <div className="font-semibold text-slate-200">{realm.name}</div>
                        <div className="text-[11px] text-slate-400 font-mono">{realm.id}</div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 bg-slate-800 text-indigo-300 rounded text-[11px] border border-slate-700">
                          {realm.net_ring}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex flex-col gap-0.5 text-[11px] text-slate-300">
                          {realm.paths.map((p, pi) => (
                            <span key={pi} className="text-slate-300">{p}</span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        {realm.allowed_tools.length === 0 ? (
                          <span className="text-rose-400">Zero Tools (Locked)</span>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {realm.allowed_tools.map((t, ti) => (
                              <span key={ti} className="bg-slate-800 px-1.5 py-0.5 rounded text-[10px] text-slate-300">
                                {t}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {realm.require_user_confirmation ? (
                          <span className="text-amber-400 font-sans font-medium flex items-center gap-1">
                            <Lock className="w-3.5 h-3.5" />
                            <span>Yes (Gatekeeper)</span>
                          </span>
                        ) : (
                          <span className="text-slate-400 font-sans">No (Automated)</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Interactive Policy Query Tester */}
      <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="space-y-0.5">
            <h4 className="text-sm font-semibold text-slate-200">
              Interactive Policy Query Sandbox
            </h4>
            <p className="text-xs text-slate-400">
              Test how any custom file path, tool action, and network destination evaluates against the active policy.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
          <div>
            <label className="block text-slate-400 font-sans mb-1 text-[11px]">
              Target File Path
            </label>
            <input
              type="text"
              value={testPath}
              onChange={(e) => setTestPath(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-indigo-500"
              placeholder="e.g. src/auth/token.ts"
            />
          </div>

          <div>
            <label className="block text-slate-400 font-sans mb-1 text-[11px]">
              Requested Tool
            </label>
            <input
              type="text"
              value={testTool}
              onChange={(e) => setTestTool(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-indigo-500"
              placeholder="e.g. code_refactor or fs_read"
            />
          </div>

          <div>
            <label className="block text-slate-400 font-sans mb-1 text-[11px]">
              Outbound Egress Destination
            </label>
            <input
              type="text"
              value={testUrl}
              onChange={(e) => setTestUrl(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-indigo-500"
              placeholder="e.g. https://api.openai.com/v1"
            />
          </div>
        </div>

        {/* Evaluation Output Preview */}
        <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 text-xs">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-slate-400 font-sans">Resolved Realm:</span>
              <span className="font-semibold text-slate-100">{resolvedRealm.name}</span>
              <span className="font-mono text-indigo-400">({resolvedRealm.id})</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-slate-400 font-sans">Tool Check:</span>
              <span className={`font-mono font-medium ${toolCheck.allowed ? 'text-emerald-400' : 'text-rose-400'}`}>
                {toolCheck.allowed ? 'GRANTED' : 'DENIED'}
              </span>
              <span className="text-slate-400 text-[11px]">— {toolCheck.reason}</span>
            </div>
            {egressCheck && (
              <div className="flex items-center gap-2">
                <span className="text-slate-400 font-sans">Net-Ring Check:</span>
                <span className={`font-mono font-medium ${egressCheck.allowed ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {egressCheck.allowed ? 'PERMITTED' : 'BLOCKED'}
                </span>
                <span className="text-slate-400 text-[11px]">— {egressCheck.reason}</span>
              </div>
            )}
          </div>

          <div className="shrink-0">
            <span
              className={`px-3 py-1.5 rounded-lg font-mono text-xs font-semibold uppercase ${
                toolCheck.allowed && (!egressCheck || egressCheck.allowed)
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                  : 'bg-rose-950 text-rose-300 border border-rose-500/40'
              }`}
            >
              {toolCheck.allowed && (!egressCheck || egressCheck.allowed) ? 'PASS' : 'BLOCKED'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
