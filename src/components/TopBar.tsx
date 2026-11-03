import React from 'react';
import { Shield, ShieldAlert, CheckCircle2 } from 'lucide-react';

export type ActiveTab = 'ide' | 'policy' | 'gatekeeper' | 'source';

interface TopBarProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  isSignedAndValid: boolean;
  onRunAudit: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  onTabChange,
  isSignedAndValid,
  onRunAudit,
}) => {
  return (
    <header className="flex items-center justify-between gap-8 px-6 py-3.5 bg-slate-900 border-b border-slate-800 text-white select-none">
      {/* Zone 1: Brand Wordmark (Single text element) */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="w-8 h-8 rounded-lg bg-indigo-600/30 border border-indigo-500/40 flex items-center justify-center text-indigo-400">
          <Shield className="w-4 h-4" />
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-semibold tracking-tight text-slate-100 whitespace-nowrap">
            Local Agent Security Architecture
          </span>
          <span className="text-[11px] text-slate-400 font-mono">
            VS Code Extension · Realm & Net-Ring Guard
          </span>
        </div>
      </div>

      {/* Zone 2: Navigation Links (Single-line controls) */}
      <nav className="hidden md:flex items-center gap-1 bg-slate-950/60 p-1 rounded-lg border border-slate-800/80">
        <button
          onClick={() => onTabChange('ide')}
          className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'ide'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
          }`}
        >
          IDE Interceptor
        </button>

        <button
          onClick={() => onTabChange('policy')}
          className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'policy'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
          }`}
        >
          Policy & Net-Rings
        </button>

        <button
          onClick={() => onTabChange('gatekeeper')}
          className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
            activeTab === 'gatekeeper'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
          }`}
        >
          <span>Gatekeeper Lab</span>
          {isSignedAndValid ? (
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          ) : (
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          )}
        </button>

        <button
          onClick={() => onTabChange('source')}
          className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'source'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
          }`}
        >
          Source Code & Exports
        </button>
      </nav>

      {/* Zone 3: Primary Action */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          onClick={onRunAudit}
          className="px-3.5 py-1.5 text-xs font-medium text-white bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 rounded-lg transition-colors whitespace-nowrap shrink-0 shadow-sm flex items-center gap-1.5"
        >
          <span>Run All Tests</span>
        </button>
      </div>
    </header>
  );
};
