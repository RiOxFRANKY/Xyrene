import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { CheckCircle, AlertCircle } from 'lucide-react';

export default function SettingsPage() {
  const [apiUrl, setApiUrl] = useState('http://127.0.0.1:5000');
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'success' | 'error'>('idle');
  const [iface, setIface] = useState('eth0');
  const [verbose, setVerbose] = useState(false);
  const [suspThreshold, setSuspThreshold] = useState('5');
  const [malThreshold, setMalThreshold] = useState('3');
  const [windowTime, setWindowTime] = useState('60');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [slackUrl, setSlackUrl] = useState('');
  const [webhookEnabled, setWebhookEnabled] = useState(false);
  const [slackEnabled, setSlackEnabled] = useState(false);
  const [whitelist, setWhitelist] = useState('192.168.1.1\n10.0.0.1');

  const testConnection = () => {
    setConnectionStatus('success');
    setTimeout(() => setConnectionStatus('idle'), 3000);
  };

  const inputClass = "h-8 w-full rounded-md bg-secondary text-secondary-foreground border border-border px-3 text-xs font-mono placeholder:text-muted-foreground";
  const labelClass = "text-[11px] text-muted-foreground block mb-1";

  return (
    <div className="max-w-2xl space-y-6">
      {/* API */}
      <Section title="API Connection">
        <div>
          <label className={labelClass}>API URL</label>
          <div className="flex gap-2">
            <input value={apiUrl} onChange={(e) => setApiUrl(e.target.value)} className={inputClass} />
            <Button size="sm" className="h-8 text-xs shrink-0" onClick={testConnection}>Test Connection</Button>
          </div>
          {connectionStatus === 'success' && (
            <div className="flex items-center gap-1.5 mt-1.5 text-zone-safe text-[11px]">
              <CheckCircle className="h-3 w-3" /> Connected
            </div>
          )}
          {connectionStatus === 'error' && (
            <div className="flex items-center gap-1.5 mt-1.5 text-destructive text-[11px]">
              <AlertCircle className="h-3 w-3" /> Failed to connect
            </div>
          )}
        </div>
      </Section>

      {/* Capture */}
      <Section title="Capture Settings">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={labelClass}>Network Interface</label>
            <select value={iface} onChange={(e) => setIface(e.target.value)} className={inputClass}>
              <option>eth0</option>
              <option>wlan0</option>
              <option>lo</option>
            </select>
          </div>
          <div>
            <label className={labelClass}>Verbose Mode</label>
            <button
              onClick={() => setVerbose(!verbose)}
              className={`h-8 w-12 rounded-full border border-border transition-colors ${verbose ? 'bg-primary' : 'bg-secondary'}`}
            >
              <div className={`h-5 w-5 rounded-full bg-foreground transition-transform mx-0.5 ${verbose ? 'translate-x-5' : 'translate-x-0.5'}`} />
            </button>
          </div>
        </div>
      </Section>

      {/* Thresholds */}
      <Section title="Threshold Settings">
        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className={labelClass}>Suspicious (X events)</label>
            <input value={suspThreshold} onChange={(e) => setSuspThreshold(e.target.value)} type="number" className={inputClass} />
          </div>
          <div>
            <label className={labelClass}>Malicious (Y events)</label>
            <input value={malThreshold} onChange={(e) => setMalThreshold(e.target.value)} type="number" className={inputClass} />
          </div>
          <div>
            <label className={labelClass}>Window (seconds)</label>
            <input value={windowTime} onChange={(e) => setWindowTime(e.target.value)} type="number" className={inputClass} />
          </div>
        </div>
        <Button size="sm" className="h-8 text-xs mt-3">Save Thresholds</Button>
      </Section>

      {/* Alerts */}
      <Section title="Alert Settings">
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setWebhookEnabled(!webhookEnabled)}
              className={`h-5 w-9 rounded-full border border-border transition-colors shrink-0 ${webhookEnabled ? 'bg-primary' : 'bg-secondary'}`}
            >
              <div className={`h-3.5 w-3.5 rounded-full bg-foreground transition-transform mx-0.5 ${webhookEnabled ? 'translate-x-3.5' : 'translate-x-0.5'}`} />
            </button>
            <input value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} placeholder="Webhook URL" className={inputClass} />
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSlackEnabled(!slackEnabled)}
              className={`h-5 w-9 rounded-full border border-border transition-colors shrink-0 ${slackEnabled ? 'bg-primary' : 'bg-secondary'}`}
            >
              <div className={`h-3.5 w-3.5 rounded-full bg-foreground transition-transform mx-0.5 ${slackEnabled ? 'translate-x-3.5' : 'translate-x-0.5'}`} />
            </button>
            <input value={slackUrl} onChange={(e) => setSlackUrl(e.target.value)} placeholder="Slack Webhook URL" className={inputClass} />
          </div>
        </div>
      </Section>

      {/* Whitelist */}
      <Section title="Whitelist">
        <div>
          <label className={labelClass}>Trusted IPs (one per line)</label>
          <textarea
            value={whitelist}
            onChange={(e) => setWhitelist(e.target.value)}
            rows={5}
            className="w-full rounded-md bg-secondary text-secondary-foreground border border-border px-3 py-2 text-xs font-mono placeholder:text-muted-foreground resize-none"
          />
        </div>
        <Button size="sm" className="h-8 text-xs mt-2">Save Whitelist</Button>
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-card border border-border rounded-md p-4 space-y-3">
      <h2 className="text-xs font-semibold text-card-foreground uppercase tracking-wider">{title}</h2>
      {children}
    </div>
  );
}
