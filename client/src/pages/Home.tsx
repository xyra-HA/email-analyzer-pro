import { useState, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import {
  Upload, Settings, Copy, Check, AlertCircle, Shield, Zap,
  Download, Trash2, Mail, Globe, Server, Hash, Key, FileText,
  AlertTriangle, Database, Search, List, ChevronRight, Wifi
} from 'lucide-react';
import { toast } from 'sonner';

interface IOC {
  type: string;
  value: string;
  defanged: string;
  context?: string;
}

interface EmailAuth {
  spf: string;
  dkim: string;
  dmarc: string;
  raw: string;
}

interface RoutingHop {
  from: string;
  by: string;
  time: string;
  delay: string;
}

interface Anomaly {
  severity: 'high' | 'medium' | 'low';
  description: string;
}

interface AnalysisResult {
  emails: IOC[];
  ips: IOC[];
  urls: IOC[];
  domains: IOC[];
  hashes: IOC[];
  auth: EmailAuth;
  routing: RoutingHop[];
  anomalies: Anomaly[];
  headers: Record<string, string>;
  subject: string;
  from: string;
  to: string;
  date: string;
  messageId: string;
}

const defang = (v: string) =>
  v.replace(/\./g, '[.]').replace(/http/g, 'hxxp').replace(/:/g, '[:]').replace(/@/g, '[@]');

const unique = (arr: string[]) => Array.from(new Set(arr));

function parseHeaders(text: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const lines = text.split('\n');
  let currentKey = '';
  for (const line of lines) {
    if (/^\s+/.test(line) && currentKey) {
      headers[currentKey] += ' ' + line.trim();
    } else {
      const match = line.match(/^([^:]+):\s*(.*)$/);
      if (match) { currentKey = match[1].trim(); headers[currentKey] = match[2].trim(); }
    }
  }
  return headers;
}

function extractAuth(text: string): EmailAuth {
  const authResults = text.match(/Authentication-Results:[\s\S]*?(?=\n[^\s]|$)/i)?.[0] || '';
  const spf = text.match(/spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i)?.[1]?.toUpperCase() || 'NONE';
  const dkim = text.match(/dkim=(pass|fail|none|neutral|temperror|permerror)/i)?.[1]?.toUpperCase() || 'NONE';
  const dmarc = text.match(/dmarc=(pass|fail|none|bestguesspass)/i)?.[1]?.toUpperCase() || 'NONE';
  return { spf, dkim, dmarc, raw: authResults };
}

function extractRouting(text: string): RoutingHop[] {
  const hops: RoutingHop[] = [];
  const receivedHeaders = [...text.matchAll(/Received:\s*([\s\S]*?)(?=\nReceived:|\nFrom:|\nTo:|\nSubject:|$)/gi)];
  for (const match of receivedHeaders) {
    const block = match[1];
    const from = block.match(/from\s+([^\s]+)/i)?.[1] || '—';
    const by = block.match(/by\s+([^\s]+)/i)?.[1] || '—';
    const time = block.match(/;\s*(.+)$/m)?.[1]?.trim() || '—';
    hops.push({ from, by, time, delay: '—' });
  }
  return hops;
}

function detectAnomalies(text: string, auth: EmailAuth, headers: Record<string, string>): Anomaly[] {
  const anomalies: Anomaly[] = [];
  if (auth.spf === 'FAIL' || auth.spf === 'SOFTFAIL')
    anomalies.push({ severity: 'high', description: `SPF ${auth.spf} — sender may be spoofed` });
  if (auth.dkim === 'FAIL')
    anomalies.push({ severity: 'high', description: 'DKIM signature failed — email may be tampered' });
  if (auth.dmarc === 'FAIL')
    anomalies.push({ severity: 'high', description: 'DMARC policy failed — likely spoofed domain' });
  if (auth.spf === 'NONE' && auth.dkim === 'NONE')
    anomalies.push({ severity: 'medium', description: 'No SPF or DKIM configured on sender domain' });
  if (/urgent|immediately|verify|suspended|limited|click here|confirm your/i.test(text))
    anomalies.push({ severity: 'medium', description: 'Phishing keywords detected in email body' });
  if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(headers['From'] || ''))
    anomalies.push({ severity: 'high', description: 'IP address used in From header instead of domain' });
  if (!headers['Message-ID'])
    anomalies.push({ severity: 'medium', description: 'Missing Message-ID header — suspicious' });
  if (anomalies.length === 0)
    anomalies.push({ severity: 'low', description: 'No major anomalies detected' });
  return anomalies;
}

function generateSIEM(result: AnalysisResult): string {
  const lines: string[] = [
    `// SPL (Splunk)`,
    `index=email subject="${result.subject}" src_user="${result.from}"`,
    `| eval spf="${result.auth.spf}", dkim="${result.auth.dkim}", dmarc="${result.auth.dmarc}"`,
    ``,
    `// KQL (Microsoft Sentinel)`,
    `EmailEvents`,
    `| where SenderFromAddress == "${result.from}"`,
    `| where Subject contains "${result.subject}"`,
    ``,
    `// Sigma Rule`,
    `title: Suspicious Email IOC`,
    `status: experimental`,
    `logsource:`,
    `  category: email`,
    `detection:`,
    `  selection:`,
    `    from: '${result.from}'`,
    `    subject: '${result.subject}'`,
    `  condition: selection`,
  ];
  if (result.ips.length > 0) {
    lines.push(``, `// IP IOCs`);
    result.ips.forEach(ip => lines.push(`// ${ip.value}`));
  }
  return lines.join('\n');
}

function analyzeEmail(text: string): AnalysisResult {
  const headers = parseHeaders(text);
  const auth = extractAuth(text);
  const routing = extractRouting(text);
  const anomalies = detectAnomalies(text, auth, headers);

  const emailMatches = unique(text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []);
  const ipMatches = unique(text.match(/\b(?:(?!0\.|255\.)(?:\d{1,3}\.){3}\d{1,3})\b/g) || []);
  const urlMatches = unique(text.match(/https?:\/\/[^\s"'<>]+/g) || []);
  const domainMatches = unique(text.match(/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/gi) || [])
    .filter(d => !emailMatches.some(e => e.includes(d)));
  const hashMatches = unique(text.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g) || []);

  return {
    emails: emailMatches.map(v => ({ type: 'Email', value: v, defanged: defang(v) })),
    ips: ipMatches.map(v => ({ type: 'IP', value: v, defanged: defang(v) })),
    urls: urlMatches.map(v => ({ type: 'URL', value: v, defanged: defang(v) })),
    domains: domainMatches.map(v => ({ type: 'Domain', value: v, defanged: defang(v) })),
    hashes: hashMatches.map(v => ({ type: 'Hash', value: v, defanged: v })),
    auth, routing, anomalies, headers,
    subject: headers['Subject'] || '—',
    from: headers['From'] || '—',
    to: headers['To'] || '—',
    date: headers['Date'] || '—',
    messageId: headers['Message-ID'] || '—',
  };
}

function AuthBadge({ value }: { value: string }) {
  const color = value === 'PASS' ? 'bg-green-900 text-green-300 border-green-700'
    : value === 'FAIL' || value === 'SOFTFAIL' ? 'bg-red-900 text-red-300 border-red-700'
    : 'bg-zinc-800 text-zinc-400 border-zinc-700';
  return <span className={`px-2 py-0.5 rounded text-xs font-mono border ${color}`}>{value}</span>;
}

function SeverityBadge({ severity }: { severity: string }) {
  const color = severity === 'high' ? 'bg-red-900/60 text-red-300 border-red-700'
    : severity === 'medium' ? 'bg-yellow-900/60 text-yellow-300 border-yellow-700'
    : 'bg-green-900/60 text-green-300 border-green-700';
  return <span className={`px-2 py-0.5 rounded text-xs font-semibold border uppercase ${color}`}>{severity}</span>;
}

function CopyBtn({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const handle = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast.success(`Copied ${label}`);
  };
  return (
    <button onClick={handle}
      className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-white/5 hover:bg-burgundy/20 border border-white/10 hover:border-burgundy/40 transition-all text-zinc-300 hover:text-white">
      {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
      {copied ? 'Copied' : label}
    </button>
  );
}

function IOCCard({ ioc }: { ioc: IOC }) {
  return (
    <div className="rounded-lg border border-white/8 bg-white/3 p-3 space-y-2 hover:border-burgundy/30 transition-all">
      <div className="flex items-center justify-between gap-2">
        <span className="px-2 py-0.5 rounded text-xs font-semibold bg-burgundy/20 text-burgundy-light border border-burgundy/30">
          {ioc.type}
        </span>
        <div className="flex gap-1.5">
          <CopyBtn text={ioc.defanged} label="Copy defanged" />
          <CopyBtn text={ioc.value} label="Copy raw" />
        </div>
      </div>
      <code className="block text-sm text-zinc-200 font-mono break-all">{ioc.value}</code>
      <div className="text-xs text-zinc-500">
        Defanged: <code className="text-zinc-400 font-mono">{ioc.defanged}</code>
      </div>
      <div className="text-xs text-zinc-600 flex items-center gap-1">
        <span className="w-2 h-2 rounded-full bg-zinc-700 inline-block" />
        No API keys configured —{' '}
        <button onClick={() => {}} className="text-burgundy-light hover:underline">configure to enrich</button>
      </div>
    </div>
  );
}

export default function Home() {
  const [isDragging, setIsDragging] = useState(false);
  const [rawEmail, setRawEmail] = useState('');
  const [results, setResults] = useState<AnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [apiKeys, setApiKeys] = useState({
    virustotal: localStorage.getItem('vt-key') || '',
    abuseipdb: localStorage.getItem('abuse-key') || '',
    otx: localStorage.getItem('otx-key') || '',
  });
  const fileInputRef = useRef<HTMLInputElement>(null);

  const totalIOCs = results
    ? results.emails.length + results.ips.length + results.urls.length + results.domains.length + results.hashes.length
    : 0;

  const allIOCs = results
    ? [...results.emails, ...results.ips, ...results.urls, ...results.domains, ...results.hashes]
    : [];

  const handleFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setRawEmail(content);
      runAnalysis(content);
    };
    reader.readAsText(file);
  };

  const runAnalysis = (text: string) => {
    setIsAnalyzing(true);
    setTimeout(() => {
      setResults(analyzeEmail(text));
      setIsAnalyzing(false);
      toast.success('Analysis complete!');
    }, 600);
  };

  const exportJSON = () => {
    if (!results) return;
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'iocs.json'; a.click();
  };

  const exportTXT = () => {
    if (!results) return;
    const lines = allIOCs.map(i => `[${i.type}] ${i.value} | defanged: ${i.defanged}`);
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'iocs.txt'; a.click();
  };

  const copyDefanged = () => {
    const text = allIOCs.map(i => i.defanged).join('\n');
    navigator.clipboard.writeText(text);
    toast.success('All defanged IOCs copied!');
  };

  const handleSaveKeys = () => {
    localStorage.setItem('vt-key', apiKeys.virustotal);
    localStorage.setItem('abuse-key', apiKeys.abuseipdb);
    localStorage.setItem('otx-key', apiKeys.otx);
    setShowSettings(false);
    toast.success('API keys saved!');
  };

  const apiConfigured = !!(apiKeys.virustotal || apiKeys.abuseipdb || apiKeys.otx);

  return (
    <div className="min-h-screen bg-black text-zinc-100">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-white/8 bg-black/80 backdrop-blur-md">
        <div className="container flex items-center justify-between py-3">
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-burgundy-light" />
            <span className="text-lg font-bold text-white">SOCAnalyzer</span>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-burgundy/30 text-burgundy-light border border-burgundy/40 ml-1">v1.0</span>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowSettings(true)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm border transition-all ${
                apiConfigured
                  ? 'bg-green-900/30 border-green-700/50 text-green-300'
                  : 'bg-white/5 border-white/10 text-zinc-400 hover:text-white'
              }`}
            >
              <div className={`w-2 h-2 rounded-full ${apiConfigured ? 'bg-green-400' : 'bg-zinc-500'}`} />
              {apiConfigured ? 'All APIs Configured' : 'Configure APIs'}
            </button>
            <Button variant="outline" size="sm" onClick={() => setShowSettings(true)} className="gap-2 border-white/10 bg-white/5 hover:bg-white/10">
              <Settings className="w-4 h-4" /> Settings
            </Button>
          </div>
        </div>
      </header>

      <main className="container py-8 space-y-6">
        {/* Upload Zone */}
        <Card
          className={`border-2 border-dashed p-10 flex flex-col items-center justify-center gap-4 cursor-pointer transition-all duration-300 bg-zinc-950 ${
            isDragging ? 'border-burgundy bg-burgundy/5' : 'border-white/10 hover:border-burgundy/40'
          }`}
          onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={(e) => { e.preventDefault(); setIsDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
          onClick={() => fileInputRef.current?.click()}
        >
          <div className="p-4 rounded-full bg-burgundy/10 border border-burgundy/20">
            <Mail className="w-8 h-8 text-burgundy-light" />
          </div>
          <div className="text-center">
            <p className="font-semibold text-white">Drag & drop your email file here</p>
            <p className="text-sm text-zinc-500 mt-1">Supports .eml · .txt · or paste raw email content below</p>
          </div>
          <Button variant="outline" size="sm" className="border-white/15 bg-white/5 hover:bg-white/10 text-zinc-300">
            Browse File
          </Button>
          <input ref={fileInputRef} type="file" accept=".eml,.txt" className="hidden"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }} />
        </Card>

        {/* Paste Zone */}
        <Card className="p-5 bg-zinc-950 border border-white/8 space-y-3">
          <p className="text-sm text-zinc-400 font-medium">Or paste raw email content:</p>
          <Textarea
            placeholder="Paste raw email headers and body here…"
            value={rawEmail}
            onChange={(e) => setRawEmail(e.target.value)}
            className="min-h-36 font-mono text-sm resize-none bg-black/40 border-white/10 text-zinc-200 placeholder:text-zinc-600"
          />
          <Button
            onClick={() => { if (!rawEmail.trim()) { toast.error('Paste email content first'); return; } runAnalysis(rawEmail); }}
            disabled={isAnalyzing || !rawEmail.trim()}
            className="w-full btn-gradient text-white font-semibold py-2.5"
          >
            {isAnalyzing ? <><Zap className="w-4 h-4 animate-spin mr-2" />Analyzing…</> : 'Analyze Pasted Email'}
          </Button>
        </Card>

        {/* Results */}
        {results && (
          <div className="space-y-4">
            {/* Results Header */}
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-xl font-bold text-white">Analysis Results</h2>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" onClick={copyDefanged}
                  className="gap-1.5 border-white/10 bg-white/5 hover:bg-white/10 text-zinc-300 text-xs">
                  <Copy className="w-3 h-3" /> Copy Defanged IOCs
                </Button>
                <Button size="sm" variant="outline" onClick={exportJSON}
                  className="gap-1.5 border-white/10 bg-white/5 hover:bg-white/10 text-zinc-300 text-xs">
                  <Download className="w-3 h-3" /> Export JSON
                </Button>
                <Button size="sm" variant="outline" onClick={exportTXT}
                  className="gap-1.5 border-white/10 bg-white/5 hover:bg-white/10 text-zinc-300 text-xs">
                  <FileText className="w-3 h-3" /> Export TXT
                </Button>
                <Button size="sm" variant="outline"
                  onClick={() => { setResults(null); setRawEmail(''); }}
                  className="gap-1.5 border-red-900/40 bg-red-950/20 hover:bg-red-950/40 text-red-400 text-xs">
                  <Trash2 className="w-3 h-3" /> Clear
                </Button>
              </div>
            </div>

            {/* IOC Count Badges */}
            <div className="flex flex-wrap gap-2">
              <span className="px-3 py-1 rounded-full text-sm font-semibold bg-burgundy/20 text-burgundy-light border border-burgundy/30">
                {totalIOCs} Total IOCs
              </span>
              {results.emails.length > 0 && <span className="px-3 py-1 rounded-full text-sm bg-white/5 border border-white/10 text-zinc-300">{results.emails.length} Emails</span>}
              {results.ips.length > 0 && <span className="px-3 py-1 rounded-full text-sm bg-white/5 border border-white/10 text-zinc-300">{results.ips.length} IPs</span>}
              {results.urls.length > 0 && <span className="px-3 py-1 rounded-full text-sm bg-white/5 border border-white/10 text-zinc-300">{results.urls.length} URLs</span>}
              {results.domains.length > 0 && <span className="px-3 py-1 rounded-full text-sm bg-white/5 border border-white/10 text-zinc-300">{results.domains.length} Domains</span>}
              {results.hashes.length > 0 && <span className="px-3 py-1 rounded-full text-sm bg-white/5 border border-white/10 text-zinc-300">{results.hashes.length} Hashes</span>}
            </div>

            {/* Tabs */}
            <Tabs defaultValue="iocs" className="space-y-4">
              <TabsList className="bg-zinc-950 border border-white/8 flex-wrap h-auto gap-1 p-1">
                <TabsTrigger value="iocs" className="data-[state=active]:bg-burgundy/20 data-[state=active]:text-burgundy-light text-xs gap-1.5">
                  <List className="w-3 h-3" /> IOC Details
                </TabsTrigger>
                <TabsTrigger value="defanged" className="data-[state=active]:bg-burgundy/20 data-[state=active]:text-burgundy-light text-xs gap-1.5">
                  <Shield className="w-3 h-3" /> Defanged IOCs
                </TabsTrigger>
                <TabsTrigger value="auth" className="data-[state=active]:bg-burgundy/20 data-[state=active]:text-burgundy-light text-xs gap-1.5">
                  <Key className="w-3 h-3" /> Email Auth
                </TabsTrigger>
                <TabsTrigger value="routing" className="data-[state=active]:bg-burgundy/20 data-[state=active]:text-burgundy-light text-xs gap-1.5">
                  <Wifi className="w-3 h-3" /> Routing Path
                </TabsTrigger>
                <TabsTrigger value="anomalies" className="data-[state=active]:bg-burgundy/20 data-[state=active]:text-burgundy-light text-xs gap-1.5">
                  <AlertTriangle className="w-3 h-3" /> Anomalies
                </TabsTrigger>
                <TabsTrigger value="payloads" className="data-[state=active]:bg-burgundy/20 data-[state=active]:text-burgundy-light text-xs gap-1.5">
                  <Globe className="w-3 h-3" /> Payloads
                </TabsTrigger>
                <TabsTrigger value="whois" className="data-[state=active]:bg-burgundy/20 data-[state=active]:text-burgundy-light text-xs gap-1.5">
                  <Database className="w-3 h-3" /> WHOIS
                </TabsTrigger>
                <TabsTrigger value="siem" className="data-[state=active]:bg-burgundy/20 data-[state=active]:text-burgundy-light text-xs gap-1.5">
                  <Search className="w-3 h-3" /> SIEM Queries
                </TabsTrigger>
                <TabsTrigger value="headers" className="data-[state=active]:bg-burgundy/20 data-[state=active]:text-burgundy-light text-xs gap-1.5">
                  <FileText className="w-3 h-3" /> Headers
                </TabsTrigger>
              </TabsList>

              {/* IOC Details */}
              <TabsContent value="iocs" className="space-y-3">
                {allIOCs.length === 0 ? (
                  <div className="text-center py-12 text-zinc-500">No IOCs found in this email</div>
                ) : (
                  <div className="grid md:grid-cols-2 gap-3">
                    {allIOCs.map((ioc, i) => <IOCCard key={i} ioc={ioc} />)}
                  </div>
                )}
              </TabsContent>

              {/* Defanged IOCs */}
              <TabsContent value="defanged">
                <Card className="p-4 bg-zinc-950 border border-white/8">
                  <div className="flex justify-between items-center mb-3">
                    <h3 className="text-sm font-semibold text-zinc-300">All Defanged IOCs</h3>
                    <CopyBtn text={allIOCs.map(i => i.defanged).join('\n')} label="Copy all" />
                  </div>
                  <pre className="text-xs font-mono text-zinc-400 whitespace-pre-wrap leading-6">
                    {allIOCs.map(i => `[${i.type}] ${i.defanged}`).join('\n') || 'No IOCs found'}
                  </pre>
                </Card>
              </TabsContent>

              {/* Email Auth */}
              <TabsContent value="auth" className="space-y-4">
                <Card className="p-5 bg-zinc-950 border border-white/8 space-y-4">
                  <h3 className="text-sm font-semibold text-zinc-300">Authentication Results</h3>
                  <div className="grid grid-cols-3 gap-4">
                    {(['spf', 'dkim', 'dmarc'] as const).map(k => (
                      <div key={k} className="text-center space-y-2 p-4 rounded-lg bg-black/40 border border-white/8">
                        <p className="text-xs text-zinc-500 uppercase font-semibold">{k}</p>
                        <AuthBadge value={results.auth[k]} />
                      </div>
                    ))}
                  </div>
                  {results.auth.raw && (
                    <div>
                      <p className="text-xs text-zinc-500 mb-2">Raw Authentication-Results header:</p>
                      <pre className="text-xs font-mono text-zinc-400 bg-black/40 p-3 rounded border border-white/8 whitespace-pre-wrap">{results.auth.raw}</pre>
                    </div>
                  )}
                </Card>
                <Card className="p-5 bg-zinc-950 border border-white/8 space-y-2">
                  <h3 className="text-sm font-semibold text-zinc-300 mb-3">Email Metadata</h3>
                  {[
                    ['From', results.from], ['To', results.to],
                    ['Subject', results.subject], ['Date', results.date],
                    ['Message-ID', results.messageId],
                  ].map(([k, v]) => (
                    <div key={k} className="flex gap-3 text-sm border-b border-white/5 pb-2">
                      <span className="text-zinc-500 w-24 shrink-0">{k}:</span>
                      <span className="text-zinc-300 font-mono break-all">{v}</span>
                    </div>
                  ))}
                </Card>
              </TabsContent>

              {/* Routing Path */}
              <TabsContent value="routing">
                <Card className="p-5 bg-zinc-950 border border-white/8">
                  <h3 className="text-sm font-semibold text-zinc-300 mb-4">Email Routing Path</h3>
                  {results.routing.length === 0 ? (
                    <p className="text-zinc-500 text-sm">No Received headers found</p>
                  ) : (
                    <div className="space-y-3">
                      {results.routing.map((hop, i) => (
                        <div key={i} className="flex items-start gap-3">
                          <div className="flex flex-col items-center">
                            <div className="w-6 h-6 rounded-full bg-burgundy/20 border border-burgundy/40 flex items-center justify-center text-xs text-burgundy-light font-bold">{i + 1}</div>
                            {i < results.routing.length - 1 && <div className="w-px h-8 bg-white/10 mt-1" />}
                          </div>
                          <div className="flex-1 p-3 rounded-lg bg-black/40 border border-white/8 space-y-1">
                            <p className="text-xs text-zinc-300"><span className="text-zinc-500">From:</span> <code className="font-mono">{hop.from}</code></p>
                            <p className="text-xs text-zinc-300"><span className="text-zinc-500">By:</span> <code className="font-mono">{hop.by}</code></p>
                            <p className="text-xs text-zinc-500">{hop.time}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </Card>
              </TabsContent>

              {/* Anomalies */}
              <TabsContent value="anomalies">
                <Card className="p-5 bg-zinc-950 border border-white/8 space-y-3">
                  <h3 className="text-sm font-semibold text-zinc-300">Detected Anomalies</h3>
                  {results.anomalies.map((a, i) => (
                    <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-black/40 border border-white/8">
                      <AlertTriangle className={`w-4 h-4 mt-0.5 shrink-0 ${
                        a.severity === 'high' ? 'text-red-400' : a.severity === 'medium' ? 'text-yellow-400' : 'text-green-400'
                      }`} />
                      <div className="space-y-1">
                        <SeverityBadge severity={a.severity} />
                        <p className="text-sm text-zinc-300">{a.description}</p>
                      </div>
                    </div>
                  ))}
                </Card>
              </TabsContent>

              {/* Payloads */}
              <TabsContent value="payloads">
                <Card className="p-5 bg-zinc-950 border border-white/8 space-y-3">
                  <h3 className="text-sm font-semibold text-zinc-300">URLs & Potential Payloads</h3>
                  {results.urls.length === 0 ? (
                    <p className="text-zinc-500 text-sm">No URLs found</p>
                  ) : results.urls.map((url, i) => (
                    <div key={i} className="p-3 rounded-lg bg-black/40 border border-white/8 space-y-1.5">
                      <code className="text-xs font-mono text-red-300 break-all">{url.value}</code>
                      <p className="text-xs text-zinc-500">Defanged: <code className="text-zinc-400 font-mono">{url.defanged}</code></p>
                      <div className="flex gap-2">
                        <CopyBtn text={url.defanged} label="Copy defanged" />
                        <CopyBtn text={url.value} label="Copy raw" />
                      </div>
                    </div>
                  ))}
                </Card>
              </TabsContent>

              {/* WHOIS */}
              <TabsContent value="whois">
                <Card className="p-5 bg-zinc-950 border border-white/8 space-y-3">
                  <h3 className="text-sm font-semibold text-zinc-300">WHOIS Lookup</h3>
                  {results.domains.length === 0 && results.ips.length === 0 ? (
                    <p className="text-zinc-500 text-sm">No domains or IPs to look up</p>
                  ) : [...results.domains, ...results.ips].map((ioc, i) => (
                    <div key={i} className="p-3 rounded-lg bg-black/40 border border-white/8 flex items-center justify-between">
                      <code className="text-sm font-mono text-zinc-300">{ioc.value}</code>
                      <a href={`https://who.is/whois/${ioc.value}`} target="_blank" rel="noopener noreferrer"
                        className="text-xs text-burgundy-light hover:underline flex items-center gap-1">
                        Lookup <ChevronRight className="w-3 h-3" />
                      </a>
                    </div>
                  ))}
                </Card>
              </TabsContent>

              {/* SIEM */}
              <TabsContent value="siem">
                <Card className="p-5 bg-zinc-950 border border-white/8 space-y-3">
                  <div className="flex justify-between items-center">
                    <h3 className="text-sm font-semibold text-zinc-300">SIEM Query Templates</h3>
                    <CopyBtn text={generateSIEM(results)} label="Copy all" />
                  </div>
                  <pre className="text-xs font-mono text-zinc-400 bg-black/60 p-4 rounded border border-white/8 whitespace-pre-wrap leading-5 overflow-x-auto">
                    {generateSIEM(results)}
                  </pre>
                </Card>
              </TabsContent>

              {/* Headers */}
              <TabsContent value="headers">
                <Card className="p-5 bg-zinc-950 border border-white/8 space-y-2">
                  <div className="flex justify-between items-center mb-3">
                    <h3 className="text-sm font-semibold text-zinc-300">Raw Headers</h3>
                    <CopyBtn text={Object.entries(results.headers).map(([k,v]) => `${k}: ${v}`).join('\n')} label="Copy all" />
                  </div>
                  <div className="space-y-1 max-h-96 overflow-y-auto">
                    {Object.entries(results.headers).map(([k, v]) => (
                      <div key={k} className="flex gap-3 text-xs border-b border-white/5 pb-1.5">
                        <span className="text-burgundy-light font-mono w-40 shrink-0 truncate">{k}</span>
                        <span className="text-zinc-400 font-mono break-all">{v}</span>
                      </div>
                    ))}
                  </div>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        )}
      </main>

      {/* Settings Dialog */}
      <Dialog open={showSettings} onOpenChange={setShowSettings}>
        <DialogContent className="max-w-md bg-zinc-950 border border-white/10">
          <DialogHeader>
            <DialogTitle className="text-white">API Key Settings</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-zinc-500">Keys stored only in your browser. Never sent to our servers.</p>
            {[
              { key: 'virustotal', label: 'VirusTotal API Key', link: 'https://www.virustotal.com/gui/my-apikey' },
              { key: 'abuseipdb', label: 'AbuseIPDB API Key', link: 'https://www.abuseipdb.com/account/api' },
              { key: 'otx', label: 'OTX AlienVault API Key', link: 'https://otx.alienvault.com/api' },
            ].map(({ key, label, link }) => (
              <div key={key} className="space-y-1.5">
                <label className="text-sm font-medium text-zinc-300">{label}</label>
                <Input type="password" placeholder={`Enter ${label}…`}
                  value={apiKeys[key as keyof typeof apiKeys]}
                  onChange={(e) => setApiKeys({ ...apiKeys, [key]: e.target.value })}
                  className="bg-black/40 border-white/10 text-zinc-200" />
                <a href={link} target="_blank" rel="noopener noreferrer"
                  className="text-xs text-burgundy-light hover:underline">Get free key ↗</a>
              </div>
            ))}
            <div className="flex gap-3 pt-2">
              <Button variant="outline" onClick={() => setShowSettings(false)} className="flex-1 border-white/10 bg-white/5">Cancel</Button>
              <Button onClick={handleSaveKeys} className="flex-1 btn-gradient">Save Keys</Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <footer className="border-t border-white/8 py-6 mt-8">
        <div className="container text-center text-xs text-zinc-600">
          SOCAnalyzer v1.0 • All processing is local & client-side • No data leaves your browser
        </div>
      </footer>
    </div>
  );
}
