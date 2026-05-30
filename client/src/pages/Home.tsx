import { useState, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Upload, Settings, Copy, Check, AlertCircle, Shield, Zap } from 'lucide-react';
import { toast } from 'sonner';

interface IOC {
  type: string;
  value: string;
  defanged: string;
}

interface AnalysisResult {
  emails: string[];
  ips: IOC[];
  urls: IOC[];
  domains: IOC[];
  hashes: IOC[];
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
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const defangIOC = (value: string): string => {
    return value
      .replace(/\./g, '[.]')
      .replace(/http/g, 'hxxp')
      .replace(/:/g, '[:]')
      .replace(/@/g, '[@]');
  };

  const extractIOCs = (text: string): AnalysisResult => {
    const uniqueArray = (arr: string[]) => Array.from(new Set(arr));
    
    const emails = uniqueArray(text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []);
    
    const ips = uniqueArray(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).map(ip => ({
      type: 'IP',
      value: ip,
      defanged: defangIOC(ip),
    }));

    const urls = uniqueArray(text.match(/https?:\/\/[^\s]+/g) || []).map(url => ({
      type: 'URL',
      value: url,
      defanged: defangIOC(url),
    }));

    const domains = uniqueArray(text.match(/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/gi) || []).map(domain => ({
      type: 'Domain',
      value: domain,
      defanged: defangIOC(domain),
    }));

    const hashes = uniqueArray(text.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g) || []).map(hash => ({
      type: 'Hash',
      value: hash,
      defanged: defangIOC(hash),
    }));

    return { emails, ips, urls, domains, hashes };
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFile(files[0]);
    }
  };

  const handleFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setRawEmail(content);
      analyzeEmail(content);
    };
    reader.readAsText(file);
  };

  const analyzeEmail = (emailContent: string) => {
    setIsAnalyzing(true);
    setTimeout(() => {
      const analysis = extractIOCs(emailContent);
      setResults(analysis);
      setIsAnalyzing(false);
      toast.success('Email analyzed successfully!');
    }, 500);
  };

  const handleAnalyzeClick = () => {
    if (!rawEmail.trim()) {
      toast.error('Please paste email content first');
      return;
    }
    analyzeEmail(rawEmail);
  };

  const handleSaveKeys = () => {
    localStorage.setItem('vt-key', apiKeys.virustotal);
    localStorage.setItem('abuse-key', apiKeys.abuseipdb);
    localStorage.setItem('otx-key', apiKeys.otx);
    setShowSettings(false);
    toast.success('API keys saved securely in your browser');
  };

  const copyToClipboard = (text: string, index: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
    toast.success('Copied to clipboard');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-secondary">
      {/* Header */}
      <header className="sticky top-0 z-50 glass border-b border-border/50">
        <div className="container flex items-center justify-between py-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-gradient-to-br from-primary to-accent">
              <Shield className="w-6 h-6 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-xl font-bold gradient-text">Email Analyzer Pro</h1>
              <p className="text-xs text-muted-foreground">IOC Extraction & Analysis</p>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowSettings(true)}
            className="gap-2"
          >
            <Settings className="w-4 h-4" />
            Settings
          </Button>
        </div>
      </header>

      {/* Main Content */}
      <main className="container py-12">
        <div className="grid lg:grid-cols-2 gap-8 fade-in-up-stagger">
          {/* Left Column - Input */}
          <div className="space-y-6">
            <div>
              <h2 className="text-2xl font-bold mb-2">Analyze Email</h2>
              <p className="text-muted-foreground">
                Upload or paste email content to extract IOCs and indicators of compromise
              </p>
            </div>

            {/* Drag & Drop Zone */}
            <Card
              className={`p-8 border-2 border-dashed cursor-pointer transition-all duration-300 ${
                isDragging
                  ? 'border-accent bg-accent/5 scale-105'
                  : 'border-border hover:border-accent/50'
              }`}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
            >
              <div className="flex flex-col items-center justify-center gap-4">
                <div className="p-4 rounded-lg bg-primary/10">
                  <Upload className="w-8 h-8 text-primary" />
                </div>
                <div className="text-center">
                  <p className="font-semibold text-foreground">Drag & drop email file</p>
                  <p className="text-sm text-muted-foreground">
                    Supports .eml, .txt, or raw email content
                  </p>
                </div>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,.txt"
                onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
                className="hidden"
              />
            </Card>

            {/* Raw Email Paste */}
            <div className="space-y-3">
              <label className="block text-sm font-medium">Or paste raw email content:</label>
              <Textarea
                placeholder="Paste raw email headers and body here…"
                value={rawEmail}
                onChange={(e) => setRawEmail(e.target.value)}
                className="min-h-48 font-mono text-sm resize-none"
              />
              <Button
                onClick={handleAnalyzeClick}
                disabled={isAnalyzing || !rawEmail.trim()}
                className="w-full btn-gradient"
              >
                {isAnalyzing ? (
                  <>
                    <Zap className="w-4 h-4 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4" />
                    Analyze Email
                  </>
                )}
              </Button>
            </div>
          </div>

          {/* Right Column - Results */}
          <div className="space-y-6">
            {results ? (
              <>
                <div>
                  <h2 className="text-2xl font-bold mb-2">Analysis Results</h2>
                  <p className="text-muted-foreground">
                    Extracted indicators of compromise
                  </p>
                </div>

                {/* Results Summary */}
                <div className="grid grid-cols-2 gap-3">
                  <Card className="p-4 bg-primary/5 border-primary/20">
                    <p className="text-xs text-muted-foreground mb-1">Emails</p>
                    <p className="text-2xl font-bold text-primary">{results.emails.length}</p>
                  </Card>
                  <Card className="p-4 bg-accent/5 border-accent/20">
                    <p className="text-xs text-muted-foreground mb-1">IPs</p>
                    <p className="text-2xl font-bold text-accent">{results.ips.length}</p>
                  </Card>
                  <Card className="p-4 bg-destructive/5 border-destructive/20">
                    <p className="text-xs text-muted-foreground mb-1">URLs</p>
                    <p className="text-2xl font-bold text-destructive">{results.urls.length}</p>
                  </Card>
                  <Card className="p-4 bg-secondary/5 border-secondary/20">
                    <p className="text-xs text-muted-foreground mb-1">Domains</p>
                    <p className="text-2xl font-bold text-secondary-foreground">{results.domains.length}</p>
                  </Card>
                </div>

                {/* IOCs List */}
                <div className="space-y-4 max-h-96 overflow-y-auto">
                  {/* Emails */}
                  {results.emails.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="font-semibold text-sm text-primary flex items-center gap-2">
                        <AlertCircle className="w-4 h-4" />
                        Email Addresses ({results.emails.length})
                      </h3>
                      <div className="space-y-2">
                        {results.emails.map((email, idx) => (
                          <div
                            key={`email-${idx}`}
                            className="p-3 bg-card border border-border rounded-lg flex items-center justify-between group hover:border-primary/50 transition-colors"
                          >
                            <code className="text-xs font-mono text-foreground break-all">{email}</code>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => copyToClipboard(email, `email-${idx}`)}
                              className="opacity-0 group-hover:opacity-100 transition-opacity"
                            >
                              {copiedIndex === `email-${idx}` ? (
                                <Check className="w-4 h-4 text-green-500" />
                              ) : (
                                <Copy className="w-4 h-4" />
                              )}
                            </Button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* IPs */}
                  {results.ips.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="font-semibold text-sm text-accent flex items-center gap-2">
                        <AlertCircle className="w-4 h-4" />
                        IP Addresses ({results.ips.length})
                      </h3>
                      <div className="space-y-2">
                        {results.ips.map((ip, idx) => (
                          <div
                            key={`ip-${idx}`}
                            className="p-3 bg-card border border-border rounded-lg space-y-1 group hover:border-accent/50 transition-colors"
                          >
                            <div className="flex items-center justify-between">
                              <code className="text-xs font-mono text-foreground">{ip.value}</code>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => copyToClipboard(ip.value, `ip-${idx}`)}
                                className="opacity-0 group-hover:opacity-100 transition-opacity"
                              >
                                {copiedIndex === `ip-${idx}` ? (
                                  <Check className="w-4 h-4 text-green-500" />
                                ) : (
                                  <Copy className="w-4 h-4" />
                                )}
                              </Button>
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Defanged: <code className="text-foreground">{ip.defanged}</code>
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* URLs */}
                  {results.urls.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="font-semibold text-sm text-destructive flex items-center gap-2">
                        <AlertCircle className="w-4 h-4" />
                        URLs ({results.urls.length})
                      </h3>
                      <div className="space-y-2">
                        {results.urls.map((url, idx) => (
                          <div
                            key={`url-${idx}`}
                            className="p-3 bg-card border border-border rounded-lg space-y-1 group hover:border-destructive/50 transition-colors"
                          >
                            <div className="flex items-center justify-between">
                              <code className="text-xs font-mono text-foreground break-all">{url.value}</code>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => copyToClipboard(url.value, `url-${idx}`)}
                                className="opacity-0 group-hover:opacity-100 transition-opacity"
                              >
                                {copiedIndex === `url-${idx}` ? (
                                  <Check className="w-4 h-4 text-green-500" />
                                ) : (
                                  <Copy className="w-4 h-4" />
                                )}
                              </Button>
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Defanged: <code className="text-foreground break-all">{url.defanged}</code>
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Domains */}
                  {results.domains.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="font-semibold text-sm text-secondary-foreground flex items-center gap-2">
                        <AlertCircle className="w-4 h-4" />
                        Domains ({results.domains.length})
                      </h3>
                      <div className="space-y-2">
                        {results.domains.map((domain, idx) => (
                          <div
                            key={`domain-${idx}`}
                            className="p-3 bg-card border border-border rounded-lg space-y-1 group hover:border-secondary/50 transition-colors"
                          >
                            <div className="flex items-center justify-between">
                              <code className="text-xs font-mono text-foreground">{domain.value}</code>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => copyToClipboard(domain.value, `domain-${idx}`)}
                                className="opacity-0 group-hover:opacity-100 transition-opacity"
                              >
                                {copiedIndex === `domain-${idx}` ? (
                                  <Check className="w-4 h-4 text-green-500" />
                                ) : (
                                  <Copy className="w-4 h-4" />
                                )}
                              </Button>
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Defanged: <code className="text-foreground">{domain.defanged}</code>
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Hashes */}
                  {results.hashes.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="font-semibold text-sm text-muted-foreground flex items-center gap-2">
                        <AlertCircle className="w-4 h-4" />
                        Hashes ({results.hashes.length})
                      </h3>
                      <div className="space-y-2">
                        {results.hashes.map((hash, idx) => (
                          <div
                            key={`hash-${idx}`}
                            className="p-3 bg-card border border-border rounded-lg flex items-center justify-between group hover:border-muted-foreground/50 transition-colors"
                          >
                            <code className="text-xs font-mono text-foreground break-all">{hash.value}</code>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => copyToClipboard(hash.value, `hash-${idx}`)}
                              className="opacity-0 group-hover:opacity-100 transition-opacity"
                            >
                              {copiedIndex === `hash-${idx}` ? (
                                <Check className="w-4 h-4 text-green-500" />
                              ) : (
                                <Copy className="w-4 h-4" />
                              )}
                            </Button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <Button
                  variant="outline"
                  onClick={() => {
                    setResults(null);
                    setRawEmail('');
                  }}
                  className="w-full"
                >
                  Clear Results
                </Button>
              </>
            ) : (
              <Card className="p-8 border-dashed border-2 border-border flex flex-col items-center justify-center min-h-96 text-center">
                <div className="p-4 rounded-lg bg-muted mb-4">
                  <AlertCircle className="w-8 h-8 text-muted-foreground" />
                </div>
                <h3 className="font-semibold text-foreground mb-2">No analysis yet</h3>
                <p className="text-sm text-muted-foreground">
                  Upload or paste an email to see extracted IOCs and indicators
                </p>
              </Card>
            )}
          </div>
        </div>
      </main>

      {/* Settings Dialog */}
      <Dialog open={showSettings} onOpenChange={setShowSettings}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>API Key Settings</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Keys are stored only in your browser's localStorage. They are never sent anywhere except to the respective official APIs.
            </p>

            <div className="space-y-2">
              <label className="text-sm font-medium">VirusTotal API Key</label>
              <Input
                type="password"
                placeholder="Enter your VirusTotal API key…"
                value={apiKeys.virustotal}
                onChange={(e) => setApiKeys({ ...apiKeys, virustotal: e.target.value })}
              />
              <a
                href="https://www.virustotal.com/gui/my-apikey"
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-primary hover:underline"
              >
                Get free key ↗
              </a>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">AbuseIPDB API Key</label>
              <Input
                type="password"
                placeholder="Enter your AbuseIPDB API key…"
                value={apiKeys.abuseipdb}
                onChange={(e) => setApiKeys({ ...apiKeys, abuseipdb: e.target.value })}
              />
              <a
                href="https://www.abuseipdb.com/account/api"
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-primary hover:underline"
              >
                Get free key ↗
              </a>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">OTX AlienVault API Key</label>
              <Input
                type="password"
                placeholder="Enter your OTX AlienVault API key…"
                value={apiKeys.otx}
                onChange={(e) => setApiKeys({ ...apiKeys, otx: e.target.value })}
              />
              <a
                href="https://otx.alienvault.com/api"
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-primary hover:underline"
              >
                Get free key ↗
              </a>
            </div>

            <div className="flex gap-3 pt-4">
              <Button
                variant="outline"
                onClick={() => setShowSettings(false)}
                className="flex-1"
              >
                Cancel
              </Button>
              <Button
                onClick={handleSaveKeys}
                className="flex-1 btn-gradient"
              >
                Save Keys
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Footer */}
      <footer className="border-t border-border/50 mt-16 py-8 bg-muted/30">
        <div className="container text-center text-sm text-muted-foreground">
          <p>Email Analyzer Pro • Built for security analysts • All processing is local & client-side</p>
        </div>
      </footer>
    </div>
  );
}
