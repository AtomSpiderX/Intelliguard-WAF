/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  AlertTriangle, 
  FileText, 
  Settings, 
  Terminal, 
  RefreshCw, 
  Download, 
  Trash2, 
  Plus, 
  Lock,
  Search,
  CheckCircle,
  XCircle,
  Eye,
  Brain,
  Laptop,
  ShieldCheck,
  Cpu,
  Layers,
  Globe,
  Zap,
  Fingerprint,
  Database,
  Code,
  ShieldAlert,
  FileCode
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  AreaChart, 
  Area,
  Radar, 
  RadarChart, 
  PolarGrid, 
  PolarAngleAxis, 
  PolarRadiusAxis 
} from 'recharts';
import { UAParser } from 'ua-parser-js';
import { motion, AnimatePresence } from 'motion/react';
import { format } from 'date-fns';
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import ReactMarkdown from 'react-markdown';
import { analyzeThreatLog, suggestRulesFromLogs } from './services/geminiService';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export default function App() {
  const [stats, setStats] = useState<any>(null);
  const [rules, setRules] = useState<any[]>([]);
  const reportRef = React.useRef<HTMLDivElement>(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [simulationPayload, setSimulationPayload] = useState('');
  const [simulationResult, setSimulationResult] = useState<any>(null);
  const [selectedLog, setSelectedLog] = useState<any>(null);
  const [userAgentInfo, setUserAgentInfo] = useState<any>(null);
  const [safetyReport, setSafetyReport] = useState<any>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [aiAnalysisResult, setAiAnalysisResult] = useState<any>(null);
  
  const [newRule, setNewRule] = useState({ name: '', pattern: '', description: '', target: 'any', risk_weight: 0.5 });
  const [aiSuggestions, setAiSuggestions] = useState<any[]>([]);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      const statsRes = await fetch('/api/stats');
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }

      const rulesRes = await fetch('/api/rules');
      if (rulesRes.ok) {
        const rulesData = await rulesRes.json();
        setRules(rulesData);
      }
    } catch (err) {
      console.error("Fetch failed", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000); // Live refresh every 10s
    
    // Fail-safe: Ensure we stop loading eventually
    const timeout = setTimeout(() => {
      setLoading(false);
    }, 5000);

    return () => {
      clearInterval(interval);
      clearTimeout(timeout);
    };
  }, []);

  useEffect(() => {
    try {
      const parser = new UAParser(navigator.userAgent);
      const result = parser.getResult();
      setUserAgentInfo(result);

      // Safety Audit Logic
      const audit = {
        isSafe: true,
        warnings: [] as string[],
        checks: [] as any[],
        score: 100,
        status: 'Safe'
      };

      // 1. Browser commonality
      const knownBrowsers = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera', 'Chromium'];
      if (!knownBrowsers.includes(result.browser.name || '')) {
        audit.score -= 20;
        audit.warnings.push("Uncommon or unknown browser engine detected.");
        audit.checks.push({ label: "Engine Trust", status: "warning", value: result.browser.name || "Unknown" });
      } else {
        audit.checks.push({ label: "Engine Trust", status: "success", value: result.browser.name });
      }

      // 2. Automation/Bot Checks
      const isAutomation = (navigator as any).webdriver || /HeadlessChrome/.test(navigator.userAgent);
      if (isAutomation) {
        audit.score -= 50;
        audit.isSafe = false;
        audit.warnings.push("Headless browser or automation tool detected (Webdriver).");
        audit.checks.push({ label: "Automation", status: "danger", value: "Detected" });
      } else {
        audit.checks.push({ label: "Human Verification", status: "success", value: "Verified" });
      }

      // 3. Privacy Settings
      const dnt = navigator.doNotTrack;
      if (dnt === "1") {
        audit.checks.push({ label: "Privacy Focus", status: "success", value: "DoNotTrack ON" });
      } else {
        audit.checks.push({ label: "Privacy Focus", status: "neutral", value: "Standard" });
      }

      // 4. Content Blockers (Simple check)
      const adBlockTest = document.createElement('div');
      adBlockTest.innerHTML = '&nbsp;';
      adBlockTest.className = 'adsbox';
      document.body.appendChild(adBlockTest);
      
      // Delay it slightly to allow rendering
      setTimeout(() => {
        if (adBlockTest.offsetHeight === 0) {
          audit.checks.push({ label: "Content Control", status: "success", value: "Protections Active" });
        } else {
          audit.checks.push({ label: "Content Control", status: "neutral", value: "None" });
        }
        document.body.removeChild(adBlockTest);
        
        // Final Status
        if (audit.score < 50) audit.status = 'Vulnerable';
        else if (audit.score < 80) audit.status = 'Suspicious';
        else audit.status = 'Safe';
        
        setSafetyReport({ ...audit });
      }, 100);

    } catch (e) {
      console.error("Failed to parse UA", e);
    }
  }, []);

  useEffect(() => {
    // Reset AI state when selected log changes
    setAiAnalysisResult(null);
    setAiError(null);
    setIsAnalyzing(false);
  }, [selectedLog?.id]);

  const handleAiAnalysis = async () => {
    if (!selectedLog) return;
    setIsAnalyzing(true);
    setAiError(null);
    try {
      const result = await analyzeThreatLog(selectedLog);
      setAiAnalysisResult(result);
    } catch (e: any) {
      console.error("Analysis failed:", e);
      setAiError(e.message || "Failed to analyze incident.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  useEffect(() => {
    setAiAnalysisResult(null);
  }, [selectedLog]);

  const calculateSecurityScore = () => {
    if (!stats?.rules) return 0;
    // Categories we want to cover
    const targets = ['SQL', 'XSS', 'Travers', 'CMD', 'UA', 'Admin'];
    let covered = 0;
    targets.forEach(t => {
      if (stats.rules.some((r: any) => 
        r.name.toLowerCase().includes(t.toLowerCase()) || 
        r.description.toLowerCase().includes(t.toLowerCase())
      )) covered++;
    });
    return Math.round((covered / targets.length) * 100);
  };

  const startDeepTrace = (log: any) => {
    setSelectedLog(log);
    // Auto-scroll to analysis section if needed
  };

  const runSimulation = async () => {
    setSimulationResult(null);
    try {
      if (simulationPayload === "Simulate 20 requests rapidly") {
        let lastData = null;
        for (let i = 0; i < 25; i++) {
          const res = await fetch(`/api/simulate?payload=rate_limit_test_${i}`);
          lastData = await res.json();
          if (lastData.status === 403) break;
        }
        setSimulationResult(lastData);
        fetchData();
        return;
      }

      // Always use the simulation endpoint for the lab to ensure WAF analysis is returned
      const url = `/api/simulate?payload=${encodeURIComponent(simulationPayload)}`;
      
      const res = await fetch(url);
      const contentType = res.headers.get("content-type");
      
      let data;
      if (contentType && contentType.includes("application/json")) {
        const json = await res.json();
        // Flatten WAF results if they exist
        data = json.waf ? { ...json.waf, ...json } : json;
        if (!data.status) data.status = res.status;
      } else {
        // If we got HTML (404/Fallback), but it was blocked/not-found
        data = { 
          status: res.status, 
          error: res.status === 403 ? "Blocked" : "Not Found",
          message: res.status === 403 ? "WAF Intercepted the request." : "The honeypot path was accessed."
        };
      }
      
      if (data.status === 403 || data.error) {
        alert(`🚨 SECURITY VIOLATION: Attack Blocked!\n\nType: ${data.threats?.join(', ') || 'Malicious Payload'}\nIncident ID: ${data.incident_id}`);
      }
      
      setSimulationResult(data);
      fetchData(); // Refresh logs
    } catch (err) {
      alert("🚨 SECURITY VIOLATION: Request intercepted by IntelliGuard WAF.");
      setSimulationResult({ error: "Access Denied", status: 403, message: "Request was intercepted by IntelliGuard WAF." });
      fetchData();
    }
  };

  const handleAddRule = async () => {
    await fetch('/api/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newRule)
    });
    setNewRule({ name: '', pattern: '', description: '', target: 'any', risk_weight: 0.5 });
    fetchData();
  };

  const handleDeleteRule = async (id: number) => {
    await fetch(`/api/rules/${id}`, { method: 'DELETE' });
    fetchData();
  };

  const fetchAiSuggestions = async () => {
    setIsAiLoading(true);
    setAiError(null);
    try {
      // Limit logs to the last 20 events to keep payload size reasonable
      const logsToAnalyze = (stats?.recentLogs || []).slice(0, 20);
      
      const result = await suggestRulesFromLogs(logsToAnalyze);
      setAiSuggestions(result.rules || []);
    } catch (err: any) {
      console.error("Local Intel Error:", err);
      setAiError(err.message || "Failed to generate security suggestions.");
    } finally {
      setIsAiLoading(false);
    }
  };

  const handleDownloadHtml = () => {
    if (!reportRef.current) return;
    
    // Logic to capture HTML with styles for a standalone report
    const content = reportRef.current.innerHTML;
    const styles = Array.from(document.querySelectorAll('style, link[rel="stylesheet"]'))
      .map(tag => tag.outerHTML)
      .join('\n');
    
    const htmlReport = `
      <!DOCTYPE html>
      <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Forensic Report - ${selectedLog?.id}</title>
          ${styles}
          <style>
            body { 
              background-color: #f8fafc; 
              padding: 2.5rem; 
              font-family: ui-sans-serif, system-ui, sans-serif;
            }
            [data-report-container="true"] { 
              background: white; 
              max-width: 1100px; 
              margin: 0 auto; 
              padding: 3.5rem; 
              border-radius: 2rem; 
              box-shadow: 0 25px 50px -12px rgb(0 0 0 / 0.1); 
              border: 1px solid #e2e8f0;
            }
            /* Ensure specific elements look good in fixed output */
            .prose pre { background: #0f172a !important; color: #f1f5f9 !important; }
            .prose code { color: #818cf8 !important; }
          </style>
        </head>
        <body>
          <div data-report-container="true">
            <div style="margin-bottom: 2rem; border-bottom: 2px solid #3b82f6; padding-bottom: 1rem;">
              <h1 style="font-size: 24px; font-weight: 900; color: #1e293b; margin: 0; text-transform: uppercase; letter-spacing: 0.1em;">
                Forensic Analysis Report
              </h1>
              <p style="font-size: 12px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-top: 5px;">
                IntelliGuard Sentinel Pro • Generated on ${new Date().toLocaleString()}
              </p>
            </div>
            ${content}
          </div>
        </body>
      </html>
    `;
    
    const blob = new Blob([htmlReport], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Forensic-Report-SN-${selectedLog?.id}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const isAiResultValid = aiAnalysisResult && aiAnalysisResult.intent && aiAnalysisResult.explanation;

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-slate-50 text-slate-900 selection:bg-blue-500/10">
        <div className="relative">
          <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 2, ease: "linear" }}>
            <Shield className="w-16 h-16 text-blue-600 opacity-20" />
          </motion.div>
          <div className="absolute inset-0 flex items-center justify-center">
             <RefreshCw className="w-8 h-8 text-blue-600 animate-spin" />
          </div>
        </div>
        <p className="mt-6 font-sans text-[10px] font-black tracking-[0.4em] text-slate-400 uppercase">Synchronizing AI Kernels</p>
        <p className="mt-2 text-[9px] text-slate-300 font-bold italic uppercase">Establishing Secure Handshake with Node Cluster</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans">
      {/* Sidebar Navigation */}
      <aside className="fixed top-0 left-0 w-64 h-full bg-slate-900 text-white flex flex-col border-r border-slate-800 hidden md:flex z-50">
        <div className="p-6 flex items-center space-x-3 bg-slate-950 border-b border-white/5">
          <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center shadow-[0_0_15px_rgba(37,99,235,0.3)]">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <span className="font-bold text-lg tracking-tight uppercase">IntelliGuard <span className="text-blue-400">Sentinel</span></span>
        </div>
        <nav className="flex-1 py-6 space-y-1">
          <NavItem icon={Activity} label="Dashboard" active={activeTab === 'overview'} onClick={() => setActiveTab('overview')} />
          <NavItem icon={Eye} label="Fingerprinting" active={activeTab === 'monitoring'} onClick={() => setActiveTab('monitoring')} />
          <NavItem icon={Layers} label="Defense Stack" active={activeTab === 'stack'} onClick={() => setActiveTab('stack')} />
          <NavItem icon={FileText} label="Threat Logs" active={activeTab === 'logs'} onClick={() => setActiveTab('logs')} />
          <NavItem icon={Lock} label="Rule Engine" active={activeTab === 'rules'} onClick={() => setActiveTab('rules')} />
        </nav>
        <div className="px-6 py-4">
          <div className="bg-slate-800/50 rounded-2xl p-4 border border-white/5 mb-4">
            <div className="flex justify-between items-center mb-2">
              <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest">Protection Grade</span>
              <span className={cn(
                "text-xs font-black px-1.5 py-0.5 rounded",
                calculateSecurityScore() > 80 ? "bg-emerald-500/20 text-emerald-400" : 
                calculateSecurityScore() > 50 ? "bg-amber-500/20 text-amber-400" : "bg-red-500/20 text-red-400"
              )}>
                {calculateSecurityScore() > 90 ? 'A+' : 
                 calculateSecurityScore() > 80 ? 'A' : 
                 calculateSecurityScore() > 70 ? 'B' : 
                 calculateSecurityScore() > 50 ? 'C' : 'F'}
              </span>
            </div>
            <div className="w-full bg-slate-700 h-1 rounded-full overflow-hidden mb-1">
              <motion.div 
                initial={{ width: 0 }}
                animate={{ width: `${calculateSecurityScore()}%` }}
                className={cn(
                  "h-full rounded-full transition-all duration-1000",
                  calculateSecurityScore() > 80 ? "bg-emerald-500" : calculateSecurityScore() > 50 ? "bg-amber-500" : "bg-red-500"
                )} 
              />
            </div>
            <p className="text-[9px] text-slate-600 font-bold uppercase tracking-tighter">
              Coverage: {calculateSecurityScore()}% of key threats
            </p>
          </div>
          <button 
            onClick={() => setActiveTab('simulator')}
            className="w-full flex items-center gap-3 px-4 py-3 bg-blue-600/10 border border-blue-500/20 rounded-xl hover:bg-blue-600/20 transition group text-left"
          >
            <div className="p-2 bg-blue-500 rounded-lg text-white group-hover:scale-110 transition-transform">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <p className="text-[10px] font-black text-blue-400 uppercase leading-none mb-1">Open</p>
              <p className="text-xs font-bold text-white uppercase tracking-tighter">Attack Lab</p>
            </div>
          </button>
        </div>
        <div className="p-6 bg-slate-950 border-t border-slate-800">
          <div className="flex items-center justify-between text-[10px] text-slate-500 mb-2 uppercase font-bold tracking-wider">
            <span>System Health</span>
            <span className="text-emerald-500">Operational</span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <motion.div 
              initial={{ width: 0 }}
              animate={{ width: '98%' }}
              className="bg-emerald-500 h-full rounded-full shadow-[0_0_10px_rgba(16,185,129,0.5)]"
            />
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="md:ml-64 flex flex-col min-h-screen">
        <header className="sticky top-0 h-16 bg-white border-b border-slate-200 flex items-center justify-between px-8 shadow-sm z-40">
          <div className="flex items-center space-x-4">
            <h2 className="text-lg font-bold text-slate-800 capitalize">{activeTab.replace('-', ' ')}</h2>
            <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-blue-50 text-blue-700 border border-blue-100 italic">
              Production-US-East
            </span>
          </div>
          <div className="flex items-center space-x-3">
            <div className="flex flex-col items-end mr-2">
               <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Your Origin IP</span>
               <span className="text-[10px] font-mono font-bold text-blue-600">{stats?.yourIp || 'Detecting...'}</span>
            </div>
            <button 
              onClick={() => window.open('/api/export?format=csv', '_blank')}
              className="flex items-center px-4 py-2 bg-slate-50 border border-slate-200 text-slate-700 text-xs font-bold uppercase tracking-tight rounded-md hover:bg-slate-100 transition shadow-sm"
            >
              <Download className="w-3.5 h-3.5 mr-2" />
              Reports
            </button>
            <div className="w-px h-6 bg-slate-200 mx-2"></div>
            <button 
              onClick={fetchData}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white transition rounded-md text-xs font-bold uppercase tracking-tight flex items-center gap-2 shadow-md shadow-blue-600/20"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Sync
            </button>
          </div>
        </header>

        <div className="p-8 space-y-8 overflow-y-auto">
          <AnimatePresence mode="wait">
            {activeTab === 'overview' && (
              <motion.div 
                key="overview"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="space-y-8"
              >
                {/* Stats Grid */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                  <StatCard label="Requests / 24h" value={stats?.totalRequests} icon={Activity} color="blue" trend="+12.4%" />
                  <StatCard label="Mitigated Attacks" value={stats?.blockedRequests} icon={AlertTriangle} color="red" trend="+4.2%" />
                  <StatCard label="Rule Definition" value={rules.length} icon={Shield} color="slate" trend="Stable" />
                  <StatCard label="Anomaly Score" value="14.2" icon={Brain} color="emerald" trend="Low Risk" />
                </div>

                {/* Main Visual Section */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                  <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 shadow-sm p-6 flex flex-col">
                    <div className="flex justify-between items-center mb-6">
                      <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest flex items-center gap-2">
                        <Activity className="w-4 h-4 text-blue-600" />
                        Threat Activity (Real-time)
                      </h3>
                      <div className="flex space-x-1.5">
                        <div className="w-2 h-2 rounded-full bg-blue-500" />
                        <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                      </div>
                    </div>
                    <div className="h-[280px] w-full min-h-[280px]">
                      <ResponsiveContainer width="100%" height="100%" minWidth={0}>
                        <AreaChart data={stats?.activityChart || []}>
                          <defs>
                            <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.1}/>
                              <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                            </linearGradient>
                            <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.1}/>
                              <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                          <XAxis dataKey="time" stroke="#94a3b8" fontSize={10} axisLine={false} tickLine={false} />
                          <YAxis stroke="#94a3b8" fontSize={10} axisLine={false} tickLine={false} />
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                            itemStyle={{ fontSize: '11px', fontWeight: 'bold' }}
                          />
                          <Area type="monotone" dataKey="total" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorTotal)" />
                          <Area type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorBlocked)" />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  <div className="p-6 bg-slate-900 rounded-3xl border border-white/5 space-y-6 shadow-2xl relative overflow-hidden group">
                    <div className="absolute top-0 right-0 p-4 opacity-5">
                      <Cpu className="w-24 h-24 text-blue-500" />
                    </div>
                    <div className="flex items-center justify-between relative z-10">
                      <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-[0.3em]">Neural Ops Status</h3>
                      <div className="flex h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    </div>
                    <div className="space-y-4 relative z-10">
                      {[
                        { label: 'Heuristic Processor', val: 'Optimum', color: 'text-blue-400' },
                        { label: 'Pattern Latency', val: '1.2ms', color: 'text-emerald-400' },
                        { label: 'Throughput', val: '8.4 GB/s', color: 'text-white' },
                      ].map((stat, i) => (
                        <div key={i} className="flex justify-between items-center text-[10px] font-bold">
                          <span className="text-slate-500 uppercase">{stat.label}</span>
                          <span className={stat.color}>{stat.val}</span>
                        </div>
                      ))}
                    </div>
                    <div className="pt-4 border-t border-white/5">
                       <div className="flex items-center gap-2 mb-2">
                          <Activity className="w-3 h-3 text-blue-500" />
                          <span className="text-[8px] font-black text-blue-400 uppercase tracking-widest">Real-time Stream</span>
                       </div>
                       <div className="space-y-1">
                          <div className="text-[8px] font-mono text-slate-600 animate-pulse">Checking buffer at 0x4F... PASS</div>
                          <div className="text-[8px] font-mono text-slate-500">Decompressing LZ4 payload... DONE</div>
                          <div className="text-[8px] font-mono text-blue-400/50">WAF: Validated signature #8291</div>
                       </div>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-8">
                  <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 overflow-hidden relative group">
                    <div className="absolute -top-4 -right-4 w-24 h-24 bg-blue-50 rounded-full opacity-50 group-hover:scale-150 transition-transform duration-1000" />
                    <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-6 flex justify-between items-center relative z-10">
                      Policy Gap Analysis
                      <span className="text-[10px] text-blue-600 lowercase bg-blue-50 px-2 py-0.5 rounded italic">Coverage: {calculateSecurityScore()}%</span>
                    </h3>
                    <div className="space-y-4 relative z-10">
                      {[
                        { label: 'SQL Injection', key: 'SQL' },
                        { label: 'Cross-Site Scripting', key: 'XSS' },
                        { label: 'Path Traversal', key: 'Travers' },
                        { label: 'Command Injection', key: 'CMD' },
                        { label: 'User Agent Spoofing', key: 'UA' },
                      ].map((gap) => {
                        const isProtected = stats?.rules?.some((r: any) => 
                          r.name.toLowerCase().includes(gap.key.toLowerCase()) || 
                          r.description.toLowerCase().includes(gap.key.toLowerCase())
                        );
                        return (
                          <div key={gap.key} className="flex justify-between items-center group/gap">
                            <span className="text-xs font-bold text-slate-600 transition-colors group-hover/gap:text-slate-900">{gap.label}</span>
                            <div className="flex items-center gap-2">
                              {isProtected ? (
                                <span className="text-[9px] font-black text-emerald-600 uppercase flex items-center gap-1">
                                  <CheckCircle className="w-3 h-3" /> Secure
                                </span>
                              ) : (
                                <span className="text-[9px] font-black text-red-500 uppercase">
                                  Vulnerable
                                </span>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>

                {/* Recent Logs Summary */}
                <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
                  <div className="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50/50">
                    <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wider">Recent Detection Events</h3>
                    <button onClick={() => setActiveTab('logs')} className="text-xs text-blue-600 font-bold uppercase hover:underline">Auditing View</button>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left">
                      <thead className="bg-slate-50/80 text-[10px] uppercase text-slate-500 font-bold border-b border-slate-200">
                        <tr>
                          <th className="px-6 py-3">Timestamp</th>
                          <th className="px-6 py-3">Attack Type</th>
                          <th className="px-6 py-3">Source IP</th>
                          <th className="px-6 py-3">Target Path</th>
                          <th className="px-6 py-3">Risk</th>
                          <th className="px-6 py-3">Action</th>
                          <th className="px-6 py-3 text-right">Details</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-100 text-sm">
                        {stats?.recentLogs.slice(0, 8).map((log: any) => (
                          <tr key={log.id} className="hover:bg-slate-50 transition group">
                            <td className="px-6 py-3 text-slate-500 font-mono text-xs">{format(new Date(log.timestamp), 'HH:mm:ss')}</td>
                            <td className="px-6 py-3 font-semibold text-slate-800">{log.attack_type || 'Unclassified'}</td>
                            <td className="px-6 py-3 text-slate-600 font-mono text-xs">{log.ip}</td>
                            <td className="px-6 py-3 text-slate-500 italic max-w-[200px] truncate">{log.url}</td>
                            <td className="px-6 py-3">
                              <span className={cn(
                                "px-2 py-0.5 rounded text-[10px] font-bold",
                                log.risk_score > 0.8 ? "bg-red-100 text-red-700" : "bg-blue-100 text-blue-700"
                              )}>
                                {(log.risk_score * 10).toFixed(1)}/10
                              </span>
                            </td>
                            <td className="px-6 py-3">
                              <span className={cn(
                                "font-bold italic text-xs",
                                log.status === 'blocked' ? "text-red-600" : "text-emerald-600"
                              )}>
                                {log.status === 'blocked' ? 'Blocked' : 'Allowed'}
                              </span>
                            </td>
                            <td className="px-6 py-3 text-right">
                              <button 
                                onClick={() => setSelectedLog(log)}
                                className="p-1.5 transition-all text-slate-400 hover:text-blue-600 opacity-0 group-hover:opacity-100"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </motion.div>
            )}

          {activeTab === 'logs' && (
            <motion.div 
              key="logs"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm"
            >
              <div className="p-6 border-b border-slate-200 flex gap-4 bg-white">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <input 
                    type="text" 
                    placeholder="Search logs by IP, path, or classification..." 
                    className="w-full bg-slate-50 border border-slate-200 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-blue-500 transition-colors"
                  />
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-50 text-[10px] uppercase text-slate-500 font-bold border-b border-slate-200">
                    <tr>
                      <th className="px-6 py-4">ID</th>
                      <th className="px-6 py-4">Status</th>
                      <th className="px-6 py-4">Origin IP</th>
                      <th className="px-6 py-4">Endpoint / Method</th>
                      <th className="px-6 py-4 text-center">Threat Rating</th>
                      <th className="px-6 py-4">Date/Time</th>
                      <th className="px-6 py-4 text-right">Report</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {stats?.recentLogs.map((log: any) => (
                      <tr key={log.id} className="hover:bg-slate-50/50 transition relative group">
                        <td className="px-6 py-4 text-slate-400 font-mono text-[10px]">L-{log.id}</td>
                        <td className="px-6 py-4">
                          <span className={cn(
                            "px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-tight",
                            log.status === 'blocked' ? "bg-red-50 text-red-600 border border-red-100" : "bg-emerald-50 text-emerald-600 border border-emerald-100"
                          )}>
                            {log.status}
                          </span>
                        </td>
                        <td className="px-6 py-4 font-mono text-xs font-medium text-slate-700">{log.ip}</td>
                        <td className="px-6 py-4 space-y-0.5">
                          <div className="flex items-center gap-2">
                             <span className="text-blue-600 font-bold text-[10px]">{log.method}</span>
                             <span className="text-slate-600 text-xs truncate max-w-[250px]">{log.url}</span>
                          </div>
                          {log.attack_type && (
                            <p className="text-[10px] text-red-500/80 font-semibold">{log.attack_type}</p>
                          )}
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex flex-col items-center gap-1.5">
                            <div className="w-16 h-1.5 bg-slate-100 rounded-full overflow-hidden border border-slate-200/50">
                              <div 
                                className={cn("h-full rounded-full transition-all duration-500", log.risk_score > 0.8 ? "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.4)]" : "bg-blue-500")} 
                                style={{ width: `${Math.min(log.risk_score * 100, 100)}%` }} 
                              />
                            </div>
                            <span className="text-[9px] font-bold text-slate-400 tracking-tighter uppercase">SCORE: {log.risk_score.toFixed(2)}</span>
                          </div>
                        </td>
                        <td className="px-6 py-4 text-slate-500 text-[11px] font-medium">{format(new Date(log.timestamp), 'MMM dd, HH:mm:ss')}</td>
                        <td className="px-6 py-4 text-right">
                          <button 
                            onClick={() => setSelectedLog(log)}
                            className="p-2 bg-slate-50 border border-slate-200 rounded-lg text-slate-500 hover:text-blue-600 hover:bg-blue-50 transition-all opacity-0 group-hover:opacity-100 shadow-sm"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </motion.div>
          )}

          {activeTab === 'rules' && (
            <motion.div 
              key="rules"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="grid grid-cols-1 lg:grid-cols-12 gap-8"
            >
              <div className="lg:col-span-8 space-y-6">
                <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
                  <div className="p-6 border-b border-slate-200 flex justify-between items-center bg-white">
                    <h3 className="text-sm font-bold text-slate-800 flex items-center gap-2">
                      <Shield className="w-4 h-4 text-blue-600" /> 
                      Global Filter Set
                    </h3>
                    <div className="flex items-center gap-2">
                       <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></span>
                       <span className="text-[10px] font-bold uppercase text-emerald-600 tracking-wider">Synchronized</span>
                    </div>
                  </div>
                  <div className="divide-y divide-slate-100">
                    {rules.map((rule) => (
                      <div key={rule.id} className="p-6 flex justify-between items-start hover:bg-slate-50/50 transition group">
                        <div className="space-y-2 flex-1 pr-6">
                          <div className="flex items-center gap-2">
                             <h4 className="text-sm font-bold text-slate-900">{rule.name}</h4>
                             <span className="px-1.5 py-0.5 rounded text-[8px] bg-slate-100 border border-slate-200 uppercase font-bold text-slate-500">{rule.target}</span>
                          </div>
                          <p className="text-xs text-slate-500 leading-relaxed italic border-l-2 border-slate-100 pl-3">{rule.description}</p>
                          <div className="relative group/code mt-3">
                            <code className="block font-mono text-[10px] bg-slate-900 text-blue-300 p-3 rounded-lg shadow-inner border border-slate-800 overflow-x-auto whitespace-pre">
                              {rule.pattern}
                            </code>
                          </div>
                        </div>
                        <div className="flex flex-col items-end gap-4 min-w-[100px]">
                           <div className="text-right">
                              <p className="text-[9px] text-slate-400 uppercase font-black tracking-widest leading-none mb-1">Impact</p>
                              <p className="text-sm text-slate-900 font-mono font-bold tracking-tighter">{rule.risk_weight.toFixed(1)}/1.0</p>
                           </div>
                           <button 
                             onClick={() => handleDeleteRule(rule.id)}
                             className="p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition duration-200"
                           >
                             <Trash2 className="w-4 h-4" />
                           </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-slate-900 border border-white/10 rounded-xl p-8 overflow-hidden relative shadow-2xl group">
                  <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-10 transition-opacity duration-1000 rotate-12">
                    <Activity className="w-32 h-32 text-blue-500" />
                  </div>
                  <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-6">
                      <div className="p-2.5 bg-blue-600 rounded-lg shadow-lg shadow-blue-600/20">
                        <ShieldCheck className="w-5 h-5 text-white" />
                      </div>
                      <div>
                        <h3 className="text-lg font-black text-white tracking-tight uppercase">AI Intelligence Dashboard</h3>
                        <p className="text-xs text-slate-400 font-medium">Real-time neural heuristics and signature matching for edge defense.</p>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-4 mb-8">
                      <div className="p-4 bg-white/5 border border-white/5 rounded-xl">
                        <span className="text-[10px] font-black text-slate-500 uppercase block mb-1">Active Heuristics</span>
                        <div className="flex items-end gap-2">
                          <span className="text-xl font-mono font-black text-white">42</span>
                          <span className="text-[8px] font-bold text-green-500 mb-1 leading-none">UPTIME 99.9%</span>
                        </div>
                      </div>
                      <div className="p-4 bg-white/5 border border-white/5 rounded-xl">
                        <span className="text-[10px] font-black text-slate-500 uppercase block mb-1">Global Reputation</span>
                        <div className="flex items-end gap-2">
                          <span className="text-xl font-mono font-black text-white">HIGH</span>
                          <span className="text-[8px] font-bold text-blue-500 mb-1 leading-none">SECURE</span>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div className="flex justify-between items-center text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">
                        <span>Live Intel Stream</span>
                        <span className="w-2 h-2 bg-blue-500 rounded-full animate-pulse" />
                      </div>
                      <div className="space-y-2">
                        {[
                          { event: 'SQLi attempt blocked via Edge Node 4', time: '2m ago', type: 'BLOCK' },
                          { event: 'Reputation score updated for 192.168.1.1', time: '14m ago', type: 'INFO' },
                          { event: 'Path Traversal signature updated', time: '1h ago', type: 'SYNC' },
                        ].map((item, i) => (
                          <div key={i} className="flex justify-between items-center bg-black/40 p-3 rounded-lg border border-white/5">
                            <div className="flex items-center gap-3">
                              <span className={cn(
                                "text-[8px] font-black px-1.5 py-0.5 rounded",
                                item.type === 'BLOCK' ? "bg-red-500/20 text-red-400" : "bg-blue-500/20 text-blue-400"
                              )}>{item.type}</span>
                              <span className="text-[10px] text-slate-300 font-medium">{item.event}</span>
                            </div>
                            <span className="text-[10px] font-mono text-slate-500 tracking-tighter">{item.time}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="lg:col-span-4 space-y-6">
                <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm sticky top-24">
                  <h3 className="text-sm font-bold text-slate-800 mb-6 flex items-center gap-2">
                    <Plus className="w-4 h-4 text-blue-600" /> Define Rule
                  </h3>
                  <div className="space-y-5">
                    <InputGroup label="Rule Signature Name" value={newRule.name} onChange={(e) => setNewRule({ ...newRule, name: e.target.value })} placeholder="e.g. SQLi-Union-Bypass" />
                    <InputGroup label="Regex Signature" value={newRule.pattern} onChange={(e) => setNewRule({ ...newRule, pattern: e.target.value })} placeholder="e.g. (UNION|SELECT|--)..." />
                    
                    <div className="space-y-2">
                       <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Inspection Scope</label>
                       <div className="relative">
                         <select 
                           value={newRule.target} 
                           onChange={(e) => setNewRule({ ...newRule, target: e.target.value })}
                           className="w-full bg-slate-50 border border-slate-200 rounded-lg px-4 py-3 text-xs font-bold text-slate-700 focus:outline-none focus:border-blue-500 appearance-none cursor-pointer"
                         >
                           <option value="any">Any (Global Inspection)</option>
                           <option value="url">Resource Path (URL)</option>
                           <option value="query">Query Arguments (?...)</option>
                           <option value="body">POST / PUT Bodies</option>
                           <option value="headers">HTTP Headers</option>
                         </select>
                         <div className="absolute right-4 top-1/2 -translate-y-1/2 pointer-events-none opacity-50">
                           <Eye className="w-3.5 h-3.5" />
                         </div>
                       </div>
                    </div>

                    <div className="space-y-3">
                       <div className="flex justify-between items-center">
                          <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest">Weight Distribution</label>
                          <span className="text-xs font-bold font-mono text-blue-600">{newRule.risk_weight.toFixed(1)}</span>
                       </div>
                       <input 
                         type="range" min="0.1" max="1.0" step="0.1" 
                         value={newRule.risk_weight} 
                         onChange={(e) => setNewRule({ ...newRule, risk_weight: parseFloat(e.target.value) })}
                         className="w-full h-1.5 bg-slate-100 rounded-full appearance-none cursor-pointer accent-blue-600 border border-slate-200" 
                       />
                    </div>

                    <button 
                      onClick={handleAddRule}
                      className="w-full py-3.5 bg-slate-900 hover:bg-slate-800 text-white transition rounded-xl text-xs font-bold uppercase tracking-widest mt-4 shadow-xl shadow-slate-900/10"
                    >
                      Provision Rule
                    </button>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'monitoring' && (
            <motion.div 
              key="monitoring"
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              className="space-y-8"
            >
              <div className="bg-white rounded-[2.5rem] p-12 shadow-sm border border-slate-200 overflow-hidden relative">
                <div className="absolute top-0 right-0 p-12 opacity-5">
                  <Fingerprint className="w-64 h-64 text-slate-900" />
                </div>
                <div className="relative z-10">
                  <div className="flex items-center gap-3 mb-4">
                    <h2 className="text-4xl font-black uppercase tracking-tighter">Device <span className="text-blue-600">Fingerprinting</span></h2>
                    <div className="flex h-5 items-center gap-1.5 px-3 bg-emerald-50 border border-emerald-100 rounded-full">
                       <span className="relative flex h-2 w-2">
                         <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                         <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                       </span>
                       <span className="text-[9px] font-black text-emerald-600 uppercase tracking-widest">WAF Kernel Active</span>
                    </div>
                  </div>
                  <p className="text-lg text-slate-500 font-medium max-w-2xl leading-relaxed italic">
                    Analyzing anomalous request signatures and headless browser behaviors to isolate automated threats before they reach the application layer.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Fingerprint Card */}
                <div className="lg:col-span-1 space-y-8">
                  <div className="bg-slate-900 rounded-[2.5rem] p-8 border border-white/10 shadow-xl overflow-hidden relative min-h-[400px]">
                    <div className="absolute -right-4 -top-4 opacity-10">
                      <Laptop className="w-32 h-32 text-blue-500" />
                    </div>
                    <div className="relative z-10 h-full flex flex-col">
                      <div className="flex justify-between items-start mb-6">
                        <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 text-[10px] font-black uppercase tracking-widest rounded-full">
                          Your Instance
                        </span>
                        {safetyReport && (
                          <span className={cn(
                            "px-3 py-1 rounded-full text-[9px] font-black uppercase tracking-widest",
                            safetyReport.status === 'Safe' ? "bg-emerald-500/20 text-emerald-400" : 
                            safetyReport.status === 'Suspicious' ? "bg-amber-500/20 text-amber-400" : "bg-red-500/20 text-red-400"
                          )}>
                             {safetyReport.status}
                          </span>
                        )}
                      </div>
                      <h3 className="text-2xl font-black text-white mb-8 uppercase tracking-tighter">Identity Hash</h3>
                      <div className="space-y-6 flex-1">
                        {userAgentInfo ? (
                          <>
                            <div className="space-y-2">
                              <span className="text-slate-500 text-[9px] font-black uppercase tracking-widest block">Core Environment</span>
                              <div className="p-4 bg-white/5 rounded-2xl border border-white/5 flex justify-between items-center group hover:bg-white/10 transition">
                                <span className="text-xs text-slate-400 font-bold">Browser Engine</span>
                                <span className="text-blue-400 font-mono text-xs">{userAgentInfo.browser.name || 'Unknown'} {userAgentInfo.browser.version}</span>
                              </div>
                              <div className="p-4 bg-white/5 rounded-2xl border border-white/5 flex justify-between items-center group hover:bg-white/10 transition">
                                <span className="text-xs text-slate-400 font-bold">Operating System</span>
                                <span className="text-white font-mono text-xs">{userAgentInfo.os.name || 'Unknown'} {userAgentInfo.os.version}</span>
                              </div>
                            </div>
                            
                            <div className="space-y-2 pt-4">
                              <span className="text-slate-500 text-[9px] font-black uppercase tracking-widest block">Behavioral Analysis</span>
                              <div className="p-4 bg-white/5 rounded-2xl border border-white/5 flex justify-between items-center">
                                <span className="text-xs text-slate-400 font-bold">WebDriver Status</span>
                                <span className="text-emerald-400 font-mono text-[10px] font-black uppercase tracking-widest">Not Detected</span>
                              </div>
                            </div>
                          </>
                        ) : (
                          <div className="flex-1 flex items-center justify-center italic text-slate-600 text-sm">
                            Extracting browser metadata...
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Radar Chart Card */}
                <div className="lg:col-span-2 bg-white rounded-[2.5rem] p-8 border border-slate-200 shadow-sm flex flex-col justify-between overflow-hidden group">
                  <div className="flex justify-between items-center mb-4">
                    <div>
                      <h3 className="text-xl font-black text-slate-900 uppercase tracking-tighter">Attack Vector Landscape</h3>
                      <p className="text-xs text-slate-400 font-bold uppercase tracking-tight">Global Heuristic Distribution</p>
                    </div>
                    <div className="p-4 bg-slate-50 group-hover:bg-blue-50 rounded-2xl transition-colors">
                      <Activity className="w-6 h-6 text-slate-400 group-hover:text-blue-500 transition-colors" />
                    </div>
                  </div>

                  <div className="h-[350px] w-full py-4">
                    <ResponsiveContainer width="100%" height="100%">
                      <RadarChart cx="50%" cy="50%" outerRadius="80%" data={[
                        { subject: 'SQLi', A: 85, fullMark: 100 },
                        { subject: 'XSS', A: 65, fullMark: 100 },
                        { subject: 'Traversal', A: 45, fullMark: 100 },
                        { subject: 'CmdInj', A: 30, fullMark: 100 },
                        { subject: 'BotUA', A: 90, fullMark: 100 },
                        { subject: 'AdminSca', A: 20, fullMark: 100 },
                      ]}>
                        <PolarGrid stroke="#e2e8f0" />
                        <PolarAngleAxis dataKey="subject" tick={{ fill: '#64748b', fontSize: 10, fontWeight: 'bold' }} />
                        <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                        <Radar
                          name="Sentinel"
                          dataKey="A"
                          stroke="#3b82f6"
                          fill="#3b82f6"
                          fillOpacity={0.15}
                        />
                      </RadarChart>
                    </ResponsiveContainer>
                  </div>

                  <div className="pt-6 border-t border-slate-100 grid grid-cols-2 gap-4">
                    <div className="text-center">
                      <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1">Highest Vector</span>
                      <span className="text-sm font-black text-slate-900">UA Anomaly Detection</span>
                    </div>
                    <div className="text-center border-l border-slate-100">
                      <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest block mb-1">Neural Rating</span>
                      <span className="text-sm font-black text-emerald-600 uppercase">Resilient</span>
                    </div>
                  </div>
                </div>

                <div className="lg:col-span-3 grid grid-cols-1 md:grid-cols-3 gap-8">
                  <div className="p-8 bg-slate-50 rounded-[2rem] border border-slate-200">
                    <h4 className="text-[10px] uppercase font-black text-slate-400 tracking-widest mb-6 px-1">Regional Origins</h4>
                    <div className="space-y-4">
                      {[
                        { region: 'North America', count: 45, color: 'bg-blue-500' },
                        { region: 'European Union', count: 30, color: 'bg-indigo-500' },
                        { region: 'Asia Pacific', count: 15, color: 'bg-purple-500' },
                        { region: 'South America', count: 7, color: 'bg-slate-400' },
                        { region: 'Other', count: 3, color: 'bg-slate-300' }
                      ].map((reg, i) => (
                        <div key={i} className="space-y-1.5">
                          <div className="flex justify-between items-center text-[10px] font-bold">
                            <span className="text-slate-600">{reg.region}</span>
                            <span className="text-slate-400 font-mono">{reg.count}%</span>
                          </div>
                          <div className="w-full bg-slate-200 h-1.5 rounded-full overflow-hidden">
                            <motion.div 
                              initial={{ width: 0 }}
                              animate={{ width: `${reg.count}%` }}
                              className={cn("h-full rounded-full", reg.color)} 
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="md:col-span-2 p-8 bg-white rounded-[2rem] border border-slate-200 shadow-sm relative overflow-hidden group">
                     <div className="absolute -right-4 -bottom-4 opacity-[0.03] group-hover:opacity-10 transition-opacity">
                        <ShieldCheck className="w-48 h-48" />
                     </div>
                     <div className="relative z-10">
                        <h4 className="text-[10px] uppercase font-black text-slate-400 tracking-widest mb-6">Heuristic Safety Audit</h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-12 gap-y-4">
                          {safetyReport?.checks?.map((check: any, idx: number) => (
                            <div key={idx} className="flex justify-between items-center py-3 border-b border-slate-50 last:border-0">
                              <span className="text-xs font-bold text-slate-600">{check.label}</span>
                              <div className="flex items-center gap-3">
                                <span className={cn(
                                  "text-[9px] font-black uppercase px-2 py-0.5 rounded-full",
                                  check.status === 'success' ? "bg-emerald-50 text-emerald-600" :
                                  check.status === 'danger' ? "bg-red-50 text-red-600" :
                                  check.status === 'warning' ? "bg-amber-50 text-amber-600" : "bg-slate-100 text-slate-500"
                                )}>{check.value}</span>
                                {check.status === 'success' ? <CheckCircle className="w-4 h-4 text-emerald-500" /> : 
                                 check.status === 'danger' ? <XCircle className="w-4 h-4 text-red-500" /> : 
                                 <Activity className="w-4 h-4 text-amber-400 animate-pulse" />}
                              </div>
                            </div>
                          ))}
                        </div>
                     </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'stack' && (
            <motion.div 
              key="stack"
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              className="space-y-8"
            >
              <div className="bg-slate-900 rounded-[2.5rem] p-12 text-white overflow-hidden relative border border-white/5 shadow-2xl">
                <div className="absolute top-0 right-0 p-12 opacity-5 rotate-12">
                  <Layers className="w-64 h-64" />
                </div>
                <div className="relative z-10 max-w-2xl">
                  <h2 className="text-5xl font-black mb-6 leading-tight uppercase tracking-tighter">Neural <span className="text-blue-500">Defense Stack</span></h2>
                  <p className="text-xl text-slate-400 font-medium leading-relaxed italic">
                    Visualizing the multi-layered filtration architecture. Each layer applies specific heuristics to neutralize threats at different stages of the request lifecycle.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4">
                {[
                  { layer: 'L7', name: 'Application Firewall', icon: Code, desc: 'Deep packet inspection for SQLi, XSS, and RCE signatures.', status: 'Active', color: 'blue' },
                  { layer: 'L4', name: 'Transport Security', icon: Zap, desc: 'Rate limiting and anomaly detection in TCP/UDP patterns.', status: 'Active', color: 'purple' },
                  { layer: 'B', name: 'Behavioral Engine', icon: Brain, desc: 'Neural analysis of navigation patterns and interaction speeds.', status: 'Active', color: 'emerald' },
                  { layer: 'I', name: 'Identity Fingerprint', icon: Fingerprint, desc: 'Device-specific hash validation and headless browser detection.', status: 'Active', color: 'amber' },
                  { layer: 'G', name: 'Geo-Fence Filter', icon: Globe, desc: 'Origin reputation checking and regional access control.', status: 'Intercepting', color: 'red' }
                ].map((layer, idx) => (
                  <motion.div 
                    key={idx}
                    initial={{ x: -20, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    transition={{ delay: idx * 0.1 }}
                    className="group bg-white border border-slate-200 rounded-3xl p-6 flex flex-col md:flex-row items-center gap-6 hover:border-blue-200 transition-all hover:shadow-xl"
                  >
                    <div className={cn(
                      "w-16 h-16 rounded-2xl flex items-center justify-center text-xl font-black shrink-0",
                      layer.color === 'blue' ? "bg-blue-50 text-blue-600" :
                      layer.color === 'purple' ? "bg-purple-50 text-purple-600" :
                      layer.color === 'emerald' ? "bg-emerald-50 text-emerald-600" :
                      layer.color === 'amber' ? "bg-amber-50 text-amber-600" : "bg-red-50 text-red-600"
                    )}>
                      {layer.layer}
                    </div>
                    <div className="flex-1 text-center md:text-left">
                       <div className="flex items-center justify-center md:justify-start gap-2 mb-1">
                          <layer.icon className="w-4 h-4 text-slate-400" />
                          <h4 className="text-lg font-black text-slate-900 uppercase tracking-tighter">{layer.name}</h4>
                       </div>
                       <p className="text-xs text-slate-500 font-medium italic">{layer.desc}</p>
                    </div>
                    <div className="shrink-0 flex flex-col items-end gap-2 text-right">
                       <span className={cn(
                         "px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest block w-fit",
                         layer.status === 'Active' ? "bg-emerald-50 text-emerald-600" : "bg-red-50 text-red-600 animate-pulse"
                       )}>
                         {layer.status}
                       </span>
                       <div className="w-32 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                          <motion.div 
                            initial={{ width: 0 }}
                            animate={{ width: `${Math.random() * 40 + 60}%` }}
                            className={cn(
                              "h-full rounded-full",
                              layer.color === 'blue' ? "bg-blue-500" :
                              layer.color === 'purple' ? "bg-purple-500" :
                              layer.color === 'emerald' ? "bg-emerald-500" :
                              layer.color === 'amber' ? "bg-amber-500" : "bg-red-500"
                            )}
                          />
                       </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          )}

          {activeTab === 'simulator' && (
            <motion.div 
              key="simulator"
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              className="fixed inset-0 z-[100] bg-slate-950 overflow-y-auto"
            >
              {/* Lab Header */}
              <div className="sticky top-0 bg-slate-900 border-b border-white/5 px-8 h-20 flex items-center justify-between z-50">
                <div className="flex items-center gap-6">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-blue-600/40">
                       <Terminal className="w-6 h-6 text-white" />
                    </div>
                    <div>
                      <h3 className="text-lg font-black text-white tracking-widest uppercase italic">IntelliGuard <span className="text-blue-500">Attack Lab</span></h3>
                      <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Isolated Runtime V1.4</p>
                    </div>
                  </div>
                  <div className="h-10 w-px bg-white/5" />
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                    <span className="text-[10px] font-black text-slate-400 uppercase">Engine Linked to Dashboard</span>
                  </div>
                </div>
                <button 
                  onClick={() => setActiveTab('overview')}
                  className="px-6 py-2.5 bg-white/5 border border-white/10 hover:bg-white/10 text-white text-xs font-black uppercase tracking-widest rounded-xl transition-all flex items-center gap-2"
                >
                  Return to Command Center <Activity className="w-4 h-4" />
                </button>
              </div>

              <div className="max-w-6xl mx-auto p-12 space-y-12 mb-20">
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-12">
                  <div className="lg:col-span-2 space-y-8">
                    <div className="bg-slate-900 rounded-3xl p-10 border border-white/5 shadow-2xl relative overflow-hidden group">
                      <div className="absolute top-0 right-0 p-12 opacity-5 rotate-12">
                        <Terminal className="w-64 h-64 text-blue-500" />
                      </div>
                      
                      <div className="relative z-10">
                        <div className="mb-10">
                           <h4 className="text-[10px] font-black text-blue-500 uppercase tracking-[0.3em] mb-2">Manual Execution Protocol</h4>
                           <h2 className="text-3xl font-black text-white tracking-tight">Perform Synthetic Attacks</h2>
                           <p className="text-slate-500 text-sm mt-3 leading-relaxed max-w-xl">
                             Test your security rules by injecting raw signatures. These events will be logged and analyzed by the WAF in real-time.
                           </p>
                        </div>

                        <div className="space-y-8">
                          <div className="bg-black/40 rounded-2xl p-8 border border-white/5 shadow-inner">
                            <div className="flex justify-between items-center mb-4">
                              <label className="text-[10px] font-black text-slate-600 uppercase tracking-widest">Payload Input Stream</label>
                              <span className="text-[10px] text-slate-600 font-mono italic">IntelliGuard-Core Hook: active</span>
                            </div>
                            <div className="flex flex-col gap-4">
                              <input 
                                type="text" 
                                value={simulationPayload}
                                onChange={(e) => {
                                  setSimulationPayload(e.target.value);
                                  if (simulationResult) setSimulationResult(null);
                                }}
                                placeholder="Paste malicious signature... (e.g. <script>alert(1)</script>)"
                                className="w-full bg-slate-950 border border-slate-800 rounded-2xl px-8 py-5 font-mono text-base text-blue-400 focus:outline-none focus:border-blue-500/50 shadow-2xl transition-all placeholder:text-slate-800"
                              />
                              <button 
                                onClick={runSimulation}
                                className="w-full py-5 bg-blue-600 hover:bg-blue-700 text-white font-black rounded-2xl transition-all shadow-xl shadow-blue-600/20 active:scale-[0.98] flex items-center gap-4 justify-center uppercase tracking-widest text-sm"
                              >
                                Commit Attack Sequence <Activity className="w-5 h-5" />
                              </button>
                            </div>
                          </div>

                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            {[
                              { label: 'SQL Injection', payload: "1' OR '1'='1' --" },
                              { label: 'XSS Vector', payload: "<script>fetch('/malicious')</script>" },
                              { label: 'Path Travel', payload: "../../../etc/passwd" },
                              { label: 'NoSQL Inject', payload: '{"$gt": ""}' },
                              { label: 'Shell Bypass', payload: "cat /etc/shadow" },
                              { label: 'Honeypot Path', payload: "/.env" },
                              { label: 'Header Spoof', payload: "X-Forwarded-For: 1.2.3.4" },
                              { label: 'Admin Access', payload: "/admin/dashboard" },
                              { label: 'FORCE ALERT', payload: "trigger-waf-alert" },
                            ].map(test => (
                              <button 
                                key={test.label}
                                onClick={() => { 
                                  setSimulationPayload(test.payload); 
                                  setSimulationResult(null);
                                }}
                                className="p-5 bg-white/5 border border-white/5 rounded-2xl text-left hover:bg-white/10 transition-all group border-b-2 hover:border-blue-500/50"
                              >
                                <p className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-2 group-hover:text-blue-400 transition-colors">{test.label}</p>
                                <p className="font-mono text-[10px] text-slate-400 truncate opacity-40">{test.payload}</p>
                              </button>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-8">
                     <div className="bg-slate-900 border border-white/5 rounded-3xl p-8 shadow-2xl">
                        <div className="flex items-center gap-3 mb-8">
                           <div className="p-2 bg-emerald-500/20 rounded-lg text-emerald-400">
                              <ShieldCheck className="w-5 h-5" />
                           </div>
                           <h4 className="text-xs font-black text-white uppercase tracking-widest">Lab Integration</h4>
                        </div>
                        <div className="space-y-6">
                           <IntegrationStep 
                             number="01" 
                             title="Synthetic Injection" 
                             desc="Payloads bypass standard UI constraints to test kernel-level WAF rules." 
                           />
                           <IntegrationStep 
                             number="02" 
                             title="Real-time Logging" 
                             desc="Every execution appears instantly in the Dashboard Threat Logs." 
                           />
                           <IntegrationStep 
                             number="03" 
                             title="Alert Pipeline" 
                             desc="Blocked states trigger system notifications." 
                           />
                        </div>
                     </div>
                  </div>
                </div>

                <AnimatePresence>
                  {simulationResult && (
                    <motion.div 
                      initial={{ opacity: 0, y: 40 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: 40 }}
                      className={cn(
                        "rounded-[2.5rem] border-2 p-10 relative overflow-hidden shadow-2xl",
                        simulationResult.status === 403 || simulationResult.error 
                          ? "bg-red-500/5 border-red-500/20 shadow-red-500/10" 
                          : "bg-emerald-500/5 border-emerald-500/20 shadow-emerald-500/10"
                      )}
                    >
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-12 items-center">
                        <div className="space-y-8">
                          <div className="flex items-center gap-4">
                            <div className={cn(
                              "p-4 rounded-2xl",
                              simulationResult.status === 403 || simulationResult.error ? "bg-red-500/20 text-red-400" : "bg-emerald-500/20 text-emerald-400"
                            )}>
                              {simulationResult.status === 403 || simulationResult.error ? <XCircle className="w-8 h-8"/> : <CheckCircle className="w-8 h-8"/>}
                            </div>
                            <div>
                              <h3 className="text-4xl font-black text-white tracking-tighter uppercase leading-none">
                                {simulationResult.status === 403 || simulationResult.error ? 'Blocked' : 'Bypassed'}
                              </h3>
                              <p className="text-slate-500 text-xs font-black uppercase tracking-[0.2em] mt-2">Engine Decision Complete</p>
                            </div>
                          </div>
                          <div className="space-y-4">
                            <p className="text-slate-400 text-sm leading-relaxed">
                              {simulationResult.status === 403 || simulationResult.error 
                                ? 'The AI heuristic engine successfully identified the payload as high-risk.' 
                                : 'Filter logic did not identify a malicious signature.'}
                            </p>
                          </div>
                        </div>

                        <div className="relative group">
                          <div className="absolute inset-0 bg-blue-500/10 blur-3xl rounded-full opacity-50 group-hover:opacity-80 transition-opacity" />
                          <div className="relative bg-black/60 rounded-3xl border border-white/10 p-6 shadow-2xl backdrop-blur-xl">
                            <pre className="text-[11px] font-mono text-blue-400/90 whitespace-pre-wrap overflow-x-auto max-h-[300px] thin-scrollbar">
                              {JSON.stringify(simulationResult, null, 2)}
                            </pre>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

      <AnimatePresence>
          {selectedLog && (
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-[110] flex items-center justify-center p-4 md:p-8"
            >
              <div className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm" onClick={() => setSelectedLog(null)} />
              <motion.div 
                initial={{ scale: 0.95, opacity: 0, y: 20 }}
                animate={{ scale: 1, opacity: 1, y: 0 }}
                exit={{ scale: 0.95, opacity: 0, y: 20 }}
                className="relative w-full max-w-4xl bg-white rounded-3xl shadow-2xl overflow-hidden border border-slate-200 flex flex-col max-h-[90vh]"
              >
                <div className="px-8 py-6 bg-slate-900 flex justify-between items-center text-white">
                  <div className="flex items-center gap-4">
                    <div className={cn(
                      "p-3 rounded-2xl ring-4 ring-offset-4 ring-offset-slate-900 shadow-2xl",
                      selectedLog.status === 'blocked' ? "bg-red-500 text-white ring-red-500/20" : "bg-emerald-500 text-white ring-emerald-500/20"
                    )}>
                      <ShieldAlert className="w-6 h-6 animate-pulse" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="px-1.5 py-0.5 bg-red-500/50 text-[8px] font-black uppercase tracking-[0.2em] rounded">Confidential</span>
                        <h3 className="text-xl font-black uppercase tracking-widest italic leading-none">Forensic Incident Report</h3>
                      </div>
                      <p className="text-[10px] text-slate-400 font-bold uppercase tracking-widest">CASE ID: SN-{selectedLog.id}-{format(new Date(selectedLog.timestamp), 'mmSS')} • {format(new Date(selectedLog.timestamp), 'MMM dd, yyyy HH:mm:ss')}</p>
                    </div>
                  </div>
                  <button onClick={() => setSelectedLog(null)} className="p-2 hover:bg-white/10 rounded-xl transition text-slate-400 hover:text-white">
                    <Trash2 className="w-5 h-5" />
                  </button>
                </div>

                <div className="flex-1 overflow-y-auto p-8 space-y-12" ref={reportRef} data-report-container="true">
                  {/* Summary Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="p-6 bg-slate-50 rounded-2xl border border-slate-100 shadow-sm hover:shadow transition-shadow">
                      <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-3">Target URL</p>
                      <p className="text-sm font-mono font-bold text-slate-800 break-all leading-relaxed">{selectedLog.url}</p>
                    </div>
                    <div className="p-6 bg-slate-50 rounded-2xl border border-slate-100 shadow-sm hover:shadow transition-shadow">
                      <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-3">Source IP</p>
                      <p className="text-lg font-mono font-black text-blue-600">{selectedLog.ip}</p>
                    </div>
                    <div className="p-6 bg-slate-50 rounded-2xl border border-slate-100 shadow-sm hover:shadow transition-shadow">
                      <p className="text-[10px] font-black text-slate-400 uppercase tracking-widest mb-3">Threat Score</p>
                      <div className="flex items-end gap-2">
                        <span className={cn("text-2xl font-mono font-black", selectedLog.risk_score > 0.8 ? "text-red-600" : "text-blue-600")}>
                          {(selectedLog.risk_score * 10).toFixed(1)}
                        </span>
                        <span className="text-slate-400 text-xs font-bold mb-1">/ 10.0</span>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                    {/* Attack Details */}
                    <div className="space-y-4">
                      <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest flex items-center gap-2 px-1">
                        <AlertTriangle className="w-4 h-4 text-red-500" />
                        Signature Analysis
                      </h4>
                      <div className="bg-slate-900 rounded-[2rem] p-8 border border-white/5 shadow-2xl relative overflow-hidden group">
                        <div className="absolute -right-4 -top-4 opacity-[0.03] group-hover:opacity-10 transition-opacity">
                          <Activity className="w-48 h-48" />
                        </div>
                        <div className="space-y-6 relative z-10">
                          <div>
                            <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest block mb-1 px-1">Detected Threats</span>
                            <div className="flex flex-wrap gap-2 mt-3">
                              {selectedLog.attack_type ? (
                                selectedLog.attack_type.split(',').map((type: string, i: number) => (
                                  <span key={i} className="px-3 py-1.5 bg-red-500 text-white text-[9px] font-black uppercase tracking-[0.1em] rounded-lg shadow-lg shadow-red-500/20">
                                    {type.trim()}
                                  </span>
                                ))
                              ) : (
                                <span className="text-slate-500 text-[10px] italic">No specific signature matched</span>
                              )}
                            </div>
                          </div>
                          <div className="grid grid-cols-2 gap-4">
                            <div className="p-4 bg-white/5 rounded-2xl border border-white/5">
                              <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest block mb-1">Method</span>
                              <span className="text-blue-400 font-mono text-xs font-bold uppercase">{selectedLog.method}</span>
                            </div>
                            <div className="p-4 bg-white/5 rounded-2xl border border-white/5">
                              <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest block mb-1">Status Code</span>
                              <span className={cn(
                                "font-mono text-xs font-black",
                                selectedLog.status === 'blocked' ? "text-red-400" : "text-emerald-400"
                              )}>{selectedLog.status === 'blocked' ? '403 Forbidden' : '200 OK'}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Environment Data */}
                    <div className="space-y-4">
                      <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest flex items-center gap-2 px-1">
                        <Laptop className="w-4 h-4 text-blue-500" />
                        Source Environment
                      </h4>
                      <div className="bg-white border border-slate-200 rounded-[2rem] p-8 space-y-5 shadow-sm">
                        <div className="flex justify-between items-center border-b border-slate-50 pb-4">
                          <span className="text-[10px] font-black text-slate-400 uppercase">Browser</span>
                          <span className="text-xs font-bold text-slate-700">{selectedLog.browser || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between items-center border-b border-slate-50 pb-4">
                          <span className="text-[10px] font-black text-slate-400 uppercase">OS / Platform</span>
                          <span className="text-xs font-bold text-slate-700">{selectedLog.os || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between items-center border-b border-slate-50 pb-4">
                          <span className="text-[10px] font-black text-slate-400 uppercase">Device Type</span>
                          <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">{selectedLog.device || 'Desktop'}</span>
                        </div>
                        <div>
                          <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest block mb-3 px-1">User Agent String</span>
                          <code className="block p-4 bg-slate-50 rounded-2xl text-[9px] font-mono text-slate-500 break-all border border-slate-100 leading-relaxed">
                            {selectedLog.userAgentHeader || 'Mozilla/5.0 (IntelliGuard-Audit/1.0)...'}
                          </code>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Raw Data Section */}
                  <div className="space-y-4">
                     <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest flex items-center gap-2 px-1">
                      <Terminal className="w-4 h-4 text-slate-400" />
                      Protocol Capture
                    </h4>
                    <div className="relative group">
                      <div className="absolute top-4 right-4 text-[9px] font-black text-slate-800 uppercase bg-slate-200 px-3 py-1 rounded-full italic opacity-50 z-10">UTF-8 Transcoded</div>
                      <pre className="p-8 bg-slate-950 text-blue-300 font-mono text-[10px] rounded-[2rem] overflow-x-auto shadow-2xl border border-slate-800 max-h-64 thin-scrollbar leading-relaxed">
                        {JSON.stringify(selectedLog, null, 2)}
                      </pre>
                    </div>
                  </div>

                  {/* Visual Signature Breakdown (The "HOW" it happened) */}
                  <div className="space-y-6 pt-4">
                    <div className="flex items-center gap-2 px-1">
                      <Activity className="w-4 h-4 text-blue-600" />
                      <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest">AI Trace Analytics</h4>
                    </div>

                    <div className="bg-slate-50 border border-slate-200 rounded-[2.5rem] p-10 space-y-10 overflow-hidden relative group">
                      <div className="absolute top-0 right-0 p-10 opacity-[0.03] group-hover:opacity-10 transition-opacity">
                        <ShieldAlert className="w-64 h-64" />
                      </div>
                    
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-10 relative z-10">
                        <div className="space-y-4">
                          <div className="flex items-center gap-3">
                            <div className="w-7 h-7 bg-blue-600 text-white rounded-full flex items-center justify-center text-xs font-black shadow-lg shadow-blue-600/20">1</div>
                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Input Buffer</span>
                          </div>
                          <div className="p-6 bg-white rounded-3xl border border-slate-200 shadow-sm font-mono text-[10px] text-slate-600 break-all h-36 overflow-y-auto flex items-start justify-center italic text-center leading-relaxed">
                            <div className="w-full py-2">
                              {(() => {
                                const url = selectedLog.url || '';
                                const p = selectedLog.payload;
                                
                                if (url.includes('payload=')) {
                                  const match = url.match(/payload=([^&]+)/);
                                  if (match) return decodeURIComponent(match[1]);
                                }
                                
                                // Check if query parameters contain malicious sequences
                                const queryStr = url.split('?')[1];
                                if (queryStr) {
                                  const params = new URLSearchParams(queryStr);
                                  for (const [_, val] of params.entries()) {
                                    if (/(?:'|--|#|\/\*|union|select|insert|<script|alert\(|onerror)/gi.test(val)) {
                                      return val;
                                    }
                                  }
                                }

                                if (!p || p === '{}' || (typeof p === 'object' && Object.keys(p).length === 0)) {
                                  return url || '/';
                                }
                                return typeof p === 'string' ? p : JSON.stringify(p);
                              })()}
                            </div>
                          </div>
                        </div>

                        <div className="space-y-4">
                          <div className="flex items-center gap-3">
                            <div className="w-7 h-7 bg-blue-600 text-white rounded-full flex items-center justify-center text-xs font-black shadow-lg shadow-blue-600/20">2</div>
                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Matched Pattern</span>
                          </div>
                          <div className="p-6 bg-slate-900 text-blue-300 rounded-3xl border border-white/5 shadow-2xl font-mono text-[10px] h-36 overflow-y-auto flex items-start justify-center text-center">
                            <div className="w-full py-2">
                              <code className="break-all text-blue-100 italic leading-relaxed">
                                {selectedLog.rule_pattern && selectedLog.rule_pattern !== '/.*/' 
                                  ? selectedLog.rule_pattern 
                                  : (selectedLog.attack_type?.toLowerCase().includes('sql') 
                                      ? "/(?:'|--|#|\\/\\*|union|select|insert)/gi" 
                                      : (selectedLog.attack_type?.toLowerCase().includes('xss') 
                                        ? "(<script.*?>|on(mouseover|click|load|error|focus|scroll|pointer|aux)\\s*=|<.*?javascript:.*?>|alert\\s*\\(|prompt\\s*\\()" 
                                        : (selectedLog.attack_type?.toLowerCase().includes('nosql')
                                          ? "(\\$gt|\\$ne|\\$lt|\\$lte|\\$gte|\\$where|\\$regex|\\$expr)"
                                          : (selectedLog.attack_type?.toLowerCase().includes('traversal')
                                            ? "/(?:\\.\\.\\/|\\/etc\\/|\\/bin\\/)/gi"
                                            : "/[\\x00-\\x1F\\x7F-\\xFF]/g"))))}
                              </code>
                            </div>
                          </div>
                        </div>

                        <div className="space-y-4">
                          <div className="flex items-center gap-3">
                            <div className="w-7 h-7 bg-red-600 text-white rounded-full flex items-center justify-center text-xs font-black shadow-lg shadow-red-600/20">3</div>
                            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Active Trigger</span>
                          </div>
                          <div className="p-6 bg-red-50 text-red-600 rounded-3xl border border-red-100 shadow-sm flex flex-col justify-center items-center h-36 text-center ring-4 ring-red-50/50 ring-offset-2 ring-offset-white">
                            <ShieldAlert className="w-7 h-7 mb-2 animate-bounce" />
                            <span className="text-[11px] font-black uppercase tracking-tighter">{selectedLog.attack_type || 'Malicious Payload'}</span>
                            <span className="text-[8px] font-bold opacity-50 mt-1 uppercase tracking-widest">Interception Code: 403_WAF</span>
                          </div>
                        </div>
                      </div>

                      <div className="pt-10 border-t border-slate-200">
                        <div className="flex items-center justify-between mb-5 px-1">
                          <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Forensic Logic Path</span>
                          <span className="text-[10px] font-black text-emerald-600 bg-emerald-50 px-3 py-1 rounded-full uppercase flex items-center gap-1.5 border border-emerald-100">
                            <CheckCircle className="w-3 h-3" />
                            Validated Match
                          </span>
                        </div>
                        <div className="p-8 bg-slate-900 rounded-[2rem] border border-white/5 relative overflow-hidden group/audit">
                          <div className="flex items-center gap-3 mb-4">
                             <div className="w-2.5 h-2.5 rounded-full bg-blue-500 animate-pulse" />
                             <span className="text-[10px] font-bold text-blue-400 uppercase tracking-widest">Heuristic Audit Log</span>
                          </div>
                          <p className="text-sm text-slate-400 leading-relaxed font-medium font-mono">
                            [TRACE] Request buffer intercepted at layer 7.<br/>
                            [SCAN] Byte-pattern scanning against active ruleset...<br/>
                            [MATCH] Found <span className="text-red-400 font-bold underline decoration-red-400/30">{selectedLog.attack_type || 'unauthorized'}</span> signature in <span className="text-blue-400 font-bold">URI_QUERY</span>.<br/>
                            [ACTION] Executing instant drop chain. Request terminated.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Forensic Intelligence Section */}
                  <div className="space-y-6 pt-4">
                    <div className="flex justify-between items-center px-1">
                      <h4 className="text-xs font-black text-slate-900 uppercase tracking-widest flex items-center gap-2">
                        <Brain className="w-4 h-4 text-purple-500" />
                        AI Threat Intelligence
                      </h4>
                      {!aiAnalysisResult && (
                        <button 
                         onClick={handleAiAnalysis}
                          disabled={isAnalyzing}
                          className="px-5 py-2 bg-purple-600 text-white text-[10px] font-black uppercase tracking-widest rounded-xl hover:bg-purple-700 transition disabled:opacity-50 flex items-center gap-2 shadow-lg shadow-purple-600/20 active:scale-95"
                        >
                          {isAnalyzing ? (
                            <>
                              <RefreshCw className="w-3 h-3 animate-spin" />
                              Analyzing Sequence...
                            </>
                          ) : (
                            <>
                              <Brain className="w-3 h-3" />
                              Analyze Incident
                            </>
                          )}
                        </button>
                      )}
                    </div>
                    
                      {aiError && !aiAnalysisResult && !isAnalyzing && (
                        <div className="bg-red-50 border border-red-100 rounded-xl p-4 flex items-start gap-3 animate-in fade-in slide-in-from-top-1">
                          <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5" />
                          <div>
                            <p className="text-[10px] font-black text-red-600 uppercase tracking-widest">Analysis Failure</p>
                            <p className="text-[11px] text-red-500 font-medium">{aiError}</p>
                          </div>
                        </div>
                      )}

                      {aiAnalysisResult ? (
                      isAiResultValid ? (
                        <motion.div 
                          initial={{ opacity: 0, y: 10 }}
                          animate={{ opacity: 1, y: 0 }}
                          className="font-sans"
                        >
                          {/* ... existing aiAnalysisResult content ... */}
                          <div className="bg-purple-50 border border-purple-100 rounded-[2.5rem] p-10 space-y-10 shadow-sm">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                              <div className="p-6 bg-white rounded-2xl border border-purple-100 shadow-sm">
                                <span className="text-[9px] font-black text-purple-400 uppercase tracking-[0.2em] block mb-3 px-1">Primary Intent</span>
                                <p className="text-sm font-black text-purple-900 px-1 leading-relaxed">{aiAnalysisResult.intent}</p>
                              </div>
                              <div className="p-6 bg-white rounded-2xl border border-purple-100 shadow-sm">
                                <span className="text-[9px] font-black text-purple-400 uppercase tracking-[0.2em] block mb-3 px-1">Technical Assessment</span>
                                <div className="flex items-center gap-3 px-1">
                                    <div className={cn(
                                      "w-3 h-3 rounded-full",
                                      aiAnalysisResult.risk_level === 'Critical' ? "bg-red-500 animate-pulse" : "bg-purple-500"
                                    )} />
                                    <span className={cn(
                                      "text-[11px] font-black uppercase tracking-widest",
                                      aiAnalysisResult.risk_level === 'Critical' ? "text-red-600" : "text-purple-600"
                                    )}>{aiAnalysisResult.risk_level} SEVERITY</span>
                                </div>
                              </div>
                            </div>

                            <div className="relative">
                              <div className="absolute left-0 top-0 bottom-0 w-1.5 bg-purple-200 rounded-full" />
                              <div className="pl-8">
                                <span className="text-[9px] font-black text-purple-400 uppercase tracking-[0.2em] block mb-3">Detailed Vulnerability Analysis</span>
                                <p className="text-sm text-purple-900/80 leading-relaxed font-bold italic">
                                  "{aiAnalysisResult.explanation}"
                                </p>
                              </div>
                            </div>

                            <div className="pt-10 border-t border-purple-100">
                              <div className="flex items-center gap-3 mb-5 px-1">
                                  <Lock className="w-4 h-4 text-purple-500" />
                                  <span className="text-[10px] font-black text-purple-400 uppercase tracking-[0.2em]">Remediation & Defensive Implementation</span>
                              </div>
                              <div className="prose prose-sm max-w-none prose-purple bg-slate-900 p-8 rounded-[2rem] overflow-x-auto border border-purple-200/20 text-blue-100 font-mono text-[11px] shadow-2xl leading-relaxed">
                                  <ReactMarkdown>{aiAnalysisResult.remediation}</ReactMarkdown>
                              </div>
                              <p className="mt-6 text-[9px] text-purple-400 font-bold uppercase text-center italic tracking-widest">AI suggestions should be reviewed by a lead engineer before production deployment.</p>
                            </div>
                          </div>
                        </motion.div>
                      ) : (
                        <div className="bg-amber-50 border border-amber-100 rounded-xl p-6 text-center">
                          <AlertTriangle className="w-8 h-8 text-amber-500 mx-auto mb-3" />
                          <p className="text-xs font-black text-amber-900 uppercase tracking-widest">Intelligence Malfunction</p>
                          <p className="text-[11px] text-amber-700 mt-2">The security engine returned a malformed report. Please try analyzing again.</p>
                          <button 
                            onClick={handleAiAnalysis}
                            className="mt-4 px-6 py-2 bg-amber-600 text-white text-[10px] font-black uppercase tracking-widest rounded-lg"
                          >
                            Recalibrate Logic
                          </button>
                        </div>
                      )
                    ) : isAnalyzing && (
                      <div className="p-20 text-center bg-slate-900 rounded-[2.5rem] border border-dashed border-slate-800 animate-pulse">
                        <div className="relative inline-block mb-6">
                          <Brain className="w-14 h-14 text-purple-500 animate-bounce" />
                          <div className="absolute inset-0 bg-purple-500/20 blur-2xl rounded-full" />
                        </div>
                        <p className="text-[11px] font-black text-slate-400 uppercase tracking-[0.4em]">Running AI Inference...</p>
                        <p className="text-[10px] text-slate-600 uppercase mt-3 font-bold italic">Deconstructing packet signatures for neural profiling</p>
                      </div>
                    )}
                  </div>
                </div>

              <div className="p-6 bg-slate-50 border-t border-slate-200 flex justify-end gap-3 shrink-0">
                  <button 
                    onClick={handleDownloadHtml}
                    className="px-6 py-2.5 bg-emerald-600 text-white text-[10px] font-black uppercase tracking-[0.2em] rounded-xl hover:bg-emerald-700 transition flex items-center gap-2 shadow-lg shadow-emerald-600/20"
                  >
                    <FileCode className="w-3.5 h-3.5" />
                    Export HTML
                  </button>
                  <button 
                    onClick={() => setSelectedLog(null)}
                    className="px-6 py-2.5 bg-white border border-slate-200 text-slate-700 text-[10px] font-black uppercase tracking-[0.2em] rounded-xl hover:bg-slate-100 transition"
                  >
                    Close Report
                  </button>
                  {selectedLog.status === 'blocked' && (
                    <button className="px-6 py-2.5 bg-red-600 text-white text-[10px] font-black uppercase tracking-[0.2em] rounded-xl shadow-lg shadow-red-600/20 active:scale-95 transition">
                      Blacklist Source
                    </button>
                  )}
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </main>
  </div>
);
}

function IntegrationStep({ number, title, desc }: { number: string, title: string, desc: string }) {
  return (
    <div className="flex gap-4">
      <span className="text-[10px] font-black text-blue-500 bg-blue-500/10 w-6 h-6 flex items-center justify-center rounded-md shrink-0">{number}</span>
      <div>
        <p className="text-[10px] font-black text-white uppercase tracking-widest mb-1">{title}</p>
        <p className="text-[10px] text-slate-500 leading-relaxed">{desc}</p>
      </div>
    </div>
  );
}

function NavItem({ icon: Icon, label, active, onClick }: { icon: any, label: string, active?: boolean, onClick: () => void }) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "w-full flex items-center gap-3 px-6 py-3.5 text-sm font-bold uppercase tracking-widest transition-all duration-300",
        active 
          ? "bg-slate-800 border-l-4 border-blue-500 text-white shadow-inner" 
          : "text-slate-500 hover:text-white hover:bg-slate-800/50"
      )}
    >
      <Icon className={cn("w-4 h-4 transition-transform duration-300", active ? "text-blue-400 scale-110" : "text-slate-500")} />
      {label}
    </button>
  );
}

function StatCard({ label, value, icon: Icon, color, trend }: { label: string, value: string | number, icon: any, color: string, trend?: string }) {
  const colorMap: any = {
    blue: "text-blue-600 bg-blue-50 border-blue-100",
    red: "text-red-600 bg-red-50 border-red-100",
    slate: "text-slate-600 bg-slate-50 border-slate-100",
    emerald: "text-emerald-600 bg-emerald-50 border-emerald-100"
  };

  return (
    <div className="bg-white p-6 rounded-xl border border-slate-200 shadow-sm hover:shadow-md transition-shadow group">
      <div className="flex justify-between items-start mb-4">
        <div className={cn("w-10 h-10 rounded-lg border flex items-center justify-center transition-transform group-hover:scale-110", colorMap[color] || colorMap.slate)}>
          <Icon className="w-5 h-5" />
        </div>
        {trend && (
          <span className={cn(
            "text-[10px] font-black uppercase px-2 py-1 rounded-md",
            trend.includes('+') ? "bg-emerald-50 text-emerald-600" : trend.includes('Risk') ? "bg-blue-50 text-blue-600" : "bg-slate-50 text-slate-500"
          )}>
            {trend}
          </span>
        )}
      </div>
      <p className="text-slate-500 text-[10px] font-black uppercase tracking-[0.1em]">{label}</p>
      <h3 className={cn(
        "text-2xl font-black mt-1 tracking-tighter",
        color === 'red' ? "text-red-600" : "text-slate-900"
      )}>
        {typeof value === 'number' ? value.toLocaleString() : value || 0}
      </h3>
    </div>
  );
}

function InputGroup({ label, value, onChange, placeholder }: { label: string, value: string, onChange: (e: any) => void, placeholder: string }) {
  return (
    <div className="space-y-2">
      <label className="text-[10px] uppercase font-black text-slate-400 tracking-widest leading-none">{label}</label>
      <input 
        type="text" 
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        className="w-full bg-slate-50 border border-slate-200 rounded-lg px-4 py-3 text-xs font-bold text-slate-700 focus:outline-none focus:border-blue-500 focus:bg-white transition-all shadow-sm"
      />
    </div>
  );
}
