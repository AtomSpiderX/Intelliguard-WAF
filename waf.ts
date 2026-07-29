import "dotenv/config";
import { Request, Response, NextFunction } from "express";
import db from "./database.ts";
import { UAParser } from "ua-parser-js";

// Ensure .env variables take precedence
import dotenv from "dotenv";
dotenv.config({ override: true });

interface WafRule {
  id: number;
  name: string;
  pattern: string;
  target: string;
  risk_weight: number;
}

async function sendTelegramNotification(message: string) {
  let token = process.env.TELEGRAM_BOT_TOKEN;
  let chatId = process.env.TELEGRAM_CHAT_ID;

  // Sanitize
  if (token) token = token.trim().replace(/^["']|["']$/g, '');
  if (chatId) chatId = chatId.trim().replace(/^["']|["']$/g, '');

  console.log(`[Telegram] Attempting to send message. Token: ${token ? 'SET' : 'MISSING'}, ChatId: ${chatId ? 'SET' : 'MISSING'}`);

  if (!token || !chatId) {
    console.warn("[Telegram] Missing credentials, skipping notification.");
    return;
  }

  try {
    const url = `https://api.telegram.org/bot${token}/sendMessage`;
    const telegramPayload = {
        chat_id: chatId,
        text: message,
        parse_mode: "HTML",
      };
    console.log("[Telegram] Payload:", JSON.stringify(telegramPayload));

    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(telegramPayload),
    });
    
    const result = await response.json();
    if (!response.ok) {
      console.error("[Telegram] API Error:", result);
    } else {
      console.log("[Telegram] Notification sent successfully.");
    }
  } catch (err) {
    console.error("[Telegram] Failed to send notification:", err);
  }
}

export function wafMiddleware(req: Request, res: Response, next: NextFunction) {
  try {
    let ip = req.ip || "unknown";
    const forwarded = req.headers["x-forwarded-for"];
    if (forwarded) {
      ip = Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0].trim();
    }
    ip = String(ip);
    
    // In development mode, don't block localhost even if it's in the blacklist table
    const isLocalhost = 
      ip === "127.0.0.1" || 
      ip === "::1" || 
      ip === "::ffff:127.0.0.1" || 
      ip.includes("localhost") ||
      ip.startsWith("192.168.") || 
      ip.startsWith("10.") ||
      ip.startsWith("172."); // common local network IPs

    console.log(`[WAF] Request: ${req.method} ${req.url} from ${ip} (Local: ${isLocalhost})`);

    // 1. Skip WAF for static assets or internal dashboard assets
    const pathName = req.path;
    const isApiRequest = pathName.startsWith("/api/");
    
    // 1. Skip WAF for static assets or internal dashboard assets
    const skipList = [
      "/@vite", "node_modules", "/@id", "/@fs", ".vite", "/src",
      "/api/stats", "/api/rules", "/api/blacklist", "/api/logs",
      "/api/ai/analyze", "/api/ai/suggest"
    ];

    const staticExtensions = [".js", ".ts", ".tsx", ".css", ".svg", ".png", ".ico", ".json", ".map", "favicon"];

    const isSystemAsset = skipList.some(s => pathName.includes(s));
    const isStaticFile = staticExtensions.some(ext => pathName.endsWith(ext));
    const isRoot = pathName === "/";

    // IN DEV MODE: Skip WAF for anything that isn't a PROTECTED API call
    // This fixes the blank screen by allowing Vite/React assets to load
    if (process.env.NODE_ENV !== "production" && isLocalhost) {
      if (!isApiRequest || isSystemAsset) {
        console.log(`[WAF] [DEV-BYPASS] Allowing system/app request: ${req.url}`);
        return next();
      }
    }

    // PRODUCTION/STRICT RULES:
    if (isRoot || isSystemAsset || isStaticFile) {
      console.log(`[WAF] Skipping security check for asset/root: ${req.url}`);
      return next();
    }
  
    // 2. Check Blacklist
    const isBlacklisted = db.prepare("SELECT * FROM blacklist WHERE ip = ?").get(ip) as { reason: string } | undefined;
    
    if (isBlacklisted && !req.url.includes("/api/simulate")) {
      // Don't block localhost in dev unless it's a specific simulation
      if (process.env.NODE_ENV !== "production" && isLocalhost) {
         // Allow but flag in logs
         console.log(`[WAF] Localhost is blacklisted but allowing in DEV mode: ${ip}`);
      } else {
        // Log the blocked attempt
        const ua = new UAParser(req.headers["user-agent"] as string).getResult();
        db.prepare(`
          INSERT INTO logs (ip, method, url, headers, payload, attack_type, risk_score, status, user_agent)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          String(ip),
          req.method,
          req.url,
          JSON.stringify(req.headers),
          JSON.stringify(req.body),
          `Blacklisted: ${isBlacklisted.reason}`,
          1.0,
          "blocked",
          `${ua.browser.name} ${ua.os.name}`
        );

        if (req.path.startsWith("/api/")) {
           return res.status(403).json({ 
             error: "Access Denied", 
             reason: "IP Blacklisted", 
             detail: isBlacklisted.reason,
             incident_id: Date.now() 
           });
        }
        return res.status(403).send(generateBlockPage(ip, "IP Blacklisted", isBlacklisted.reason, 1.0, ["Blacklist Entry"]));
      }
    }

  // 1.2 Data Collection & Base Inspection
  let riskScore = 0;
  let detectedAttacks: string[] = [];

  const rawUrl = req.url;
  const decodedUrl = decodeURIComponent(rawUrl);
  const queryData = JSON.stringify(req.query);
  const bodyData = JSON.stringify(req.body);
  const headerData = JSON.stringify(req.headers);
  
  // Inspect both raw and decoded to catch both direct and encoded attacks
  const fullData = `${rawUrl} ${decodedUrl} ${queryData} ${bodyData} ${headerData}`;

  // 1.3 Honeypot Detection - Focused on URL only to prevent false positives in body/headers
  const honeypots = ["/wp-admin", "/admin/config.php", "/.env", "/backup.sql", "/phpmyadmin", "/admin/", "/config/"];
  
  if (honeypots.some(h => decodedUrl.toLowerCase().includes(h))) {
    riskScore += 1.2;
    detectedAttacks.push("Honeypot Trap");
    console.log(`[WAF] Honeypot triggered: ${ip} -> ${req.url}`);
  }

  // 2. Rule-Based Detection
  const activeRules = db.prepare("SELECT * FROM rules WHERE active = 1").all() as WafRule[];

  for (const rule of activeRules) {
    try {
      const regex = new RegExp(rule.pattern, "i");
      let targetData = "";

      if (rule.target === "body") targetData = bodyData;
      else if (rule.target === "query") targetData = queryData;
      else if (rule.target === "headers") targetData = headerData;
      else if (rule.target === "url") targetData = `${rawUrl} ${decodedUrl}`;
      else targetData = `${queryData} ${bodyData}`; // 'any' now excludes headers/url for better precision

      if (targetData && regex.test(targetData)) {
        console.log(`[WAF] MATCHED rule: "${rule.name}" on ${rule.target}. Pattern: ${rule.pattern}`);
        riskScore += rule.risk_weight;
        detectedAttacks.push(rule.name);
      }
    } catch (e) {
      console.error(`Invalid regex for rule ${rule.name}:`, rule.pattern);
    }
  }

  // 3. Dynamic Rate Limiting
  // The threshold adapts based on the current risk. If rules were triggered (suspicious content), 
  // we significantly lower the allowed request frequency for this IP.
  const windowSize = 10; // last 10 seconds
  let requestCount = 0;
  
  try {
    const row = db.prepare(`
      SELECT count(*) as count 
      FROM logs 
      WHERE ip = ? 
      AND timestamp > datetime('now', '-' || ? || ' seconds')
    `).get(ip, windowSize) as { count: number };
    requestCount = row?.count || 0;
  } catch (err) {
    console.error("Rate limit query failed", err);
  }
  
  // Default threshold: 20 requests in 10 seconds.
  // Tight threshold: 5 requests in 10 seconds if request content is suspicious.
  const dynamicThreshold = riskScore > 0.4 ? 5 : 20;

  if (requestCount > dynamicThreshold) {
    riskScore += 0.8;
    detectedAttacks.push(`Dynamic Rate Limit: ${requestCount}/${dynamicThreshold} requests`);
  }

  // 4. Anomaly-Based Detection (Simple Example)
  if (fullData.length > 10000) { // Large payload anomaly
    riskScore += 0.5;
    detectedAttacks.push("Abnormal Payload Size");
  }

  // 5. Final Decision
  const status = riskScore >= 1.0 ? "blocked" : riskScore > 0.3 ? "flagged" : "allowed";
  
  const parser = new UAParser(req.headers["user-agent"] as string);
  const uaResult = parser.getResult();
  const browserInfo = `${uaResult.browser.name || "Unknown"} ${uaResult.browser.version || ""}`.trim();
  const osInfo = `${uaResult.os.name || "Unknown"} ${uaResult.os.version || ""}`.trim();
  const deviceInfo = uaResult.device.type || "desktop";

  // Server-side Safety Heuristics
  let safetyScore = 100;
  const isHeadless = /HeadlessChrome|PhantomJS|Zombie/.test(req.headers["user-agent"] || "");
  const isAutomation = !!req.headers["webdriver"] || isHeadless;
  const isCommonBrowser = ["Chrome", "Firefox", "Safari", "Edge", "Opera"].includes(uaResult.browser.name || "");

  if (isAutomation) safetyScore -= 50;
  if (!isCommonBrowser) safetyScore -= 20;
  if (!req.headers["user-agent"]) safetyScore -= 30;
  if (req.headers["x-forwarded-for"]) {
    // Check for proxy anomalies if needed
  }
  
  // Ensure score stays in 0-100 range
  safetyScore = Math.max(0, Math.min(100, safetyScore));

  // Attach analysis to request for downstream routes (like simulation)
  (req as any).wafAnalysis = {
    score: riskScore,
    status,
    threats: detectedAttacks,
    fingerprint: {
      browser: browserInfo,
      os: osInfo,
      device: deviceInfo,
      safetyScore
    }
  };

  // Log the request
  db.prepare(`
    INSERT INTO logs (ip, method, url, headers, payload, attack_type, risk_score, status, user_agent, browser, os, device, safety_score)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    String(ip),
    req.method,
    req.url,
    headerData,
    bodyData,
    detectedAttacks.join(", "),
    riskScore,
    status,
    req.headers["user-agent"] || "unknown",
    browserInfo,
    osInfo,
    deviceInfo,
    safetyScore
  );

    if (status === "blocked") {
      console.log(`[WAF] BLOCKING request from ${ip}. Score: ${riskScore}. Threats: ${detectedAttacks.join(", ")}`);
      
      // Auto-blacklist high-risk IPs
      const blacklistReason = detectedAttacks.length > 0 ? detectedAttacks[0] : "Multiple Security Violations";
      db.prepare("INSERT OR REPLACE INTO blacklist (ip, reason) VALUES (?, ?)").run(ip, blacklistReason);

      // Send Telegram notification
      // Use code blocks for dynamic content to avoid Markdown parsing errors
    const escapeHTML = (str: string) => str.replace(/[&<>"']/g, m => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[m] || m));

    const telegramMsg = `🚨 <b>Sentinel WAF Alert</b>: Blocked Attack
<b>IP</b>: <code>${escapeHTML(ip)}</code>
<b>Method</b>: <code>${escapeHTML(req.method)}</code>
<b>URL</b>: <code>${escapeHTML(req.url)}</code>
<b>Threats</b>: <b>${escapeHTML(detectedAttacks.join(", "))}</b>
<b>Score</b>: <code>${riskScore.toFixed(2)}</code>
<b>Browser</b>: <code>${escapeHTML(browserInfo)}</code>
<b>OS</b>: <code>${escapeHTML(osInfo)}</code>`;
      
      sendTelegramNotification(telegramMsg).catch(err => {
        console.error("[WAF] Failed to send Telegram notification (async catch):", err);
      });

      if (req.path.startsWith("/api/")) {
        return res.status(403).json({
          error: "Security Violation",
          message: "Your request was blocked by Sentinel WAF",
          incident_id: Date.now(),
          score: riskScore,
          threats: detectedAttacks,
          fingerprint: {
            browser: browserInfo,
            os: osInfo
          }
        });
      }

      return res.status(403).send(generateBlockPage(ip, "Security Violation", "Request blocked due to malicious patterns", riskScore, detectedAttacks));
    }

    next();
  } catch (err) {
    console.error("WAF Middleware Error:", err);
    next(); // Fail open for safety in this demo
  }
}

function generateBlockPage(ip: string, title: string, reason: string, score: number, threats: string[]) {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Access Denied - Sentinel WAF</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700;900&display=swap" rel="stylesheet">
        <style>
            body { font-family: 'Inter', sans-serif; }
            .glitch { animation: glitch 1s linear infinite; }
            @keyframes glitch {
                2%, 64% { transform: translate(2px, 0) skew(0deg); }
                4%, 60% { transform: translate(-2px, 0) skew(0deg); }
                62% { transform: translate(0, 0) skew(5deg); }
            }
        </style>
    </head>
    <body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center p-6 selection:bg-red-500/30">
        <div class="max-w-2xl w-full">
            <div class="mb-12 flex items-center gap-4">
                <div class="w-12 h-12 bg-red-600 rounded-2xl flex items-center justify-center shadow-lg shadow-red-600/20">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" class="text-white"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                </div>
                <div>
                    <h1 class="text-2xl font-black uppercase tracking-widest text-red-500 glitch">Sentinel Protocol Active</h1>
                    <p class="text-[10px] font-bold text-slate-500 uppercase tracking-[0.4em]">Enterprise Security Layer 0x99</p>
                </div>
            </div>

            <div class="bg-slate-900/50 border border-red-500/20 rounded-[2.5rem] p-10 backdrop-blur-xl shadow-2xl">
                <div class="space-y-8">
                    <div>
                        <span class="text-[9px] font-black text-red-400 uppercase tracking-[0.2em] block mb-2">Access Status</span>
                        <h2 class="text-4xl font-black text-white leading-tight uppercase">${title}</h2>
                    </div>

                    <div class="grid grid-cols-2 gap-4">
                        <div class="p-4 bg-slate-950/50 rounded-2xl border border-white/5">
                            <span class="text-[8px] font-bold text-slate-500 uppercase tracking-widest block mb-1">Source IP</span>
                            <span class="text-sm font-mono text-red-400 font-bold">${ip}</span>
                        </div>
                        <div class="p-4 bg-slate-950/50 rounded-2xl border border-white/5">
                            <span class="text-[8px] font-bold text-slate-500 uppercase tracking-widest block mb-1">Threat Score</span>
                            <span class="text-sm font-mono text-red-500 font-bold">${(score * 100).toFixed(0)}% MALICIOUS</span>
                        </div>
                    </div>

                    <div class="p-6 bg-red-500/5 rounded-2xl border border-red-500/10">
                        <span class="text-[9px] font-black text-red-400 uppercase tracking-[0.2em] block mb-3">Security Rationale</span>
                        <p class="text-sm text-slate-300 leading-relaxed font-medium">"${reason}"</p>
                    </div>

                    ${threats.length > 0 ? `
                    <div class="space-y-3">
                        <span class="text-[9px] font-black text-slate-500 uppercase tracking-[0.2em] block">Identified Signatures</span>
                        <div class="flex flex-wrap gap-2">
                            ${threats.map(t => `<span class="px-3 py-1 bg-red-500/10 text-red-400 text-[10px] font-black uppercase rounded-full border border-red-500/20">${t}</span>`).join('')}
                        </div>
                    </div>
                    ` : ''}

                    <div class="pt-8 border-t border-white/5 flex flex-col md:flex-row items-center justify-between gap-6">
                        <p class="text-[9px] text-slate-500 font-bold uppercase tracking-wider leading-relaxed text-center md:text-left">
                            This incident has been logged and reported to the system administrator.<br/>
                            Your fingerprint has been indexed for forensic analysis.
                        </p>
                        <a href="/" class="px-8 py-3 bg-white text-slate-950 text-[11px] font-black uppercase tracking-widest rounded-xl hover:bg-slate-200 transition shadow-xl shadow-white/5 active:scale-95">
                            Return Home
                        </a>
                    </div>
                </div>
            </div>

            <p class="mt-10 text-center text-[8px] font-bold text-slate-600 uppercase tracking-[0.5em]">Powered by Sentinel AI Defense Cluster</p>
        </div>
    </body>
    </html>
  `;
}
