# IntelliGuard WAF - Setup & Telegram Threat Detection Guide

IntelliGuard WAF (Sentinel WAF) is a full-stack Web Application Firewall and Threat Intelligence Dashboard built with React, Vite, Express, and SQLite. It provides real-time traffic inspection, signature matching, dynamic rate-limiting, risk scoring, auto-blacklisting, and instant Telegram security alerts.

---

## 🚀 1. Local Setup Instructions

### Prerequisites
- **Node.js**: v18+ recommended
- **npm**: Package manager
- **Telegram App**: For receiving real-time security alerts

### Installation
1. Clone the repository and navigate to the project directory:
   ```bash
   cd intelliguard-waf
   ```
2. Install project dependencies:
   ```bash
   npm install
   ```

---

## 📲 2. Telegram Bot Configuration

To receive real-time notifications when an attack is detected and blocked by the WAF:

### Step 1: Create a Telegram Bot
1. Open Telegram and search for **`@BotFather`**.
2. Start a chat and send `/newbot`.
3. Follow the prompts to set a name and username for your bot.
4. `@BotFather` will give you an **HTTP API Token** (e.g., `8645508427:AAE93J7BXr...`). Copy this token.

### Step 2: Get Your Telegram Chat ID
1. Search for **`@userinfobot`** (or `@RawDataBot`) in Telegram.
2. Send `/start` to the bot.
3. The bot will reply with your numerical **Chat ID** (e.g., `8661262877`).

### Step 3: Configure Environment Variables
Create or update your `.env` file in the project root:

```env
# Server Configuration
PORT=3000
DATABASE_PATH="waf.db"
JWT_SECRET="super-secret-waf-key-123"

# Optional AI Analysis
GEMINI_API_KEY="YOUR_GEMINI_API_KEY_HERE"

# Telegram Notification Credentials
TELEGRAM_BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID="YOUR_TELEGRAM_CHAT_ID_HERE"
```

---

## ▶️ 3. Running the Application

Start the Express backend and React frontend dev server:

```bash
npm run dev
```

Open your browser at `http://localhost:3000` to access the IntelliGuard WAF Dashboard.

---

## 🎯 4. Testing Attacks & Telegram Alerts (Step-by-Step)

> 💡 **Important Note on `curl` Formatting**:
> When using `curl` from terminal or Linux (e.g., Kali Linux, Ubuntu, Windows PowerShell), URL characters like quotes `'`, spaces, or `<script>` tags can cause URL parsing errors.
> Always use `curl -G --data-urlencode` or properly URL-encode raw payloads.

Below are step-by-step commands to trigger the WAF and verify Telegram alerts:

### Attack Vector 1: SQL Injection (SQLi)
Simulate a SQL injection attempt in URL parameter:

```bash
curl -G --data-urlencode "id=1' OR 1=1 --" http://localhost:3000/api/simulate
```
*Alternative encoded syntax:*
```bash
curl "http://localhost:3000/api/simulate?id=1%27%20OR%201=1%20--"
```

### Attack Vector 2: Cross-Site Scripting (XSS)
Simulate an inline script injection payload:

```bash
curl -G --data-urlencode "search=<script>alert('XSS')</script>" http://localhost:3000/api/simulate
```

### Attack Vector 3: Path Traversal / Honeypot Probe
Simulate directory traversal or admin honeypot access:

```bash
curl "http://localhost:3000/api/simulate?file=../../../../etc/passwd"
```

### Attack Vector 4: Malicious Scanner User-Agent
Simulate requests from automated security scanning tools (e.g., `sqlmap`, `nikto`, `nmap`):

```bash
curl -H "User-Agent: sqlmap/1.5#stable" http://localhost:3000/api/simulate
```

### Attack Vector 5: Dynamic Rate Limiting / Brute Force
Trigger rate limiting by sending rapid requests in a short window:

```bash
for i in {1..15}; do curl -s "http://localhost:3000/api/simulate?q=test"; done
```

---

## 📩 5. Expected WAF Response & Telegram Notification

### WAF Terminal / API Response (HTTP 403 Forbidden)
```json
{
  "error": "Security Violation",
  "message": "Your request was blocked by Sentinel WAF",
  "incident_id": 1746685412000,
  "score": 1.2,
  "threats": [
    "SQL Injection Detected"
  ],
  "fingerprint": {
    "browser": "curl 8.5.0",
    "os": "Linux"
  }
}
```

### Telegram Alert Format
When an attack is blocked, your Telegram bot instantly receives a formatted message:

```text
🚨 Sentinel WAF Alert: Blocked Attack
IP: 127.0.0.1
Method: GET
URL: /api/simulate?id=1%27%20OR%201=1%20--
Threats: SQL Injection Detected
Score: 1.20
Browser: curl 8.5.0
OS: Linux
```

---

## 📊 Features & Architecture Overview

- 🛡️ **Rule Signature Engine**: Pre-built regex patterns for SQLi, XSS, RCE, LFI, and scanner User-Agents.
- ⚡ **Dynamic Rate Limiting**: Automatically lowers request thresholds for suspicious IPs.
- 🤖 **Telegram Alerting**: Async dispatch of threat notifications to configured Telegram chats.
- 📈 **Real-time Monitoring**: Visual charts for risk scores, attack distribution, and total requests.
- 🔍 **Forensic Deep-Dive**: Inspect headers, payloads, device fingerprints, and safety scores.
- ⛔ **IP Blacklist Engine**: Automated or manual IP banning and unbanning.

