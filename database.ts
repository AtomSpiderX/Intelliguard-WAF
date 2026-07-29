import Database from "better-sqlite3";
import path from "path";

const dbPath = process.env.DATABASE_PATH || "waf.db";
const db = new Database(dbPath);

export function initDb() {
  // Logs table
  db.exec(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      ip TEXT,
      method TEXT,
      url TEXT,
      headers TEXT,
      payload TEXT,
      attack_type TEXT,
      risk_score REAL,
      status TEXT, -- 'allowed' | 'blocked' | 'flagged'
      user_agent TEXT,
      browser TEXT,
      os TEXT,
      device TEXT,
      safety_score REAL DEFAULT 100
    )
  `);

  // Migration for existing tables
  try { db.exec("ALTER TABLE logs ADD COLUMN browser TEXT"); } catch(e) {}
  try { db.exec("ALTER TABLE logs ADD COLUMN os TEXT"); } catch(e) {}
  try { db.exec("ALTER TABLE logs ADD COLUMN device TEXT"); } catch(e) {}
  try { db.exec("ALTER TABLE logs ADD COLUMN safety_score REAL DEFAULT 100"); } catch(e) {}

  // Rules table
  db.exec(`
    CREATE TABLE IF NOT EXISTS rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      pattern TEXT NOT NULL, -- Regex pattern
      target TEXT NOT NULL, -- 'body' | 'query' | 'headers' | 'url'
      risk_weight REAL DEFAULT 1.0,
      active INTEGER DEFAULT 1
    )
  `);

  // Blocked IPs table
  db.exec(`
    CREATE TABLE IF NOT EXISTS blacklist (
      ip TEXT PRIMARY KEY,
      reason TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME
    )
  `);

  // Seed default rules
  db.prepare("DELETE FROM rules").run();
  db.prepare("DELETE FROM blacklist").run(); // Clear any accidental blocks on restart
  
  const insert = db.prepare("INSERT INTO rules (name, description, pattern, target, risk_weight) VALUES (?, ?, ?, ?, ?)");
  
  // SQL Injection - Refined to be more specific to avoid false positives with XSS/Standard strings
  insert.run("SQL Injection", "Detects common SQLi keywords and bypass patterns", "((UNION\\s+SELECT|UNION\\s+ALL\\s+SELECT|INSERT\\s+INTO|UPDATE\\s+.*\\s+SET|DELETE\\s+FROM|DROP\\s+TABLE|'\\s+OR\\s+1\\s*=\\s*1)|(['\"]\\s*(OR|AND)\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+['\"]?)|(\\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP)\\b.*\\b(FROM|INTO|SET|WHERE|TABLE)\\b)|(--\\s|#\\s|\\/\\*))", "any", 1.0);
  
  // NoSQL Injection
  insert.run("NoSQL Injection", "Detects MongoDB operators like $gt, $ne", "(\\$gt|\\$ne|\\$lt|\\$lte|\\$gte|\\$where|\\$regex|\\$expr|\\$inc)", "any", 1.0);

  // XSS Detection - Use stricter boundaries to prevent false positives in plain text while catching malicious patterns
  insert.run("XSS Attack", "Detects malicious script execution patterns and event handlers", "(<script[\\s>].*?>|\\bon(mouseover|click|load|error|focus|scroll|pointer|aux)\\s*=|(\\b|\\s)javascript:|\\b(alert|prompt|confirm|eval)\\s*\\()", "any", 1.0);
  
  // Path Traversal
  insert.run("Path Traversal", "Detects ../ or ..\\ patterns", "(\\.\\.[\\\\/]|etc/passwd|/windows/system32|/boot\\.ini)", "any", 1.0);
  
  // RCE / Command Injection
  insert.run("Command Injection", "Detects shell command symbols", "([;&|`]\\s*(cat|ls|whoami|pwd|sh|bash|curl|wget|nc|phpinfo|system\\s*\\(|exec\\s*\\())", "any", 1.0);

  // User Agent Anomaly
  insert.run("UA Anomaly", "Detects suspicious tools", "(PycURL|libwww-perl|Zgrab|Masscan|Nmap)", "headers", 0.6);

  // Admin Access Attempt (More specific)
  insert.run("Admin Hijack", "Detects attempts to access sensitive admin paths", "(phpmyadmin|wp-admin|wp-config|\\.env|\\.git|setup\\.php|install\\.php)", "url", 1.1);

  // Honeypot Signature Rule
  insert.run("Honeypot Hit", "Matches specific honeypot traps", "(/\\.env|/backup\\.sql|/wp-admin|/admin/config\\.php)", "url", 1.2);

  // Seed initial logs if empty to show dashboard activity
  const logCount = db.prepare("SELECT count(*) as count FROM logs").get() as { count: number };
  if (logCount.count === 0) {
    const hours = [2, 4, 6, 8, 10, 12];
    hours.forEach(h => {
      db.prepare(`
        INSERT INTO logs (ip, method, url, status, risk_score, attack_type, timestamp, user_agent)
        VALUES ('192.168.1.1', 'GET', '/', 'allowed', 0.1, '', datetime('now', '-${h} hours'), 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0')
      `).run();
    });

    // Add one blocked demo event
    db.prepare(`
      INSERT INTO logs (ip, method, url, status, risk_score, attack_type, timestamp, user_agent)
      VALUES ('45.33.22.11', 'POST', '/login', 'blocked', 1.0, 'SQL Injection', datetime('now', '-1 hours'), 'curl/7.68.0')
    `).run();
  }
}

export default db;
