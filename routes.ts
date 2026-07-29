import express from "express";
import db from "./database.ts";

export const apiRouter = express.Router();

// Get Dashboard Stats
apiRouter.get("/stats", (req, res) => {
  const totalRequests = db.prepare("SELECT count(*) as count FROM logs").get() as any;
  const blockedRequests = db.prepare("SELECT count(*) as count FROM logs WHERE status = 'blocked'").get() as any;
  
  // High-performance aggregation in JS for attack types
  const allAttacks = db.prepare("SELECT attack_type FROM logs WHERE attack_type != ''").all() as { attack_type: string }[];
  const attackCounts: Record<string, number> = {};
  
  allAttacks.forEach(row => {
    const types = row.attack_type.split(",").map(t => t.trim());
    types.forEach(type => {
      if (type) {
        // Normalize for display
        let display = type;
        if (type.includes("Dynamic Rate Limit")) display = "Rate Limit";
        attackCounts[display] = (attackCounts[display] || 0) + 1;
      }
    });
  });

  const threatsByType = Object.entries(attackCounts)
    .map(([attack_type, count]) => ({ attack_type, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const trafficChart = Object.entries(attackCounts).map(([name, value]) => ({
    name,
    value
  }));

  const recentLogs = db.prepare("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50").all();
  
  // Fingerprinting stats
  const browsers = db.prepare("SELECT browser, count(*) as count FROM logs WHERE browser IS NOT NULL GROUP BY browser ORDER BY count DESC").all();
  const oss = db.prepare("SELECT os, count(*) as count FROM logs WHERE os IS NOT NULL GROUP BY os ORDER BY count DESC").all();

  // Activity over time (last 24 hours) - Use a more robust grouping
  const activityChart = db.prepare(`
    SELECT 
      strftime('%H:00', timestamp) as time, 
      count(*) as total, 
      SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked
    FROM logs 
    WHERE timestamp > datetime('now', '-24 hours')
    GROUP BY time
    ORDER BY timestamp ASC
  `).all();

  let ip = req.ip || "unknown";
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    ip = Array.isArray(forwarded) ? forwarded[0] : forwarded.split(',')[0].trim();
  }

  res.json({
    totalRequests: totalRequests.count,
    blockedRequests: blockedRequests.count,
    threatsByType,
    recentLogs,
    trafficChart, // For the pie chart
    activityChart, // For the line chart (renamed to avoid confusion)
    browsers,
    oss,
    yourIp: ip
  });
});

// Logs Endpoint
apiRouter.get("/logs", (req, res) => {
  const logs = db.prepare("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 500").all();
  res.json(logs);
});

// Rules CRUD
apiRouter.get("/rules", (req, res) => {
  const rules = db.prepare("SELECT * FROM rules").all();
  res.json(rules);
});

apiRouter.post("/rules", (req, res) => {
  const { name, pattern, target, risk_weight, description } = req.body;
  const stmt = db.prepare("INSERT INTO rules (name, pattern, target, risk_weight, description) VALUES (?, ?, ?, ?, ?)");
  stmt.run(name, pattern, target || 'any', risk_weight || 0.5, description || '');
  res.json({ success: true });
});

apiRouter.delete("/rules/:id", (req, res) => {
  db.prepare("DELETE FROM rules WHERE id = ?").run(req.params.id);
  res.json({ success: true });
});

// Blacklist Management
apiRouter.get("/blacklist", (req, res) => {
  const list = db.prepare("SELECT * FROM blacklist").all();
  res.json(list);
});

apiRouter.post("/blacklist", (req, res) => {
  const { ip, reason } = req.body;
  db.prepare("INSERT OR REPLACE INTO blacklist (ip, reason) VALUES (?, ?)").run(ip, reason);
  res.json({ success: true });
});

// Attack Simulator - Helper Route to trigger WAF
apiRouter.get("/simulate", (req, res) => {
  res.json({ 
    message: "Payload received.", 
    query: req.query,
    waf: (req as any).wafAnalysis 
  });
});

// Export Data (JSON/CSV)
apiRouter.get("/export", (req, res) => {
  const format = req.query.format || "json";
  const logs = db.prepare("SELECT * FROM logs ORDER BY timestamp DESC").all();
  
  if (format === "csv") {
    const headers = Object.keys(logs[0] || {}).join(",");
    const rows = logs.map((log: any) => 
      Object.values(log).map(val => `"${String(val).replace(/"/g, '""')}"`).join(",")
    ).join("\n");
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", "attachment; filename=waf_logs.csv");
    return res.send(`${headers}\n${rows}`);
  }
  
  res.json(logs);
});
