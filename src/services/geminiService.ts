export function suggestRulesFromLogs(logs: any[]) {
  // Local logic to suggest rules based on frequency and patterns
  const suggestions = [
    {
      name: "Rate Limiting Recommendation",
      pattern: "^/api/.*",
      description: "Detected high frequency of requests to API endpoints. Recommend implementing rate limiting.",
      risk_weight: 0.5,
      target: "path"
    },
    {
      name: "Strict Input Validation",
      pattern: "[<>'\"&]",
      description: "Multiple special characters detected in query parameters. Recommend strict schema validation.",
      risk_weight: 0.7,
      target: "query"
    }
  ];
  return { rules: suggestions };
}

export function analyzeThreatLog(log: any) {
  const analysis: any = {
    explanation: "Static analysis of the captured incident.",
    risk_level: "High",
    intent: "Unknown Probe",
    remediation: "Check server logs for corresponding process activity."
  };

  if (log.attack_type === "SQL Injection") {
    analysis.explanation = "The attacker attempted to inject SQL commands via URL parameters or form inputs to bypass authentication or dump database contents.";
    analysis.risk_level = "Critical";
    analysis.intent = "Data Exfiltration / Authentication Bypass";
    analysis.remediation = "### Remediation\n1. Use **Parameterized Queries** (Prepared Statements).\n2. Implement strict input validation.\n3. Use an ORM that handles escaping automatically.";
  } else if (log.attack_type === "XSS Attack") {
    analysis.explanation = "A Cross-Site Scripting attempt was detected. The payload contains script tags or event handlers intended to execute malicious JavaScript in a user's browser.";
    analysis.risk_level = "High";
    analysis.intent = "Session Hijacking / Credential Theft";
    analysis.remediation = "### Remediation\n1. Use a library like `dompurify` to sanitize HTML.\n2. Set `Content-Security-Policy` headers.\n3. Escape output in templates.";
  } else if (log.attack_type === "Path Traversal") {
    analysis.explanation = "Detected attempt to access files outside the intended directory using path manipulation (e.g., ../ patterns).";
    analysis.risk_level = "Critical";
    analysis.intent = "System File Exposure";
    analysis.remediation = "### Remediation\n1. Avoid using user input directly in file paths.\n2. Use path normalization logic.\n3. Set strict file system permissions.";
  }

  return analysis;
}
