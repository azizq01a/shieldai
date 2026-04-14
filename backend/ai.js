import dotenv from "dotenv";
dotenv.config();

import OpenAI from "openai";

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  timeout: 30000,
});

export async function analyzeSecurity(url, issues) {
  if (!url || typeof url !== 'string') {
    throw new Error('URL is required and must be a string');
  }

  if (!Array.isArray(issues)) {
    throw new Error('Issues must be an array');
  }

  const issuesText = issues.length === 0 
    ? "No obvious security issues detected in basic headers."
    : issues.join("\n");

  const prompt = `
You are a senior cybersecurity expert.

Analyze this website:

URL: ${url}

Detected issues:
${issuesText}

Return STRICT JSON. Do NOT include any text outside the JSON. Use this exact format:

{
  "riskScore": 0-100,
  "riskLevel": "Low|Medium|High|Critical",
  "summary": "...",
  "vulnerabilities": [],
  "fixes": [],
  "exploitRisk": "..."
}

Important rules:
- riskScore: 0-20=Low, 21-50=Medium, 51-80=High, 81-100=Critical
- vulnerabilities: List specific security weaknesses
- fixes: Actionable recommendations with code examples if possible
- exploitRisk: Describe how easily these issues can be exploited
`;

  try {
    const res = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.3,
      response_format: { type: "json_object" },
    });

    const content = res.choices[0].message.content;
    
    if (!content) {
      throw new Error("Empty response from OpenAI");
    }

    let parsed;
    try {
      parsed = JSON.parse(content);
    } catch (parseError) {
      console.error("Failed to parse AI response:", content);
      throw new Error("Invalid JSON response from AI");
    }

    const requiredFields = ['riskScore', 'riskLevel', 'summary', 'vulnerabilities', 'fixes', 'exploitRisk'];
    for (const field of requiredFields) {
      if (!(field in parsed)) {
        throw new Error(`Missing required field: ${field}`);
      }
    }

    if (typeof parsed.riskScore !== 'number' || parsed.riskScore < 0 || parsed.riskScore > 100) {
      parsed.riskScore = 50;
    }

    const validLevels = ['Low', 'Medium', 'High', 'Critical'];
    if (!validLevels.includes(parsed.riskLevel)) {
      parsed.riskLevel = 'Medium';
    }

    if (!Array.isArray(parsed.vulnerabilities)) {
      parsed.vulnerabilities = [];
    }

    if (!Array.isArray(parsed.fixes)) {
      parsed.fixes = [];
    }

    return parsed;

  } catch (error) {
    console.error("AI Security Analysis Error:", error.message);
    
    return {
      riskScore: Math.min(issues.length * 20, 100),
      riskLevel: issues.length === 0 ? "Low" : issues.length > 3 ? "Critical" : issues.length > 2 ? "High" : "Medium",
      summary: `Analysis completed with ${issues.length} security issues found.`,
      vulnerabilities: issues.length > 0 ? issues : ["No vulnerabilities detected"],
      fixes: issues.length > 0 ? ["Review security headers configuration", "Implement missing security headers"] : ["Maintain current security posture"],
      exploitRisk: issues.length > 0 ? "Medium to High risk of exploitation" : "Low risk",
      error: true
    };
  }
}

export function analyzeSecurityLocally(issues) {
  const riskScore = Math.min(issues.length * 20, 100);
  let riskLevel = "Low";
  if (riskScore > 80) riskLevel = "Critical";
  else if (riskScore > 60) riskLevel = "High";
  else if (riskScore > 30) riskLevel = "Medium";
  
  return {
    riskScore,
    riskLevel,
    summary: `Found ${issues.length} security header issues.`,
    vulnerabilities: issues,
    fixes: issues.map(issue => {
      if (issue.includes("X-Frame-Options")) return "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'";
      if (issue.includes("CSP")) return "Implement Content-Security-Policy header";
      if (issue.includes("HSTS")) return "Enable Strict-Transport-Security";
      if (issue.includes("X-Content-Type-Options")) return "Add 'X-Content-Type-Options: nosniff'";
      if (issue.includes("HTTPS")) return "Redirect to HTTPS and install SSL certificate";
      return "Review security headers configuration";
    }),
    exploitRisk: issues.length > 0 ? "Potential for clickjacking, XSS, or MITM attacks" : "Low risk",
    localAnalysis: true
  };
}