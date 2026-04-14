import express from "express";
import cors from "cors";
import axios from "axios";
import dotenv from "dotenv";
import { XSSEngine } from "./scanners/xssEngine.js";
import { ReflectionTester } from "./scanners/reflectionTester.js";
import { RobotsParser } from "./scanners/robotsParser.js";
import { JSEndpointExtractor } from "./scanners/jsEndpointExtractor.js";

dotenv.config();

const app = express();

// ============================================
// ✅ CORS CONFIGURATION - PRODUCTION READY
// ============================================
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5000',
  'https://shieldai-tau.vercel.app',
  'https://shieldai-fy9m.onrender.com'
];

// CORS middleware
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  
  res.header('Access-Control-Allow-Credentials', true);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json());

// ============== DISCLAIMER PROFESSIONNEL ==============
const DISCLAIMER = `
⚠️ IMPORTANT DISCLAIMER ⚠️

ShieldAI is an automated security observation tool, not a vulnerability scanner.
All findings require MANUAL VERIFICATION by a qualified security professional.

- No findings are confirmed vulnerabilities
- Bounty estimates are illustrative examples only
- Real bounties depend on manual verification and business impact

Use responsibly. Only scan websites you own or have explicit permission to test.
`;

// ============== SYSTÈME DE CONFIANCE RÉALISTE ==============
const confidenceSystem = {
  High: { 
    score: 80, 
    label: "High Confidence",
    requires: "Pattern confirmed by multiple tests",
    color: "#28a745"
  },
  Medium: { 
    score: 50, 
    label: "Medium Confidence - Needs Verification",
    requires: "Pattern detected, manual verification required",
    color: "#ffc107"
  },
  Low: { 
    score: 20, 
    label: "Low Confidence - Informational Only",
    requires: "Not a security issue without additional context",
    color: "#6c757d"
  }
};

// ============== CLASSIFICATION RÉALISTE ==============
const classifyObservation = (finding) => {
  const name = finding.name.toLowerCase();
  
  // Informational - Pas de sécurité
  if (name.includes('cpanel') || name.includes('webmail') || name.includes('plesk') ||
      name.includes('robots.txt') || name.includes('favicon') || name.includes('sitemap')) {
    return { 
      severity: 'Informational', 
      confidence: 'Low',
      type: 'Hosting Service Endpoint',
      bountyEstimate: '$0 - Not a security issue',
      requiresVerification: false
    };
  }
  
  // Security Headers - Bonnes pratiques
  if (name.includes('referrer-policy') || name.includes('x-content-type-options') ||
      name.includes('csp') || name.includes('hsts') || name.includes('x-frame-options')) {
    return { 
      severity: 'Security Observation', 
      confidence: 'High',
      type: 'Security Header Analysis',
      bountyEstimate: '$0 - Defense in depth',
      requiresVerification: false
    };
  }
  
  // Potential Issues - Nécessite vérification
  if (name.includes('xss') || name.includes('reflection')) {
    return { 
      severity: 'Potential Risk', 
      confidence: 'Medium',
      type: 'Input Reflection Detected',
      bountyEstimate: '$0 until manual verification',
      requiresVerification: true
    };
  }
  
  // Attack Surface Mapping
  if (name.includes('endpoint') || name.includes('api')) {
    return { 
      severity: 'Attack Surface', 
      confidence: 'Low',
      type: 'Endpoint Discovery',
      bountyEstimate: '$0 - Requires context',
      requiresVerification: true
    };
  }
  
  return { 
    severity: 'Observation', 
    confidence: 'Low',
    type: 'General Finding',
    bountyEstimate: '$0 - Needs manual review',
    requiresVerification: true
  };
};

// ============== MAIN SECURITY ANALYSIS ENDPOINT ==============
app.post("/api/security/analyze", async (req, res) => {
  const { url, deepAnalysis = true } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  const analysis = {
    target: url,
    timestamp: new Date().toISOString(),
    observations: [],
    attackSurface: null,
    reflections: null,
    robotsData: null,
    executiveSummary: "",
    attackSurfaceScore: 100,
    nextSteps: [],
    requiresManualReview: [],
    disclaimer: DISCLAIMER
  };

  try {
    console.log(`🎯 Starting Security Analysis for: ${url}`);
    
    // Fetch target
    let response;
    try {
      response = await axios.get(url, { timeout: 10000 });
    } catch (err) {
      return res.status(500).json({ error: "Cannot reach target website", details: err.message });
    }
    
    const headers = response.headers;
    
    // 1. Security Headers Analysis
    const headerObservations = [
      { name: 'X-Frame-Options', header: headers['x-frame-options'], title: 'Clickjacking Protection' },
      { name: 'Content-Security-Policy', header: headers['content-security-policy'], title: 'CSP (XSS Protection)' },
      { name: 'Strict-Transport-Security', header: headers['strict-transport-security'], title: 'HSTS' },
      { name: 'X-Content-Type-Options', header: headers['x-content-type-options'], title: 'MIME Sniffing Protection' },
      { name: 'Referrer-Policy', header: headers['referrer-policy'], title: 'Referrer Policy' }
    ];
    
    for (const header of headerObservations) {
      if (!header.header) {
        const classification = classifyObservation({ name: header.title });
        analysis.observations.push({
          name: `Missing ${header.title}`,
          severity: classification.severity,
          confidence: classification.confidence,
          confidenceLabel: confidenceSystem[classification.confidence].label,
          type: classification.type,
          description: `The ${header.name} header is not configured. This is a defense-in-depth security control.`,
          remediation: getRemediation(header.name),
          location: "HTTP Response Headers",
          bountyEstimate: classification.bountyEstimate,
          requiresManualVerification: classification.requiresVerification
        });
        
        if (classification.severity !== 'Informational') {
          analysis.attackSurfaceScore -= 5;
        }
      }
    }
    
    // 2. Hosting Endpoints (Informational Only)
    const hostingEndpoints = ['/cpanel', '/webmail', '/plesk', '/mail'];
    for (const endpoint of hostingEndpoints) {
      try {
        const fullUrl = `${url}${endpoint}`;
        const epResponse = await axios.get(fullUrl, { timeout: 3000 });
        if (epResponse.status === 200) {
          analysis.observations.push({
            name: `${endpoint} Endpoint Detected`,
            severity: 'Informational',
            confidence: 'High',
            confidenceLabel: confidenceSystem.High.label,
            type: 'Hosting Service Endpoint',
            description: `Default hosting control panel endpoint detected. This is typically password-protected by default.`,
            location: fullUrl,
            bountyEstimate: '$0 - Standard hosting feature',
            requiresManualVerification: false
          });
        }
      } catch(e) {}
    }
    
    // 3. Robots.txt Analysis
    const robotsParser = new RobotsParser();
    const robotsData = await robotsParser.parseRobotsTxt(url);
    analysis.robotsData = robotsData;
    
    if (robotsData.exists && robotsData.disallowed.length > 0) {
      analysis.observations.push({
        name: `Robots.txt Discloses ${robotsData.disallowed.length} Paths`,
        severity: 'Informational',
        confidence: 'High',
        confidenceLabel: confidenceSystem.High.label,
        type: 'Information Disclosure',
        description: `robots.txt file lists ${robotsData.disallowed.length} paths that the site owner prefers search engines not to crawl.`,
        location: `${url}/robots.txt`,
        bountyEstimate: '$0 - Not a vulnerability',
        requiresManualVerification: false,
        details: robotsData.disallowed.slice(0, 10)
      });
    }
    
    // 4. JavaScript Endpoint Extraction
    const jsExtractor = new JSEndpointExtractor();
    const jsEndpoints = await jsExtractor.extractFromJS(url);
    analysis.attackSurface = jsEndpoints;
    
    if (jsEndpoints.total > 0) {
      analysis.observations.push({
        name: `${jsEndpoints.total} Endpoints Discovered in JavaScript`,
        severity: 'Attack Surface',
        confidence: 'Medium',
        confidenceLabel: confidenceSystem.Medium.label,
        type: 'API Endpoint Discovery',
        description: `Discovered ${jsEndpoints.total} potential API endpoints from JavaScript files. Manual review recommended.`,
        bountyEstimate: '$0 - Requires manual investigation',
        requiresManualVerification: true,
        sampleEndpoints: jsEndpoints.allEndpoints?.slice(0, 5) || []
      });
    }
    
    // 5. XSS Reflection Analysis
    console.log("🔬 Testing for input reflection...");
    const xssEngine = new XSSEngine();
    const xssResults = await xssEngine.scanXSS(url);
    analysis.reflections = xssResults;
    
    if (xssResults.confirmedXSS?.length > 0) {
      for (const xss of xssResults.confirmedXSS) {
        analysis.observations.push({
          name: `Input Reflection Detected in '${xss.parameter}' Parameter`,
          severity: 'Potential Risk',
          confidence: 'Medium',
          confidenceLabel: confidenceSystem.Medium.label,
          type: 'Input Reflection',
          description: `Input is reflected in the response. Manual testing required to determine if XSS is possible.`,
          location: xss.url,
          bountyEstimate: '$0 until manual verification confirms exploitability',
          requiresManualVerification: true,
          testPayload: xss.payload
        });
        analysis.attackSurfaceScore -= 10;
      }
    } else if (xssResults.reflections?.length > 0) {
      analysis.observations.push({
        name: `Input Reflection Detected on ${xssResults.reflections.length} Parameter(s)`,
        severity: 'Attack Surface',
        confidence: 'Medium',
        confidenceLabel: confidenceSystem.Medium.label,
        type: 'Input Reflection',
        description: `Input is reflected in the response on ${xssResults.reflections.length} parameters. Manual security testing recommended.`,
        bountyEstimate: '$0 - Requires manual verification',
        requiresManualVerification: true
      });
      analysis.attackSurfaceScore -= 5;
    }
    
    // Calculate Final Score
    analysis.attackSurfaceScore = Math.max(0, Math.min(100, analysis.attackSurfaceScore));
    
    // Executive Summary - Version Réaliste
    const potentialRisks = analysis.observations.filter(o => o.severity === 'Potential Risk').length;
    const attackSurface = analysis.observations.filter(o => o.severity === 'Attack Surface').length;
    const informational = analysis.observations.filter(o => o.severity === 'Informational').length;
    
    if (potentialRisks > 0) {
      analysis.executiveSummary = `📋 Security Analysis Complete: ${potentialRisks} potential risk(s) detected that require manual verification. No confirmed vulnerabilities found by automated analysis.`;
    } else if (attackSurface > 0) {
      analysis.executiveSummary = `📋 Security Analysis Complete: ${attackSurface} attack surface observations identified. Manual security testing recommended to verify impact.`;
    } else {
      analysis.executiveSummary = `✅ Security Analysis Complete: No immediate risks detected. ${informational} informational findings for defense in depth.`;
    }
    
    // Next Steps - Professionnels
    analysis.nextSteps = [
      "🔍 Manually verify all 'Potential Risk' observations with Burp Suite or OWASP ZAP",
      "📝 Review discovered endpoints for sensitive data exposure",
      "🔐 Test reflected parameters for XSS using manual techniques",
      "📊 Review robots.txt paths for any unintended exposure",
      "🧪 Perform authenticated testing if applicable"
    ];
    
    analysis.requiresManualReview = analysis.observations.filter(o => o.requiresManualVerification);
    
    res.json({
      success: true,
      analysis: analysis,
      methodology: "OWASP Top 10 + Security Best Practices Analysis",
      note: "Automated security observations require manual verification. No findings are confirmed vulnerabilities.",
      disclaimer: DISCLAIMER
    });
    
  } catch (error) {
    console.error("Analysis failed:", error);
    res.status(500).json({ error: "Analysis failed", details: error.message });
  }
});

// ============== XSS ANALYSIS ENDPOINT ==============
app.post("/api/xss/analyze", async (req, res) => {
  const { url, params = null } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  try {
    console.log(`🎯 Starting XSS analysis on: ${url}`);
    const xssEngine = new XSSEngine();
    const results = await xssEngine.scanXSS(url, params);
    
    res.json({
      success: true,
      target: url,
      timestamp: new Date().toISOString(),
      results: results,
      disclaimer: "XSS analysis results require manual verification in a browser. Automated tests cannot confirm exploitability."
    });
  } catch (error) {
    res.status(500).json({ error: "XSS analysis failed", details: error.message });
  }
});

// ============== PARAMETER DISCOVERY ENDPOINT ==============
app.post("/api/params/discover", async (req, res) => {
  const { url } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  try {
    const xssEngine = new XSSEngine();
    const params = await xssEngine.discoverParameters(url);
    
    res.json({
      success: true,
      target: url,
      totalParams: params.length,
      parameters: params,
      note: "Discovered parameters are potential attack surface points. Manual investigation recommended."
    });
  } catch (error) {
    res.status(500).json({ error: "Parameter discovery failed", details: error.message });
  }
});

// ============== HEALTH CHECK ==============
app.get("/health", (req, res) => {
  res.json({ 
    status: "OK", 
    timestamp: new Date().toISOString(),
    version: "3.0.0",
    disclaimer: "Security observation tool - not a vulnerability scanner"
  });
});

// ============== SIMPLE SCAN (Compatibility) ==============
app.post("/scan", async (req, res) => {
  const { url } = req.body;
  try {
    const response = await axios.get(url, { timeout: 10000 });
    const headers = response.headers;
    let observations = [];
    
    if (!headers["x-frame-options"]) observations.push("X-Frame-Options header missing (defense-in-depth)");
    if (!headers["content-security-policy"]) observations.push("CSP header missing (defense-in-depth)");
    if (!headers["strict-transport-security"]) observations.push("HSTS header missing (defense-in-depth)");
    
    res.json({
      success: true,
      url: url,
      statusCode: response.status,
      observations: observations,
      timestamp: new Date().toISOString(),
      note: "Security observations only. Manual verification required."
    });
  } catch(err) {
    res.status(500).json({ error: "Analysis failed" });
  }
});

// ============== HELPER FUNCTIONS ==============
function getRemediation(headerName) {
  const remediations = {
    'X-Frame-Options': 'Add header: X-Frame-Options: DENY or SAMEORIGIN',
    'Content-Security-Policy': 'Implement CSP policy: default-src "self"',
    'Strict-Transport-Security': 'Add HSTS: Strict-Transport-Security: max-age=31536000',
    'X-Content-Type-Options': 'Add: X-Content-Type-Options: nosniff',
    'Referrer-Policy': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
  };
  return remediations[headerName] || 'Review security headers documentation';
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🛡️ ShieldAI Security Analysis Platform running on port ${PORT}`);
  console.log(`📋 Realistic security observations - No fake vulnerabilities`);
  console.log(`⚠️ All findings require manual verification`);
  console.log(`✅ CORS enabled for: ${allowedOrigins.join(', ')}`);
});