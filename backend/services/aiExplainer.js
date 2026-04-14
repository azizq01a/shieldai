// services/aiExplainer.js
export class AIExplainer {
  
  static explainHeader(headerName, risk) {
    return `
🔍 **Security Analysis**: ${headerName} is missing

**What does this mean?**
This security header helps protect against ${risk}. Without it, your application has an increased attack surface.

**Potential Impact**:
- Attackers could exploit missing protections
- Defense-in-depth strategy is weakened
- Compliance requirements may not be met

**Is this critical?**
This is a security best practice, not a direct vulnerability. Many bug bounty programs consider this informational unless combined with an actual exploit.

**Recommendation**:
Implement this header as part of your defense-in-depth strategy.
    `.trim();
  }
  
  static explainTech(techStack) {
    let explanation = `🔧 **Technology Intelligence**\n\n`;
    
    if (techStack.cms) {
      explanation += `**Detected CMS**: ${techStack.cms}\n`;
      explanation += `- WordPress sites should keep core, plugins, and themes updated\n`;
      explanation += `- Common attack vectors: XML-RPC, wp-admin brute force, vulnerable plugins\n`;
    }
    
    if (techStack.framework) {
      explanation += `**Detected Framework**: ${techStack.framework}\n`;
      explanation += `- Keep framework updated to latest version\n`;
      explanation += `- Follow framework-specific security best practices\n`;
    }
    
    if (techStack.server) {
      explanation += `**Web Server**: ${techStack.server}\n`;
    }
    
    return explanation;
  }
  
  static explainEndpoints(count) {
    return `
🔍 **Attack Surface Intelligence**

**What this means**:
Discovered ${count} potential API endpoints from JavaScript analysis. These endpoints represent your application's attack surface.

**Why this matters**:
- Each endpoint is a potential entry point for attackers
- Unauthenticated endpoints may expose sensitive data
- Hidden endpoints might have weaker security controls

**Recommended Investigation**:
1. Identify which endpoints require authentication
2. Test for IDOR vulnerabilities
3. Check for excessive data exposure
4. Review rate limiting implementation

**Risk Story**:
An attacker discovering these endpoints could:
1. Map your entire API structure
2. Test each endpoint for vulnerabilities
3. Exploit weak authentication on unprotected endpoints
    `.trim();
  }
  
  static riskStory(issue) {
    const stories = {
      'Clickjacking Protection': `
**🎯 Risk Story - Clickjacking**

An attacker creates a malicious website that loads your page in an invisible iframe.
When the user clicks anywhere on the attacker's site, they actually click your page.

**Attack Scenario**:
1. Victim visits attacker's website
2. Attacker's site loads your admin panel in hidden iframe
3. Victim clicks "Play Game" but actually clicks "Delete Account"
4. Action executes with victim's privileges

**Impact**: Account takeover, unauthorized actions, data loss
      `,
      'CSP': `
**🎯 Risk Story - Cross-Site Scripting (XSS)**

Without CSP, an attacker who finds an XSS vulnerability can:
1. Inject malicious JavaScript into your pages
2. Steal session cookies and authentication tokens
3. Perform actions on behalf of the victim
4. Deface your website

**Real Impact**: Complete account takeover, data breach
      `
    };
    return stories[issue] || "Manual investigation recommended to understand potential impact.";
  }
  
  static executiveSummary(observations, score) {
    const criticalObs = observations.filter(o => o.confidence === 'High' && o.severity !== 'Informational');
    const attackSurface = observations.filter(o => o.type === 'Attack Surface Mapping');
    const informational = observations.filter(o => o.severity === 'Informational');
    
    if (criticalObs.length > 0) {
      return `
📊 **ShieldAI Security Intelligence Report**

**Summary**: ${criticalObs.length} security observations with HIGH confidence detected.

**Attack Surface Score**: ${score}/100

**Key Findings**:
- ${criticalObs.length} configuration improvements identified
- ${attackSurface.length} attack surface discoveries
- ${informational.length} informational observations

**Important Note**: These are security observations, not confirmed vulnerabilities.
Manual verification by a security professional is required.

**Next Step**: Review each observation and verify in your specific context.
      `.trim();
    }
    
    return `
📊 **ShieldAI Security Intelligence Report**

**Summary**: Security analysis complete. No high-confidence security issues detected.

**Attack Surface Score**: ${score}/100

**Findings Breakdown**:
- ${attackSurface.length} attack surface observations for manual review
- ${informational.length} informational best practices

**Security Posture**: Your application appears to follow security best practices.
Continue regular security reviews and keep dependencies updated.
    `.trim();
  }
  
  static nextSteps(observations) {
    const steps = [
      "🔍 **Manual Verification Required**: All findings need human review - automated tools cannot confirm exploits",
      "📝 **Review Discovered Endpoints**: Check each API endpoint for proper authentication",
      "🔐 **Test Authentication**: Verify that protected resources cannot be accessed without valid credentials"
    ];
    
    const hasHeaders = observations.some(o => o.type === 'Security Header Analysis');
    if (hasHeaders) {
      steps.push("🛡️ **Implement Security Headers**: Add recommended headers for defense-in-depth");
    }
    
    const hasEndpoints = observations.some(o => o.type === 'Attack Surface Mapping');
    if (hasEndpoints) {
      steps.push("🎯 **Prioritize Endpoint Review**: Focus on endpoints containing 'admin', 'api', or 'user'");
    }
    
    return steps;
  }
  
  static explainXSS(reflectionCount) {
    return `
🔬 **XSS Analysis Summary**

**Finding**: ${reflectionCount} parameter(s) reflect user input in HTTP responses.

**What this means**:
When you send data to these parameters, the same data appears in the response. This is necessary for many legitimate features (search, filters).

**Is this XSS?**:
- Input reflection is REQUIRED for XSS but NOT SUFFICIENT
- Manual testing needed to determine if JavaScript execution is possible
- Context matters: where and how the input appears

**Manual Testing Guide**:
1. Use browser DevTools (F12) to inspect where input appears
2. Test payload: <script>alert('XSS Test')</script>
3. Check if alert executes
4. If yes → XSS confirmed

**Bug Bounty Note**: 
Reflected XSS with user interaction = Medium impact
Stored XSS with admin access = High impact
    `.trim();
  }
}