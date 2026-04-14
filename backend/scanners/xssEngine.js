import axios from 'axios';

export class XSSEngine {
  
  constructor() {
    this.xssPayloads = {
      basic: [
        '<script>alert("XSS Test")</script>',
        '<img src=x onerror=alert("XSS Test")>',
        '<svg onload=alert("XSS Test")>'
      ],
      advanced: [
        '"><script>alert("XSS Test")</script>',
        'javascript:alert("XSS Test")',
        '${alert("XSS Test")}',
        '{{alert("XSS Test")}}'
      ]
    };
    this.results = { reflections: [], confirmedXSS: [], paramsDiscovered: new Set() };
  }
  
  async scanXSS(url, params = null) {
    console.log(`🔬 Starting XSS reflection analysis on: ${url}`);
    const discoveredParams = params || await this.discoverParameters(url);
    this.results.paramsDiscovered = discoveredParams;
    
    for (const param of discoveredParams.slice(0, 30)) {
      await this.testParameter(url, param);
    }
    await this.testURLFragment(url);
    await this.analyzeReflectionContext();
    
    return {
      totalParamsTested: discoveredParams.length,
      reflections: this.results.reflections,
      confirmedXSS: this.results.confirmedXSS,
      contextAnalysis: this.results.contextAnalysis,
      summary: this.generateSummary()
    };
  }
  
  async discoverParameters(url) {
    const discovered = new Set();
    try {
      const response = await axios.get(url, { timeout: 10000 });
      const html = response.data;
      
      const inputRegex = /<input[^>]+name=["']([^"']+)["']/gi;
      let match;
      while ((match = inputRegex.exec(html)) !== null) discovered.add(match[1]);
      
      const formRegex = /<form[^>]+action=["']([^"']+)["']/gi;
      while ((match = formRegex.exec(html)) !== null) {
        const action = match[1];
        if (action.includes('?')) {
          const params = new URLSearchParams(action.split('?')[1]);
          params.forEach((v, k) => discovered.add(k));
        }
      }
      
      const urlParamRegex = /[?&]([a-zA-Z_][a-zA-Z0-9_]*)=/g;
      while ((match = urlParamRegex.exec(html)) !== null) discovered.add(match[1]);
      
    } catch(e) {}
    
    const commonParams = [
      'q', 'search', 's', 'id', 'page', 'p', 'user', 'name', 'email',
      'redirect', 'url', 'next', 'return', 'callback', 'debug', 'test',
      'mode', 'action', 'format', 'type', 'order', 'sort', 'limit',
      'offset', 'filter', 'query', 'keyword', 'term', 'value'
    ];
    commonParams.forEach(p => discovered.add(p));
    
    console.log(`📊 Discovered ${discovered.size} parameters for analysis`);
    return Array.from(discovered);
  }
  
  async testParameter(url, param) {
    for (const payloadType of ['basic', 'advanced']) {
      const payloads = this.xssPayloads[payloadType];
      for (const payload of payloads) {
        const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
        try {
          const response = await axios.get(testUrl, { 
            timeout: 8000, 
            validateStatus: (status) => status < 500 
          });
          
          const reflection = this.checkReflection(response.data, payload);
          if (reflection.reflected) {
            const context = this.analyzeContext(response.data, payload);
            const finding = { 
              parameter: param, 
              payload: payload, 
              url: testUrl, 
              reflectionType: reflection.type, 
              context: context 
            };
            this.results.reflections.push(finding);
            
            if (context.executable) {
              this.results.confirmedXSS.push({
                ...finding,
                severity: 'Potential Risk',
                confidence: 'Medium',
                note: 'Manual verification required in browser'
              });
            }
            break;
          }
        } catch(e) {}
      }
    }
  }
  
  checkReflection(html, payload) {
    if (html.includes(payload)) return { reflected: true, type: 'full' };
    if (html.includes(encodeURIComponent(payload))) return { reflected: true, type: 'encoded' };
    return { reflected: false, type: null };
  }
  
  analyzeContext(html, payload) {
    const context = { location: null, executable: false, difficulty: 'high' };
    const payloadIndex = html.indexOf(payload);
    if (payloadIndex === -1) return context;
    
    const surrounding = html.substring(
      Math.max(0, payloadIndex - 100),
      Math.min(html.length, payloadIndex + payload.length + 100)
    );
    
    if (surrounding.match(/<script[^>]*>[\s\S]*?<\/script>/i)) {
      context.location = 'inside_script';
      context.executable = true;
      context.difficulty = 'easy';
    }
    else if (surrounding.match(/<[^>]*on\w+="[^"]*"/i)) {
      context.location = 'inside_event_handler';
      context.executable = true;
      context.difficulty = 'easy';
    }
    else if (surrounding.match(/<[^>]*>/i)) {
      context.location = 'inside_html_tag';
      context.executable = payload.includes('>');
      context.difficulty = 'medium';
    }
    else if (surrounding.match(/['"][^'"]*['"]/)) {
      context.location = 'inside_attribute';
      context.executable = payload.includes('"') || payload.includes("'");
      context.difficulty = 'medium';
    }
    else {
      context.location = 'plain_text';
      context.executable = false;
      context.difficulty = 'hard';
    }
    
    return context;
  }
  
  async testURLFragment(url) {
    const fragmentPayloads = ['#<script>alert("Test")</script>', '#"><img src=x onerror=alert("Test")>'];
    for (const payload of fragmentPayloads) {
      const testUrl = `${url}${payload}`;
      try {
        const response = await axios.get(testUrl, { timeout: 5000 });
        if (response.data.includes(payload.replace('#', ''))) {
          this.results.reflections.push({
            parameter: 'url_fragment',
            payload: payload,
            url: testUrl,
            reflectionType: 'fragment',
            note: 'Client-side verification required'
          });
        }
      } catch(e) {}
    }
  }
  
  async analyzeReflectionContext() {
    this.results.contextAnalysis = this.results.reflections.map(r => ({
      parameter: r.parameter,
      canExecute: r.context?.executable || false,
      bypassTechniques: r.reflectionType === 'encoded' ? ['Double encoding', 'Unicode encoding'] : [],
      recommendation: r.context?.executable ? 'Manual verification required' : 'Low priority'
    }));
  }
  
  generateSummary() {
    return {
      totalReflections: this.results.reflections.length,
      confirmedXSS: this.results.confirmedXSS.length,
      requiresManual: this.results.reflections.length - this.results.confirmedXSS.length,
      riskLevel: this.results.confirmedXSS.length > 0 ? 'Manual Review Required' : 'Informational',
      recommendation: this.results.confirmedXSS.length > 0 ? 
        'Manual security testing recommended' : 
        'No immediate concerns detected'
    };
  }
}