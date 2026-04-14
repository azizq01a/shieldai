import axios from 'axios';

export class JSEndpointExtractor {
  
  constructor() {
    this.endpoints = new Set();
    this.jsFiles = [];
    this.apiPatterns = [
      /\/api\/[a-zA-Z0-9\/\-_?=&]+/g,
      /\/v\d\/[a-zA-Z0-9\/\-_?=&]+/g,
      /\/graphql\b/g,
      /fetch\(['"`]([^'"`]+)['"`]/g,
      /axios\.(?:get|post)\(['"`]([^'"`]+)['"`]/g,
      /\/[a-zA-Z0-9\/\-_]+\.(?:php|asp|aspx|jsp|do|action|json|xml)/g
    ];
  }
  
  async extractFromJS(targetUrl) {
    console.log(`🔍 Extracting endpoints from JavaScript on: ${targetUrl}`);
    
    await this.findJSFiles(targetUrl);
    
    for (const jsFile of this.jsFiles) {
      await this.extractFromSingleJS(jsFile);
    }
    
    await this.extractInlineScripts(targetUrl);
    
    return this.formatResults();
  }
  
  async findJSFiles(url) {
    try {
      const response = await axios.get(url, { timeout: 10000 });
      const html = response.data;
      
      const jsRegex = /<script[^>]+src=["']([^"']+\.js)["'][^>]*>/gi;
      let match;
      while ((match = jsRegex.exec(html)) !== null) {
        const jsUrl = new URL(match[1], url).href;
        if (!this.jsFiles.includes(jsUrl)) {
          this.jsFiles.push(jsUrl);
          console.log(`📄 Found JavaScript: ${jsUrl.substring(0, 80)}...`);
        }
      }
    } catch(e) {}
  }
  
  async extractFromSingleJS(jsUrl) {
    try {
      const response = await axios.get(jsUrl, { timeout: 10000 });
      const content = response.data;
      
      for (const pattern of this.apiPatterns) {
        const matches = content.matchAll(pattern);
        for (const match of matches) {
          let endpoint = match[1] || match[0];
          endpoint = endpoint.split('?')[0].replace(/\/$/, '').replace(/['"]/g, '');
          
          if (endpoint && endpoint.length > 3 && endpoint.length < 200 && 
              !endpoint.includes('{') && !endpoint.includes('}')) {
            this.endpoints.add(JSON.stringify({
              url: endpoint,
              source: jsUrl,
              type: this.classifyEndpoint(endpoint)
            }));
          }
        }
      }
    } catch(e) {}
  }
  
  async extractInlineScripts(url) {
    try {
      const response = await axios.get(url, { timeout: 10000 });
      const html = response.data;
      const inlineScriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
      let match;
      
      while ((match = inlineScriptRegex.exec(html)) !== null) {
        const scriptContent = match[1];
        for (const pattern of this.apiPatterns) {
          const matches = scriptContent.matchAll(pattern);
          for (const endpointMatch of matches) {
            let endpoint = endpointMatch[1] || endpointMatch[0];
            endpoint = endpoint.split('?')[0].replace(/\/$/, '').replace(/['"]/g, '');
            if (endpoint && endpoint.length > 3) {
              this.endpoints.add(JSON.stringify({
                url: endpoint,
                source: 'inline-script',
                type: this.classifyEndpoint(endpoint)
              }));
            }
          }
        }
      }
    } catch(e) {}
  }
  
  classifyEndpoint(endpoint) {
    const lower = endpoint.toLowerCase();
    if (lower.includes('admin')) return 'Admin Interface';
    if (lower.includes('api')) return 'API Endpoint';
    if (lower.includes('user')) return 'User Data';
    if (lower.includes('login') || lower.includes('auth')) return 'Authentication';
    if (lower.includes('upload')) return 'File Upload';
    return 'General Endpoint';
  }
  
  formatResults() {
    const endpoints = Array.from(this.endpoints).map(e => JSON.parse(e));
    const grouped = {
      'Admin Interface': [],
      'API Endpoint': [],
      'User Data': [],
      'Authentication': [],
      'File Upload': [],
      'General Endpoint': []
    };
    
    endpoints.forEach(e => {
      if (grouped[e.type]) grouped[e.type].push(e);
      else grouped['General Endpoint'].push(e);
    });
    
    return {
      total: endpoints.length,
      grouped: grouped,
      allEndpoints: endpoints.slice(0, 20),
      jsFilesScanned: this.jsFiles.length,
      note: 'Discovered endpoints represent potential attack surface. Manual investigation recommended.'
    };
  }
}