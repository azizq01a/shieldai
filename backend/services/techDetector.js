// services/techDetector.js
export class TechDetector {
  
  async detect(html, headers) {
    const tech = {
      cms: null,
      framework: null,
      server: null,
      javascript: [],
      confidence: {}
    };
    
    // Detect CMS
    if (html.includes('wp-content') || html.includes('wp-includes')) {
      tech.cms = 'WordPress';
      tech.confidence.cms = 'High';
      
      // Detect WordPress version
      const versionMatch = html.match(/ver=([0-9.]+)/);
      if (versionMatch) tech.version = versionMatch[1];
    }
    
    if (html.includes('Joomla')) {
      tech.cms = 'Joomla';
      tech.confidence.cms = 'High';
    }
    
    if (html.includes('Drupal')) {
      tech.cms = 'Drupal';
      tech.confidence.cms = 'High';
    }
    
    // Detect Frameworks
    if (html.includes('react') || html.includes('React')) {
      tech.framework = 'React';
      tech.javascript.push('React');
      tech.confidence.framework = 'High';
    }
    
    if (html.includes('vue') || html.includes('Vue')) {
      tech.framework = 'Vue.js';
      tech.javascript.push('Vue.js');
      tech.confidence.framework = 'High';
    }
    
    if (html.includes('angular') || html.includes('Angular')) {
      tech.framework = 'Angular';
      tech.javascript.push('Angular');
      tech.confidence.framework = 'High';
    }
    
    if (html.includes('next') || html.includes('Next.js')) {
      tech.framework = 'Next.js';
      tech.javascript.push('Next.js');
    }
    
    // Detect Server
    if (headers.server) {
      tech.server = headers.server;
      tech.confidence.server = 'High';
    }
    
    if (headers['x-powered-by']) {
      tech.poweredBy = headers['x-powered-by'];
    }
    
    return tech;
  }
}