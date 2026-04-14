// scanners/wordpressScanner.js - نسخة بدون cheerio
import axios from 'axios';

export async function scanWordpress(url) {
  const results = {
    isWordpress: false,
    version: null,
    plugins: [],
    themes: [],
    vulnerabilities: [],
    securityIssues: []
  };

  try {
    console.log(`🔍 Scanning for WordPress at: ${url}`);
    
    const response = await axios.get(url, {
      timeout: 10000,
      headers: { 'User-Agent': 'ShieldAI-Scanner/2.0' }
    });
    
    const html = response.data;
    
    // التحقق من وجود WordPress
    if (html.includes('wp-content') || html.includes('wp-includes') || 
        html.includes('/wp-') || html.includes('WordPress')) {
      results.isWordpress = true;
      console.log('✅ WordPress detected!');
      
      // اكتشاف الإصدار
      const versionMatch = html.match(/ver=([0-9.]+)/);
      if (versionMatch) {
        results.version = versionMatch[1];
      }
      
      // اكتشاف الإضافات
      const pluginMatches = html.match(/\/wp-content\/plugins\/([^\/\s'"]+)/g);
      if (pluginMatches) {
        const plugins = [...new Set(pluginMatches.map(p => p.split('/')[3]))];
        results.plugins = plugins;
      }
      
      // اكتشاف القوالب
      const themeMatches = html.match(/\/wp-content\/themes\/([^\/\s'"]+)/g);
      if (themeMatches) {
        const themes = [...new Set(themeMatches.map(t => t.split('/')[3]))];
        results.themes = themes;
      }
      
      // فحص الثغرات حسب الإصدار
      if (results.version) {
        const majorVersion = results.version.substring(0, 3);
        const knownVulns = {
          '5.0': ['RCE vulnerability in comments', 'XSS in media library'],
          '5.1': ['CSRF in plugin installation'],
          '5.2': ['SQL injection in WP_Query'],
          '5.5': ['XSS in block editor'],
          '5.8': ['Widgets block editor RCE']
        };
        
        if (knownVulns[majorVersion]) {
          results.vulnerabilities.push(...knownVulns[majorVersion]);
        }
      }
    }
    
  } catch (error) {
    console.error('WordPress scan error:', error.message);
  }
  
  return results;
}