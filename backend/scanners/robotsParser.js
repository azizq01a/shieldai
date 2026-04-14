import axios from 'axios';

export class RobotsParser {
  
  async parseRobotsTxt(url) {
    const robotsUrl = `${url}/robots.txt`;
    const results = { 
      exists: false, 
      url: robotsUrl, 
      disallowed: [], 
      sitemaps: [], 
      observations: [] 
    };
    
    try {
      const response = await axios.get(robotsUrl, { 
        timeout: 5000, 
        validateStatus: (status) => status < 400 
      });
      
      if (response.status === 200) {
        results.exists = true;
        const lines = response.data.split('\n');
        
        for (const line of lines) {
          if (line.toLowerCase().startsWith('disallow:')) {
            const path = line.substring(9).trim();
            if (path && path !== '/' && path !== '') {
              results.disallowed.push({
                path: path,
                fullUrl: `${url}${path}`,
                observation: 'Path listed in robots.txt - Not a vulnerability'
              });
            }
          }
          if (line.toLowerCase().startsWith('sitemap:')) {
            results.sitemaps.push(line.substring(8).trim());
          }
        }
        
        if (results.disallowed.length > 0) {
          results.observations.push({
            type: 'Information Disclosure',
            description: `${results.disallowed.length} paths listed in robots.txt`,
            recommendation: 'Review if any sensitive paths are unintentionally exposed'
          });
        }
      }
    } catch(e) {
      // robots.txt not accessible - normal
    }
    
    return results;
  }
}