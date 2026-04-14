import dns from 'dns';
import { promisify } from 'util';

const resolveDns = promisify(dns.resolve);

// قائمة النطاقات الفرعية الشائعة
const commonSubdomains = [
  'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
  'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
  'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
  'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs',
  'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web',
  'media', 'email', 'images', 'img', 'download', 'dns', 'piwik', 'stats',
  'dashboard', 'portal', 'manage', 'start', 'info', 'app', 'login', 'api',
  'stage', 'staging', 'backup', 'cdn', 'cloud', 'store', 'shopify', 'checkout',
  'payment', 'gateway', 'auth', 'account', 'user', 'profile', 'upload', 'files'
];

export async function scanSubdomains(domain) {
  const results = [];
  const promises = [];

  console.log(`🔍 Scanning subdomains for: ${domain}`);

  for (const sub of commonSubdomains) {
    const fullDomain = `${sub}.${domain}`;
    const promise = resolveDns(fullDomain)
      .then(() => {
        results.push({
          subdomain: fullDomain,
          status: 'active',
          type: 'A'
        });
        console.log(`✅ Found: ${fullDomain}`);
      })
      .catch(() => {
        // Silently fail - subdomain doesn't exist
      });
    promises.push(promise);
  }

  await Promise.all(promises);
  
  console.log(`📊 Found ${results.length} active subdomains`);
  return results;
}

export async function scanSubdomainsAdvanced(domain) {
  // استخدام API خارجي للحصول على نتائج أفضل
  const results = [];
  
  try {
    // يمكن إضافة APIs مثل SecurityTrails, Crunchbase, etc.
    const response = await fetch(`https://dns.bufferover.run/dns?q=.${domain}`);
    const data = await response.json();
    
    if (data.FDNS_A) {
      data.FDNS_A.forEach(record => {
        const subdomain = record.split(',')[1];
        if (subdomain && !results.includes(subdomain)) {
          results.push({ subdomain, source: 'bufferover' });
        }
      });
    }
  } catch (error) {
    console.log('Advanced scan failed, using basic results only');
  }
  
  return results;
}