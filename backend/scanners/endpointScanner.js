import axios from 'axios';

const commonEndpoints = [
  // API endpoints
  '/api', '/api/v1', '/api/v2', '/api/v3', '/api/users', '/api/admin',
  '/api/login', '/api/auth', '/api/token', '/api/keys', '/api/config',
  '/graphql', '/v1/graphql', '/graphiql', '/playground',
  
  // Admin panels
  '/admin', '/administrator', '/admin.php', '/admin/login', '/admin/dashboard',
  '/wp-admin', '/wp-login.php', '/cpanel', '/webmail', '/plesk',
  
  // Hidden directories
  '/backup', '/backups', '/backup.zip', '/backup.tar.gz', '/db_backup',
  '/old', '/old_site', '/temp', '/tmp', '/test', '/testing', '/dev',
  '/hidden', '/secret', '/private', '/confidential', '/internal',
  
  // Config files
  '/.env', '/config.php', '/config.json', '/settings.php', '/wp-config.php',
  '/.git/config', '/.gitignore', '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
  
  // Debug endpoints
  '/debug', '/debug.php', '/status', '/health', '/info', '/phpinfo.php',
  '/server-status', '/server-info', '/metrics', '/actuator', '/actuator/health',
  
  // Upload endpoints
  '/upload', '/uploads', '/fileupload', '/imageupload', '/media/upload',
  '/api/upload', '/admin/upload', '/wp-content/uploads',
  
  // Database endpoints
  '/phpmyadmin', '/pma', '/mysql', '/db', '/database', '/sql', '/adminer',
  
  // Development files
  '/.idea', '/.vscode', '/.DS_Store', '/Thumbs.db', '/README.md', '/package.json',
  '/composer.json', '/yarn.lock', '/Gemfile', '/requirements.txt'
];

export async function scanEndpoints(baseUrl) {
  const results = [];
  const promises = [];

  console.log(`🔍 Scanning endpoints for: ${baseUrl}`);

  for (const endpoint of commonEndpoints) {
    const fullUrl = `${baseUrl}${endpoint}`;
    const promise = axios.get(fullUrl, {
      timeout: 5000,
      validateStatus: (status) => status < 500,
      headers: {
        'User-Agent': 'ShieldAI-Scanner/2.0'
      }
    })
      .then(response => {
        if (response.status !== 404) {
          results.push({
            url: fullUrl,
            status: response.status,
            title: getTitle(response.data),
            contentLength: response.data.length,
            contentType: response.headers['content-type']
          });
          console.log(`🎯 Found: ${fullUrl} (${response.status})`);
        }
      })
      .catch(() => {
        // Silently fail
      });
    promises.push(promise);
  }

  await Promise.all(promises);
  
  console.log(`📊 Found ${results.length} accessible endpoints`);
  return results;
}

function getTitle(html) {
  const match = html.match(/<title>([^<]*)<\/title>/i);
  return match ? match[1] : 'No title';
}