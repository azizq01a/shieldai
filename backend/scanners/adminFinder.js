import axios from 'axios';

const adminPaths = [
  '/admin', '/administrator', '/admin.php', '/admincp', '/admindir',
  '/admin/login', '/admin/dashboard', '/admin/index.php', '/admin/panel',
  '/admin_area', '/adminarea', '/adminLogin', '/admins', '/administratorlogin',
  '/backend', '/cms', '/console', '/control', '/controlpanel', '/dashboard',
  '/login', '/logon', '/manage', '/manager', '/member', '/members',
  '/moderator', '/operator', '/panel', '/staff', '/superadmin', '/sysadmin',
  '/system', '/user', '/userpanel', '/webadmin', '/wp-admin', '/wp-login.php',
  '/cpanel', '/plesk', '/webmail', '/phpmyadmin', '/mysql', '/database'
];

const weakCredentials = [
  { user: 'admin', pass: 'admin' },
  { user: 'admin', pass: 'password' },
  { user: 'admin', pass: '123456' },
  { user: 'admin', pass: 'admin123' },
  { user: 'root', pass: 'root' },
  { user: 'root', pass: 'toor' },
  { user: 'user', pass: 'user' },
  { user: 'test', pass: 'test' },
  { user: 'administrator', pass: 'administrator' },
  { user: 'administrator', pass: 'password' }
];

export async function findAdminPanels(url) {
  const results = {
    panels: [],
    weakCredentials: [],
    recommendations: []
  };
  
  console.log(`🔍 Scanning for admin panels on: ${url}`);
  
  for (const path of adminPaths) {
    const fullUrl = `${url}${path}`;
    try {
      const response = await axios.get(fullUrl, {
        timeout: 5000,
        validateStatus: (status) => status < 500,
        headers: { 'User-Agent': 'ShieldAI-Scanner/2.0' }
      });
      
      if (response.status !== 404) {
        results.panels.push({
          url: fullUrl,
          status: response.status,
          type: detectAdminType(response.data)
        });
        console.log(`✅ Found admin panel: ${fullUrl}`);
        
        // فحص نقاط الضعف في لوحة التحكم
        await checkAdminWeakness(fullUrl, results);
      }
    } catch (error) {
      // Path not found
    }
  }
  
  return results;
}

function detectAdminType(html) {
  if (html.includes('WordPress')) return 'WordPress';
  if (html.includes('Joomla')) return 'Joomla';
  if (html.includes('Drupal')) return 'Drupal';
  if (html.includes('Magento')) return 'Magento';
  if (html.includes('cPanel')) return 'cPanel';
  if (html.includes('phpMyAdmin')) return 'phpMyAdmin';
  if (html.includes('Login') && html.includes('Password')) return 'Custom Admin';
  return 'Generic Admin';
}

async function checkAdminWeakness(adminUrl, results) {
  // التحقق من وجود صفحة تسجيل دخول
  try {
    const response = await axios.get(adminUrl, { timeout: 5000 });
    const html = response.data;
    
    // فحص مشاكل أمنية شائعة
    if (html.includes('input type="password"')) {
      // فحص وجود CSRF token
      if (!html.includes('csrf') && !html.includes('_token') && !html.includes('nonce')) {
        results.recommendations.push(`${adminUrl}: Missing CSRF protection on login form`);
      }
      
      // فحص وجود HTTPS
      if (!adminUrl.startsWith('https')) {
        results.recommendations.push(`${adminUrl}: Login page not using HTTPS`);
      }
    }
    
    // اختبار كلمات المرور الضعيفة (آمن - لا يحاول تسجيل الدخول فعلياً)
    const loginForm = detectLoginForm(html);
    if (loginForm) {
      results.recommendations.push(`${adminUrl}: Consider implementing strong password policy and 2FA`);
    }
    
  } catch (error) {
    // Unable to analyze
  }
}

function detectLoginForm(html) {
  return html.includes('password') && 
         (html.includes('login') || html.includes('signin') || html.includes('auth'));
}

export function getSecurityRecommendations(panels) {
  const recommendations = [];
  
  if (panels.length > 0) {
    recommendations.push('Implement IP whitelisting for admin access');
    recommendations.push('Enable Two-Factor Authentication (2FA) on all admin panels');
    recommendations.push('Use strong, unique passwords with password managers');
    recommendations.push('Implement rate limiting on login attempts');
    recommendations.push('Monitor and log all admin access attempts');
    recommendations.push('Change default admin URLs to custom paths');
    recommendations.push('Regularly audit admin panel access logs');
  }
  
  return recommendations;
}