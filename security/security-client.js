/**
 * YINITECH SECURITY - Client Integration
 * Include this script in all pages for 7-layer protection
 */

// Security initialization - runs immediately
(function() {
  'use strict';

  // Configuration from meta tags or defaults
  const SECURITY_CONFIG = {
    hmacSecret: document.querySelector('meta[name="security-hmac"]')?.content || null,
    webhookUrl: document.querySelector('meta[name="security-webhook"]')?.content || null,
    telegramBot: document.querySelector('meta[name="security-telegram"]')?.content || null,
    enableRateLimit: true,
    enableWAF: true,
    enableAudit: true,
    logLevel: 'warn'
  };

  // Security instance
  let security = null;
  let initialized = false;

  // Initialize security system
  async function initSecurity() {
    if (initialized || !window.YinitechSecurity) return;

    try {
      security = new window.YinitechSecurity();
      await security.initialize(
        SECURITY_CONFIG.hmacSecret,
        SECURITY_CONFIG.webhookUrl,
        SECURITY_CONFIG.telegramBot
      );
      initialized = true;
      console.log('[SECURITY] 7-Layer protection initialized');
    } catch (e) {
      console.error('[SECURITY] Initialization failed:', e);
    }
  }

  // Intercept fetch for security checks
  const originalFetch = window.fetch;
  window.fetch = async function(url, options = {}) {
    // Initialize if not done
    if (!initialized) await initSecurity();

    if (!security) return originalFetch.apply(this, arguments);

    const request = new Request(url, options);
    const clientIP = 'client'; // In real app, get from server header

    // Run security checks
    const result = await security.handleRequest(request, {
      ip: clientIP,
      category: getCategoryFromUrl(url),
      permission: getPermissionFromUrl(url),
      resource: getResourceFromUrl(url),
      requireHMAC: options.method === 'POST' && url.includes('/api/')
    });

    if (!result.allowed) {
      // Return blocked response
      return new Response(JSON.stringify({
        error: 'SECURITY_BLOCKED',
        layer: result.layer,
        reason: result.reason || result.errors?.join(', ')
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Add security headers to request
    const secureOptions = { ...options };
    secureOptions.headers = {
      ...secureOptions.headers,
      'X-Request-ID': result.requestId,
      'X-Client-Fingerprint': getClientFingerprint()
    };

    // Add HMAC signature for POST requests
    if (secureOptions.method === 'POST' && security.encryption.hmacKey) {
      const body = secureOptions.body || '';
      const signature = await security.encryption.sign(body);
      secureOptions.headers['X-Signature'] = signature;
    }

    return originalFetch.apply(this, [url, secureOptions]);
  };

  // Determine rate limit category from URL
  function getCategoryFromUrl(url) {
    if (url.includes('/checkout') || url.includes('/capture-email')) return 'checkout';
    if (url.includes('/search')) return 'search';
    if (url.includes('/api/')) return 'api';
    return 'global';
  }

  // Determine required permission from URL
  function getPermissionFromUrl(url) {
    if (url.includes('/checkout') || url.includes('/capture-email')) return 'initiate_checkout';
    if (url.includes('/download')) return 'download_product';
    if (url.includes('/api/admin')) return 'admin_access';
    return 'view_products';
  }

  // Determine resource from URL
  function getResourceFromUrl(url) {
    if (url.includes('/products')) return 'products';
    if (url.includes('/orders')) return 'orders';
    if (url.includes('/payments')) return 'payments';
    if (url.includes('/users')) return 'users';
    return 'products';
  }

  // Generate client fingerprint
  function getClientFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('fingerprint', 2, 2);
    const canvasFp = canvas.toDataURL();

    const fp = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset(),
      canvasFp
    ].join('|');

    // Simple hash
    let hash = 0;
    for (let i = 0; i < fp.length; i++) {
      hash = ((hash << 5) - hash) + fp.charCodeAt(i);
      hash |= 0;
    }
    return 'fp_' + Math.abs(hash).toString(36);
  }

  // Secure checkout function for buy buttons
  window.secureCheckout = async function(productName, price, productId) {
    if (!initialized) await initSecurity();
    if (!security) throw new Error('Security not initialized');

    const email = prompt('Ingresa tu email para recibir el acceso:');
    if (!email || !email.includes('@')) {
      alert('Email inválido');
      return;
    }

    try {
      const result = await security.secureCheckout({
        productId: productId || `prod_${Date.now()}`,
        productName,
        price,
        userId: localStorage.getItem('user_id') || email,
        gateway: 'vitawallet', // default
        amount: 6.99,
        currency: 'USD',
        email
      });

      if (result.success) {
        alert('✅ ¡Compra completada! Revisa tu email para el acceso.');
        security.auditor.log('purchase_completed', {
          productId: result.deliveryToken.productId,
          userId: result.deliveryToken.userId,
          transactionId: result.transactionId
        });
      }
    } catch (error) {
      console.error('[SECURITY] Checkout failed:', error);
      alert('❌ Error en la compra: ' + error.message);
    }
  };

  // Auto-initialize on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSecurity);
  } else {
    initSecurity();
  }

  // Export for manual use
  window.YINITECH_SECURITY = {
    init: initSecurity,
    getInstance: () => security,
    secureCheckout: window.secureCheckout
  };
})();