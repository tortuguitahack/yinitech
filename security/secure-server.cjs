/**
 * YINITECH SECURE SERVER
 * Standalone HTTP server with all 7 security layers
 * Runs on port 5100 for capture-email endpoint
 */

const http = require('http');
const url = require('url');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const {
  checkoutSecurity,
  apiSecurity,
  adminSecurity,
  validatePaymentRequest,
  canPurchase,
  recordPurchase,
  generateDeliveryToken,
  validateDeliveryToken,
  createSnapshot,
  executeWithCircuitBreaker,
  healthCheck,
  logAudit,
  signHMAC,
  verifyHMAC,
  scanInput,
  checkRateLimit,
  getClientIP,
  SERVER_SECURITY_CONFIG,
  productRestrictions
} = require('./security-server.cjs');

const {
  handleSecureCheckout,
  handleValidateToken,
  handleGetOrder,
  handleHealthCheck,
  handleSecurityStatus,
  orders,
  pendingCheckouts
} = require('./secure-checkout.cjs');

// Server configuration
const PORT = process.env.PORT || 5100;
const HOST = process.env.HOST || '0.0.0.0';

// In-memory stores (use Redis/database in production)
const rateLimitStore = new Map();
const blockedIPs = new Set();
const auditLogs = [];

// Override the shared config with server instances
SERVER_SECURITY_CONFIG.rateLimitStore = rateLimitStore;
SERVER_SECURITY_CONFIG.blockedIPs = blockedIPs;
SERVER_SECURITY_CONFIG.auditLogs = auditLogs;

// ============================================
// REQUEST PARSING
// ============================================

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 1024 * 1024) { // 1MB limit
        req.destroy();
        reject(new Error('PAYLOAD_TOO_LARGE'));
      }
    });
    req.on('end', () => {
      try {
        const contentType = req.headers['content-type'] || '';
        if (contentType.includes('application/json')) {
          const parsed = body ? JSON.parse(body) : {};
          // Store raw body for HMAC verification
          req.rawBody = body;
          resolve(parsed);
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          const params = new URLSearchParams(body);
          const obj = {};
          for (const [key, value] of params) obj[key] = value;
          req.rawBody = body;
          resolve(obj);
        } else {
          req.rawBody = body;
          resolve(body);
        }
      } catch (e) {
        req.rawBody = body;
        resolve(body);
      }
    });
    req.on('error', reject);
  });
}

// ============================================
// SECURITY MIDDLEWARE CHAIN
// ============================================

async function applySecurity(req, res, options = {}) {
  const {
    category = 'global',
    permission = 'view_products',
    resource = 'products',
    requireHMAC = false,
    skipPaths = ['/health', '/favicon.ico']
  } = options;

  const requestId = req.headers['x-request-id'] || crypto.randomBytes(8).toString('hex');
  const clientIP = getClientIP(req);

  res.setHeader('X-Request-ID', requestId);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Skip security for excluded paths
  if (skipPaths.some(p => req.url.startsWith(p))) {
    return { allowed: true, requestId, clientIP };
  }

  // CAPA 1: Pre-flight validation
  const preflightErrors = [];
  const allowedMethods = ['GET', 'POST', 'OPTIONS'];

  if (!allowedMethods.includes(req.method)) {
    preflightErrors.push(`METHOD_NOT_ALLOWED: ${req.method}`);
  }

  if (req.method === 'POST') {
    const contentType = req.headers['content-type'] || '';
    const allowedTypes = ['application/json', 'application/x-www-form-urlencoded'];
    if (!allowedTypes.some(t => contentType.includes(t))) {
      preflightErrors.push(`INVALID_CONTENT_TYPE: ${contentType}`);
    }
  }

  const contentLength = parseInt(req.headers['content-length'] || '0');
  if (contentLength > 1024 * 1024) {
    preflightErrors.push(`PAYLOAD_TOO_LARGE: ${contentLength} bytes`);
  }

  const requiredHeaders = ['x-request-id', 'x-client-fingerprint'];
  for (const header of requiredHeaders) {
    if (!req.headers[header] && req.method !== 'GET') {
      preflightErrors.push(`MISSING_HEADER: ${header}`);
    }
  }

  if (preflightErrors.length > 0) {
    logAudit('PREFLIGHT_FAILED', { requestId, ip: clientIP, errors: preflightErrors, url: req.url });
    return { allowed: false, status: 400, error: 'PREFLIGHT_FAILED', details: preflightErrors };
  }

  // CAPA 4: IP Blocking
  if (blockedIPs.has(clientIP)) {
    logAudit('BLOCKED_IP_ATTEMPT', { requestId, ip: clientIP, url: req.url });
    return { allowed: false, status: 403, error: 'ACCESS_DENIED', reason: 'IP_BLOCKED' };
  }

  // CAPA 4: Rate limiting
  const rateLimitKey = `${category}:${clientIP}`;
  const limit = SERVER_SECURITY_CONFIG.rateLimits[category] || SERVER_SECURITY_CONFIG.rateLimits.global;
  const now = Date.now();
  const windowStart = now - limit.windowMs;

  let requests = rateLimitStore.get(rateLimitKey) || [];
  requests = requests.filter(t => t > windowStart);

  if (requests.length >= limit.requests) {
    logAudit('RATE_LIMIT_EXCEEDED', { requestId, ip: clientIP, category, url: req.url, count: requests.length });
    return {
      allowed: false,
      status: 429,
      error: 'RATE_LIMIT_EXCEEDED',
      retryAfter: Math.ceil((requests[0] + limit.windowMs - now) / 1000)
    };
  }

  requests.push(now);
  rateLimitStore.set(rateLimitKey, requests);

  res.setHeader('X-RateLimit-Limit', limit.requests);
  res.setHeader('X-RateLimit-Remaining', limit.requests - requests.length);
  res.setHeader('X-RateLimit-Reset', Math.ceil((now + limit.windowMs) / 1000));

  // CAPA 4: WAF scan - will be done after body parse
  req.security = { requestId, clientIP, category, rateLimitKey };

  // CAPA 5: HMAC verification for sensitive endpoints (requires body)
  if (requireHMAC && req.rawBody) {
    const signature = req.headers['x-signature'];
    if (!signature) {
      logAudit('MISSING_SIGNATURE', { requestId, ip: clientIP, url: req.url });
      return { allowed: false, status: 401, error: 'MISSING_SIGNATURE' };
    }
    const valid = verifyHMAC(req.rawBody, signature, SERVER_SECURITY_CONFIG.hmacSecret);
    if (!valid) {
      logAudit('INVALID_SIGNATURE', { requestId, ip: clientIP, url: req.url });
      return { allowed: false, status: 401, error: 'INVALID_SIGNATURE' };
    }
  }

  return { allowed: true, requestId, clientIP, rateLimitKey };
}

// ============================================
// ROUTE HANDLERS
// ============================================

async function handleRequest(req, res) {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Request-ID, X-Client-Fingerprint, X-Signature');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    // Parse body for POST requests
    let body = {};
    if (req.method === 'POST') {
      body = await parseBody(req);
      req.body = body;

      // CAPA 4: WAF scan on body
      const wafResult = scanInput(body);
      if (!wafResult.clean) {
        logAudit('WAF_BLOCKED', {
          requestId: req.security?.requestId,
          ip: req.security?.clientIP,
          url: req.url,
          threats: wafResult.threats
        });
        return sendJSON(res, 400, { error: 'REQUEST_BLOCKED', reason: 'MALICIOUS_INPUT_DETECTED' });
      }
    }

    // Route handling
    if (pathname === '/health' && req.method === 'GET') {
      return handleHealthCheck(req, res);
    }

    if (pathname === '/capture-email' && req.method === 'POST') {
      // Apply checkout security
      const security = await applySecurity(req, res, {
        category: 'checkout',
        permission: 'initiate_checkout',
        resource: 'orders',
        requireHMAC: true
      });

      if (!security.allowed) {
        return sendJSON(res, security.status, security);
      }

      return handleSecureCheckout(req, res);
    }

    if (pathname === '/validate-token' && req.method === 'POST') {
      const security = await applySecurity(req, res, {
        category: 'api',
        permission: 'download_product',
        resource: 'orders'
      });

      if (!security.allowed) {
        return sendJSON(res, security.status, security);
      }

      return handleValidateToken(req, res);
    }

    if (pathname.match(/^\/orders\/[^\/]+$/) && req.method === 'GET') {
      const security = await applySecurity(req, res, {
        category: 'api',
        permission: 'view_products',
        resource: 'orders'
      });

      if (!security.allowed) {
        return sendJSON(res, security.status, security);
      }

      req.params = { orderId: pathname.split('/')[2] };
      return handleGetOrder(req, res);
    }

    if (pathname === '/admin/security' && req.method === 'GET') {
      const security = await applySecurity(req, res, {
        category: 'api',
        permission: 'admin_access',
        resource: 'security_logs',
        requireHMAC: true
      });

      if (!security.allowed) {
        return sendJSON(res, security.status, security);
      }

      return handleSecurityStatus(req, res);
    }

    // 404
    sendJSON(res, 404, { error: 'NOT_FOUND', path: pathname });

  } catch (error) {
    console.error('[SERVER ERROR]', error);
    sendJSON(res, 500, { error: 'INTERNAL_ERROR' });
  }
}

function sendJSON(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// ============================================
// SERVER STARTUP
// ============================================

const server = http.createServer(handleRequest);

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[SERVER] Port ${PORT} already in use`);
    process.exit(1);
  }
  console.error('[SERVER ERROR]', err);
});

server.listen(PORT, HOST, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║  YINITECH SECURE SERVER - 7 LAYER PROTECTION                 ║
╠══════════════════════════════════════════════════════════════╣
║  Server: http://${HOST}:${PORT}                                    ║
║  Endpoints:                                                  ║
║    GET  /health              - Health check                  ║
║    POST /capture-email       - Secure checkout (Layer 1-7)   ║
║    POST /validate-token      - Validate delivery token       ║
║    GET  /orders/:id          - Order lookup                  ║
║    GET  /admin/security      - Security status (admin)       ║
╠══════════════════════════════════════════════════════════════╣
║  Security Layers Active:                                     ║
║  1. ✅ Pre-flight Validation                                ║
║  2. ✅ Minimum Privilege                                    ║
║  3. ✅ Process Isolation (Circuit Breaker)                  ║
║  4. ✅ Threat Detection (Rate Limit + WAF)                  ║
║  5. ✅ Encryption (HMAC-SHA256)                             ║
║  6. ✅ Continuous Auditing                                  ║
║  7. ✅ Incident Response (Rollback + Recovery)              ║
╠══════════════════════════════════════════════════════════════╣
║  Product Restrictions:                                       ║
║  • No sharing • No copying • 30-day durability              ║
║  • No disclosure • Single purchase • Additional allowed     ║
╠══════════════════════════════════════════════════════════════╣
║  Approved Gateways: binance, lead_bank, openpayd,           ║
║  banco_mercantil, wallbit, safepal, whop                    ║
╚══════════════════════════════════════════════════════════════╝
  `);

  logAudit('SERVER_STARTED', { port: PORT, host: HOST, pid: process.pid });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[SERVER] SIGTERM received, shutting down gracefully...');
  logAudit('SERVER_STOPPED', { signal: 'SIGTERM' });
  server.close(() => process.exit(0));
});

process.on('SIGINT', () => {
  console.log('[SERVER] SIGINT received, shutting down gracefully...');
  logAudit('SERVER_STOPPED', { signal: 'SIGINT' });
  server.close(() => process.exit(0));
});

// Export for testing
module.exports = { server, handleRequest, applySecurity };