/**
 * YINITECH SECURITY - Server-side Middleware (Node.js/Bun)
 * Use with Express, Fastify, Hono, or native HTTP server
 */

const crypto = require('crypto');

// Security configuration
const SERVER_SECURITY_CONFIG = {
  // HMAC secret for request signing (set via env)
  hmacSecret: process.env.SECURITY_HMAC_SECRET || 'yinitech-hmac-secret-2026-change-in-production',

  // Rate limiting storage (use Redis in production)
  rateLimitStore: new Map(),

  // Blocked IPs
  blockedIPs: new Set(),

  // Suspicious activity tracking
  suspiciousActivity: new Map(),

  // Audit logs
  auditLogs: [],

  // Approved gateways
  approvedGateways: [
    'binance',
    'lead_bank',
    'openpayd',
    'banco_mercantil',
    'wallbit',
    'safepal',
    'whop',
    'vitawallet'
  ],

  // Rate limits
  rateLimits: {
    global: { requests: 100, windowMs: 60000 },
    checkout: { requests: 5, windowMs: 60000 },
    search: { requests: 30, windowMs: 60000 },
    api: { requests: 60, windowMs: 60000 }
  },

  // WAF patterns
  wafPatterns: {
    sqlInjection: [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)/i,
      /(--|#|\/\*|\*\/)/,
      /(\bOR\b\s*\d+\s*=\s*\d+)/i
    ],
    xss: [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /on\w+\s*=/gi,
      /javascript:/gi
    ],
    pathTraversal: [
      /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)/i
    ],
    commandInjection: [
      /(eval\(|exec\(|system\(|shell_exec)/i,
      /(base64_decode|gzinflate|str_rot13)/i
    ]
  }
};

// ============================================
// UTILITY FUNCTIONS
// ============================================

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-real-ip'] ||
         req.ip ||
         req.connection?.remoteAddress ||
         'unknown';
}

function getRateLimitKey(req, category) {
  const ip = getClientIP(req);
  return `${category}:${ip}`;
}

function checkRateLimit(key, category = 'global') {
  const limit = SERVER_SECURITY_CONFIG.rateLimits[category] || SERVER_SECURITY_CONFIG.rateLimits.global;
  const now = Date.now();
  const windowStart = now - limit.windowMs;

  let requests = SERVER_SECURITY_CONFIG.rateLimitStore.get(key) || [];
  requests = requests.filter(t => t > windowStart);

  if (requests.length >= limit.requests) {
    return { allowed: false, remaining: 0, resetAt: requests[0] + limit.windowMs, limit: limit.requests };
  }

  requests.push(now);
  SERVER_SECURITY_CONFIG.rateLimitStore.set(key, requests);

  return { allowed: true, remaining: limit.requests - requests.length, resetAt: now + limit.windowMs, limit: limit.requests };
}

function scanInput(input) {
  const threats = [];
  const str = typeof input === 'string' ? input : JSON.stringify(input);

  // Check all WAF patterns
  for (const [category, patterns] of Object.entries(SERVER_SECURITY_CONFIG.wafPatterns)) {
    for (const pattern of patterns) {
      if (pattern.test(str)) {
        threats.push({ type: category.toUpperCase(), pattern: pattern.toString(), match: str.substring(0, 100) });
      }
    }
  }

  return { clean: threats.length === 0, threats };
}

function verifyHMAC(data, signature, secret) {
  const expected = crypto.createHmac('sha256', secret).update(data).digest('hex');
  // timingSafeEqual requires same length buffers
  if (expected.length !== signature.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

function signHMAC(data, secret) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

function logAudit(event, data) {
  const entry = {
    timestamp: new Date().toISOString(),
    event,
    data: sanitizeData(data),
    severity: getSeverity(event)
  };

  SERVER_SECURITY_CONFIG.auditLogs.push(entry);
  if (SERVER_SECURITY_CONFIG.auditLogs.length > 10000) {
    SERVER_SECURITY_CONFIG.auditLogs.shift();
  }

  // Console output for critical events
  if (entry.severity === 'critical' || entry.severity === 'high') {
    console.error('[SECURITY AUDIT]', entry);
  } else if (entry.severity === 'medium') {
    console.warn('[SECURITY AUDIT]', entry);
  }

  return entry;
}

function sanitizeData(data) {
  const sanitized = { ...data };
  const sensitiveKeys = ['password', 'token', 'secret', 'key', 'card', 'cvv', 'ssn', 'hmac', 'signature'];
  for (const key of Object.keys(sanitized)) {
    if (sensitiveKeys.some(k => key.toLowerCase().includes(k))) {
      sanitized[key] = '[REDACTED]';
    }
  }
  return sanitized;
}

function getSeverity(event) {
  const critical = ['purchase_completed', 'payment_received', 'SQL_INJECTION', 'XSS_ATTEMPT', 'COMMAND_INJECTION'];
  const high = ['access_denied', 'rate_limit_exceeded', 'waf_blocked', 'suspicious_activity', 'IP_BLOCKED', 'INVALID_SIGNATURE'];
  const medium = ['purchase_initiated', 'purchase_failed', 'config_change'];

  if (critical.some(e => event.includes(e))) return 'critical';
  if (high.some(e => event.includes(e))) return 'high';
  if (medium.some(e => event.includes(e))) return 'medium';
  return 'low';
}

// ============================================
// MAIN SECURITY MIDDLEWARE
// ============================================

function securityMiddleware(options = {}) {
  const {
    category = 'global',
    permission = 'view_products',
    resource = 'products',
    requireHMAC = false,
    skipPaths = ['/health', '/favicon.ico']
  } = options;

  return async function(req, res, next) {
    const startTime = Date.now();
    const requestId = req.headers['x-request-id'] || crypto.randomBytes(8).toString('hex');
    const clientIP = getClientIP(req);

    // Add request ID to response
    res.setHeader('X-Request-ID', requestId);

    // Skip security for excluded paths
    if (skipPaths.some(p => req.url.startsWith(p))) {
      return next();
    }

    // CAPA 1: Pre-flight validation
    const preflightErrors = [];

    // Check method
    const allowedMethods = ['GET', 'POST', 'OPTIONS'];
    if (!allowedMethods.includes(req.method)) {
      preflightErrors.push(`METHOD_NOT_ALLOWED: ${req.method}`);
    }

    // Check content type for POST
    if (req.method === 'POST') {
      const contentType = req.headers['content-type'] || '';
      const allowedTypes = ['application/json', 'application/x-www-form-urlencoded'];
      if (!allowedTypes.some(t => contentType.includes(t))) {
        preflightErrors.push(`INVALID_CONTENT_TYPE: ${contentType}`);
      }
    }

    // Check payload size
    const contentLength = parseInt(req.headers['content-length'] || '0');
    if (contentLength > 1024 * 1024) { // 1MB
      preflightErrors.push(`PAYLOAD_TOO_LARGE: ${contentLength} bytes`);
    }

    // Check required headers
    const requiredHeaders = ['x-request-id', 'x-client-fingerprint'];
    for (const header of requiredHeaders) {
      if (!req.headers[header] && req.method !== 'GET') {
        preflightErrors.push(`MISSING_HEADER: ${header}`);
      }
    }

    if (preflightErrors.length > 0) {
      logAudit('PREFLIGHT_FAILED', { requestId, ip: clientIP, errors: preflightErrors, url: req.url });
      return res.status(400).json({ error: 'PREFLIGHT_FAILED', details: preflightErrors });
    }

    // CAPA 4: IP Blocking check
    if (SERVER_SECURITY_CONFIG.blockedIPs.has(clientIP)) {
      logAudit('BLOCKED_IP_ATTEMPT', { requestId, ip: clientIP, url: req.url });
      return res.status(403).json({ error: 'ACCESS_DENIED', reason: 'IP_BLOCKED' });
    }

    // CAPA 4: Rate limiting
    const rateLimitKey = getRateLimitKey(req, category);
    const rateLimit = checkRateLimit(rateLimitKey, category);

    res.setHeader('X-RateLimit-Limit', rateLimit.limit);
    res.setHeader('X-RateLimit-Remaining', rateLimit.remaining);
    res.setHeader('X-RateLimit-Reset', Math.ceil(rateLimit.resetAt / 1000));

    if (!rateLimit.allowed) {
      logAudit('RATE_LIMIT_EXCEEDED', { requestId, ip: clientIP, category, url: req.url, ...rateLimit });
      return res.status(429).json({
        error: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil((rateLimit.resetAt - Date.now()) / 1000)
      });
    }

    // CAPA 4: WAF scan on request body
    if (req.method === 'POST' && req.body) {
      const wafResult = scanInput(req.body);
      if (!wafResult.clean) {
        logAudit('WAF_BLOCKED', { requestId, ip: clientIP, url: req.url, threats: wafResult.threats });
        return res.status(400).json({ error: 'REQUEST_BLOCKED', reason: 'MALICIOUS_INPUT_DETECTED' });
      }
    }

    // CAPA 5: HMAC verification for sensitive endpoints
    if (requireHMAC && req.headers['x-signature']) {
      const body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {});
      const valid = verifyHMAC(body, req.headers['x-signature'], SERVER_SECURITY_CONFIG.hmacSecret);

      if (!valid) {
        logAudit('INVALID_SIGNATURE', { requestId, ip: clientIP, url: req.url });
        return res.status(401).json({ error: 'INVALID_SIGNATURE' });
      }
    }

    // CAPA 2: Privilege check (simplified - in production use proper auth)
    // This would integrate with your auth system
    const userRole = req.user?.role || 'anonymous';
    const privileges = {
      anonymous: ['view_products', 'view_categories', 'initiate_checkout'],
      buyer: ['view_products', 'view_categories', 'initiate_checkout', 'complete_purchase', 'download_product'],
      admin: ['*']
    };

    const userPrivileges = privileges[userRole] || privileges.anonymous;
    if (!userPrivileges.includes('*') && !userPrivileges.includes(permission)) {
      logAudit('ACCESS_DENIED', { requestId, ip: clientIP, permission, resource, role: userRole, url: req.url });
      return res.status(403).json({ error: 'INSUFFICIENT_PRIVILEGES', required: permission });
    }

    // CAPA 6: Audit logging
    logAudit('REQUEST_ALLOWED', {
      requestId,
      ip: clientIP,
      method: req.method,
      url: req.url,
      userRole,
      duration: Date.now() - startTime
    });

    // Add security context to request
    req.security = {
      requestId,
      clientIP,
      userRole,
      rateLimit
    };

    next();
  };
}

// ============================================
// SPECIFIC MIDDLEWARES
// ============================================

// Checkout endpoint security
const checkoutSecurity = securityMiddleware({
  category: 'checkout',
  permission: 'initiate_checkout',
  resource: 'orders',
  requireHMAC: true
});

// API security
const apiSecurity = securityMiddleware({
  category: 'api',
  permission: 'view_products',
  resource: 'products'
});

// Admin security
const adminSecurity = securityMiddleware({
  category: 'api',
  permission: 'admin_access',
  resource: 'users',
  requireHMAC: true
});

// ============================================
// PAYMENT VALIDATION
// ============================================

function validatePaymentRequest(paymentData) {
  const { gateway, amount, currency, productId } = paymentData;

  if (!SERVER_SECURITY_CONFIG.approvedGateways.includes(gateway)) {
    return { valid: false, reason: 'UNAPPROVED_GATEWAY' };
  }

  const gatewayConfigs = {
    binance: { currencies: ['USDT', 'BTC', 'ETH', 'BNB'] },
    lead_bank: { currencies: ['USD'] },
    openpayd: { currencies: ['EUR', 'GBP', 'USD'] },
    banco_mercantil: { currencies: ['BOB'] },
    wallbit: { currencies: ['USD'] },
    safepal: { currencies: ['USDT', 'BTC', 'ETH', 'BNB'] },
    whop: { currencies: ['USD'] },
    vitawallet: { currencies: ['USD'] }
  };

  const config = gatewayConfigs[gateway];
  if (!config || !config.currencies.includes(currency)) {
    return { valid: false, reason: 'CURRENCY_NOT_SUPPORTED' };
  }

  // Validate amount (base price $6.99 USD)
  if (Math.abs(amount - 6.99) > 0.01) {
    return { valid: false, reason: 'AMOUNT_MISMATCH' };
  }

  return { valid: true };
}

// ============================================
// PRODUCT RESTRICTIONS
// ============================================

const productRestrictions = {
  noSharing: true,
  noCopying: true,
  durabilityDays: 30,
  noDisclosure: true,
  singlePurchase: true,
  additionalPurchasesAllowed: true,
  oneAtATimeOrBulk: true
};

const purchaseHistory = new Map(); // In production, use database

function canPurchase(userId, productId) {
  const history = purchaseHistory.get(userId) || new Set();

  if (productRestrictions.singlePurchase && history.has(productId)) {
    return { allowed: false, reason: 'PRODUCT_ALREADY_PURCHASED' };
  }

  if (!productRestrictions.additionalPurchasesAllowed && history.size > 0) {
    return { allowed: false, reason: 'NO_ADDITIONAL_PURCHASES' };
  }

  return { allowed: true };
}

function recordPurchase(userId, productId, data) {
  if (!purchaseHistory.has(userId)) {
    purchaseHistory.set(userId, new Set());
  }
  purchaseHistory.get(userId).add(productId);

  logAudit('purchase_completed', { userId, productId, ...data });
}

function generateDeliveryToken(productId, userId) {
  const timestamp = Date.now();
  const expiry = timestamp + (productRestrictions.durabilityDays * 24 * 60 * 60 * 1000);

  return {
    productId,
    userId,
    issuedAt: timestamp,
    expiresAt: expiry,
    restrictions: {
      noSharing: productRestrictions.noSharing,
      noCopying: productRestrictions.noCopying,
      noDisclosure: productRestrictions.noDisclosure,
      maxDownloads: 1
    },
    signature: signHMAC(`${productId}:${userId}:${timestamp}:${expiry}`, SERVER_SECURITY_CONFIG.hmacSecret)
  };
}

function validateDeliveryToken(token) {
  const now = Date.now();

  if (now > token.expiresAt) {
    return { valid: false, reason: 'TOKEN_EXPIRED' };
  }

  const expectedSig = signHMAC(`${token.productId}:${token.userId}:${token.issuedAt}:${token.expiresAt}`, SERVER_SECURITY_CONFIG.hmacSecret);
  if (!crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(token.signature))) {
    return { valid: false, reason: 'INVALID_TOKEN_SIGNATURE' };
  }

  return { valid: true };
}

// ============================================
// INCIDENT RESPONSE
// ============================================

const systemSnapshots = [];
const circuitBreakers = new Map();

function createSnapshot(state) {
  const snapshot = {
    id: `snap_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
    timestamp: new Date().toISOString(),
    state: JSON.parse(JSON.stringify(state)),
    checksum: crypto.createHash('sha256').update(JSON.stringify(state)).digest('hex')
  };

  systemSnapshots.push(snapshot);
  if (systemSnapshots.length > 10) systemSnapshots.shift();

  return snapshot.id;
}

function rollbackToSnapshot(snapshotId) {
  const snapshot = systemSnapshots.find(s => s.id === snapshotId);
  if (!snapshot) throw new Error('SNAPSHOT_NOT_FOUND');

  const currentChecksum = crypto.createHash('sha256').update(JSON.stringify(snapshot.state)).digest('hex');
  if (currentChecksum !== snapshot.checksum) {
    throw new Error('SNAPSHOT_CORRUPTED');
  }

  logAudit('ROLLBACK_INITIATED', { targetSnapshot: snapshotId });
  return snapshot.state;
}

function getCircuitBreaker(serviceName) {
  if (!circuitBreakers.has(serviceName)) {
    circuitBreakers.set(serviceName, {
      state: 'closed',
      failures: 0,
      lastFailure: null,
      nextAttempt: null,
      halfOpenSuccesses: 0
    });
  }
  return circuitBreakers.get(serviceName);
}

async function executeWithCircuitBreaker(serviceName, fn) {
  const cb = getCircuitBreaker(serviceName);
  const config = { failureThreshold: 5, resetTimeout: 60000, halfOpenRequests: 3 };

  if (cb.state === 'open') {
    if (Date.now() > cb.nextAttempt) {
      cb.state = 'half-open';
      cb.halfOpenSuccesses = 0;
    } else {
      throw new Error(`CIRCUIT_OPEN: ${serviceName}`);
    }
  }

  try {
    const result = await fn();

    if (cb.state === 'half-open') {
      cb.halfOpenSuccesses++;
      if (cb.halfOpenSuccesses >= config.halfOpenRequests) {
        cb.state = 'closed';
        cb.failures = 0;
      }
    } else {
      cb.failures = 0;
    }

    return result;
  } catch (error) {
    cb.failures++;
    cb.lastFailure = Date.now();

    if (cb.failures >= config.failureThreshold) {
      cb.state = 'open';
      cb.nextAttempt = Date.now() + config.resetTimeout;
      logAudit('CIRCUIT_BREAKER_OPENED', { service: serviceName });
    }

    throw error;
  }
}

// ============================================
// HEALTH CHECK
// ============================================

function healthCheck() {
  return {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    security: {
      rateLimitStoreSize: SERVER_SECURITY_CONFIG.rateLimitStore.size,
      blockedIPs: SERVER_SECURITY_CONFIG.blockedIPs.size,
      auditLogs: SERVER_SECURITY_CONFIG.auditLogs.length,
      snapshots: systemSnapshots.length,
      circuitBreakers: Object.fromEntries(
        Array.from(circuitBreakers.entries()).map(([k, v]) => [k, v.state])
      )
    }
  };
}

// ============================================
// EXPORTS
// ============================================

module.exports = {
  securityMiddleware,
  checkoutSecurity,
  apiSecurity,
  adminSecurity,
  validatePaymentRequest,
  canPurchase,
  recordPurchase,
  generateDeliveryToken,
  validateDeliveryToken,
  createSnapshot,
  rollbackToSnapshot,
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
};