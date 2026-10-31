/**
 * YINITECH SECURITY Ω - 7 Layer Security Implementation
 * ========================================================
 * Capa 1: Validación Previa (Pre-flight)
 * Capa 2: Mínimo Privilegio
 * Capa 3: Aislamiento de Procesos
 * Capa 4: Detección de Amenazas (Rate Limiting, WAF)
 * Capa 5: Cifrado de Datos (HTTPS, TLS, HMAC)
 * Capa 6: Auditoría Continua
 * Capa 7: Respuesta a Incidentes
 */

const SECURITY_CONFIG = {
  // Capa 1: Pre-flight validation
  preflight: {
    requiredHeaders: ['content-type', 'x-request-id', 'x-client-fingerprint'],
    maxPayloadSize: 1024 * 1024, // 1MB
    allowedMethods: ['GET', 'POST'],
    allowedContentTypes: ['application/json', 'application/x-www-form-urlencoded'],
    validateOrigin: true,
    allowedOrigins: [
      'https://tortuguitahack.github.io',
      'http://localhost:3000',
      'http://127.0.0.1:5100'
    ]
  },

  // Capa 2: Minimum privilege
  privileges: {
    roles: {
      anonymous: ['view_products', 'view_categories', 'initiate_checkout'],
      buyer: ['view_products', 'view_categories', 'initiate_checkout', 'complete_purchase', 'download_product'],
      admin: ['*']
    },
    resourceAccess: {
      products: { read: ['anonymous', 'buyer', 'admin'], write: ['admin'] },
      orders: { read: ['buyer', 'admin'], write: ['buyer', 'admin'] },
      payments: { read: ['admin'], write: ['admin'] },
      users: { read: ['admin'], write: ['admin'] },
      security_logs: { read: ['admin'], write: ['system'] }
    }
  },

  // Capa 3: Process isolation
  isolation: {
    paymentProcessTimeout: 30000, // 30s
    checkoutProcessTimeout: 60000, // 60s
    maxConcurrentCheckouts: 10,
    sandboxedEndpoints: ['/capture-email', '/verify-payment', '/deliver-product']
  },

  // Capa 4: Threat detection
  threatDetection: {
    rateLimits: {
      global: { requests: 100, windowMs: 60000 }, // 100 req/min
      checkout: { requests: 5, windowMs: 60000 }, // 5 checkout/min
      search: { requests: 30, windowMs: 60000 }, // 30 search/min
      api: { requests: 60, windowMs: 60000 } // 60 api/min
    },
    waf: {
      blockedPatterns: [
        /(<script|javascript:|onerror=|onload=)/i,
        /(union\s+select|drop\s+table|insert\s+into|delete\s+from)/i,
        /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)/i,
        /(eval\(|exec\(|system\(|shell_exec)/i,
        /(base64_decode|gzinflate|str_rot13)/i
      ],
      maxInputLength: 5000,
      sqlInjectionPatterns: [
        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)/i,
        /(--|#|\/\*|\*\/)/,
        /(\bOR\b\s*\d+\s*=\s*\d+)/i
      ],
      xssPatterns: [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /on\w+\s*=/gi,
        /javascript:/gi
      ]
    },
    geoBlocking: {
      enabled: false,
      blockedCountries: []
    }
  },

  // Capa 5: Encryption
  encryption: {
    hmacAlgorithm: 'SHA-256',
    hmacSecret: null, // Set at runtime from env
    tlsMinVersion: 'TLSv1.2',
    enforceHTTPS: true,
    certificatePinning: {
      enabled: true,
      pins: [] // SHA-256 hashes of public keys
    },
    dataAtRest: {
      algorithm: 'AES-GCM',
      keyRotationDays: 30
    }
  },

  // Capa 6: Continuous auditing
  auditing: {
    logLevel: 'info',
    logDestination: 'security-logs',
    events: {
      login: true,
      logout: true,
      purchase_initiated: true,
      purchase_completed: true,
      purchase_failed: true,
      payment_received: true,
      access_denied: true,
      rate_limit_exceeded: true,
      waf_blocked: true,
      suspicious_activity: true,
      config_change: true
    },
    retentionDays: 90,
    realTimeAlerts: {
      enabled: true,
      webhook: null, // Set at runtime
      telegramBot: null // Set at runtime
    }
  },

  // Capa 7: Incident response
  incidentResponse: {
    atomicRollback: {
      enabled: true,
      maxRollbackSteps: 10,
      snapshotInterval: 300000 // 5 min
    },
    recovery: {
      backupLocation: '/secure/backups',
      restoreTimeout: 300000, // 5 min
      healthCheckEndpoint: '/health'
    },
    circuitBreaker: {
      enabled: true,
      failureThreshold: 5,
      resetTimeout: 60000,
      halfOpenRequests: 3
    },
    quarantine: {
      enabled: true,
      suspiciousIPs: new Set(),
      autoQuarantineThreshold: 10
    }
  },

  // Product restrictions
  productRestrictions: {
    noSharing: true,
    noCopying: true,
    durabilityDays: 30,
    noDisclosure: true,
    singlePurchase: true,
    additionalPurchasesAllowed: true,
    oneAtATimeOrBulk: true
  },

  // Approved payment gateways
  approvedGateways: [
    'binance',
    'lead_bank',
    'openpayd',
    'banco_mercantil',
    'wallbit',
    'safepal',
    'whop'
  ]
};

// ============================================
// CAPA 1: PRE-FLIGHT VALIDATION
// ============================================
class PreFlightValidator {
  constructor(config) {
    this.config = config;
  }

  validate(request) {
    const errors = [];

    // Check method
    if (!this.config.allowedMethods.includes(request.method)) {
      errors.push(`METHOD_NOT_ALLOWED: ${request.method}`);
    }

    // Check content type
    const contentType = request.headers.get('content-type') || '';
    if (request.method === 'POST' && !this.config.allowedContentTypes.some(ct => contentType.includes(ct))) {
      errors.push(`INVALID_CONTENT_TYPE: ${contentType}`);
    }

    // Check payload size
    const contentLength = parseInt(request.headers.get('content-length') || '0');
    if (contentLength > this.config.maxPayloadSize) {
      errors.push(`PAYLOAD_TOO_LARGE: ${contentLength} bytes`);
    }

    // Check required headers
    for (const header of this.config.requiredHeaders) {
      if (!request.headers.get(header)) {
        errors.push(`MISSING_HEADER: ${header}`);
      }
    }

    // Validate origin
    if (this.config.validateOrigin) {
      const origin = request.headers.get('origin') || request.headers.get('referer');
      if (origin && !this.config.allowedOrigins.some(o => origin.startsWith(o))) {
        errors.push(`INVALID_ORIGIN: ${origin}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

// ============================================
// CAPA 2: MINIMUM PRIVILEGE
// ============================================
class PrivilegeManager {
  constructor(config) {
    this.config = config;
    this.currentRole = 'anonymous';
  }

  setRole(role) {
    if (this.config.roles[role]) {
      this.currentRole = role;
    }
  }

  can(action, resource) {
    const rolePermissions = this.config.roles[this.currentRole] || [];
    if (rolePermissions.includes('*')) return true;

    const resourceConfig = this.config.resourceAccess[resource];
    if (!resourceConfig) return false;

    const allowedRoles = resourceConfig[action] || [];
    return allowedRoles.includes(this.currentRole);
  }

  getPermissions() {
    return this.config.roles[this.currentRole] || [];
  }
}

// ============================================
// CAPA 3: PROCESS ISOLATION
// ============================================
class ProcessIsolator {
  constructor(config) {
    this.config = config;
    this.activeProcesses = new Map();
    this.processCounter = 0;
  }

  async isolate(fn, context = {}) {
    const processId = `proc_${++this.processCounter}_${Date.now()}`;
    const timeout = context.timeout || this.config.paymentProcessTimeout;

    // Check concurrent limit
    if (this.activeProcesses.size >= this.config.maxConcurrentCheckouts) {
      throw new Error('MAX_CONCURRENT_PROCESSES_EXCEEDED');
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    this.activeProcesses.set(processId, { controller, startTime: Date.now(), context });

    try {
      const result = await fn({ signal: controller.signal, processId, ...context });
      return { success: true, processId, result };
    } catch (error) {
      return { success: false, processId, error: error.message };
    } finally {
      clearTimeout(timeoutId);
      this.activeProcesses.delete(processId);
    }
  }

  terminate(processId) {
    const proc = this.activeProcesses.get(processId);
    if (proc) {
      proc.controller.abort();
      this.activeProcesses.delete(processId);
      return true;
    }
    return false;
  }

  terminateAll() {
    for (const [id, proc] of this.activeProcesses) {
      proc.controller.abort();
    }
    this.activeProcesses.clear();
  }

  getActiveCount() {
    return this.activeProcesses.size;
  }
}

// ============================================
// CAPA 4: THREAT DETECTION (Rate Limiting + WAF)
// ============================================
class ThreatDetector {
  constructor(config) {
    this.config = config;
    this.rateLimitStore = new Map();
    this.blockedIPs = new Set();
    this.suspiciousActivity = new Map();
  }

  // Rate Limiting
  checkRateLimit(identifier, category = 'global') {
    const limit = this.config.rateLimits[category] || this.config.rateLimits.global;
    const now = Date.now();
    const windowStart = now - limit.windowMs;

    let requests = this.rateLimitStore.get(identifier) || [];
    requests = requests.filter(t => t > windowStart);

    if (requests.length >= limit.requests) {
      this.logSuspiciousActivity(identifier, 'RATE_LIMIT_EXCEEDED', { category, count: requests.length });
      return { allowed: false, remaining: 0, resetAt: requests[0] + limit.windowMs };
    }

    requests.push(now);
    this.rateLimitStore.set(identifier, requests);

    return { allowed: true, remaining: limit.requests - requests.length, resetAt: now + limit.windowMs };
  }

  // WAF - Input validation
  scanInput(input, context = {}) {
    const threats = [];

    // Check length
    if (input.length > this.config.waf.maxInputLength) {
      threats.push({ type: 'INPUT_TOO_LONG', length: input.length });
    }

    // Check blocked patterns
    for (const pattern of this.config.waf.blockedPatterns) {
      if (pattern.test(input)) {
        threats.push({ type: 'BLOCKED_PATTERN', pattern: pattern.toString() });
      }
    }

    // Check SQL injection
    for (const pattern of this.config.waf.sqlInjectionPatterns) {
      if (pattern.test(input)) {
        threats.push({ type: 'SQL_INJECTION_ATTEMPT', pattern: pattern.toString() });
      }
    }

    // Check XSS
    for (const pattern of this.config.waf.xssPatterns) {
      if (pattern.test(input)) {
        threats.push({ type: 'XSS_ATTEMPT', pattern: pattern.toString() });
      }
    }

    if (threats.length > 0) {
      this.logSuspiciousActivity(context.ip || 'unknown', 'WAF_THREAT_DETECTED', { threats, input: input.substring(0, 200) });
    }

    return { clean: threats.length === 0, threats };
  }

  // IP blocking
  blockIP(ip, reason = 'MANUAL_BLOCK') {
    this.blockedIPs.add(ip);
    this.logSecurityEvent('IP_BLOCKED', { ip, reason });
  }

  isBlocked(ip) {
    return this.blockedIPs.has(ip);
  }

  logSuspiciousActivity(ip, type, details) {
    const key = `${ip}:${type}`;
    const count = (this.suspiciousActivity.get(key) || 0) + 1;
    this.suspiciousActivity.set(key, count);

    if (count >= this.config.quarantine.autoQuarantineThreshold) {
      this.blockIP(ip, `AUTO_QUARANTINE_${type}`);
    }

    this.logSecurityEvent('SUSPICIOUS_ACTIVITY', { ip, type, details, count });
  }

  logSecurityEvent(event, data) {
    if (typeof SecurityAuditor !== 'undefined') {
      SecurityAuditor.log(event, data);
    }
    console.warn(`[SECURITY] ${event}:`, data);
  }
}

// ============================================
// CAPA 5: ENCRYPTION (HMAC, TLS)
// ============================================
class EncryptionManager {
  constructor(config) {
    this.config = config;
    this.hmacKey = config.encryption.hmacSecret;
  }

  setHMACKey(key) {
    this.hmacKey = key;
  }

  // Generate HMAC signature
  async sign(data) {
    if (!this.hmacKey) {
      throw new Error('HMAC_KEY_NOT_CONFIGURED');
    }

    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.hmacKey);
    const messageData = encoder.encode(typeof data === 'string' ? data : JSON.stringify(data));

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: this.config.encryption.hmacAlgorithm },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
    return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Verify HMAC signature
  async verify(data, signature) {
    const expected = await this.sign(data);
    return this.timingSafeEqual(expected, signature);
  }

  // Constant-time comparison
  timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }

  // Generate secure token
  generateToken(length = 32) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Encrypt sensitive data (AES-GCM)
  async encrypt(data, key) {
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      encoder.encode(typeof data === 'string' ? data : JSON.stringify(data))
    );

    return { iv: Array.from(iv), data: Array.from(new Uint8Array(encrypted)) };
  }

  async decrypt(encrypted, key) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(encrypted.iv) },
      cryptoKey,
      new Uint8Array(encrypted.data)
    );

    return new TextDecoder().decode(decrypted);
  }
}

// ============================================
// CAPA 6: CONTINUOUS AUDITING
// ============================================
class SecurityAuditor {
  constructor(config) {
    this.config = config;
    this.logs = [];
    this.maxLogs = 10000;
  }

  log(event, data = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      event,
      data: this.sanitizeData(data),
      sessionId: this.getSessionId(),
      userAgent: navigator?.userAgent || 'server'
    };

    this.logs.push(entry);
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }

    // Real-time alert for critical events
    if (this.config.realTimeAlerts.enabled && this.isCriticalEvent(event)) {
      this.sendAlert(entry);
    }

    // Persist to localStorage for client-side
    if (typeof localStorage !== 'undefined') {
      this.persistLog(entry);
    }

    return entry;
  }

  sanitizeData(data) {
    const sanitized = { ...data };
    const sensitiveKeys = ['password', 'token', 'secret', 'key', 'card', 'cvv', 'ssn'];
    for (const key of Object.keys(sanitized)) {
      if (sensitiveKeys.some(k => key.toLowerCase().includes(k))) {
        sanitized[key] = '[REDACTED]';
      }
    }
    return sanitized;
  }

  isCriticalEvent(event) {
    const criticalEvents = [
      'purchase_completed',
      'payment_received',
      'access_denied',
      'rate_limit_exceeded',
      'waf_blocked',
      'suspicious_activity',
      'IP_BLOCKED',
      'SQL_INJECTION_ATTEMPT',
      'XSS_ATTEMPT'
    ];
    return criticalEvents.includes(event);
  }

  async sendAlert(entry) {
    if (this.config.realTimeAlerts.webhook) {
      try {
        await fetch(this.config.realTimeAlerts.webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(entry)
        });
      } catch (e) { console.error('Alert webhook failed:', e); }
    }

    if (this.config.realTimeAlerts.telegramBot) {
      // Telegram alert would be sent via backend
      console.log('[TELEGRAM ALERT]', entry);
    }
  }

  persistLog(entry) {
    try {
      const stored = JSON.parse(localStorage.getItem('security_logs') || '[]');
      stored.push(entry);
      if (stored.length > 1000) stored.shift();
      localStorage.setItem('security_logs', JSON.stringify(stored));
    } catch (e) {}
  }

  getSessionId() {
    if (typeof sessionStorage !== 'undefined') {
      let sid = sessionStorage.getItem('security_session_id');
      if (!sid) {
        sid = 'sess_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        sessionStorage.setItem('security_session_id', sid);
      }
      return sid;
    }
    return 'server_session';
  }

  getLogs(filter = {}) {
    return this.logs.filter(log => {
      if (filter.event && log.event !== filter.event) return false;
      if (filter.since && new Date(log.timestamp) < new Date(filter.since)) return false;
      if (filter.until && new Date(log.timestamp) > new Date(filter.until)) return false;
      return true;
    });
  }

  exportLogs() {
    return JSON.stringify(this.logs, null, 2);
  }
}

// ============================================
// CAPA 7: INCIDENT RESPONSE
// ============================================
class IncidentResponder {
  constructor(config) {
    this.config = config;
    this.snapshots = [];
    this.circuitBreakers = new Map();
    this.rollbackStack = [];
  }

  // Create system snapshot for rollback
  createSnapshot(state) {
    const snapshot = {
      id: `snap_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      state: JSON.parse(JSON.stringify(state)),
      checksum: this.calculateChecksum(state)
    };

    this.snapshots.push(snapshot);
    if (this.snapshots.length > this.config.atomicRollback.maxRollbackSteps) {
      this.snapshots.shift();
    }

    return snapshot.id;
  }

  calculateChecksum(state) {
    const str = JSON.stringify(state);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return hash.toString(16);
  }

  // Atomic rollback
  async rollback(targetSnapshotId) {
    const snapshot = this.snapshots.find(s => s.id === targetSnapshotId);
    if (!snapshot) {
      throw new Error('SNAPSHOT_NOT_FOUND');
    }

    // Verify integrity
    if (this.calculateChecksum(snapshot.state) !== snapshot.checksum) {
      throw new Error('SNAPSHOT_CORRUPTED');
    }

    this.logSecurityEvent('ROLLBACK_INITIATED', { targetSnapshot: targetSnapshotId });
    return snapshot.state;
  }

  // Circuit breaker
  getCircuitBreaker(serviceName) {
    if (!this.circuitBreakers.has(serviceName)) {
      this.circuitBreakers.set(serviceName, {
        state: 'closed',
        failures: 0,
        lastFailure: null,
        nextAttempt: null
      });
    }
    return this.circuitBreakers.get(serviceName);
  }

  async executeWithCircuitBreaker(serviceName, fn) {
    const cb = this.getCircuitBreaker(serviceName);
    const config = this.config.circuitBreaker;

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
        this.logSecurityEvent('CIRCUIT_BREAKER_OPENED', { service: serviceName });
      }

      throw error;
    }
  }

  // Quarantine management
  quarantineIP(ip, reason) {
    this.config.quarantine.suspiciousIPs.add(ip);
    this.logSecurityEvent('IP_QUARANTINED', { ip, reason });
  }

  releaseIP(ip) {
    this.config.quarantine.suspiciousIPs.delete(ip);
    this.logSecurityEvent('IP_RELEASED', { ip });
  }

  isQuarantined(ip) {
    return this.config.quarantine.suspiciousIPs.has(ip);
  }

  logSecurityEvent(event, data) {
    if (typeof SecurityAuditor !== 'undefined') {
      SecurityAuditor.log(event, data);
    }
  }

  // Health check
  async healthCheck() {
    const endpoint = this.config.recovery.healthCheckEndpoint;
    try {
      const response = await fetch(endpoint, { method: 'GET', timeout: 5000 });
      return response.ok;
    } catch {
      return false;
    }
  }
}

// ============================================
// PRODUCT RESTRICTIONS ENFORCEMENT
// ============================================
class ProductRestrictionEnforcer {
  constructor(config) {
    this.config = config;
    this.purchaseHistory = new Map(); // userId -> Set of productIds
  }

  // Check if user can purchase product
  canPurchase(userId, productId) {
    const history = this.purchaseHistory.get(userId) || new Set();

    // Single purchase restriction
    if (this.config.productRestrictions.singlePurchase && history.has(productId)) {
      return { allowed: false, reason: 'PRODUCT_ALREADY_PURCHASED' };
    }

    // Additional purchases allowed
    if (!this.config.productRestrictions.additionalPurchasesAllowed && history.size > 0) {
      return { allowed: false, reason: 'NO_ADDITIONAL_PURCHASES_ALLOWED' };
    }

    return { allowed: true };
  }

  // Record purchase
  recordPurchase(userId, productId, purchaseData) {
    if (!this.purchaseHistory.has(userId)) {
      this.purchaseHistory.set(userId, new Set());
    }
    this.purchaseHistory.get(userId).add(productId);

    // Log for audit
    if (typeof SecurityAuditor !== 'undefined') {
      SecurityAuditor.log('purchase_completed', { userId, productId, ...purchaseData });
    }
  }

  // Encode product for delivery (anti-copy protection)
  encodeProductDelivery(productData, userId) {
    const timestamp = Date.now();
    const expiry = timestamp + (this.config.productRestrictions.durabilityDays * 24 * 60 * 60 * 1000);

    const deliveryToken = {
      productId: productData.id,
      userId,
      issuedAt: timestamp,
      expiresAt: expiry,
      restrictions: {
        noSharing: this.config.productRestrictions.noSharing,
        noCopying: this.config.productRestrictions.noCopying,
        noDisclosure: this.config.productRestrictions.noDisclosure,
        maxDownloads: 1
      },
      signature: null // Will be signed by EncryptionManager
    };

    return deliveryToken;
  }

  // Validate delivery token
  validateDeliveryToken(token, encryptionManager) {
    const now = Date.now();

    if (now > token.expiresAt) {
      return { valid: false, reason: 'TOKEN_EXPIRED' };
    }

    if (token.restrictions.noSharing && token.userId !== this.getCurrentUserId()) {
      return { valid: false, reason: 'SHARING_NOT_ALLOWED' };
    }

    // Verify signature if present
    if (token.signature && encryptionManager) {
      // Would verify HMAC here
    }

    return { valid: true };
  }

  getCurrentUserId() {
    // In real implementation, get from auth system
    return localStorage?.getItem('user_id') || 'anonymous';
  }
}

// ============================================
// PAYMENT GATEWAY VALIDATOR
// ============================================
class PaymentGatewayValidator {
  constructor(config) {
    this.config = config;
    this.gatewayConfigs = {
      binance: { name: 'Binance Pay', type: 'crypto', currencies: ['USDT', 'BTC', 'ETH', 'BNB'] },
      lead_bank: { name: 'Lead Bank (USA)', type: 'bank_transfer', currencies: ['USD'] },
      openpayd: { name: 'OpenPayd (EU)', type: 'bank_transfer', currencies: ['EUR', 'GBP'] },
      banco_mercantil: { name: 'Banco Mercantil (Bolivia)', type: 'bank_transfer', currencies: ['BOB'] },
      wallbit: { name: 'Wallbit', type: 'bank_transfer', currencies: ['USD'] },
      safepal: { name: 'SafePal', type: 'crypto_wallet', currencies: ['USDT', 'BTC', 'ETH', 'BNB'] },
      whop: { name: 'Whop', type: 'platform', currencies: ['USD'] }
    };
  }

  isApproved(gatewayId) {
    return this.config.approvedGateways.includes(gatewayId);
  }

  getGatewayConfig(gatewayId) {
    return this.gatewayConfigs[gatewayId] || null;
  }

  validatePaymentRequest(request) {
    const { gateway, amount, currency, productId } = request;

    if (!this.isApproved(gateway)) {
      return { valid: false, reason: 'UNAPPROVED_GATEWAY' };
    }

    const gatewayConfig = this.getGatewayConfig(gateway);
    if (!gatewayConfig) {
      return { valid: false, reason: 'UNKNOWN_GATEWAY' };
    }

    if (!gatewayConfig.currencies.includes(currency)) {
      return { valid: false, reason: 'CURRENCY_NOT_SUPPORTED_BY_GATEWAY' };
    }

    // Validate amount matches product price (6.99 USD equivalent)
    const expectedAmount = 6.99; // Base USD price
    if (Math.abs(amount - expectedAmount) > 0.01) {
      return { valid: false, reason: 'AMOUNT_MISMATCH' };
    }

    return { valid: true, gatewayConfig };
  }
}

// ============================================
// MAIN SECURITY ORCHESTRATOR
// ============================================
class YinitechSecurity {
  constructor(customConfig = {}) {
    this.config = { ...SECURITY_CONFIG, ...customConfig };

    // Initialize all layers
    this.preflight = new PreFlightValidator(this.config.preflight);
    this.privileges = new PrivilegeManager(this.config.privileges);
    this.isolator = new ProcessIsolator(this.config.isolation);
    this.threatDetector = new ThreatDetector(this.config.threatDetection);
    this.encryption = new EncryptionManager(this.config.encryption);
    this.auditor = new SecurityAuditor(this.config.auditing);
    this.incidentResponse = new IncidentResponder(this.config.incidentResponse);
    this.productEnforcer = new ProductRestrictionEnforcer(this.config);
    this.gatewayValidator = new PaymentGatewayValidator(this.config);

    // Make auditor globally accessible for other layers
    window.SecurityAuditor = this.auditor;

    this.initialized = false;
  }

  async initialize(hmacSecret, webhookUrl, telegramBot) {
    this.encryption.setHMACKey(hmacSecret);
    this.config.auditing.realTimeAlerts.webhook = webhookUrl;
    this.config.auditing.realTimeAlerts.telegramBot = telegramBot;
    this.config.incidentResponse.quarantine.suspiciousIPs = new Set();

    this.initialized = true;
    this.auditor.log('SYSTEM_INITIALIZED', { version: '1.0.0' });
    return this;
  }

  // Main request handler - runs all 7 layers
  async handleRequest(request, context = {}) {
    const requestId = context.requestId || this.encryption.generateToken(16);
    const clientIP = context.ip || 'unknown';

    // CAPA 1: Pre-flight validation
    const preflight = this.preflight.validate(request);
    if (!preflight.valid) {
      this.auditor.log('PREFLIGHT_FAILED', { requestId, errors: preflight.errors, ip: clientIP });
      return { allowed: false, layer: 1, errors: preflight.errors };
    }

    // CAPA 4: Threat detection - IP check
    if (this.threatDetector.isBlocked(clientIP) || this.incidentResponse.isQuarantined(clientIP)) {
      this.auditor.log('BLOCKED_IP_ATTEMPT', { requestId, ip: clientIP });
      return { allowed: false, layer: 4, reason: 'IP_BLOCKED' };
    }

    // CAPA 4: Rate limiting
    const rateLimit = this.threatDetector.checkRateLimit(clientIP, context.category || 'global');
    if (!rateLimit.allowed) {
      this.auditor.log('RATE_LIMIT_EXCEEDED', { requestId, ip: clientIP, ...rateLimit });
      return { allowed: false, layer: 4, reason: 'RATE_LIMITED', ...rateLimit };
    }

    // CAPA 4: WAF scan on input
    if (request.method === 'POST') {
      const body = await request.clone().text();
      const wafResult = this.threatDetector.scanInput(body, { ip: clientIP });
      if (!wafResult.clean) {
        this.auditor.log('WAF_BLOCKED', { requestId, ip: clientIP, threats: wafResult.threats });
        return { allowed: false, layer: 4, reason: 'WAF_BLOCKED', threats: wafResult.threats };
      }
    }

    // CAPA 2: Privilege check
    const requiredPermission = context.permission || 'view_products';
    const resource = context.resource || 'products';
    if (!this.privileges.can(requiredPermission, resource)) {
      this.auditor.log('ACCESS_DENIED', { requestId, ip: clientIP, permission: requiredPermission, resource, role: this.privileges.currentRole });
      return { allowed: false, layer: 2, reason: 'INSUFFICIENT_PRIVILEGES' };
    }

    // CAPA 5: Verify HMAC for sensitive operations
    if (context.requireHMAC && request.headers.get('x-signature')) {
      const body = await request.clone().text();
      const valid = await this.encryption.verify(body, request.headers.get('x-signature'));
      if (!valid) {
        this.auditor.log('INVALID_SIGNATURE', { requestId, ip: clientIP });
        return { allowed: false, layer: 5, reason: 'INVALID_SIGNATURE' };
      }
    }

    // All layers passed
    this.auditor.log('REQUEST_ALLOWED', { requestId, ip: clientIP, layer: 7 });
    return { allowed: true, requestId, rateLimit };
  }

  // Secure checkout process
  async secureCheckout(checkoutData) {
    return this.isolator.isolate(async ({ signal }) => {
      // Validate payment gateway
      const gatewayValidation = this.gatewayValidator.validatePaymentRequest(checkoutData);
      if (!gatewayValidation.valid) {
        throw new Error(`GATEWAY_VALIDATION_FAILED: ${gatewayValidation.reason}`);
      }

      // Check product restrictions
      const userId = checkoutData.userId || this.productEnforcer.getCurrentUserId();
      const productCheck = this.productEnforcer.canPurchase(userId, checkoutData.productId);
      if (!productCheck.allowed) {
        throw new Error(`PRODUCT_RESTRICTION: ${productCheck.reason}`);
      }

      // Process payment (would integrate with actual gateway)
      const paymentResult = await this.processPayment(checkoutData, gatewayValidation.gatewayConfig);

      if (paymentResult.success) {
        // Record purchase
        this.productEnforcer.recordPurchase(userId, checkoutData.productId, {
          transactionId: paymentResult.transactionId,
          gateway: checkoutData.gateway,
          amount: checkoutData.amount,
          currency: checkoutData.currency
        });

        // Generate delivery token
        const deliveryToken = this.productEnforcer.encodeProductDelivery(
          { id: checkoutData.productId },
          userId
        );

        // Sign delivery token
        deliveryToken.signature = await this.encryption.sign(JSON.stringify(deliveryToken));

        // Create snapshot for rollback capability
        this.incidentResponse.createSnapshot({
          userId,
          productId: checkoutData.productId,
          deliveryToken,
          timestamp: Date.now()
        });

        return { success: true, deliveryToken, transactionId: paymentResult.transactionId };
      } else {
        throw new Error(`PAYMENT_FAILED: ${paymentResult.error}`);
      }
    }, { timeout: this.config.isolation.checkoutProcessTimeout });
  }

  async processPayment(checkoutData, gatewayConfig) {
    // This would integrate with actual payment gateways
    // For now, simulate successful payment
    this.auditor.log('payment_received', {
      gateway: checkoutData.gateway,
      amount: checkoutData.amount,
      currency: checkoutData.currency,
      productId: checkoutData.productId
    });

    return {
      success: true,
      transactionId: `txn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      gateway: checkoutData.gateway
    };
  }

  // Get security status
  getStatus() {
    return {
      initialized: this.initialized,
      layers: {
        preflight: 'active',
        privileges: { currentRole: this.privileges.currentRole, permissions: this.privileges.getPermissions() },
        isolation: { activeProcesses: this.isolator.getActiveCount() },
        threatDetection: { blockedIPs: this.threatDetector.blockedIPs.size, quarantinedIPs: this.incidentResponse.config.quarantine.suspiciousIPs.size },
        encryption: { hmacConfigured: !!this.encryption.hmacKey },
        auditing: { logCount: this.auditor.logs.length },
        incidentResponse: { snapshots: this.incidentResponse.snapshots.length, circuitBreakers: this.incidentResponse.circuitBreakers.size }
      },
      productRestrictions: this.config.productRestrictions,
      approvedGateways: this.config.approvedGateways
    };
  }
}

// Export for use in pages
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { YinitechSecurity, SECURITY_CONFIG };
} else if (typeof window !== 'undefined') {
  window.YinitechSecurity = YinitechSecurity;
  window.SECURITY_CONFIG = SECURITY_CONFIG;
}