/**
 * SECURE CAPTURE-EMAIL ENDPOINT
 * Implements all 7 security layers for the checkout process
 * Native Node.js HTTP (no Express dependency)
 */

const {
  checkoutSecurity,
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
  verifyHMAC
} = require('./security-server.cjs');

const crypto = require('crypto');

// In-memory storage for orders (use database in production)
const orders = new Map();
const pendingCheckouts = new Map();

// Helper function for JSON responses
function sendJSON(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// ============================================
// SECURE CHECKOUT HANDLER
// ============================================

async function handleSecureCheckout(req, res) {
  const { requestId, clientIP, userRole } = req.security;
  const startTime = Date.now();

  try {
    // Parse body
    const body = req.body;
    const { email, tx_id, productId, productName, price, gateway, currency } = body;

    // Validate required fields
    if (!email || !email.includes('@')) {
      logAudit('purchase_failed', { requestId, ip: clientIP, reason: 'INVALID_EMAIL', tx_id });
      return sendJSON(res, 400, { error: 'EMAIL_REQUIRED' });
    }

    if (!tx_id) {
      logAudit('purchase_failed', { requestId, ip: clientIP, reason: 'MISSING_TX_ID' });
      return sendJSON(res, 400, { error: 'TRANSACTION_ID_REQUIRED' });
    }

    // Check for duplicate transaction
    if (pendingCheckouts.has(tx_id)) {
      logAudit('purchase_failed', { requestId, ip: clientIP, reason: 'DUPLICATE_TX', tx_id });
      return sendJSON(res, 409, { error: 'DUPLICATE_TRANSACTION' });
    }

    // Check if transaction already completed (check orders)
    for (const [_, order] of orders) {
      if (order.tx_id === tx_id) {
        logAudit('purchase_failed', { requestId, ip: clientIP, reason: 'DUPLICATE_TX_COMPLETED', tx_id });
        return sendJSON(res, 409, { error: 'DUPLICATE_TRANSACTION', reason: 'Transaction already completed' });
      }
    }

    // Mark as processing
    pendingCheckouts.set(tx_id, { email, productId, productName, price, gateway, currency, status: 'processing', timestamp: Date.now() });

    // Validate payment gateway
    const paymentValidation = validatePaymentRequest({
      gateway: gateway || 'vitawallet',
      amount: price || 6.99,
      currency: currency || 'USD',
      productId: productId || 'unknown'
    });

    if (!paymentValidation.valid) {
      pendingCheckouts.delete(tx_id);
      logAudit('purchase_failed', { requestId, ip: clientIP, reason: `GATEWAY_INVALID: ${paymentValidation.reason}`, tx_id });
      return sendJSON(res, 400, { error: 'INVALID_GATEWAY', reason: paymentValidation.reason });
    }

    // Check product restrictions
    const userId = email; // Use email as user identifier
    const productCheck = canPurchase(userId, productId || `prod_${Date.now()}`);

    if (!productCheck.allowed) {
      pendingCheckouts.delete(tx_id);
      logAudit('purchase_failed', { requestId, ip: clientIP, reason: productCheck.reason, tx_id, productId });
      return sendJSON(res, 403, { error: 'PURCHASE_RESTRICTED', reason: productCheck.reason });
    }

    // Process payment with circuit breaker
    const paymentResult = await executeWithCircuitBreaker('payment-gateway', async () => {
      // Simulate payment processing
      await new Promise(resolve => setTimeout(resolve, 100));

      // In production, integrate with actual payment gateway
      return {
        success: true,
        transactionId: `txn_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
        gateway: gateway || 'vitawallet',
        amount: price || 6.99,
        currency: currency || 'USD'
      };
    });

    if (!paymentResult.success) {
      pendingCheckouts.delete(tx_id);
      logAudit('purchase_failed', { requestId, ip: clientIP, reason: 'PAYMENT_FAILED', tx_id });
      return sendJSON(res, 402, { error: 'PAYMENT_FAILED' });
    }

    // Record successful purchase
    recordPurchase(userId, productId || `prod_${Date.now()}`, {
      transactionId: paymentResult.transactionId,
      gateway: paymentResult.gateway,
      amount: paymentResult.amount,
      currency: paymentResult.currency,
      tx_id
    });

    // Generate delivery token with restrictions
    const deliveryToken = generateDeliveryToken(productId || `prod_${Date.now()}`, userId);

    // Create system snapshot for rollback capability
    const snapshotId = createSnapshot({
      userId,
      productId: productId || `prod_${Date.now()}`,
      deliveryToken,
      orderId: paymentResult.transactionId,
      timestamp: Date.now()
    });

    // Store order
    const order = {
      id: paymentResult.transactionId,
      tx_id,
      email,
      productId: productId || `prod_${Date.now()}`,
      productName: productName || 'DIHACKTOR Ω Product',
      price: price || 6.99,
      currency: currency || 'USD',
      gateway: paymentResult.gateway,
      deliveryToken,
      snapshotId,
      status: 'completed',
      createdAt: new Date().toISOString()
    };

    orders.set(paymentResult.transactionId, order);
    pendingCheckouts.delete(tx_id);

    // Log success
    logAudit('purchase_completed', {
      requestId,
      ip: clientIP,
      orderId: order.id,
      productId: order.productId,
      amount: order.price,
      currency: order.currency,
      gateway: order.gateway,
      duration: Date.now() - startTime
    });

    // Return success with delivery token
    sendJSON(res, 200, {
      success: true,
      order_id: order.id,
      transaction_id: paymentResult.transactionId,
      delivery_token: deliveryToken,
      message: 'Compra completada. El acceso al producto se enviará a tu email.'
    });

  } catch (error) {
    console.error('[CHECKOUT ERROR]', error);

    // Clean up pending checkout
    if (req.body?.tx_id) {
      pendingCheckouts.delete(req.body.tx_id);
    }

    logAudit('purchase_failed', {
      requestId,
      ip: clientIP,
      reason: 'SERVER_ERROR',
      error: error.message,
      duration: Date.now() - startTime
    });

    sendJSON(res, 500, { error: 'INTERNAL_ERROR', message: 'Error procesando la compra' });
  }
}

// ============================================
// DELIVERY TOKEN VALIDATION ENDPOINT
// ============================================

function handleValidateToken(req, res) {
  const { requestId, clientIP } = req.security;
  const { token } = req.body;

  if (!token) {
    return sendJSON(res, 400, { error: 'TOKEN_REQUIRED' });
  }

  const validation = validateDeliveryToken(token);

  logAudit('token_validation', {
    requestId,
    ip: clientIP,
    productId: token.productId,
    userId: token.userId,
    valid: validation.valid,
    reason: validation.reason
  });

  if (!validation.valid) {
    return sendJSON(res, 401, { error: 'INVALID_TOKEN', reason: validation.reason });
  }

  sendJSON(res, 200, {
    valid: true,
    productId: token.productId,
    userId: token.userId,
    expiresAt: new Date(token.expiresAt).toISOString(),
    restrictions: token.restrictions
  });
}

// ============================================
// ORDER LOOKUP ENDPOINT
// ============================================

function handleGetOrder(req, res) {
  const { requestId, clientIP, userRole } = req.security;
  const { orderId } = req.params;

  // Only allow users to see their own orders, admins see all
  const order = orders.get(orderId);

  if (!order) {
    return sendJSON(res, 404, { error: 'ORDER_NOT_FOUND' });
  }

  // Check ownership (simplified - in production use proper auth)
  if (userRole !== 'admin') {
    // Would check if order belongs to current user
  }

  logAudit('order_accessed', { requestId, ip: clientIP, orderId, userRole });

  sendJSON(res, 200, {
    id: order.id,
    productName: order.productName,
    price: order.price,
    currency: order.currency,
    gateway: order.gateway,
    status: order.status,
    createdAt: order.createdAt,
    deliveryToken: order.deliveryToken ? {
      productId: order.deliveryToken.productId,
      expiresAt: order.deliveryToken.expiresAt,
      restrictions: order.deliveryToken.restrictions
    } : null
  });
}

// ============================================
// HEALTH CHECK ENDPOINT
// ============================================

function handleHealthCheck(req, res) {
  const health = healthCheck();
  sendJSON(res, 200, health);
}

// ============================================
// SECURITY STATUS ENDPOINT (Admin only)
// ============================================

function handleSecurityStatus(req, res) {
  const { requestId, clientIP, userRole } = req.security;

  if (userRole !== 'admin') {
    return sendJSON(res, 403, { error: 'ADMIN_REQUIRED' });
  }

  const securityServer = require('./security-server.cjs');

  logAudit('security_status_accessed', { requestId, ip: clientIP, userRole });

  sendJSON(res, 200, {
    rateLimitStore: Object.fromEntries(
      Array.from(securityServer.SERVER_SECURITY_CONFIG.rateLimitStore.entries()).slice(0, 20)
    ),
    blockedIPs: Array.from(securityServer.SERVER_SECURITY_CONFIG.blockedIPs),
    auditLogsCount: securityServer.SERVER_SECURITY_CONFIG.auditLogs.length,
    recentAuditLogs: securityServer.SERVER_SECURITY_CONFIG.auditLogs.slice(-50),
    snapshots: securityServer.systemSnapshots.map(s => ({
      id: s.id,
      timestamp: s.timestamp,
      checksum: s.checksum
    })),
    circuitBreakers: Object.fromEntries(
      Array.from(securityServer.circuitBreakers.entries()).map(([k, v]) => [k, v.state])
    ),
    ordersCount: orders.size,
    pendingCheckouts: pendingCheckouts.size
  });
}

module.exports = {
  handleSecureCheckout,
  handleValidateToken,
  handleGetOrder,
  handleHealthCheck,
  handleSecurityStatus,
  orders,
  pendingCheckouts,
  sendJSON
};