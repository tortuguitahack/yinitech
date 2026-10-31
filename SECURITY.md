# YINITECH SECURITY Ω - 7 Layer Security Implementation

## Overview
Complete 7-layer security implementation for the YINITECH web platform protecting digital product sales with enterprise-grade security.

---

## 7 Security Layers

### CAPA 1: Validación Previa (Pre-flight Validation)
**Archivo:** `security/security-core.js` → `PreFlightValidator`
- Validación de método HTTP (GET, POST únicamente)
- Validación de Content-Type (application/json, application/x-www-form-urlencoded)
- Límite de payload: 1MB máximo
- Headers requeridos: `x-request-id`, `x-client-fingerprint`
- Validación de origen (CORS) contra lista blanca

### CAPA 2: Mínimo Privilegio (Minimum Privilege)
**Archivo:** `security/security-core.js` → `PrivilegeManager`
- Roles: `anonymous`, `buyer`, `admin`
- Permisos por recurso:
  - `products`: read (all), write (admin)
  - `orders`: read (buyer, admin), write (buyer, admin)
  - `payments`: read/write (admin)
  - `users`: read/write (admin)
  - `security_logs`: read (admin), write (system)

### CAPA 3: Aislamiento de Procesos (Process Isolation)
**Archivo:** `security/security-core.js` → `ProcessIsolator`
- Timeout de proceso de pago: 30 segundos
- Timeout de checkout: 60 segundos
- Máximo 10 checkouts concurrentes
- Endpoints sandboxed: `/capture-email`, `/verify-payment`, `/deliver-product`
- AbortController para cancelación segura

### CAPA 4: Detección de Amenazas (Threat Detection)
**Archivo:** `security/security-core.js` → `ThreatDetector`

#### Rate Limiting:
| Categoría | Límite | Ventana |
|-----------|--------|---------|
| Global | 100 req | 60s |
| Checkout | 5 req | 60s |
| Search | 30 req | 60s |
| API | 60 req | 60s |

#### WAF (Web Application Firewall):
- Patrones bloqueados: XSS, SQL Injection, Path Traversal, Command Injection
- Límite de entrada: 5000 caracteres
- Auto-cuarentena tras 10 intentos sospechosos

### CAPA 5: Cifrado de Datos (Encryption)
**Archivo:** `security/security-core.js` → `EncryptionManager`
- HMAC-SHA256 para firma de requests
- TLS 1.2+ obligatorio
- AES-GCM para datos en reposo
- Rotación de claves cada 30 días
- Certificate pinning configurado

### CAPA 6: Auditoría Continua (Continuous Auditing)
**Archivo:** `security/security-core.js` → `SecurityAuditor`
- Eventos auditados:
  - Login/Logout
  - Purchase initiated/completed/failed
  - Payment received
  - Access denied
  - Rate limit exceeded
  - WAF blocked
  - Suspicious activity
  - Config changes
- Retención: 90 días
- Alertas en tiempo real via webhook + Telegram
- Logs sanitizados (PII redactado)

### CAPA 7: Respuesta a Incidentes (Incident Response)
**Archivo:** `security/security-core.js` → `IncidentResponder`
- Rollback atómico con snapshots (máx 10)
- Circuit breaker: 5 fallos → open, 60s reset
- Cuarentena automática de IPs sospechosas
- Health check endpoint: `/health`
- Backup location: `/secure/backups`

---

## Product Restrictions (Restricciones de Producto)

```javascript
productRestrictions: {
  noSharing: true,           // No compartir
  noCopying: true,           // No copiar
  durabilityDays: 30,        // Durabilidad 1 mes
  noDisclosure: true,        // No divulgar
  singlePurchase: true,      // Compra única
  additionalPurchasesAllowed: true,  // Puede comprar otros
  oneAtATimeOrBulk: true     // Uno a uno o en cantidad
}
```

**Implementación:** `security/security-core.js` → `ProductRestrictionEnforcer`
- Token de entrega firmado con HMAC
- Expiración automática a 30 días
- Máximo 1 descarga por token
- Validación de propiedad (no sharing)

---

## Approved Payment Gateways (Pasarelas Aprobadas)

| Gateway | Tipo | Monedas | Configuración |
|---------|------|---------|---------------|
| `binance` | Crypto | USDT, BTC, ETH, BNB | Binance Pay API |
| `lead_bank` | Bank Transfer | USD | Lead Bank USA (Routing: 101019644) |
| `openpayd` | Bank Transfer | EUR, GBP, USD | OpenPayd EU (IBAN: MT12CFTE...) |
| `banco_mercantil` | Bank Transfer | BOB | Banco Mercantil Bolivia (Cuenta: 4069474188) |
| `wallbit` | Bank Transfer | USD | Wallbit USA |
| `safepal` | Crypto Wallet | USDT, BTC, ETH, BNB | SafePal Cold Wallet |
| `whop` | Platform | USD | Whop Marketplace |

**Validación:** `security/security-core.js` → `PaymentGatewayValidator`
- Solo gateways en lista blanca
- Validación de moneda por gateway
- Validación de monto ($6.99 USD base)

---

## File Structure

```
Tecnolog-a-Yiniayang/
├── security/
│   ├── security-core.js       # Core 7-layer implementation (client + server)
│   ├── security-client.js     # Browser integration script
│   ├── security-server.js     # Node.js/Bun middleware
│   ├── secure-checkout.js     # Secure checkout endpoint logic
│   └── secure-server.js       # Standalone HTTP server (port 5100)
├── index.html                 # Main page (updated with security)
├── paises/
│   └── bolivia/
│       └── index.html         # Bolivia page (updated with security)
└── api/
    └── products.json          # Product catalog
```

---

## Deployment

### 1. Start Secure Server (Port 5100)
```bash
cd /home/dihacktor/Tecnolog-a-Yiniayang/security
node secure-server.js
# Or with Bun:
bun secure-server.js
```

### 2. Environment Variables
```bash
export SECURITY_HMAC_SECRET="your-production-hmac-secret-256-bit"
export SECURITY_WEBHOOK_URL="https://your-webhook.endpoint"
export SECURITY_TELEGRAM_BOT="@your_bot"
export PORT=5100
```

### 3. Include in HTML Pages
```html
<!-- Security meta tags -->
<meta name="security-hmac" content="your-hmac-secret">
<meta name="security-webhook" content="https://your-webhook">
<meta name="security-telegram" content="@your_bot">

<!-- Security client script -->
<script src="/security/security-client.js"></script>
```

### 4. Verify Security Headers
```bash
curl -I http://localhost:5100/health
# Should return security headers:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# X-XSS-Protection: 1; mode=block
# Referrer-Policy: strict-origin-when-cross-origin
```

---

## Testing Security Layers

### Test Rate Limiting
```bash
for i in {1..10}; do curl -s -o /dev/null -w "%{http_code} " http://localhost:5100/capture-email -X POST -H "Content-Type: application/json" -d '{"email":"test@test.com","tx_id":"test"}'; done
# Should return 429 after 5 requests
```

### Test WAF
```bash
curl -X POST http://localhost:5100/capture-email \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","tx_id":"test<script>alert(1)</script>"}'
# Should return 400 REQUEST_BLOCKED
```

### Test HMAC
```bash
# Valid request with signature
BODY='{"email":"test@test.com","tx_id":"test123"}'
SIG=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "yinitech-hmac-secret-2026-change-in-production" | cut -d' ' -f2)
curl -X POST http://localhost:5100/capture-email \
  -H "Content-Type: application/json" \
  -H "X-Signature: $SIG" \
  -d "$BODY"
```

### Test Health Check
```bash
curl http://localhost:5100/health
# Should return security status
```

---

## Security Status Endpoint (Admin)
```bash
curl -H "X-Signature: <hmac>" http://localhost:5100/admin/security
# Returns: rate limits, blocked IPs, audit logs, snapshots, circuit breakers
```

---

## Monitoring & Alerts

### Real-time Alerts
- Webhook: `https://api.dihacktor.com/security/webhook`
- Telegram: `@d3h1ckt4r_bot`

### Critical Events (Immediate Alert)
- `purchase_completed`
- `payment_received`
- `SQL_INJECTION_ATTEMPT`
- `XSS_ATTEMPT`
- `COMMAND_INJECTION`
- `IP_BLOCKED`

### High Priority Events
- `access_denied`
- `rate_limit_exceeded`
- `waf_blocked`
- `suspicious_activity`
- `INVALID_SIGNATURE`

---

## Rollback Procedure

1. **Identify compromised snapshot**
2. **Verify integrity:** `calculateChecksum(snapshot.state) === snapshot.checksum`
3. **Execute rollback:** `incidentResponse.rollback(snapshotId)`
4. **Verify system health:** `await incidentResponse.healthCheck()`
5. **Audit log:** Automatic `ROLLBACK_INITIATED` event

---

## Circuit Breaker States

```
CLOSED (Normal) → 5 failures → OPEN (Blocking)
OPEN → 60s timeout → HALF-OPEN (Testing)
HALF-OPEN → 3 successes → CLOSED
HALF-OPEN → 1 failure → OPEN
```

---

## Compliance

- ✅ OWASP Top 10 protection
- ✅ PCI DSS compatible (no card storage)
- ✅ GDPR ready (data minimization, retention)
- ✅ HMAC request signing
- ✅ Rate limiting & WAF
- ✅ Audit trail with tamper evidence
- ✅ Incident response procedures

---

## Maintenance

### Daily
- Review audit logs for anomalies
- Check circuit breaker states
- Verify health endpoint

### Weekly
- Rotate HMAC secret (update env + redeploy)
- Review blocked IP list
- Clean old rate limit entries

### Monthly
- Full security audit
- Penetration testing
- Update WAF patterns
- Review product restrictions compliance

---

## Contact
- **Security Team:** techinnovationany@gmail.com
- **Telegram:** @d3h1ckt4r_bot
- **Emergency:** Use `/admin/security` endpoint for real-time status