require('dotenv').config();
const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');
const Stripe = require('stripe');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_WEBHOOK_AGE = Number(process.env.WHOP_MAX_TIMESTAMP_AGE_SECONDS || 300);
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map((origin) => origin.trim()).filter(Boolean);

// Server-owned catalog and prices; client-supplied price/name is never trusted.
const PRODUCTS = Object.freeze({
  'copywriting-ia-2026': { name: 'Tutorial Copywriting IA 2026', amountCents: 699 },
  'agentes-n8n': { name: 'Masterclass de Agentes de IA con n8n', amountCents: 699 },
  'prompts-rag': { name: 'Pack de Prompts RAG', amountCents: 699 }
});
const METHODS = new Set(['stripe', 'bank_transfer', 'altoke', 'crypto']);

const supabase = process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false }
    })
  : null;
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

app.disable('x-powered-by');
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));
// Preserve exact raw payload bytes for signed provider webhooks. JSON parsing is
// deliberately skipped for these routes and applied only to normal API requests.
app.use((req, res, next) => {
  if (req.path === '/api/webhooks/stripe' || req.path === '/webhooks/whop') return next();
  return express.json({ limit: '32kb' })(req, res, next);
});

function requireStorage(res) {
  if (!supabase) {
    res.status(503).json({ error: 'Backend database is not configured.' });
    return false;
  }
  return true;
}

function isEmail(value) {
  return typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', stripeConfigured: Boolean(stripe), storageConfigured: Boolean(supabase) });
});

// Create pending manual/crypto orders or a Stripe Checkout Session.
app.post('/api/checkout/sessions', async (req, res) => {
  if (!requireStorage(res)) return;
  const { productId, email, paymentMethod } = req.body || {};
  const product = PRODUCTS[productId];
  if (!product || !METHODS.has(paymentMethod) || !isEmail(email)) {
    return res.status(400).json({ error: 'Invalid product, email, or payment method.' });
  }
  if (paymentMethod === 'stripe' && !stripe) {
    return res.status(503).json({ error: 'Stripe is not configured yet.' });
  }

  const orderInsert = {
    product_id: productId,
    product_name: product.name,
    customer_email: email.trim().toLowerCase(),
    amount_cents: product.amountCents,
    currency: 'usd',
    payment_method: paymentMethod,
    status: 'pending'
  };
  const { data: order, error: insertError } = await supabase
    .from('yinitech_orders').insert(orderInsert).select('id').single();
  if (insertError) {
    console.error('order insert failed', insertError.code);
    return res.status(500).json({ error: 'Could not create order.' });
  }

  if (paymentMethod !== 'stripe') {
    // Transfer/Altoke/crypto stay pending until a trusted provider settlement
    // integration is implemented and verifies amount, asset, network and recipient.
    return res.status(202).json({
      orderId: order.id,
      status: 'pending',
      message: paymentMethod === 'crypto'
        ? 'Orden creada como pendiente. La verificación on-chain aún no está conectada; no envíes fondos hasta recibir instrucciones verificadas.'
        : 'Orden creada. El pago se confirmará después de verificar la liquidación.'
    });
  }

  try {
    const successUrl = process.env.STRIPE_SUCCESS_URL;
    const cancelUrl = process.env.STRIPE_CANCEL_URL;
    if (!successUrl || !cancelUrl) throw new Error('Stripe return URLs missing');
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      customer_email: orderInsert.customer_email,
      line_items: [{
        quantity: 1,
        price_data: {
          currency: 'usd',
          unit_amount: product.amountCents,
          product_data: { name: product.name }
        }
      }],
      metadata: { order_id: order.id, product_id: productId },
      success_url: `${successUrl}${successUrl.includes('?') ? '&' : '?'}session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: cancelUrl
    });
    const { error: updateError } = await supabase.from('yinitech_orders')
      .update({ stripe_session_id: session.id }).eq('id', order.id);
    if (updateError) throw new Error('Could not link Stripe session to order');
    return res.status(201).json({ orderId: order.id, status: 'pending', checkoutUrl: session.url });
  } catch (error) {
    console.error('Stripe session creation failed:', error.message);
    await supabase.from('yinitech_orders').update({ status: 'failed' }).eq('id', order.id);
    return res.status(502).json({ error: 'Could not start Stripe Checkout.' });
  }
});

// Stripe needs the exact raw request bytes for signature validation.
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json', limit: '1mb' }), async (req, res) => {
  if (!requireStorage(res)) return;
  if (!stripe || !process.env.STRIPE_WEBHOOK_SECRET) return res.sendStatus(503);
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (_error) {
    return res.status(400).send('Invalid Stripe signature');
  }

  const { error: eventError } = await supabase.from('yinitech_webhook_events').insert({
    provider: 'stripe', event_id: event.id, event_type: event.type
  });
  if (eventError && eventError.code === '23505') return res.json({ received: true, duplicate: true });
  if (eventError) return res.sendStatus(500);

  try {
    if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
      const session = event.data.object;
      const orderId = session.metadata?.order_id;
      if (session.payment_status === 'paid' && orderId && Number.isInteger(session.amount_total)) {
        const { data: order } = await supabase.from('yinitech_orders').select('amount_cents,currency')
          .eq('id', orderId).eq('stripe_session_id', session.id).maybeSingle();
        if (order && order.amount_cents === session.amount_total && order.currency === session.currency) {
          await supabase.from('yinitech_orders').update({
            status: 'paid', paid_at: new Date().toISOString(), provider_payment_id: session.payment_intent || session.id
          }).eq('id', orderId).eq('status', 'pending');
        }
      }
    } else if (event.type === 'checkout.session.async_payment_failed' || event.type === 'checkout.session.expired') {
      const session = event.data.object;
      if (session.metadata?.order_id) {
        await supabase.from('yinitech_orders').update({ status: 'failed' })
          .eq('id', session.metadata.order_id).eq('status', 'pending');
      }
    }
    await supabase.from('yinitech_webhook_events').update({
      processed_at: new Date().toISOString(), processing_result: 'processed'
    }).eq('provider', 'stripe').eq('event_id', event.id);
    return res.json({ received: true });
  } catch (error) {
    console.error('Stripe event processing failed:', error.message);
    return res.sendStatus(500);
  }
});

function verifyWhopSignature(rawBody, headers, secret) {
  const webhookId = headers['webhook-id'];
  const timestamp = headers['webhook-timestamp'];
  const signatureHeader = headers['webhook-signature'];
  if (!webhookId || !timestamp || !signatureHeader || !secret) return false;
  const timestampSeconds = Number(timestamp);
  if (!Number.isFinite(timestampSeconds) || Math.abs(Date.now() / 1000 - timestampSeconds) > MAX_WEBHOOK_AGE) return false;
  const signedContent = Buffer.concat([Buffer.from(`${webhookId}.${timestamp}.`, 'utf8'), rawBody]);
  const expected = crypto.createHmac('sha256', secret).update(signedContent).digest();
  return signatureHeader.split(/\s+/).some((versioned) => {
    const match = /^v1,([A-Za-z0-9+/=]+)$/.exec(versioned);
    if (!match) return false;
    const received = Buffer.from(match[1], 'base64');
    return received.length === expected.length && crypto.timingSafeEqual(received, expected);
  });
}

app.post('/webhooks/whop', express.raw({ type: 'application/json', limit: '1mb' }), async (req, res) => {
  if (!requireStorage(res)) return;
  if (!process.env.WHOP_WEBHOOK_SECRET) return res.sendStatus(503);
  if (!Buffer.isBuffer(req.body) || !verifyWhopSignature(req.body, req.headers, process.env.WHOP_WEBHOOK_SECRET)) {
    return res.status(400).send('Invalid Whop webhook signature');
  }
  let event;
  try { event = JSON.parse(req.body.toString('utf8')); }
  catch (_error) { return res.status(400).send('Invalid JSON'); }
  if (typeof event.id !== 'string' || typeof event.type !== 'string') return res.status(400).send('Missing event id/type');

  const { error: eventError } = await supabase.from('yinitech_webhook_events').insert({
    provider: 'whop', event_id: event.id, event_type: event.type
  });
  if (eventError && eventError.code === '23505') return res.json({ received: true, duplicate: true });
  if (eventError) return res.sendStatus(500);

  // Whop events are logged for automation. No Yinitech order is marked paid by
  // an event until its real payload is mapped to a Yinitech order and verified.
  await supabase.from('yinitech_webhook_events').update({
    processed_at: new Date().toISOString(), processing_result: 'signature_validated_mapping_pending'
  }).eq('provider', 'whop').eq('event_id', event.id);
  return res.status(202).json({ received: true, status: 'verified_event_mapping_pending' });
});

app.use((error, _req, res, _next) => {
  if (error.message === 'Origin not allowed') return res.status(403).json({ error: 'Origin not allowed' });
  console.error('request error:', error.message);
  return res.status(400).json({ error: 'Invalid request.' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Yinitech checkout API listening on ${PORT}`);
});
