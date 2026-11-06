# Yinitech checkout backend scaffold

Selected design: Stripe card checkout, Whop webhook intake for configured events, bank transfer/Altoke pending orders, and crypto as a planned method that remains disabled until on-chain verification is implemented.

This code is a scaffold, not a deployed or production-ready payment service. No live credentials are included.

## Payment truth and current limits

- Stripe order amounts and product names come from a server-side allowlist. An order is marked paid only by a Stripe webhook with a valid signature and matching order/session, paid status, amount, and currency.
- Bank transfer and Altoke orders remain pending. A customer-provided receipt or reference is not proof of settlement.
- Crypto is intentionally not enabled in the checkout API/UI yet. Do not send funds or display wallet instructions until you choose the exact chain/asset and deploy a verifier that checks recipient, token, amount, transaction success, confirmations, and replay/duplicate transaction hash. MetaMask/SafePal connection itself is not payment verification.
- Whop webhook requests are signature checked and event IDs are deduplicated. Events are logged only; they do not prove a Stripe, bank, Altoke, or crypto payment and do not mark Yinitech orders paid. Map Whop's real test event to an order only after confirming its schema and business purpose.
- The current `backend/server.js` persists to hosted Supabase when configured. If your Supabase runs locally, set `SUPABASE_URL` to the URL reachable from the backend process/container (not browser localhost or Proxmox `:8006`), provide the server-side service-role key privately, and test connectivity. Never expose the database port publicly.
- The LocalTunnel URL is temporary and not appropriate as a stable production webhook URL. Use a domain you control with HTTPS, routing only to the backend. Do not expose the Proxmox management panel on port 8006.
- This scaffold does not include customer order-status authentication, product delivery, refunds, or an admin reconciliation interface.

## Setup

1. Use Node.js 20+ and run `npm install`.
2. Copy `.env.example` to `.env` on the backend host. Set secrets in the host's secret manager/environment, not in GitHub or the frontend.
3. Set `SUPABASE_URL` to the backend-reachable local Supabase API endpoint if using local Supabase; configure `SUPABASE_SERVICE_ROLE_KEY` privately.
4. Review/run `backend/schema.sql` against the actual database you intend to use.
5. Set the Whop webhook endpoint to `https://YOUR-DOMAIN/webhooks/whop` only after stable HTTPS is running. Keep `WHOP_WEBHOOK_SECRET` private.
6. Configure Stripe's webhook endpoint as `https://YOUR-DOMAIN/api/webhooks/stripe` and subscribe to the checkout session events described in Stripe's current docs.
7. Run `npm start`; check `GET /health`. Start with provider test/sandbox modes and test failed, duplicate, delayed, and successful webhook deliveries.

## Frontend API contract

The frontend calls `POST https://YOUR-DOMAIN/api/checkout/sessions` with `{ "productId": "copywriting-ia-2026", "email": "buyer@example.com", "paymentMethod": "stripe" }`; do not send a trusted amount. Stripe returns a hosted `checkoutUrl`. `bank_transfer` and `altoke` return an order ID in `pending` state. Crypto requests currently must be blocked by the frontend and are rejected/not implemented until a genuine verifier and network configuration are reviewed and tested.

Never trust a browser success page, typed transaction hash, uploaded receipt, or Whop webhook receipt alone as payment proof.
