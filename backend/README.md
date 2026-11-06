# Yinitech checkout backend scaffold

This backend is a starting point for the selected flow: Stripe Checkout + manual transfer/Altoke/crypto orders, with Whop webhook receipt. It is not deployed or connected to live credentials by this commit.

## Safety and current limitations

- Configure Stripe and Supabase secrets only on the backend host. Never commit a populated `.env` or expose the Supabase service-role key.
- Stripe checkout sessions use a server-owned product allowlist and fixed USD amounts. Orders remain pending until Stripe's signed webhook validates payment status, session, amount, and currency.
- Manual bank transfer, QR/Altoke, and crypto orders are created as `pending`. This scaffold does not verify bank settlement or blockchain transfers and does not grant product access.
- Whop webhook signature verification is implemented over the raw body with replay-age checking and duplicate event IDs. The handler intentionally records verified Whop events but does not mark orders paid: confirm Whop's actual event schema and order metadata mapping with a test delivery before enabling fulfillment.
- The supplied LocalTunnel URL is `https://whop-webhook-dihacktor.loca.lt/webhooks/whop`. A LocalTunnel URL is only reachable while its tunnel process and backend are running, may change, and is not a recommended permanent production endpoint. Do not expose Proxmox management port 8006.
- This scaffold does not include authenticated customer order-status or digital-delivery endpoints.

## Setup

1. Use a supported Node.js version (20+).
2. Install dependencies with `npm install`.
3. Copy `.env.example` to `.env` on the backend machine; set `SUPABASE_SERVICE_ROLE_KEY`, Stripe secrets, and Whop signing secret there.
4. Review and run `backend/schema.sql` in the canonical Supabase project.
5. Set the Whop webhook destination to `https://whop-webhook-dihacktor.loca.lt/webhooks/whop` only after the backend is listening and the tunnel forwards to it. Configure relevant payment events in Whop's dashboard; consult its current docs for the exact event names and payload.
6. Configure Stripe's webhook endpoint as `https://YOUR-API-DOMAIN/api/webhooks/stripe`, subscribe to `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `checkout.session.async_payment_failed`, and `checkout.session.expired`.
7. Run `npm start`; check `GET /health`.

## Frontend integration contract

The frontend may call `POST https://YOUR-API-DOMAIN/api/checkout/sessions` with `{ "productId": "copywriting-ia-2026", "email": "buyer@example.com", "paymentMethod": "stripe" }` or use `bank_transfer`, `altoke`, or `crypto`. It must not send a trusted price. For Stripe, redirect to the returned `checkoutUrl`; for other methods the API returns `202` with pending status.

Do not treat the browser return URL, uploaded receipt, typed transaction ID, or Whop webhook receipt alone as proof that a manual payment settled.
