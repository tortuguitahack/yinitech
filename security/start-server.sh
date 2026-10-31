#!/bin/bash
export SECURITY_HMAC_SECRET="yinitech-hmac-secret-2026-change-in-production"
export SECURITY_WEBHOOK_URL="https://api.dihacktor.com/security/webhook"
export SECURITY_TELEGRAM_BOT="@d3h1ckt4r_bot"
export PORT=5100
exec node /home/dihacktor/Tecnolog-a-Yiniayang/security/secure-server.cjs