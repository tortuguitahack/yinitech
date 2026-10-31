const crypto = require('crypto');
const body = '{"email":"test@example.com","tx_id":"tx_123","productId":"prod_test","productName":"Test Product","price":6.99,"gateway":"vitawallet","currency":"USD"}';
const secret = 'yinitech-hmac-secret-2026-change-in-production';
const sig = crypto.createHmac('sha256', secret).update(body).digest('hex');
console.log('Server signature:', sig);
console.log('Client signature: 146e32ffc8af4a79c01942d0c384846e5a142ea6e23a6a5e29b5371f89e354cf');
console.log('Match:', sig === '146e32ffc8af4a79c01942d0c384846e5a142ea6e23a6a5e29b5371f89e354cf');