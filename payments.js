const crypto = require('crypto');

/**
 * Payment provider abstraction.
 *
 * If RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET are set in the environment, real
 * Razorpay orders are created and verified (requires `npm install razorpay`).
 *
 * If they are NOT set, the app falls back to a "mock" provider so the whole
 * booking + payment flow can be built and demoed locally without a real
 * payment gateway account. Mock orders always verify successfully — this
 * path must never be reachable in a real production deployment.
 */

const isRazorpayConfigured = Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET);

let razorpayClient = null;
function getRazorpayClient() {
  if (!razorpayClient) {
    let Razorpay;
    try {
      Razorpay = require('razorpay');
    } catch (err) {
      throw new Error(
        "RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET are set but the 'razorpay' package isn't installed. Run `npm install razorpay` in backend/."
      );
    }
    razorpayClient = new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID,
      key_secret: process.env.RAZORPAY_KEY_SECRET,
    });
  }
  return razorpayClient;
}

// amountInPaise: integer, smallest currency unit (paise for INR)
async function createOrder({ amountInPaise, receipt, notes }) {
  if (isRazorpayConfigured) {
    const client = getRazorpayClient();
    const order = await client.orders.create({
      amount: amountInPaise,
      currency: 'INR',
      receipt,
      notes,
    });
    return {
      mock: false,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID,
    };
  }

  // Mock order: deterministic fake id, no external call
  return {
    mock: true,
    orderId: `mock_order_${crypto.randomBytes(10).toString('hex')}`,
    amount: amountInPaise,
    currency: 'INR',
    keyId: null,
  };
}

// Verifies the signature Razorpay's checkout returns after a successful payment.
// For mock orders, any paymentId is accepted so local testing doesn't need real cards.
function verifyPaymentSignature({ orderId, paymentId, signature }) {
  if (orderId.startsWith('mock_order_')) {
    return Boolean(paymentId); // mock mode: presence of a paymentId is enough
  }

  if (!isRazorpayConfigured) {
    return false;
  }

  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest('hex');

  return (
    typeof signature === 'string' &&
    signature.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
  );
}

module.exports = { createOrder, verifyPaymentSignature, isRazorpayConfigured };
