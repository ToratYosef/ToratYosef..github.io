const functions = require('firebase-functions');
const admin = require('firebase-admin');
const crypto = require('crypto');
const square = require('square');

// --- START DIAGNOSTIC LOGS (Remove these lines 8-20 after successful deployment) ---
console.log('--- STARTING FUNCTIONS LOAD ---');
console.log('Type of square:', typeof square);
if (typeof square === 'object' && square !== null) {
  console.log('Keys in square object:', Object.keys(square));
  console.log('square.Client exists:', typeof square.Client);
  console.log('square.Environment exists:', typeof square.Environment);
  console.log('square.SquareClient exists:', typeof square.SquareClient);
  console.log('square.SquareEnvironment exists:', typeof square.SquareEnvironment);
  if (typeof square.SquareEnvironment === 'object' && square.SquareEnvironment !== null) {
      console.log('square.SquareEnvironment.Sandbox exists:', typeof square.SquareEnvironment.Sandbox);
  }
} else {
    console.log('Square module did not load as an object or is null/undefined.');
}
console.log('--- END DIAGNOSTIC LOGS ---');

// Initialize Firebase Admin SDK
admin.initializeApp();
const db = admin.firestore();

// --- IMPORTANT: Your Square Webhook Signature Key ---
const SQUARE_WEBHOOK_SIGNATURE_KEY = 'qVJwLsbNH_QA8RHSZQ9vRQ';

// --- Configure Square SDK Client ---
const squareClient = new square.SquareClient({
    environment: square.SquareEnvironment.Sandbox,
    accessToken: process.env.SQUARE_ACCESS_TOKEN,
});
const squareAppId = process.env.SQUARE_APP_ID;
const squareLocationId = process.env.SQUARE_LOCATION_ID;

// --- Firebase Cloud Function: recordReferral ---
exports.recordReferral = functions.https.onRequest(async (req, res) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed. This endpoint only accepts GET requests.');
  }

  const referrerId = req.query.ref;

  if (!referrerId) {
    console.warn('recordReferral: Missing referral ID in query parameters.');
    return res.status(400).send('Missing referral ID.');
  }

  try {
    const refDoc = db.collection('referrals').doc(referrerId);

    await db.runTransaction(async (transaction) => {
      const doc = await transaction.get(refDoc);
      if (!doc.exists) {
        transaction.set(refDoc, { count: 1, createdAt: admin.firestore.FieldValue.serverTimestamp(), lastClick: admin.firestore.FieldValue.serverTimestamp() });
      } else {
        const newCount = (doc.data().count || 0) + 1;
        transaction.update(refDoc, { count: newCount, lastClick: admin.firestore.FieldValue.serverTimestamp() });
      }
    });

    res.status(200).send(`Referral for ${referrerId} recorded successfully.`);
  } catch (error) {
    console.error('Error recording referral:', error);
    res.status(500).send('Internal Server Error. Check server logs for details.');
  }
});

// --- NEW Firebase Cloud Function: createSquareOrder ---
exports.createSquareOrder = functions.https.onRequest(async (req, res) => {
    // --- START: CORS HEADERS (Must be at the very beginning of the function) ---
    // Allow requests from your Firebase Hosting domain
    res.set('Access-Control-Allow-Origin', 'https://torat-yosef.web.app'); // <--- Your domain
    
    // Handle preflight OPTIONS request (sent by browsers before POST requests)
    if (req.method === 'OPTIONS') {
        res.set('Access-Control-Allow-Methods', 'POST'); // Methods your function allows
        res.set('Access-Control-Allow-Headers', 'Content-Type'); // Headers your function allows
        res.set('Access-Control-Max-Age', '3600'); // Cache preflight response for 1 hour
        return res.status(204).send(''); // Respond with 204 No Content for OPTIONS
    }
    // --- END: CORS HEADERS ---

    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed. This endpoint only accepts POST requests.');
    }

    const { referrerId, tickets = 1, prize = "Raffle Ticket" } = req.body;

    if (!referrerId || !process.env.SQUARE_LOCATION_ID || !process.env.SQUARE_ACCESS_TOKEN) {
        console.error("createSquareOrder: Missing referrerId or Square Location ID/Access Token environment variables.");
        return res.status(400).json({ error: 'Missing required data or Square config.' });
    }

    try {
        const idempotencyKey = crypto.randomUUID();

        const orderBody = {
            idempotencyKey: idempotencyKey,
            order: {
                locationId: process.env.SQUARE_LOCATION_ID,
                lineItems: [
                    {
                        name: prize,
                        quantity: tickets.toString(),
                        basePriceMoney: {
                            amount: 12600, // $126.00 in cents
                            currency: 'USD',
                        },
                    },
                ],
                metadata: {
                    referrer_id: referrerId,
                }
            },
        };

        const { result: createOrderResult } = await squareClient.ordersApi.createOrder(orderBody);
        const order = createOrderResult.order;

        if (!order) {
            console.error("createSquareOrder: Failed to create order in Square:", createOrderResult);
            return res.status(500).json({ error: 'Failed to create Square order.' });
        }

        const checkoutBody = {
            idempotencyKey: crypto.randomUUID(),
            checkout: {
                orderId: order.id,
                askForShippingAddress: false,
                merchantSupportEmail: 'info@yourwebsite.com',
                redirectUrl: process.env.SQUARE_REDIRECT_URL || 'https://your-website.com/thankyou.html',
            },
        };

        const { result: createCheckoutResult } = await squareClient.checkoutApi.createCheckout(
            process.env.SQUARE_LOCATION_ID,
            checkoutBody
        );

        const checkoutPageUrl = createCheckoutResult.checkout?.checkoutPageUrl;

        if (!checkoutPageUrl) {
            console.error("createSquareOrder: Failed to create Square checkout URL:", createCheckoutResult);
            return res.status(500).json({ error: 'Failed to generate Square checkout URL.' });
        }

        console.log(`createSquareOrder: Created Square Order ${order.id} for referrer ${referrerId}. Checkout URL generated.`);
        res.status(200).json({ checkoutUrl: checkoutPageUrl, orderId: order.id });

    } catch (error) {
        console.error('createSquareOrder: Error creating Square order or checkout:', error);
        if (error.result?.errors) {
            error.result.errors.forEach(e => console.error(`Square API Error: ${e.category} - ${e.code} - ${e.detail}`));
        }
        res.status(500).json({ error: 'Internal Server Error creating Square checkout.' });
    }
});

// --- Firebase Cloud Function: handleSquareWebhook ---
exports.handleSquareWebhook = functions.https.onRequest(async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed. Square webhooks are POST requests.');
  }

  const signature = req.header('x-square-signature');
  const bodyString = req.rawBody ? req.rawBody.toString('utf8') : JSON.stringify(req.body);

  if (!signature || !SQUARE_WEBHOOK_SIGNATURE_KEY) {
    console.warn('handleSquareWebhook: Missing x-square-signature header or SQUARE_WEBHOOK_SIGNATURE_KEY is not set.');
    return res.status(401).send('Unauthorized: Missing signature or key.');
  }

  try {
    const hmac = crypto.createHmac('sha1', SQUARE_WEBHOOK_SIGNATURE_KEY);
    hmac.update(bodyString);
    const expectedSignature = hmac.digest('base64');

    if (signature !== expectedSignature) {
    console.warn('handleSquareWebhook: Invalid signature on Square webhook. Received:', signature, 'Expected:', expectedSignature);
      return res.status(401).send('Unauthorized: Invalid webhook signature.');
    }
  } catch (error) {
    console.error('handleSquareWebhook: Error during signature verification:', error);
    return res.status(500).send('Error verifying signature.');
  }

  const event = req.body;
  console.log('handleSquareWebhook: Received Square Webhook Event Type:', event.type);

  try {
    if (event.type === 'payment.created' || event.type === 'payment.updated') {
      const payment = event.data.object.payment;

      if (!payment.order_id) {
          console.log(`handleSquareWebhook: Payment ${payment.id} has no associated order. Skipping metadata retrieval for referrer.`);
          return res.status(200).send('Payment has no linked order. Webhook acknowledged.');
      }

      let referrerId = 'unknown';

      try {
          const { result: retrieveOrderResult } = await squareClient.ordersApi.retrieveOrder(payment.order_id);
          const order = retrieveOrderResult.order;

          if (order && order.metadata) {
              referrerId = order.metadata.referrer_id || 'unknown';
              console.log(`handleSquareWebhook: Retrieved referrer_id "${referrerId}" from Order ${order.id} metadata.`);
          }
      } catch (error) {
          console.error(`handleSquareWebhook: Error retrieving Order ${payment.order_id} metadata:`, error);
          if (error.result?.errors) {
              error.result.errors.forEach(e => console.error(`Square API Error during order retrieve: ${e.category} - ${e.code} - ${e.detail}`));
          }
      }

      const customerName = payment.buyer_supplied_info?.buyer_name || 'N/A';
      const customerEmail = payment.receipt_email || payment.buyer_email_address || 'N/A';
      const customerPhone = payment.buyer_phone_number || 'N/A';
      const paymentStatus = payment.status;

      const transactionData = {
          squarePaymentId: payment.id,
          customerName: customerName,
          customerEmail: customerEmail,
          customerPhone: customerPhone,
          amountMoney: payment.amount_money,
          paymentStatus: paymentStatus,
          sourceType: payment.source_type,
          receiptUrl: payment.receipt_url || null,
          orderId: payment.order_id,
          referrerId: referrerId,
          timestamp: admin.firestore.FieldValue.serverTimestamp()
      };

      await db.collection('square_payments').doc(payment.id).set(transactionData, { merge: true });
      console.log(`handleSquareWebhook: Payment ${payment.id} (${paymentStatus}) processed and saved to Firestore for ${customerEmail}. Referrer: ${referrerId}`);

      if (paymentStatus === 'COMPLETED' && referrerId !== 'unknown') {
        try {
          await db.collection('referrals').doc(referrerId).update({
            successfulPayments: admin.firestore.FieldValue.increment(1)
          });
          console.log(`handleSquareWebhook: Incremented successful payments for referrer ${referrerId}.`);
        } catch (updateError) {
          console.error(`handleSquareWebhook: Error updating successful payments for referrer ${referrerId}:`, updateError);
        }
      }

    } else if (event.type === 'refund.created') {
      const refund = event.data.object.refund;
      console.log('handleSquareWebhook: Refund created event received:', refund.id, refund.amount_money);
      await db.collection('square_payments').doc(refund.payment_id).update({ status: 'REFUNDED', refundedAt: admin.firestore.FieldValue.serverTimestamp() });

    } else {
      console.log(`handleSquareWebhook: Received unhandled event type: ${event.type}`);
    }

    res.status(200).send('Webhook processed successfully.');

  } catch (error) {
    console.error('handleSquareWebhook: Critical error processing Square webhook event:', error);
    res.status(500).send('Internal Server Error during webhook processing.');
  }
});