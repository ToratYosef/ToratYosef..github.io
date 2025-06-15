// Firebase & PayPal Setup
const { onRequest } = require('firebase-functions/v2/https');
const { setGlobalOptions } = require('firebase-functions/v2/options');
// const { defineString } = require('firebase-functions/params'); // Remove this line if no other params are defined

const admin = require('firebase-admin');
// const fetch = require('node-fetch'); // This was already removed, keeping comment for history
const express = require('express');
const bodyParser = require('body-parser');

// Firebase Firestore Init
admin.initializeApp();
const db = admin.firestore();

// Global Function Config
setGlobalOptions({
  region: 'us-central1',
  memory: '256Mi',
  timeoutSeconds: 60,
});

// PayPal Environment Variables (read from process.env)
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
const PAYPAL_API_BASE = process.env.PAYPAL_API_BASE; // Will be https://api-m.sandbox.paypal.com or https://api-m.paypal.com
const PAYPAL_ENVIRONMENT = process.env.PAYPAL_ENVIRONMENT; // Not directly used for API_BASE now, but good to keep if needed elsewhere
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID;

// Express App
const app = express();
app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send('PayPal webhook endpoint is live.');
});

app.post('/', async (req, res) => {
  const webhookEvent = req.body;

  const headers = {
    authAlgo: req.headers['paypal-auth-algo'],
    certUrl: req.headers['paypal-cert-url'],
    transmissionId: req.headers['paypal-transmission-id'],
    transmissionSig: req.headers['paypal-transmission-sig'],
    transmissionTime: req.headers['paypal-transmission-time'],
  };

  const webhookId = PAYPAL_WEBHOOK_ID; // Access directly now
  if (!webhookId) {
    console.error('PayPal Webhook ID not set');
    return res.status(500).send('Missing webhook ID');
  }

  try {
    const verificationRes = await fetch(`${PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64')}` // Access directly
      },
      body: JSON.stringify({
        auth_algo: headers.authAlgo,
        cert_url: headers.certUrl,
        transmission_id: headers.transmissionId,
        transmission_sig: headers.transmissionSig,
        transmission_time: headers.transmissionTime,
        webhook_id: webhookId,
        webhook_event: webhookEvent
      })
    });

    const verificationData = await verificationRes.json();

    if (verificationData.verification_status !== 'SUCCESS') {
      console.error('Verification failed:', verificationData);
      return res.status(400).send('Webhook signature verification failed');
    }

    console.log('✅ Webhook verified:', webhookEvent.event_type);

    if (webhookEvent.event_type === 'CHECKOUT.ORDER.COMPLETED') {
      const orderId = webhookEvent.resource.id;
      const payerEmail = webhookEvent.resource.payer.email_address;
      const payerName = `${webhookEvent.resource.payer.name.given_name || ''} ${webhookEvent.resource.payer.name.surname || ''}`.trim();
      const capture = webhookEvent.resource.purchase_units[0].payments.captures[0];
      const transactionAmount = parseFloat(capture.amount.value);
      const currency = capture.amount.currency_code;
      const captureId = capture.id;

      try {
        const orderDocRef = db.collection('paypalOrders').doc(orderId);
        const orderDoc = await orderDocRef.get();

        let name = payerName;
        let email = payerEmail;
        let phone = null;
        let referral = null;

        if (orderDoc.exists) {
          const orderData = orderDoc.data();
          name = orderData.name || name;
          email = orderData.email || email;
          phone = orderData.phone || null;
          referral = orderData.referral || null;
        }

        const entry = {
          name,
          email,
          phone,
          referral,
          amount: transactionAmount,
          currency,
          paypalOrderId: orderId,
          paypalCaptureId: captureId,
          paymentStatus: 'paid',
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          source: 'paypalWebhook'
        };

        await db.collection('raffleEntries').doc(orderId).set(entry, { merge: true });

        if (orderDoc.exists) {
          await orderDocRef.update({
            webhookProcessed: true,
            processedAt: admin.firestore.FieldValue.serverTimestamp()
          });
        }

        return res.status(200).send('Webhook processed.');
      } catch (err) {
        console.error('❌ Error saving data:', err);
        return res.status(500).send('Internal server error');
      }
    } else {
      console.log('Unhandled event:', webhookEvent.event_type);
      return res.status(200).send('Unhandled event');
    }
  } catch (err) {
    console.error('❌ Webhook error:', err);
    return res.status(500).send('Webhook error');
  }
});

// Export the Function
exports.paypalWebhook = onRequest(app);