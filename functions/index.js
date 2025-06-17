const functions = require('firebase-functions');
const admin = require('firebase-admin');
const express = require('express');
const cors = require('cors');

// Initialize Firebase Admin SDK
if (!admin.apps.length) {
  admin.initializeApp();
}
const db = admin.firestore();

// Setup Express app
const app = express();
app.use(cors({ origin: true }));
app.use(express.json()); // Parse JSON body

// Webhook endpoint
app.post('/paypal-webhook', async (req, res) => {
  try {
    const event = req.body;
    console.log('📩 Webhook received:', event);

    // Store event in Firestore
    await db.collection('paypal_webhooks_test').add({
      receivedAt: admin.firestore.FieldValue.serverTimestamp(),
      eventType: event.event_type || 'UNKNOWN',
      fullPayload: event
    });

    res.status(200).send('✅ Webhook received and stored');
  } catch (error) {
    console.error('❌ Webhook error:', error);
    res.status(500).send('❌ Error handling webhook');
  }
});

// Firebase function export
exports.paypalWebhook = functions.https.onRequest(app);
