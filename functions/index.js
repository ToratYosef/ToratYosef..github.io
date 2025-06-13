// Required modules
const { onRequest } = require('firebase-functions/v2/https'); // Correct import for 2nd Gen
const { defineSecret } = require('firebase-functions/v2/params');
const admin = require('firebase-admin');
const stripe = require('stripe');
const corsLib = require('cors');

// Initialize Firebase
admin.initializeApp();
const db = admin.firestore();

// Define Stripe environment variables as secrets
const STRIPE_SECRET_KEY = defineSecret('STRIPE_SECRET_KEY');
const STRIPE_WEBHOOK_SECRET = defineSecret('STRIPE_WEBHOOK_SECRET');

// Allowed CORS origins
const allowedOrigins = [
  'https://torat-yosef.web.app',
  'https://www.toratyosefsummerraffle.com',
];

const cors = corsLib({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
});

// ------------------- Referral Tracker (1st Gen) -------------------
// Keep this import for the 1st Gen function
const functions = require('firebase-functions');

exports.recordReferral = functions.https.onRequest((req, res) => {
  cors(req, res, async () => {
    if (req.method !== 'GET') return res.status(405).send('Only GET allowed');
    const referrerId = req.query.ref;
    if (!referrerId) return res.status(400).send('Missing referral ID');

    try {
      const refDoc = db.collection('referrals').doc(referrerId);
      await db.runTransaction(async (tx) => {
        const doc = await tx.get(refDoc);
        if (!doc.exists) {
          tx.set(refDoc, {
            count: 1,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            lastClick: admin.firestore.FieldValue.serverTimestamp()
          });
        } else {
          tx.update(refDoc, {
            count: (doc.data().count || 0) + 1,
            lastClick: admin.firestore.FieldValue.serverTimestamp()
          });
        }
      });
      res.status(200).send(`Referral for ${referrerId} recorded.`);
    } catch (error) {
      console.error('Error recording referral:', error);
      res.status(500).send('Internal Server Error');
    }
  });
});

// ------------------- Stripe Checkout Session Creation (2nd Gen) -------------------
exports.createStripeCheckoutSession = onRequest({
  timeoutSeconds: 60,
  memory: '256MiB',
  secrets: [STRIPE_SECRET_KEY]
}, async (req, res) => { // <-- Function handler directly after options
  const stripeClient = stripe(STRIPE_SECRET_KEY.value());

  cors(req, res, async () => {
    if (req.method !== 'POST') {
      return res.status(405).send('Only POST allowed');
    }

    const { referrerId, amount, quantity, prizeDescription, successUrl, cancelUrl, fullName, email, phoneNumber } = req.body;

    if (!amount || !quantity || !prizeDescription || !successUrl || !cancelUrl || !fullName || !email) {
      const missingFields = [];
      if (!amount) missingFields.push('amount');
      if (!quantity) missingFields.push('quantity');
      if (!prizeDescription) missingFields.push('prizeDescription');
      if (!successUrl) missingFields.push('successUrl');
      if (!cancelUrl) missingFields.push('cancelUrl');
      if (!fullName) missingFields.push('fullName');
      if (!email) missingFields.push('email');
      return res.status(400).json({ error: `Missing required fields: ${missingFields.join(', ')}` });
    }

    if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format.' });
    }

    try {
      const newRaffleEntryRef = db.collection('raffle_entries').doc();

      const raffleEntryData = {
        fullName,
        email,
        phoneNumber: phoneNumber || null,
        referrerId: referrerId || 'unknown',
        quantity,
        amount,
        prizeDescription,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        status: 'checkout_initiated',
        stripeCheckoutSessionId: null,
        stripePaymentIntentId: null,
      };

      await newRaffleEntryRef.set(raffleEntryData);

      const session = await stripeClient.checkout.sessions.create({
        ui_mode: 'embedded',
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: { name: prizeDescription },
              unit_amount: amount
            },
            quantity
          }
        ],
        mode: 'payment',
        client_reference_id: referrerId || 'unknown',
        customer_email: email,
        metadata: {
          firebaseEntryId: newRaffleEntryRef.id,
          referrerId: referrerId || 'unknown',
          fullName,
          email,
          phoneNumber: phoneNumber || '',
        },
        return_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}&entry_id=${newRaffleEntryRef.id}`,
        cancel_url: `${cancelUrl}?entry_id=${newRaffleEntryRef.id}`
      });

      await newRaffleEntryRef.update({
        stripeCheckoutSessionId: session.id,
      });

      res.status(200).json({ clientSecret: session.client_secret });

    } catch (error) {
      console.error('Error creating Stripe Checkout Session:', error);
      res.status(500).json({ error: 'Failed to create Stripe Checkout Session.', details: error.message });
    }
  });
});

// ------------------- Stripe Webhook Handler (2nd Gen) -------------------
exports.handleStripeWebhook = onRequest({
  timeoutSeconds: 60,
  memory: '256MiB',
  secrets: [STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET] // Both secrets needed for webhook
}, async (req, res) => { // <-- Function handler directly after options
  const stripeClient = stripe(STRIPE_SECRET_KEY.value()); // It's fine to pass the actual secret here.

  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripeClient.webhooks.constructEvent(req.rawBody, sig, STRIPE_WEBHOOK_SECRET.value());
  } catch (err) {
    console.error(`Webhook Error: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'checkout.session.completed':
      const session = event.data.object;
      const firebaseEntryId = session.metadata.firebaseEntryId;

      if (!firebaseEntryId) {
        console.error('Missing firebaseEntryId in metadata');
        return res.status(400).send('Missing firebaseEntryId.');
      }

      const paymentData = {
        stripeSessionId: session.id,
        paymentIntentId: session.payment_intent,
        customerEmail: session.customer_details?.email || session.metadata?.email || 'N/A',
        amountTotal: session.amount_total,
        currency: session.currency,
        paymentStatus: session.payment_status,
        referrerId: session.client_reference_id || session.metadata?.referrerId || 'unknown',
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        fullName: session.metadata?.fullName || 'N/A',
        phoneNumber: session.metadata?.phoneNumber || 'N/A',
      };

      try {
        const raffleEntryRef = db.collection('raffle_entries').doc(firebaseEntryId);
        await raffleEntryRef.update({
          status: 'completed',
          paymentDetails: paymentData,
          completedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        if (paymentData.referrerId !== 'unknown') {
          await db.collection('referrals').doc(paymentData.referrerId).update({
            successfulPayments: admin.firestore.FieldValue.increment(1)
          });
        }

      } catch (error) {
        console.error(`Error updating raffle entry ${firebaseEntryId}:`, error);
        return res.status(500).send('Error processing event.');
      }
      break;

    case 'payment_intent.succeeded':
      console.log('Payment Intent Succeeded:', event.data.object.id);
      break;

    case 'checkout.session.async_payment_succeeded':
      console.log('Async Payment Succeeded:', event.data.object.id);
      break;

    case 'checkout.session.async_payment_failed':
      const failedSession = event.data.object;
      const failedFirebaseEntryId = failedSession.metadata.firebaseEntryId;
      if (failedFirebaseEntryId) {
        try {
          await db.collection('raffle_entries').doc(failedFirebaseEntryId).update({
            status: 'payment_failed',
            failedAt: admin.firestore.FieldValue.serverTimestamp(),
            failureReason: failedSession.payment_status || 'unknown'
          });
        } catch (error) {
          console.error(`Error marking failure for entry ${failedFirebaseEntryId}:`, error);
        }
      }
      break;

    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  res.status(200).send('OK');
});

// ------------------- Manual Entry Submission (2nd Gen) -------------------
exports.submitEntry = onRequest({
  timeoutSeconds: 60,
  memory: '256MiB'
}, async (req, res) => { // <-- Function handler directly after options
  cors(req, res, async () => {
    if (req.method !== 'POST') return res.status(405).send('Only POST allowed');

    const { name, email, phone, referrerId } = req.body;
    if (!name || !email || !phone) return res.status(400).send('Missing required fields.');

    try {
      await db.collection('raffle_entries').add({
        name,
        email,
        phone,
        referrerId: referrerId || 'unknown',
        submittedAt: admin.firestore.FieldValue.serverTimestamp(),
        status: 'manual_entry'
      });
      res.status(200).send('Entry submitted successfully.');
    } catch (err) {
      console.error('Error saving entry:', err);
      res.status(500).send('Internal Server Error');
    }
  });
});