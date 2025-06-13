const functions = require('firebase-functions');
const admin = require('firebase-admin');
const stripe = require('stripe');
const corsLib = require('cors');

admin.initializeApp();
const db = admin.firestore();

const STRIPE_SECRET_KEY = functions.config().stripe.secret_key;
const STRIPE_WEBHOOK_SECRET = functions.config().stripe.webhook_secret;
const stripeClient = stripe(STRIPE_SECRET_KEY);

const allowedOrigins = [
  'https://torat-yosef.web.app',
  'https://www.toratyosefsummerraffle.com'
];

const cors = corsLib({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
});

// ------------------- Referral Tracker -------------------
exports.recordReferral = functions.runWith({ runtime: 'nodejs20' }).https.onRequest((req, res) => {
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

// ------------------- Stripe Checkout Session Creation -------------------
exports.createStripeCheckoutSession = functions.runWith({ runtime: 'nodejs20' }).https.onRequest((req, res) => {
  cors(req, res, async () => {
    if (req.method !== 'POST') return res.status(405).send('Only POST allowed');

    const {
      referrerId,
      amount,
      quantity,
      prizeDescription,
      successUrl,
      cancelUrl,
      fullName,
      email
    } = req.body;

    if (!amount || !quantity || !prizeDescription || !successUrl || !cancelUrl) {
      return res.status(400).json({ error: 'Missing required fields for Stripe Checkout Session.' });
    }

    try {
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
        return_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}`,
        metadata: {
          fullName: fullName || 'unknown',
          email: email || 'unknown'
        }
      });

      res.status(200).json({ clientSecret: session.client_secret });
    } catch (error) {
      console.error('Error creating Stripe Checkout Session:', error);
      res.status(500).json({ error: 'Failed to create Stripe Checkout Session.', details: error.message });
    }
  });
});

// ------------------- Stripe Webhook Handler -------------------
exports.handleStripeWebhook = functions.runWith({ runtime: 'nodejs20' }).https.onRequest(async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripeClient.webhooks.constructEvent(req.rawBody, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error(`Webhook Error: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'checkout.session.completed':
      const session = event.data.object;
      const paymentData = {
        stripeSessionId: session.id,
        paymentIntentId: session.payment_intent,
        customerEmail: session.metadata?.email || session.customer_details?.email || 'N/A',
        customerName: session.metadata?.fullName || 'N/A',
        amountTotal: session.amount_total,
        currency: session.currency,
        paymentStatus: session.payment_status,
        referrerId: session.client_reference_id || 'unknown',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      };

      try {
        await db.collection('stripe_payments').doc(session.id).set(paymentData, { merge: true });
        if (paymentData.referrerId !== 'unknown') {
          await db.collection('referrals').doc(paymentData.referrerId).update({
            successfulPayments: admin.firestore.FieldValue.increment(1)
          });
        }
      } catch (error) {
        console.error(`Error saving Stripe payment for session ${session.id}:`, error);
        return res.status(500).send('Internal Server Error processing event.');
      }
      break;

    case 'payment_intent.succeeded':
      console.log('Payment Intent Succeeded:', event.data.object.id);
      break;

    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  res.status(200).send('OK');
});

// ------------------- Manual Entry Submission -------------------
exports.submitEntry = functions.runWith({ runtime: 'nodejs20' }).https.onRequest((req, res) => {
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
        submittedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      res.status(200).send('Entry submitted successfully.');
    } catch (err) {
      console.error('Error saving entry:', err);
      res.status(500).send('Internal Server Error');
    }
  });
});
