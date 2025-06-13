// Required modules
const functions = require('firebase-functions');
const admin = require('firebase-admin');
const stripe = require('stripe');
const corsLib = require('cors');

// Initialize Firebase Admin SDK
admin.initializeApp();
const db = admin.firestore();

// Stripe environment variables (MUST BE SET VIA `firebase functions:config:set`)
// Ensure these are set in your Firebase project config:
// firebase functions:config:set stripe.secret_key="sk_test_YOUR_STRIPE_SECRET_KEY"
// firebase functions:config:set stripe.webhook_secret="whsec_YOUR_STRIPE_WEBHOOK_SECRET"
const STRIPE_SECRET_KEY = functions.config().stripe.secret_key;
const STRIPE_WEBHOOK_SECRET = functions.config().stripe.webhook_secret;

// Initialize Stripe client
const stripeClient = stripe(STRIPE_SECRET_KEY);

// Allowed CORS origins for your frontend
const allowedOrigins = [
  'https://torat-yosef.web.app',
  'https://www.toratyosefsummerraffle.com',
  // IMPORTANT: Add any other domains where your frontend is hosted (e.g., local development)
  // Example for local development: 'http://localhost:5000' or 'http://127.0.0.1:5000'
];

const cors = corsLib({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`Not allowed by CORS for origin: ${origin}`));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'], // Explicitly allow methods
  allowedHeaders: ['Content-Type'], // Explicitly allow headers
});

// ------------------- Referral Tracker -------------------
exports.recordReferral = functions.runWith({ runtime: 'nodejs20' }).https.onRequest((req, res) => {
  cors(req, res, async () => {
    // Handle preflight OPTIONS requests immediately
    if (req.method === 'OPTIONS') {
      res.status(204).send('');
      return;
    }

    if (req.method !== 'GET') {
      return res.status(405).send('Only GET allowed');
    }

    const referrerId = req.query.ref;
    if (!referrerId) {
      console.warn('Missing referral ID for recordReferral.');
      return res.status(400).send('Missing referral ID');
    }

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
    // Handle preflight OPTIONS requests immediately
    if (req.method === 'OPTIONS') {
      res.status(204).send('');
      return;
    }

    if (req.method !== 'POST') {
      return res.status(405).send('Only POST allowed');
    }

    // Destructure all expected fields, including the new ones
    const { referrerId, amount, quantity, prizeDescription, successUrl, cancelUrl, fullName, email, phoneNumber } = req.body;

    // Server-side validation for all required fields
    if (!amount || !quantity || !prizeDescription || !successUrl || !fullName || !email) {
      // Note: cancelUrl is not strictly required for embedded mode, but successUrl is
      console.error('Missing required fields for Stripe Checkout Session:', { amount, quantity, prizeDescription, successUrl, fullName, email });
      return res.status(400).json({ error: 'Missing required fields: amount, quantity, prizeDescription, successUrl, fullName, and email are all required.' });
    }

    // Basic email format validation
    if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
      console.error('Invalid email format received:', email);
      return res.status(400).json({ error: 'Invalid email format.' });
    }

    try {
      // 1. Store this information in your database (Firestore) BEFORE creating Stripe session
      // This creates a record even if the user abandons the Stripe checkout
      const newRaffleEntryRef = db.collection('raffle_entries').doc(); // Auto-generated ID

      const raffleEntryData = {
        // Data collected from the frontend
        fullName: fullName,
        email: email,
        phoneNumber: phoneNumber || null, // Store null if not provided
        referrerId: referrerId || 'unknown',
        quantity: quantity,
        amount: amount, // Amount in cents
        prizeDescription: prizeDescription,
        // Transaction details
        timestamp: admin.firestore.FieldValue.serverTimestamp(), // When initiated
        status: 'checkout_initiated', // Initial status
        stripeCheckoutSessionId: null, // Will be updated after session creation
        stripePaymentIntentId: null, // Will be updated by webhook
      };

      await newRaffleEntryRef.set(raffleEntryData);
      console.log('Raffle entry initiation stored in Firestore with ID:', newRaffleEntryRef.id);


      // 2. Create the Stripe Checkout Session
      const session = await stripeClient.checkout.sessions.create({
        ui_mode: 'embedded',
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: { name: prizeDescription },
              unit_amount: amount // Amount in cents
            },
            quantity
          }
        ],
        mode: 'payment',
        // Use `client_reference_id` for your internal referral ID
        client_reference_id: referrerId || 'unknown',
        // Optional: Pre-fill customer email on Stripe Checkout page
        customer_email: email,

        // Pass custom data to Stripe metadata - this is crucial for webhooks
        metadata: {
          firebaseEntryId: newRaffleEntryRef.id, // Your Firestore document ID
          referrerId: referrerId || 'unknown',
          fullName: fullName,
          email: email,
          phoneNumber: phoneNumber || '', // Ensure it's a string for metadata
        },

        // For embedded mode, return_url is used to redirect if the user completes checkout
        // and is outside the iframe, or if you handle it manually.
        return_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}&entry_id=${newRaffleEntryRef.id}`,
        // IMPORTANT: cancel_url is NOT SUPPORTED with ui_mode: 'embedded'.
        // The embedded checkout handles cancellations client-side via its UI.
      });

      // Update the Firestore document with the Stripe Checkout Session ID
      await newRaffleEntryRef.update({
        stripeCheckoutSessionId: session.id,
      });
      console.log('Stripe Checkout Session created:', session.id);


      // 3. Send the client_secret back to the frontend
      res.status(200).json({ clientSecret: session.client_secret });

    } catch (error) {
      console.error('Error creating Stripe Checkout Session:', error);
      // Log more details in dev, but send generic error to client
      res.status(500).json({ error: 'Failed to create Stripe Checkout Session.', details: error.message });
    }
  });
});

// ------------------- Stripe Webhook Handler -------------------
exports.handleStripeWebhook = functions.runWith({ runtime: 'nodejs20' }).https.onRequest(async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    // Stripe expects the raw body for signature verification
    event = stripeClient.webhooks.constructEvent(req.rawBody, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error(`Webhook Error: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the event
  switch (event.type) {
    case 'checkout.session.completed':
      const session = event.data.object;
      console.log('Stripe Checkout Session Completed:', session.id);

      // Extract the firebaseEntryId from metadata
      const firebaseEntryId = session.metadata?.firebaseEntryId; // Using optional chaining

      if (!firebaseEntryId) {
        console.error('Webhook Error: Missing firebaseEntryId in metadata for session:', session.id);
        // Respond with 200 so Stripe doesn't retry, but log the error for investigation
        return res.status(200).send('OK (Missing firebaseEntryId)');
      }

      const paymentData = {
        stripeSessionId: session.id,
        paymentIntentId: session.payment_intent,
        customerEmail: session.customer_details?.email || session.metadata?.email || 'N/A', // Prioritize session email, then metadata
        amountTotal: session.amount_total,
        currency: session.currency,
        paymentStatus: session.payment_status, // Should be 'paid'
        referrerId: session.client_reference_id || session.metadata?.referrerId || 'unknown',
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        // Also capture the collected full name and phone number from metadata
        fullName: session.metadata?.fullName || 'N/A',
        phoneNumber: session.metadata?.phoneNumber || 'N/A',
      };

      try {
        // Update the existing raffle_entry document in Firestore
        const raffleEntryRef = db.collection('raffle_entries').doc(firebaseEntryId);
        await raffleEntryRef.update({
          status: 'completed', // Mark as completed
          paymentDetails: paymentData, // Store full payment details within the entry
          completedAt: admin.firestore.FieldValue.serverTimestamp() // When payment actually completed
        });
        console.log(`Raffle entry ${firebaseEntryId} updated to 'completed'.`);

        // Update referral count for successful payments
        if (paymentData.referrerId && paymentData.referrerId !== 'unknown') {
          await db.collection('referrals').doc(paymentData.referrerId).update({
            successfulPayments: admin.firestore.FieldValue.increment(1)
          });
          console.log(`Referral ${paymentData.referrerId} successful payments incremented.`);
        }

      } catch (error) {
        console.error(`Error saving Stripe payment or updating raffle entry ${firebaseEntryId}:`, error);
        return res.status(500).send('Internal Server Error processing event.');
      }
      break;

    case 'payment_intent.succeeded':
      // This event often follows checkout.session.completed.
      // You can use this to update status if needed, but `checkout.session.completed`
      // is usually sufficient for one-time payments.
      console.log('Stripe Payment Intent Succeeded:', event.data.object.id);
      break;

    // You might want to handle other events like 'checkout.session.async_payment_succeeded',
    // 'checkout.session.async_payment_failed', etc., for more robust status updates.
    // For now, focusing on completed session.

    default:
      console.log(`Unhandled Stripe event type ${event.type}`);
  }

  // Return a 200 response to acknowledge receipt of the event by Stripe
  res.status(200).send('OK');
});

// ------------------- Manual Entry Submission -------------------
exports.submitEntry = functions.runWith({ runtime: 'nodejs20' }).https.onRequest((req, res) => {
  cors(req, res, async () => {
    // Handle preflight OPTIONS requests immediately
    if (req.method === 'OPTIONS') {
      res.status(204).send('');
      return;
    }

    if (req.method !== 'POST') {
      return res.status(405).send('Only POST allowed');
    }

    const { name, email, phone, referrerId } = req.body;
    if (!name || !email || !phone) {
      console.error('Missing required fields for manual entry:', { name, email, phone });
      return res.status(400).send('Missing required fields: name, email, and phone.');
    }

    try {
      await db.collection('raffle_entries').add({
        name,
        email,
        phone,
        referrerId: referrerId || 'unknown',
        submittedAt: admin.firestore.FieldValue.serverTimestamp(),
        status: 'manual_entry' // Assign a status for manual entries
      });
      res.status(200).send('Entry submitted successfully.');
    } catch (err) {
      console.error('Error saving manual entry:', err);
      res.status(500).send('Internal Server Error');
    }
  });
});
