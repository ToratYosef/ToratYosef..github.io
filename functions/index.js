/**
 * Firebase Cloud Functions for Yeshivat Torat Yosef Raffle.
 * This file contains:
 * 1. An HTTPS function to create Stripe Checkout Sessions for raffle ticket purchases.
 * 2. A Stripe Webhook handler to securely process payment events and update Firestore.
 * 3. A sessionStatus function to check Stripe Checkout Session status.
 * 4. A recordReferral function to log referral data.
 * 5. A submitEntry function for manual or non-Stripe raffle entries.
 * 6. A healthCheck function for basic service availability monitoring.
 */

// Import necessary Firebase modules
const { onRequest } = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");
const functions = require("firebase-functions"); // Keep this if you need other 'functions' exports, but not for config()
const admin = require('firebase-admin'); // For Firestore and other Firebase services
const Stripe = require('stripe'); // Stripe Node.js library

// Initialize Firebase Admin SDK
admin.initializeApp();
const db = admin.firestore(); // Get a reference to Firestore

// Initialize Stripe with your secret key from Firebase environment variables.
// CORRECTED: Use process.env instead of functions.config()
let stripe;
try {
  // Access environment variables directly via process.env
  const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY; // Variable name from firebase functions:config:set
  const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET; // Variable name from firebase functions:config:set

  if (STRIPE_SECRET_KEY) {
    stripe = new Stripe(STRIPE_SECRET_KEY, {
      apiVersion: '2024-06-20', // Specify a recent Stripe API version
    });
    logger.info('Stripe initialized successfully from environment variables.');
  } else {
    const errorMessage = 'CRITICAL ERROR: Stripe secret key (STRIPE_SECRET_KEY) is missing from environment variables. Please set it using `firebase functions:config:set stripe.secret_key=\"YOUR_KEY\"` and redeploy.';
    logger.error(errorMessage);
    throw new Error(errorMessage);
  }
  // You might also want to explicitly check STRIPE_WEBHOOK_SECRET if it's critical for initialization
  if (!STRIPE_WEBHOOK_SECRET) {
    const errorMessage = 'CRITICAL ERROR: Stripe webhook secret (STRIPE_WEBHOOK_SECRET) is missing from environment variables. Please set it using `firebase functions:config:set stripe.webhook_secret=\"YOUR_KEY\"` and redeploy.';
    logger.error(errorMessage);
    throw new Error(errorMessage);
  }
} catch (error) {
  logger.error('CRITICAL ERROR: Unexpected error during Stripe initialization:', error);
  throw error;
}

// Define your allowed origins for CORS
const allowedOrigins = [
  'https://www.toratyosefsummerraffle.com',
  'https://torat-yosef.web.app',
  // IMPORTANT: For local development, if you're serving from localhost, add it here:
  // 'http://localhost:8080' // Or whatever port your local server runs on
];

// Helper function to set CORS headers dynamically
function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
  }
  res.set('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');
  // res.set('Access-Control-Allow-Credentials', 'true');
}


// --- Health Check Function ---
exports.healthCheck = onRequest((req, res) => {
  setCorsHeaders(req, res);
  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }
  logger.info('Health check endpoint hit.');
  res.status(200).send('OK');
});


// --- createStripeCheckoutSession function ---
exports.createStripeCheckoutSession = onRequest(async (req, res) => {
  setCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }

  if (req.method !== 'POST') {
    logger.warn('createStripeCheckoutSession: Received non-POST request.', { method: req.method });
    return res.status(405).send('Method Not Allowed');
  }

  const {
    referrerId, quantity, amount, prizeDescription, successUrl, cancelUrl, fullName, email, phoneNumber
  } = req.body;

  if (!quantity || !amount || !prizeDescription || !successUrl || !cancelUrl || !fullName || !email) {
    logger.error('createStripeCheckoutSession: Missing required parameters.', { body: req.body });
    return res.status(400).json({
      error: 'Missing required parameters: quantity, amount, prizeDescription, successUrl, cancelUrl, fullName, email'
    });
  }

  if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
    logger.error('createStripeCheckoutSession: Invalid email format provided.', { email });
    return res.status(400).json({ error: 'Invalid email format' });
  }

  logger.info("createStripeCheckoutSession: Attempting to create Stripe Checkout Session.", {
    referrerId, quantity, amount, prizeDescription, fullName, email, phoneNumber: phoneNumber || 'N/A',
  });

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: { name: prizeDescription },
            unit_amount: amount,
          },
          quantity: quantity,
        },
      ],
      mode: 'payment',
      success_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}&ref=${encodeURIComponent(referrerId || 'none')}`,
      cancel_url: `${cancelUrl}?ref=${encodeURIComponent(referrerId || 'none')}`,
      customer_email: email,
      metadata: {
        referrerId: referrerId || 'none',
        fullName: fullName,
        email: email,
        phoneNumber: phoneNumber || 'N/A',
        itemDescription: prizeDescription,
        quantity: String(quantity),
        totalAmountPaidCents: String(amount * quantity),
      },
    });

    logger.info('createStripeCheckoutSession: Stripe Checkout Session created successfully.', {
      sessionId: session.id, clientSecret: session.client_secret
    });

    res.status(200).json({ clientSecret: session.client_secret });

  } catch (error) {
    logger.error('createStripeCheckoutSession: Error creating Stripe Checkout Session.', error);
    res.status(500).json({ error: error.message || 'Failed to create payment session.' });
  }
});


// --- stripeWebhook function ---
exports.stripeWebhook = onRequest(async (req, res) => {
  setCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }

  if (req.method !== 'POST') {
    logger.warn('stripeWebhook: Received non-POST request.', { method: req.method });
    return res.status(405).send('Method Not Allowed');
  }

  const sig = req.headers['stripe-signature'];
  let event;

  try {
    // Access webhook secret from process.env
    event = stripe.webhooks.constructEvent(req.rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    logger.error('stripeWebhook: Signature verification failed.', { error: err.message, signature: sig });
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'checkout.session.completed':
      const session = event.data.object;
      logger.info('stripeWebhook: Checkout Session Completed event received.', {
        sessionId: session.id, metadata: session.metadata
      });

      const {
        id: stripeSessionId, payment_intent: paymentIntentId, amount_total: amountTotalCents,
        customer_details: { email: customerEmailFromStripe } = {},
      } = session;

      const {
        fullName, email, phoneNumber, referrerId, itemDescription, quantity, totalAmountPaidCents,
      } = session.metadata || {};

      const firestoreData = {
        stripeSessionId: stripeSessionId,
        paymentIntentId: paymentIntentId,
        status: 'completed',
        amountPaidCents: totalAmountPaidCents ? parseInt(totalAmountPaidCents, 10) : amountTotalCents,
        quantity: quantity ? parseInt(quantity, 10) : 1,
        customer: {
          fullName: fullName || 'N/A', email: email || customerEmailFromStripe, phoneNumber: phoneNumber || 'N/A'
        },
        referrerId: referrerId || 'none',
        itemDescription: itemDescription || 'Raffle Ticket',
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
      };

      try {
        await db.collection('raffleEntries').doc(stripeSessionId).set(firestoreData);
        logger.info(`stripeWebhook: Firestore document created for session: ${stripeSessionId}`);
      } catch (firestoreError) {
        logger.error('stripeWebhook: Error writing to Firestore:', firestoreError);
      }
      break;

    default:
      logger.info(`stripeWebhook: Unhandled event type: ${event.type}`);
  }

  res.status(200).json({ received: true });
});


// --- sessionStatus function ---
exports.sessionStatus = onRequest(async (req, res) => {
  setCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }

  if (req.method !== 'GET') {
    logger.warn('sessionStatus: Received non-GET request.', { method: req.method });
    return res.status(405).send('Method Not Allowed');
  }

  const sessionId = req.query.session_id;

  if (!sessionId) {
    logger.error('sessionStatus: Missing session_id parameter.', { query: req.query });
    return res.status(400).json({ error: 'Missing session_id parameter.' });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const customerEmail = session.customer_details ? session.customer_details.email : null;

    logger.info('sessionStatus: Retrieved session status.', { sessionId, status: session.status, customerEmail });

    res.status(200).json({
      status: session.status, customer_email: customerEmail
    });
  } catch (error) {
    logger.error('sessionStatus: Error retrieving session status:', error);
    res.status(500).json({ error: error.message || 'Failed to retrieve session status.' });
  }
});


// --- recordReferral function ---
exports.recordReferral = onRequest(async (req, res) => {
  setCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }

  if (req.method !== 'POST') {
    logger.warn('recordReferral: Received non-POST request.', { method: req.method });
    return res.status(405).send('Method Not Allowed');
  }

  const { referrerId, newUserId } = req.body;

  if (!referrerId || !newUserId) {
    logger.error('recordReferral: Missing referrerId or newUserId.', { body: req.body });
    return res.status(400).json({ error: 'Missing referrerId or newUserId.' });
  }

  logger.info(`recordReferral: Recording referral from ${referrerId} for user ${newUserId}.`);

  try {
    await db.collection('referrals').add({
      referrerId: referrerId,
      newUserId: newUserId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'pending_conversion'
    });
    res.status(200).json({ message: 'Referral recorded successfully.' });
  } catch (error) {
    logger.error('recordReferral: Error recording referral:', error);
    res.status(500).json({ error: 'Failed to record referral.' });
  }
});

// --- submitEntry function ---
exports.submitEntry = onRequest(async (req, res) => {
  setCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }

  if (req.method !== 'POST') {
    logger.warn('submitEntry: Received non-POST request.', { method: req.method });
    return res.status(405).send('Method Not Allowed');
  }

  const { fullName, email, ticketCount, source } = req.body;

  if (!fullName || !email || !ticketCount) {
    logger.error('submitEntry: Missing required entry details.', { body: req.body });
    return res.status(400).json({ error: 'Missing required entry details.' });
  }

  logger.info(`submitEntry: Processing entry for ${fullName} (${email}), tickets: ${ticketCount}.`);

  try {
    await db.collection('raffleManualEntries').add({
      fullName: fullName,
      email: email,
      ticketCount: ticketCount,
      source: source || 'manual_entry',
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      processed: false
    });
    res.status(200).json({ message: 'Raffle entry submitted successfully.' });
  } catch (error) {
    logger.error('submitEntry: Error submitting entry:', error);
    res.status(500).json({ error: 'Failed to submit raffle entry.' });
  }
});