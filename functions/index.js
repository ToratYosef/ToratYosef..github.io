/**
 * Firebase Cloud Functions for Yeshivat Torat Yosef Raffle.
 * This file contains:
 * 1. An HTTPS function to create Stripe Checkout Sessions for raffle ticket purchases.
 * 2. A Stripe Webhook handler to securely process payment events and update Firestore.
 * 3. A recordReferral function to log referral data.
 * 4. A submitEntry function for manual or non-Stripe raffle entries.
 * 5. A healthCheck function for basic service availability monitoring.
 */

// Import necessary Firebase modules
const { onRequest } = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");
const functions = require("firebase-functions"); // Required for functions.config()
const admin = require('firebase-admin'); // For Firestore and other Firebase services
const Stripe = require('stripe'); // Stripe Node.js library

// Initialize Firebase Admin SDK
admin.initializeApp();
const db = admin.firestore(); // Get a reference to Firestore

// Initialize Stripe with your secret key from Firebase environment config.
// This block now includes a stronger check and will throw an error if the key is missing,
// which should then appear clearly in the Cloud Run logs upon container startup failure.
let stripe;
try {
  // Check if functions.config() is loaded and has the stripe key
  if (functions.config().stripe && functions.config().stripe.secret_key) {
    stripe = new Stripe(functions.config().stripe.secret_key, {
      apiVersion: '2024-06-20', // Specify a recent Stripe API version
    });
    logger.info('Stripe initialized successfully from config.');
  } else {
    // If config is not found, throw an error. This will cause the container to fail to start.
    const errorMessage = 'CRITICAL ERROR: Stripe secret key is missing from Firebase functions config. Please set it using `firebase functions:config:set stripe.secret_key="YOUR_KEY"`.';
    logger.error(errorMessage);
    throw new Error(errorMessage); // This makes the health check fail with a clear log entry.
  }
} catch (error) {
  // Catch any unexpected errors during Stripe initialization (e.g., malformed key)
  logger.error('CRITICAL ERROR: Unexpected error during Stripe initialization:', error);
  throw error; // Re-throw to ensure container fails health check and logs this.
}

// --- Health Check Function ---
/**
 * A simple HTTPS function to confirm if the Cloud Run service is starting and
 * global initializations (like Firebase Admin and Stripe) are succeeding.
 * Access this URL directly to check its status.
 */
exports.healthCheck = onRequest((req, res) => {
  res.set('Access-Control-Allow-Origin', 'https://www.toratyosefsummerraffle.com'); // CORS for frontend calls
  res.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }
  logger.info('Health check endpoint hit. All global initializations succeeded if this log is seen.');
  res.status(200).send('OK');
});


// --- createStripeCheckoutSession function ---
/**
 * HTTPS function to create a Stripe Checkout Session.
 *
 * This function is designed to be called from your frontend. It generates a
 * Stripe Checkout Session, which is then used by the frontend to display
 * the embedded Stripe payment form.
 *
 * It expects a POST request with the following parameters in the body:
 * - `referrerId`: string (optional) - ID of the referrer for tracking.
 * - `quantity`: number - Number of raffle tickets the user wants to buy.
 * - `amount`: number - The unit price *per ticket* in cents (e.g., 12600 for $126.00).
 * - `prizeDescription`: string - A brief description of the item being purchased (e.g., "Raffle Ticket").
 * - `successUrl`: string - The URL on your site where Stripe redirects upon successful payment.
 * - `cancelUrl`: string - The URL on your site where Stripe redirects if the user cancels.
 * - `fullName`: string - The full name of the customer.
 * - `email`: string - The email address of the customer.
 * - `phoneNumber`: string (optional) - The phone number of the customer.
 */
exports.createStripeCheckoutSession = onRequest(async (req, res) => {
  // Set CORS headers to allow requests from your frontend.
  // IMPORTANT: For production, replace '*' with your actual domain(s) for security,
  // e.g., 'https://www.your-raffle-domain.com'.
  res.set('Access-Control-Allow-Origin', 'https://www.toratyosefsummerraffle.com'); // <-- Changed for CORS
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight OPTIONS request from the browser.
  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }

  // Ensure the request is a POST request.
  if (req.method !== 'POST') {
    logger.warn('createStripeCheckoutSession: Received non-POST request.', { method: req.method });
    return res.status(405).send('Method Not Allowed');
  }

  // Destructure required parameters from the request body
  const {
    referrerId,
    quantity,
    amount,
    prizeDescription,
    successUrl,
    cancelUrl,
    fullName,
    email,
    phoneNumber
  } = req.body;

  // Validate presence of essential parameters
  if (!quantity || !amount || !prizeDescription || !successUrl || !cancelUrl || !fullName || !email) {
    logger.error('createStripeCheckoutSession: Missing required parameters.', { body: req.body });
    return res.status(400).json({
      error: 'Missing required parameters: quantity, amount, prizeDescription, successUrl, cancelUrl, fullName, email'
    });
  }

  // Basic email format validation
  if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
    logger.error('createStripeCheckoutSession: Invalid email format provided.', { email });
    return res.status(400).json({ error: 'Invalid email format' });
  }

  logger.info("createStripeCheckoutSession: Attempting to create Stripe Checkout Session.", {
    referrerId,
    quantity,
    amount,
    prizeDescription,
    fullName,
    email,
    phoneNumber: phoneNumber || 'N/A', // Log 'N/A' if phone number is not provided
  });

  try {
    // Create a new Stripe Checkout Session.
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'], // Only allow card payments for this session
      line_items: [
        {
          price_data: {
            currency: 'usd', // Set your desired currency (e.g., 'usd', 'cad', 'ils')
            product_data: {
              name: prizeDescription, // Name of the product (e.g., "Raffle Ticket")
            },
            unit_amount: amount, // Price per unit in cents
          },
          quantity: quantity, // Number of units (tickets)
        },
      ],
      mode: 'payment', // Set the session mode to 'payment' for one-time purchases

      // Dynamic success and cancel URLs, preserving the referrerId and adding session ID.
      success_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}&ref=${encodeURIComponent(referrerId || 'none')}`,
      cancel_url: `${cancelUrl}?ref=${encodeURIComponent(referrerId || 'none')}`,

      // Pre-fill customer email on the Stripe Checkout page for better UX.
      customer_email: email,

      // Attach custom metadata to the Checkout Session. This data will be securely
      // passed through to Stripe and will be available in webhook events.
      // It's crucial for linking the payment back to your application's logic.
      metadata: {
        referrerId: referrerId || 'none',
        fullName: fullName,
        email: email,
        phoneNumber: phoneNumber || 'N/A',
        itemDescription: prizeDescription,
        quantity: String(quantity), // Store as string as Stripe metadata values are strings
        totalAmountPaidCents: String(amount * quantity), // Total amount in cents for the session
      },
    });

    logger.info('createStripeCheckoutSession: Stripe Checkout Session created successfully.', {
      sessionId: session.id,
      clientSecret: session.client_secret
    });

    // Respond with the client secret. The frontend uses this to render
    // the embedded Stripe Checkout UI.
    res.status(200).json({ clientSecret: session.client_secret });

  } catch (error) {
    logger.error('createStripeCheckoutSession: Error creating Stripe Checkout Session.', error);
    // Send a user-friendly error message to the frontend.
    res.status(500).json({ error: error.message || 'Failed to create payment session.' });
  }
});

// --- stripeWebhook function ---
/**
 * Stripe Webhook endpoint to handle post-payment events and update Firestore.
 *
 * This function is critical for securely confirming payments and fulfilling orders.
 * NEVER rely solely on frontend redirects for payment fulfillment, as they are unreliable.
 *
 * To use this function:
 * 1. Ensure it's deployed.
 * 2. Set `stripe.webhook_secret` in Firebase config.
 * 3. Configure a webhook in your Stripe Dashboard to point to this Cloud Function's URL
 * (e.g., `https://us-central1-YOUR_PROJECT_ID.cloudfunctions.net/stripeWebhook`).
 * Listen for the `checkout.session.completed` event.
 */
exports.stripeWebhook = onRequest(async (req, res) => {
  // CORS is not typically needed for Stripe webhooks as they are server-to-server calls,
  // but keeping it consistent with your frontend domain just in case of unusual proxy setups.
  res.set('Access-Control-Allow-Origin', 'https://www.toratyosefsummerraffle.com'); // <-- Changed for CORS
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return;
  }

  // Ensure the request is a POST request, as webhooks are always POST.
  if (req.method !== 'POST') {
    logger.warn('stripeWebhook: Received non-POST request.', { method: req.method });
    return res.status(405).send('Method Not Allowed');
  }

  const sig = req.headers['stripe-signature']; // Get the Stripe signature from request headers
  let event;

  try {
    // Construct the event from the raw request body and validate the signature.
    // `req.rawBody` contains the unprocessed body buffer, essential for signature verification.
    event = stripe.webhooks.constructEvent(req.rawBody, sig, functions.config().stripe.webhook_secret);
  } catch (err) {
    // If signature verification fails, log the error and return 400.
    logger.error('stripeWebhook: Signature verification failed.', { error: err.message, signature: sig });
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the event based on its type.
  switch (event.type) {
    case 'checkout.session.completed':
      const session = event.data.object; // The Checkout Session object
      logger.info('stripeWebhook: Checkout Session Completed event received.', {
        sessionId: session.id,
        metadata: session.metadata
      });

      // Extract relevant data from the session and its metadata.
      // Use optional chaining (`?.`) and nullish coalescing (`||`) for safety.
      const {
        id: stripeSessionId,
        payment_intent: paymentIntentId,
        amount_total: amountTotalCents, // Total amount charged for the session (from Stripe)
        customer_details: { email: customerEmailFromStripe } = {}, // Customer email from Stripe
      } = session;

      // Custom metadata you passed when creating the session
      const {
        fullName,
        email, // This email comes from your metadata, which you sent.
        phoneNumber,
        referrerId,
        itemDescription,
        quantity,
        totalAmountPaidCents, // This is from your metadata, if explicitly set
      } = session.metadata || {}; // Ensure metadata exists to avoid errors

      // Prepare the data to be stored in Firestore
      const firestoreData = {
        stripeSessionId: stripeSessionId,
        paymentIntentId: paymentIntentId,
        status: 'completed', // Mark payment as successfully completed

        // Use the totalAmountPaidCents from metadata if available and valid,
        // otherwise fall back to amountTotalCents from Stripe's session.
        // Ensure conversion to number as metadata stores strings.
        amountPaidCents: totalAmountPaidCents ? parseInt(totalAmountPaidCents, 10) : amountTotalCents,
        quantity: quantity ? parseInt(quantity, 10) : 1, // Default quantity to 1 if parsing fails or missing

        customer: {
          fullName: fullName || 'N/A',
          email: email || customerEmailFromStripe, // Prefer email from your metadata, fallback to Stripe's
          phoneNumber: phoneNumber || 'N/A'
        },
        referrerId: referrerId || 'none',
        itemDescription: itemDescription || 'Raffle Ticket',
        timestamp: admin.firestore.FieldValue.serverTimestamp(), // Firestore server timestamp for accuracy
        // Add any additional fields you need, e.g., generated ticket numbers
        // ticketsAssigned: [],
      };

      try {
        // Write the payment confirmation data to Firestore.
        // Using `doc(stripeSessionId)` ensures each payment has a unique document ID.
        await db.collection('raffleEntries').doc(stripeSessionId).set(firestoreData);
        logger.info(`stripeWebhook: Firestore document created for session: ${stripeSessionId}`);

      } catch (firestoreError) {
        logger.error('stripeWebhook: Error writing to Firestore:', firestoreError);
        // CRITICAL: If Firestore write fails, do NOT return a non-200 status to Stripe.
        // Stripe will retry the webhook, potentially leading to duplicate entries if the
        // error is transient and you fix it later. Instead, log the error loudly
        // and ensure you have an alerting system (e.g., Cloud Monitoring, email alerts)
        // to manually reconcile such failed writes.
      }
      break;

    // You can add more cases to handle other Stripe event types if needed.
    // For instance, `payment_intent.succeeded` is often used, but `checkout.session.completed`
    // is usually sufficient for fulfilling orders created via Checkout Sessions.
    // case 'payment_intent.succeeded':
    //   const paymentIntent = event.data.object;
    //   logger.info('stripeWebhook: Payment Intent Succeeded event received.', { paymentIntentId: paymentIntent.id });
    //   // Additional logic if needed for payment intent details
    //   break;

    default:
      // Log any unhandled event types for debugging or future expansion.
      logger.info(`stripeWebhook: Unhandled event type: ${event.type}`);
  }

  // ALWAYS return a 200 OK status to Stripe to acknowledge successful receipt of the event.
  // If Stripe doesn't receive a 200, it will assume the delivery failed and retry,
  // which can lead to duplicate processing if your function actually succeeded but failed to respond.
  res.status(200).json({ received: true });
});


// --- recordReferral function ---
/**
 * HTTPS function to record a referral.
 * This function would typically be called from your frontend when a new user signs up
 * via a referral link, or when a referral action is completed.
 * It expects a POST request with `referrerId` and `newUserId` (or equivalent).
 */
exports.recordReferral = onRequest(async (req, res) => {
  res.set('Access-Control-Allow-Origin', 'https://www.toratyosefsummerraffle.com'); // <-- Changed for CORS
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');

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
    // Store referral in Firestore in a 'referrals' collection
    await db.collection('referrals').add({
      referrerId: referrerId,
      newUserId: newUserId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'pending_conversion' // e.g., could change to 'converted' on a successful purchase
    });
    res.status(200).json({ message: 'Referral recorded successfully.' });
  } catch (error) {
    logger.error('recordReferral: Error recording referral:', error);
    res.status(500).json({ error: 'Failed to record referral.' });
  }
});

// --- submitEntry function ---
/**
 * HTTPS function to submit a raffle entry directly.
 * This might be used for manual entries, free entries, or specific campaigns
 * where payment is not handled via Stripe directly.
 * It expects a POST request with `fullName`, `email`, `ticketCount`, and optional `source`.
 */
exports.submitEntry = onRequest(async (req, res) => {
  res.set('Access-Control-Allow-Origin', 'https://www.toratyosefsummerraffle.com'); // <-- Changed for CORS
  res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type');

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
    // Add entry to a different Firestore collection, e.g., 'raffleManualEntries'
    // or merge with 'raffleEntries' if you have a field to differentiate source.
    await db.collection('raffleManualEntries').add({
      fullName: fullName,
      email: email,
      ticketCount: ticketCount,
      source: source || 'manual_entry', // e.g., 'admin-panel', 'free-promo'
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      processed: false // You might have a separate process to assign actual ticket numbers for these
    });
    res.status(200).json({ message: 'Raffle entry submitted successfully.' });
  } catch (error) {
    logger.error('submitEntry: Error submitting entry:', error);
    res.status(500).json({ error: 'Failed to submit raffle entry.' });
  }
});