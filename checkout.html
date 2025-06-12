const functions = require('firebase-functions');
const admin = require('firebase-admin');
const cors = require('cors')({ origin: 'https://torat-yosef.web.app' }); // <--- CORRECTED CORS ORIGIN
// For multiple origins (e.g., your custom domain and .web.app), you could use an array or a function:
// const allowedOrigins = ['https://torat-yosef.web.app', 'https://www.toratyosefsummerraffle.com'];
// const cors = require('cors')({
//   origin: (origin, callback) => {
//     if (allowedOrigins.indexOf(origin) !== -1 || !origin) { // !origin allows same-origin requests
//       callback(null, true);
//     } else {
//       callback(new Error('Not allowed by CORS'));
//     }
//   }
// });

const stripe = require('stripe');

// Initialize Firebase
admin.initializeApp();
const db = admin.firestore();

// Stripe environment variables (MUST BE SET VIA `firebase functions:config:set`)
const STRIPE_SECRET_KEY = functions.config().stripe.secret_key;
const STRIPE_WEBHOOK_SECRET = functions.config().stripe.webhook_secret;

// Initialize Stripe client
const stripeClient = stripe(STRIPE_SECRET_KEY);

// ------------------- Referral Tracker -------------------
exports.recordReferral = functions
  .runWith({ runtime: 'nodejs20' }) // Using Node.js 20 runtime
  .https.onRequest(async (req, res) => {
    // Add CORS for GET requests if they also come from a different origin
    cors(req, res, async () => { // Added cors wrapper for consistency
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
              lastClick: admin.firestore.FieldValue.serverTimestamp(),
            });
          } else {
            tx.update(refDoc, {
              count: (doc.data().count || 0) + 1,
              lastClick: admin.firestore.FieldValue.serverTimestamp(),
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
exports.createStripeCheckoutSession = functions
  .runWith({ runtime: 'nodejs20' }) // Using Node.js 20 runtime
  .https.onRequest(async (req, res) => {
    cors(req, res, async () => { // CORS middleware handles preflight and main request headers
      if (req.method !== 'POST') {
        return res.status(405).send('Only POST requests are allowed.');
      }

      const { referrerId, amount, quantity, prizeDescription, successUrl, cancelUrl } = req.body;

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
                product_data: {
                  name: prizeDescription,
                },
                unit_amount: amount, // Amount in cents (e.g., 12600 for $126.00)
              },
              quantity: quantity,
            },
          ],
          mode: 'payment',
          // Pass referrerId as client_reference_id
          client_reference_id: referrerId || 'unknown',
          return_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}`,
          // You can also add a cancel_url if needed, or let the embedded checkout handle it.
          // cancel_url: cancelUrl, // Uncomment if you want a separate cancel URL
        });

        res.status(200).json({ clientSecret: session.client_secret });

      } catch (error) {
        console.error('Error creating Stripe Checkout Session:', error);
        res.status(500).json({ error: 'Failed to create Stripe Checkout Session.', details: error.message });
      }
    });
  });

// ------------------- Stripe Webhook Handler -------------------
exports.handleStripeWebhook = functions
  .runWith({ runtime: 'nodejs20' }) // Using Node.js 20 runtime
  .https.onRequest(async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
      event = stripeClient.webhooks.constructEvent(req.rawBody, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error(`Webhook Error: ${err.message}`);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the event
    switch (event.type) {
      case 'checkout.session.completed':
        const session = event.data.object;
        console.log('Checkout Session Completed:', session.id);

        const paymentIntentId = session.payment_intent;
        const customerEmail = session.customer_details?.email || 'N/A';
        const amountTotal = session.amount_total;
        const currency = session.currency;
        const referrerId = session.client_reference_id || 'unknown'; // Retrieve referrerId from client_reference_id

        const paymentData = {
          stripeSessionId: session.id,
          paymentIntentId: paymentIntentId,
          customerEmail: customerEmail,
          amountTotal: amountTotal,
          currency: currency,
          paymentStatus: session.payment_status,
          referrerId: referrerId,
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
        };

        try {
          await db.collection('stripe_payments').doc(session.id).set(paymentData, { merge: true });
          console.log(`Stripe payment recorded for session: ${session.id}`);

          // Increment successful payments for the referrer if not 'unknown'
          if (referrerId !== 'unknown') {
            const referralRef = db.collection('referrals').doc(referrerId);
            await referralRef.update({
              successfulPayments: admin.firestore.FieldValue.increment(1),
            });
            console.log(`Referral count incremented for: ${referrerId}`);
          }

        } catch (error) {
          console.error('Error saving Stripe payment or updating referral:', error);
          return res.status(500).send('Internal Server Error processing event.');
        }
        break;

      case 'payment_intent.succeeded':
        const paymentIntent = event.data.object;
        console.log('Payment Intent Succeeded:', paymentIntent.id);
        // If you rely only on `checkout.session.completed` for Checkout Sessions,
        // you might log this but not perform further actions here to avoid duplication.
        break;

      // Handle other event types if needed
      default:
        console.log(`Unhandled event type ${event.type}`);
    }

    // Return a 200 response to acknowledge receipt of the event
    res.status(200).send('OK');
  });

// ------------------- Manual Entry Submission -------------------
exports.submitEntry = functions
  .runWith({ runtime: 'nodejs20' }) // Using Node.js 20 runtime
  .https.onRequest((req, res) => {
    cors(req, res, async () => { // CORS middleware handles preflight and main request headers
      if (req.method !== 'POST') return res.status(405).send('Only POST allowed');

      const { name, email, phone, referrerId } = req.body;
      if (!name || !email || !phone) {
        return res.status(400).send('Missing required fields.');
      }

      try {
        await db.collection('raffle_entries').add({
          name,
          email,
          phone,
          referrerId: referrerId || 'unknown',
          submittedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        res.status(200).send('Entry submitted successfully.');
      } catch (err) {
        console.error('Error saving entry:', err);
        res.status(500).send('Internal Server Error');
      }
    });
  });