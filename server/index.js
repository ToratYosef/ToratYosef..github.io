require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const paypal = require('@paypal/checkout-server-sdk');
const fetch = require('node-fetch'); // Still needed if you interact with other external APIs

const app = express();
const port = process.env.PORT || 3000;

// Configure CORS for local development (REMOVE OR RESTRICT IN PRODUCTION)
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*'); // Allow all origins for local testing
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

app.use(bodyParser.json());
app.use(express.static('../')); // Serve your frontend files from the parent directory

// Configure PayPal Environment
let environment;
if (process.env.PAYPAL_ENVIRONMENT === 'live') {
    environment = new paypal.core.LiveEnvironment(
        process.env.PAYPAL_CLIENT_ID,
        process.env.PAYPAL_CLIENT_SECRET
    );
} else {
    environment = new paypal.core.SandboxEnvironment(
        process.env.PAYPAL_CLIENT_ID,
        process.env.PAYPAL_CLIENT_SECRET
    );
}
const client = new paypal.core.PayPalHttpClient(environment);

// Placeholder for your Firestore setup in Node.js backend
// IMPORTANT: For local Node.js server, you need to set up Firebase Admin SDK
// You'd download a service account key JSON file and initialize it.
// For simplicity in this example, we'll just log and assume Firebase is handled by the Cloud Function.
// In a real app, you might use the Admin SDK here to save temporary order data.
// const admin = require('firebase-admin');
// const serviceAccount = require('./path/to/your/serviceAccountKey.json'); // <<<<<<<<<<<<<<<<< IMPORTANT
// admin.initializeApp({
//   credential: admin.credential.cert(serviceAccount),
//   databaseURL: "https://<YOUR_FIREBASE_PROJECT_ID>.firebaseio.com" // Or your Firestore project URL
// });
// const db = admin.firestore();


// Endpoint to create a PayPal order
app.post('/api/paypal/create-order', async (req, res) => {
    const { amount, name, email, phone, referral } = req.body; // Now receiving user info

    if (!amount || isNaN(amount) || parseFloat(amount) <= 0 || !name || !email || !phone) {
        return res.status(400).json({ error: 'Invalid or missing data provided.' });
    }

    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer('return=representation');
    request.requestBody({
        intent: 'CAPTURE',
        purchase_units: [
            {
                amount: {
                    currency_code: 'USD',
                    value: parseFloat(amount).toFixed(2)
                },
                // Pass custom ID or application_context for richer data (optional)
                // application_context: {
                //     shipping_preference: 'NO_SHIPPING' // For digital goods/raffle
                // }
            },
        ],
    });

    try {
        const order = await client.execute(request);
        const orderID = order.result.id;

        // Save order details to your temporary database (e.g., Firestore)
        // This data will be retrieved by the webhook to get phone/referral.
        // Assuming your backend can connect to Firebase here (setup not included in this file for brevity).
        // For now, let's just log it:
        console.log(`Created PayPal Order ID: ${orderID}. Storing temporary data for webhook retrieval.`);
        // await db.collection('paypalOrders').doc(orderID).set({
        //     name,
        //     email,
        //     phone,
        //     referral,
        //     amount: parseFloat(amount).toFixed(2),
        //     createdAt: admin.firestore.FieldValue.serverTimestamp(),
        //     status: 'pending'
        // });


        res.status(200).json({ orderID: orderID });
    } catch (error) {
        console.error('Error creating PayPal order:', error.response ? error.response.data : error);
        res.status(500).json({ error: 'Could not create PayPal order.' });
    }
});

// Endpoint to capture the PayPal order after frontend approval
app.post('/api/paypal/capture-order', async (req, res) => {
    const { orderID } = req.body; // Only orderID needed now, user info comes via webhook

    if (!orderID) {
        return res.status(400).json({ error: 'Missing PayPal Order ID.' });
    }

    const request = new paypal.orders.OrdersCaptureRequest(orderID);
    request.prefer('return=representation');

    try {
        const capture = await client.execute(request);
        const paymentStatus = capture.result.status; // Should be 'COMPLETED'

        if (paymentStatus === 'COMPLETED') {
            console.log(`PayPal Order ${orderID} captured successfully by frontend action. Capture ID: ${capture.result.id}`);
            // Do NOT call submitEntry here directly anymore.
            // The webhook will handle the final entry storage.
            res.status(200).json({ success: true, message: 'Payment captured. Confirming entry via webhook.' });
        } else {
            console.warn(`PayPal Order ${orderID} not completed during capture. Status: ${paymentStatus}`);
            res.status(400).json({ success: false, message: 'Payment not completed by PayPal.' });
        }
    } catch (error) {
        console.error('Error capturing PayPal order:', error.response ? error.response.data : error);
        res.status(500).json({ success: false, message: 'Could not capture PayPal order.', details: error.message });
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
    console.log(`Access frontend at http://localhost:${port}`);
});