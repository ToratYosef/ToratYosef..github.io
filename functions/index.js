// Corrected imports for 2nd Gen functions:
const { onRequest } = require('firebase-functions/v2/https');
const { setGlobalOptions } = require('firebase-functions/v2/options');
const { defineString } = require('firebase-functions/params'); // Import for new config system

const admin = require('firebase-admin');
const paypal = require('@paypal/checkout-server-sdk');
const express = require('express');
const bodyParser = require('body-parser');

admin.initializeApp();
const db = admin.firestore();

// Define configuration parameters using the new Firebase Functions (v2) params system
// This replaces functions.config()
const PAYPAL_CLIENT_ID = defineString('PAYPAL_CLIENT_ID');
const PAYPAL_CLIENT_SECRET = defineString('PAYPAL_CLIENT_SECRET');
const PAYPAL_ENVIRONMENT = defineString('PAYPAL_ENVIRONMENT');
const PAYPAL_WEBHOOK_ID = defineString('PAYPAL_WEBHOOK_ID');


// Set global options for all 2nd Gen functions in this file
setGlobalOptions({
    region: 'us-central1', // Ensure this matches your deployment region
    cpu: 1,
    memory: '256Mi',
    timeoutSeconds: 60
});

// Configure PayPal Environment using the new params system
let paypalEnvironment;
if (PAYPAL_ENVIRONMENT.value() === 'live') { // Access the value using .value()
    paypalEnvironment = new paypal.core.LiveEnvironment(
        PAYPAL_CLIENT_ID.value(),
        PAYPAL_CLIENT_SECRET.value()
    );
} else {
    paypalEnvironment = new paypal.core.SandboxEnvironment(
        PAYPAL_CLIENT_ID.value(),
        PAYPAL_CLIENT_SECRET.value()
    );
}
const paypalClient = new paypal.core.PayPalHttpClient(paypalEnvironment);

// Create an Express app for your webhook
const app = express();
app.use(bodyParser.json());

// Your webhook logic as an Express route
app.post('/', async (req, res) => {
    const webhookEvent = req.body;
    const authAlgo = req.headers['paypal-auth-algo'];
    const transmissionId = req.headers['paypal-transmission-id'];
    const transmissionSig = req.headers['paypal-transmission-sig'];
    const transmissionTime = req.headers['paypal-transmission-time'];
    // Access webhook ID from the defined parameter
    const webhookId = PAYPAL_WEBHOOK_ID.value();

    if (!webhookId) {
        console.error('PayPal Webhook ID is not configured in Firebase functions config.');
        return res.status(500).send('Webhook configuration error.');
    }

    const verificationRequest = new paypal.webhooks.WebhooksVerifySignatureRequest();
    verificationRequest.headers = {
        'paypal-auth-algo': authAlgo,
        'paypal-transmission-id': transmissionId,
        'paypal-transmission-sig': transmissionSig,
        'paypal-transmission-time': transmissionTime,
    };
    verificationRequest.body = JSON.stringify(webhookEvent);
    verificationRequest.path = `/v1/notifications/webhooks/${webhookId}`;

    try {
        const response = await paypalClient.execute(verificationRequest);
        if (response.result.verification_status !== 'SUCCESS') {
            console.error('Webhook verification failed:', response.result.verification_status);
            return res.status(400).send('Webhook verification failed');
        }
        console.log('Webhook successfully verified.');

    } catch (error) {
        console.error('Error verifying webhook signature:', error.response ? error.response.data : error);
        return res.status(400).send('Error verifying webhook signature');
    }

    const eventType = webhookEvent.event_type;
    console.log(`Received PayPal webhook event: ${eventType}`);

    if (eventType === 'CHECKOUT.ORDER.COMPLETED') {
        const orderId = webhookEvent.resource.id;
        const payerEmail = webhookEvent.resource.payer.email_address;
        const payerName = `${webhookEvent.resource.payer.name.given_name || ''} ${webhookEvent.resource.payer.name.surname || ''}`.trim();
        const transactionAmount = parseFloat(webhookEvent.resource.purchase_units[0].payments.captures[0].amount.value);
        const currency = webhookEvent.resource.purchase_units[0].payments.captures[0].amount.currency_code;
        const captureId = webhookEvent.resource.purchase_units[0].payments.captures[0].id;

        try {
            const orderDocRef = db.collection('paypalOrders').doc(orderId);
            const orderDoc = await orderDocRef.get();

            let customerName = payerName;
            let customerEmail = payerEmail;
            let customerPhone = null;
            let referralInfo = null;

            if (orderDoc.exists) {
                const orderData = orderDoc.data();
                customerPhone = orderData.phone || null;
                referralInfo = orderData.referral || null;
                customerName = orderData.name || customerName;
                customerEmail = orderData.email || customerEmail;
                console.log(`Retrieved additional data for order ${orderId}: Phone: ${customerPhone}, Referral: ${referralInfo}`);
            } else {
                console.warn(`Order document for ID ${orderId} not found in Firestore. Cannot retrieve phone/referral from your DB.`);
            }

            const entryData = {
                name: customerName,
                email: customerEmail,
                phone: customerPhone,
                referral: referralInfo,
                amount: transactionAmount,
                currency: currency,
                paypalOrderId: orderId,
                paypalCaptureId: captureId,
                paymentStatus: 'paid',
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                source: 'paypalWebhook'
            };

            await db.collection('raffleEntries').doc(orderId).set(entryData, { merge: true });
            console.log(`Raffle entry for PayPal Order ID ${orderId} recorded via webhook.`);

            if (orderDoc.exists) {
                await orderDocRef.update({ webhookProcessed: true, processedAt: admin.firestore.FieldValue.serverTimestamp() });
            }

            return res.status(200).send('Webhook received and processed.');

        } catch (error) {
            console.error('Error processing CHECKOUT.ORDER.COMPLETED webhook for Order ID:', orderId, error);
            return res.status(500).send('Error processing webhook.');
        }

    } else {
        console.log(`Unhandled PayPal event type: ${eventType}`);
        return res.status(200).send('Event type not handled.');
    }
});

// Export the Express app as a 2nd Gen HTTP Cloud Function
exports.paypalWebhook = onRequest(app);