require('dotenv').config();
const path = require('path');
const express = require('express');
const paypal = require('@paypal/checkout-server-sdk');
const admin = require('firebase-admin');
const ExcelJS = require('exceljs');
const Stripe = require('stripe');

const app = express();
const port = process.env.PORT || 3000;
const webRoot = path.resolve(__dirname, '..');

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.applicationDefault()
    });
}

const db = admin.firestore();
const ticketPrice = 126;
const siteDomain = process.env.DOMAIN || 'https://toratyosefsummerraffle.com';

const stripeSecret = process.env.STRIPE_SECRET_KEY;
const stripe = stripeSecret ? new Stripe(stripeSecret) : null;

let paypalEnvironment;
if (process.env.PAYPAL_ENVIRONMENT === 'live') {
    paypalEnvironment = new paypal.core.LiveEnvironment(
        process.env.PAYPAL_CLIENT_ID,
        process.env.PAYPAL_CLIENT_SECRET
    );
} else {
    paypalEnvironment = new paypal.core.SandboxEnvironment(
        process.env.PAYPAL_CLIENT_ID,
        process.env.PAYPAL_CLIENT_SECRET
    );
}
const paypalClient = new paypal.core.PayPalHttpClient(paypalEnvironment);

app.use(express.json({ limit: '2mb' }));
app.use(express.static(webRoot));

function getBearerToken(req) {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) {
        return null;
    }
    return authHeader.slice(7);
}

async function requireAuth(req, res, next) {
    try {
        const token = getBearerToken(req);
        if (!token) {
            return res.status(401).json({ error: 'Missing auth token.' });
        }
        req.user = await admin.auth().verifyIdToken(token);
        return next();
    } catch (error) {
        console.error('Auth verification failed:', error.message);
        return res.status(401).json({ error: 'Invalid auth token.' });
    }
}

function requireSuperAdmin(req, res, next) {
    if (!req.user || req.user.superAdminReferrer !== true) {
        return res.status(403).json({ error: 'Super admin access required.' });
    }
    return next();
}

function toLocalTimeString(timestamp) {
    if (!timestamp || typeof timestamp.toDate !== 'function') {
        return 'N/A';
    }
    return timestamp.toDate().toLocaleString('en-US', {
        month: '2-digit',
        day: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
        timeZone: 'America/New_York'
    });
}

async function resolveReferrerUidByRefId(refId) {
    if (!refId) {
        return null;
    }
    const snapshot = await db.collection('referrers').where('refId', '==', refId).limit(1).get();
    if (snapshot.empty) {
        return null;
    }
    return snapshot.docs[0].id;
}

app.get('/api/health', (req, res) => {
    res.status(200).json({ ok: true });
});

app.post('/api/paypal/create-order', async (req, res) => {
    const { amount, quantity, name, email, phone, referral } = req.body;
    const parsedAmount = parseFloat(amount);

    if (!parsedAmount || Number.isNaN(parsedAmount) || parsedAmount <= 0 || !name || !email || !phone) {
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
                    value: parsedAmount.toFixed(2)
                }
            }
        ]
    });

    try {
        const order = await paypalClient.execute(request);
        const orderID = order.result.id;

        await db.collection('paypal_orders').doc(orderID).set({
            name,
            email,
            phone,
            referrerRefId: referral || null,
            amount: parsedAmount,
            quantity: quantity || Math.max(1, Math.round(parsedAmount / ticketPrice)),
            status: 'PENDING',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        return res.status(200).json({ orderID });
    } catch (error) {
        console.error('Error creating PayPal order:', error.message);
        return res.status(500).json({ error: 'Could not create PayPal order.' });
    }
});

app.post('/api/paypal/capture-order', async (req, res) => {
    const { orderID } = req.body;
    if (!orderID) {
        return res.status(400).json({ error: 'Missing PayPal order ID.' });
    }

    const request = new paypal.orders.OrdersCaptureRequest(orderID);
    request.prefer('return=representation');

    try {
        const capture = await paypalClient.execute(request);
        const paymentStatus = capture.result.status;

        if (paymentStatus !== 'COMPLETED') {
            return res.status(400).json({ success: false, message: 'Payment not completed by PayPal.' });
        }

        await db.collection('paypal_orders').doc(orderID).set({
            status: 'COMPLETED',
            captureData: capture.result,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        return res.status(200).json({ success: true, message: 'Payment captured successfully.' });
    } catch (error) {
        console.error('Error capturing PayPal order:', error.message);
        return res.status(500).json({ success: false, message: 'Could not capture PayPal order.' });
    }
});

app.post('/api/paypal/webhook', async (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).send('Method Not Allowed');
    }

    try {
        const event = req.body;
        if (!event || !event.event_type) {
            return res.status(400).send('Invalid webhook payload.');
        }

        if (event.event_type !== 'CHECKOUT.ORDER.APPROVED' && event.event_type !== 'PAYMENT.CAPTURE.COMPLETED') {
            return res.status(200).send('Webhook event ignored.');
        }

        const orderID = event.resource?.id || event.resource?.supplementary_data?.related_ids?.order_id;
        if (!orderID) {
            return res.status(400).send('No order ID found in webhook event.');
        }

        const orderRef = db.collection('paypal_orders').doc(orderID);
        const orderDoc = await orderRef.get();

        if (!orderDoc.exists) {
            return res.status(200).send('Order not found locally, webhook acknowledged.');
        }

        const orderData = orderDoc.data();
        if (orderData.raffleEntryCreatedAt) {
            return res.status(200).send('Already processed.');
        }

        const resolvedReferrerUid = await resolveReferrerUidByRefId(orderData.referrerRefId);
        const ticketsBought = Math.max(1, Math.floor((orderData.amount || 0) / ticketPrice));

        await db.collection('raffle_entries').add({
            name: orderData.name,
            email: orderData.email,
            phone: orderData.phone,
            referrerRefId: orderData.referrerRefId || null,
            referrerUid: resolvedReferrerUid,
            amount: orderData.amount,
            ticketsBought,
            paymentStatus: 'completed',
            orderID,
            timestamp: orderData.createdAt || admin.firestore.FieldValue.serverTimestamp(),
            entryType: 'paypal',
            paypalEventId: event.id,
            webhookEventType: event.event_type
        });

        await orderRef.update({
            raffleEntryCreatedAt: admin.firestore.FieldValue.serverTimestamp(),
            webhookProcessed: true,
            lastWebhookEvent: event
        });

        return res.status(200).send('Webhook processed successfully.');
    } catch (error) {
        console.error('PayPal webhook error:', error.message);
        return res.status(500).send('Internal Server Error during webhook processing.');
    }
});

app.post('/api/stripe/create-checkout-session', async (req, res) => {
    if (!stripe) {
        return res.status(500).json({ error: 'Stripe is not configured on the server.' });
    }

    const { name, email, phone, referral } = req.body;
    if (!name || !email || !phone) {
        return res.status(400).json({ error: 'Missing required fields: name, email, phone.' });
    }

    try {
        const orderRef = db.collection('stripe_orders').doc();
        const orderId = orderRef.id;
        const priceCents = 12600;

        await orderRef.set({
            name,
            email,
            phone,
            referrerRefId: referral || null,
            quantity: 1,
            amount: priceCents,
            status: 'pending',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'usd',
                        product_data: {
                            name: 'Rolex Raffle Entry',
                            description: 'Raffle entry for the Rolex Datejust 41 prize.'
                        },
                        unit_amount: priceCents
                    },
                    quantity: 1
                }
            ],
            mode: 'payment',
            success_url: `${siteDomain}/success.html?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${siteDomain}/prizes.html`,
            customer_email: email,
            metadata: {
                orderId,
                name,
                phone,
                referrerRefId: referral || ''
            }
        });

        await orderRef.update({
            sessionId: session.id,
            sessionUrl: session.url
        });

        return res.status(200).json({ sessionId: session.id, url: session.url });
    } catch (error) {
        console.error('Stripe checkout error:', error.message);
        return res.status(500).json({ error: 'Failed to create Stripe checkout session.' });
    }
});

app.get('/api/admin/referrer-dashboard', requireAuth, async (req, res) => {
    try {
        const loggedInUid = req.user.uid;
        const isViewer = req.user.viewer === true && typeof req.user.viewReferrerUid === 'string';
        const isSuperAdmin = req.user.superAdminReferrer === true;

        let targetReferrerUid = loggedInUid;
        if (isViewer) {
            targetReferrerUid = req.user.viewReferrerUid;
        }

        let referrerDoc = await db.collection('referrers').doc(targetReferrerUid).get();
        if (!referrerDoc.exists && !isSuperAdmin) {
            return res.status(404).json({ error: 'Referrer data not found.' });
        }

        const currentReferrer = referrerDoc.exists ? referrerDoc.data() : {
            name: 'Master Admin',
            refId: 'N/A',
            goal: 0
        };

        let totalTicketsSold = 0;
        const buyerDetails = [];
        let allReferrersSummary = [];

        if (isSuperAdmin) {
            const allEntriesSnapshot = await db.collection('raffle_entries').get();
            const aggregated = {};

            allEntriesSnapshot.forEach((doc) => {
                const entry = doc.data();
                if (!entry.referrerUid) {
                    return;
                }
                if (!aggregated[entry.referrerUid]) {
                    aggregated[entry.referrerUid] = { totalTickets: 0, totalAmount: 0 };
                }
                aggregated[entry.referrerUid].totalTickets += entry.ticketsBought || 0;
                aggregated[entry.referrerUid].totalAmount += entry.amount || 0;
            });

            const referrersSnapshot = await db.collection('referrers').get();
            referrersSnapshot.forEach((doc) => {
                const data = doc.data();
                const sales = aggregated[doc.id] || { totalTickets: 0, totalAmount: 0 };
                allReferrersSummary.push({
                    uid: doc.id,
                    name: data.name,
                    refId: data.refId,
                    goal: data.goal || 0,
                    totalTicketsSold: sales.totalTickets,
                    totalAmountRaised: sales.totalAmount,
                    ticketsRemaining: (data.goal || 0) - sales.totalTickets
                });
            });
        }

        const ownEntriesSnapshot = await db.collection('raffle_entries')
            .where('referrerUid', '==', targetReferrerUid)
            .orderBy('timestamp', 'desc')
            .get();

        ownEntriesSnapshot.forEach((doc) => {
            const entry = doc.data();
            totalTicketsSold += entry.ticketsBought || 0;
            if (!isViewer) {
                buyerDetails.push({
                    id: doc.id,
                    name: entry.name,
                    email: entry.email,
                    phone: entry.phone,
                    ticketsBought: entry.ticketsBought,
                    timestamp: toLocalTimeString(entry.timestamp)
                });
            }
        });

        const referralLink = currentReferrer.refId && currentReferrer.refId !== 'N/A'
            ? `${siteDomain}/?ref=${currentReferrer.refId}`
            : null;

        return res.status(200).json({
            name: currentReferrer.name,
            refId: currentReferrer.refId,
            goal: currentReferrer.goal || 0,
            totalTicketsSold,
            buyerDetails,
            referralLink,
            isViewer,
            isSuperAdminReferrer: isSuperAdmin,
            allReferrersSummary
        });
    } catch (error) {
        console.error('Dashboard API error:', error.message);
        return res.status(500).json({ error: 'Failed to retrieve dashboard data.' });
    }
});

app.get('/api/admin/referrers', requireAuth, async (req, res) => {
    try {
        const snapshot = await db.collection('referrers').get();
        const referrers = [];
        snapshot.forEach((doc) => {
            const data = doc.data();
            referrers.push({ uid: doc.id, name: data.name, refId: data.refId });
        });
        return res.status(200).json({ referrers });
    } catch (error) {
        console.error('Referrer list error:', error.message);
        return res.status(500).json({ error: 'Failed to retrieve referrers list.' });
    }
});

app.post('/api/admin/manual-sale', requireAuth, requireSuperAdmin, async (req, res) => {
    const { name, email, phone, ticketsBought, referrerRefId } = req.body;
    const parsedTickets = Number(ticketsBought);

    if (!name || !email || !phone || !Number.isFinite(parsedTickets) || parsedTickets <= 0) {
        return res.status(400).json({ error: 'Missing or invalid fields for manual sale.' });
    }

    try {
        const referrerUid = await resolveReferrerUidByRefId(referrerRefId);

        await db.collection('raffle_entries').add({
            name,
            email,
            phone,
            referrerRefId: referrerRefId || null,
            referrerUid,
            amount: parsedTickets * ticketPrice,
            ticketsBought: parsedTickets,
            paymentStatus: 'manual_entry',
            orderID: `MANUAL_${Date.now()}_${Math.random().toString(36).slice(2, 9).toUpperCase()}`,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            entryType: 'manual',
            processedBy: req.user.uid
        });

        return res.status(200).json({ success: true, message: `Manual entry for ${name} was added.` });
    } catch (error) {
        console.error('Manual sale error:', error.message);
        return res.status(500).json({ error: 'Failed to add manual sale.' });
    }
});

app.get('/api/admin/all-tickets', requireAuth, requireSuperAdmin, async (req, res) => {
    try {
        const referrersMap = new Map();
        const referrersSnapshot = await db.collection('referrers').get();
        referrersSnapshot.forEach((doc) => {
            referrersMap.set(doc.id, { name: doc.data().name, refId: doc.data().refId });
        });

        const snapshot = await db.collection('raffle_entries').orderBy('timestamp', 'desc').get();
        const tickets = [];

        snapshot.forEach((doc) => {
            const sale = doc.data();
            const qty = sale.ticketsBought || 0;

            let referrerInfo = 'N/A';
            if (sale.referrerUid && referrersMap.has(sale.referrerUid)) {
                const referrer = referrersMap.get(sale.referrerUid);
                referrerInfo = `${referrer.name} (${referrer.refId})`;
            } else if (sale.referrerRefId) {
                referrerInfo = `(Ref ID: ${sale.referrerRefId})`;
            }

            for (let i = 0; i < qty; i += 1) {
                tickets.push({
                    buyerName: sale.name,
                    buyerEmail: sale.email,
                    buyerPhone: sale.phone,
                    ticketsBought: 1,
                    referrerInfo,
                    timestamp: toLocalTimeString(sale.timestamp),
                    originalOrderId: sale.orderID || sale.orderId || 'N/A',
                    ticketNumberInOrder: i + 1
                });
            }
        });

        return res.status(200).json({ tickets });
    } catch (error) {
        console.error('All tickets error:', error.message);
        return res.status(500).json({ error: 'Failed to retrieve all tickets.' });
    }
});

app.post('/api/admin/create-referrer-account', async (req, res) => {
    const { email, password, name, refId, goal, isSuperAdminReferrer } = req.body;
    const parsedGoal = Number(goal);

    if (!email || !password || !name || !refId || !Number.isFinite(parsedGoal) || parsedGoal < 0) {
        return res.status(400).json({ error: 'Missing or invalid fields: email, password, name, refId, goal.' });
    }
    if (!/^[a-zA-Z0-9]+$/.test(refId)) {
        return res.status(400).json({ error: 'Referral ID must be alphanumeric.' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    try {
        const existingRefId = await db.collection('referrers').where('refId', '==', refId).limit(1).get();
        if (!existingRefId.empty) {
            return res.status(409).json({ error: 'Referral ID already exists.' });
        }

        const userRecord = await admin.auth().createUser({
            email,
            password,
            displayName: name,
            emailVerified: false
        });

        const claims = { referrer: true };
        if (isSuperAdminReferrer === true) {
            claims.superAdminReferrer = true;
        }
        await admin.auth().setCustomUserClaims(userRecord.uid, claims);

        await db.collection('referrers').doc(userRecord.uid).set({
            name,
            email,
            refId,
            goal: parsedGoal,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        return res.status(200).json({ success: true, uid: userRecord.uid, message: 'Referrer account created successfully.' });
    } catch (error) {
        console.error('Create referrer error:', error.message);
        if (error.code === 'auth/email-already-exists') {
            return res.status(409).json({ error: 'Email already in use.' });
        }
        return res.status(500).json({ error: 'Failed to create referrer account.' });
    }
});

app.post('/api/admin/create-viewer-account', async (req, res) => {
    const { email, password, viewerName, assignedReferrerUid } = req.body;

    if (!email || !password || !viewerName || !assignedReferrerUid) {
        return res.status(400).json({ error: 'Missing fields: email, password, viewerName, assignedReferrerUid.' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    try {
        const referrerDoc = await db.collection('referrers').doc(assignedReferrerUid).get();
        if (!referrerDoc.exists) {
            return res.status(404).json({ error: 'Assigned referrer does not exist.' });
        }

        const userRecord = await admin.auth().createUser({
            email,
            password,
            displayName: viewerName,
            emailVerified: false
        });

        await admin.auth().setCustomUserClaims(userRecord.uid, {
            viewer: true,
            viewReferrerUid: assignedReferrerUid
        });

        await db.collection('viewer_configs').doc(userRecord.uid).set({
            name: viewerName,
            email,
            viewReferrerUid: assignedReferrerUid,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        return res.status(200).json({ success: true, uid: userRecord.uid, message: 'Viewer account created successfully.' });
    } catch (error) {
        console.error('Create viewer error:', error.message);
        if (error.code === 'auth/email-already-exists') {
            return res.status(409).json({ error: 'Email already in use.' });
        }
        return res.status(500).json({ error: 'Failed to create viewer account.' });
    }
});

app.get('/api/admin/check-claims', requireAuth, async (req, res) => {
    return res.status(200).json({
        uid: req.user.uid,
        email: req.user.email || null,
        claims: {
            superAdminReferrer: req.user.superAdminReferrer === true,
            referrer: req.user.referrer === true,
            viewer: req.user.viewer === true,
            viewReferrerUid: req.user.viewReferrerUid || null
        }
    });
});

app.get('/api/admin/export-raffle-entries', requireAuth, requireSuperAdmin, async (req, res) => {
    try {
        const snapshot = await db.collection('raffle_entries').orderBy('timestamp', 'desc').get();
        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Raffle Entries');

        worksheet.columns = [
            { header: 'Name', key: 'name', width: 24 },
            { header: 'Email', key: 'email', width: 30 },
            { header: 'Phone', key: 'phone', width: 20 },
            { header: 'Tickets', key: 'ticketsBought', width: 12 },
            { header: 'Amount', key: 'amount', width: 12 },
            { header: 'Referrer ID', key: 'referrerRefId', width: 14 },
            { header: 'Referrer UID', key: 'referrerUid', width: 32 },
            { header: 'Order ID', key: 'orderID', width: 28 },
            { header: 'Entry Type', key: 'entryType', width: 14 },
            { header: 'Timestamp', key: 'timestamp', width: 24 }
        ];

        snapshot.forEach((doc) => {
            const entry = doc.data();
            worksheet.addRow({
                name: entry.name || '',
                email: entry.email || '',
                phone: entry.phone || '',
                ticketsBought: entry.ticketsBought || 0,
                amount: entry.amount || 0,
                referrerRefId: entry.referrerRefId || '',
                referrerUid: entry.referrerUid || '',
                orderID: entry.orderID || entry.orderId || '',
                entryType: entry.entryType || '',
                timestamp: toLocalTimeString(entry.timestamp)
            });
        });

        const fileBuffer = await workbook.xlsx.writeBuffer();
        const fileName = `raffle_entries_${new Date().toISOString().slice(0, 10)}.xlsx`;

        return res.status(200).json({
            success: true,
            fileName,
            fileContent: Buffer.from(fileBuffer).toString('base64')
        });
    } catch (error) {
        console.error('Export error:', error.message);
        return res.status(500).json({ error: 'Failed to export raffle entries.' });
    }
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
    console.log(`Serving frontend from ${webRoot}`);
    console.log(`API base path: /api`);
});