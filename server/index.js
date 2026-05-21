require('dotenv').config();
const path = require('path');
const express = require('express');
const admin = require('firebase-admin');
const ExcelJS = require('exceljs');

// Also load env values commonly stored for cloud functions in this repo.
require('dotenv').config({ path: path.resolve(__dirname, '../functions/.env.local') });

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

function useSquareTestEnvironment() {
    return String(process.env.SQUARE_TEST_ENVIRONMENT || '').toLowerCase() === 'true';
}

function getSquareServerConfig() {
    const isTest = useSquareTestEnvironment();
    return {
        isTest,
        appId: isTest ? process.env.SQUARE_TEST_APP_ID : process.env.SQUARE_APP_ID,
        accessToken: isTest
            ? (process.env.SQUARE_TEST_TEST_ACCESS_TOKEN || process.env.SQUARE_TEST_ACCESS_TOKEN)
            : process.env.SQUARE_ACCESS_TOKEN,
        locationId: isTest
            ? (process.env.SQUARE_TEST_LOCATION_ID || process.env.SQUARE_LOCATION_ID)
            : process.env.SQUARE_LOCATION_ID,
        apiBase: isTest ? 'https://connect.squareupsandbox.com' : 'https://connect.squareup.com'
    };
}

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

app.post('/api/stripe/create-checkout-session', async (req, res) => {
    return res.status(410).json({ error: 'Stripe checkout is disabled. Please use Square checkout.' });
});

app.post('/api/square/create-checkout-session', async (req, res) => {
    const { name, email, phone, referral, quantity } = req.body;
    const normalizedReferrer = (referral || 'direct').trim() || 'direct';
    const parsedQuantity = Math.max(1, Math.min(99, parseInt(quantity, 10) || 1));
    const totalAmount = parsedQuantity * ticketPrice;
    const squareBaseUrl = process.env.SQUARE_CHECKOUT_URL;
    const squareConfig = getSquareServerConfig();
    const squareAccessToken = squareConfig.accessToken;
    const squareLocationId = squareConfig.locationId;
    const squareApiBase = squareConfig.apiBase;

    if (!name || !email || !phone) {
        return res.status(400).json({ error: 'Missing required fields: name, email, phone.' });
    }

    try {
        const orderRef = db.collection('square_orders').doc();
        const orderId = orderRef.id;

        await orderRef.set({
            name,
            email,
            phone,
            referrerRefId: normalizedReferrer === 'direct' ? null : normalizedReferrer,
            quantity: parsedQuantity,
            amount: totalAmount,
            status: 'pending_redirect',
            provider: 'square',
            squareMode: squareConfig.isTest ? 'test' : 'live',
            squareAppId: squareConfig.appId || null,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        let checkoutUrl;
        let paymentLinkId = null;

        if (squareAccessToken && squareLocationId) {
            const squareResponse = await fetch(`${squareApiBase}/v2/online-checkout/payment-links`, {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${squareAccessToken}`,
                    'Content-Type': 'application/json',
                    'Square-Version': '2025-01-23'
                },
                body: JSON.stringify({
                    idempotency_key: orderId,
                    order: {
                        location_id: squareLocationId,
                        line_items: [
                            {
                                name: 'Yeshivat Torat Yosef Raffle Ticket',
                                quantity: String(parsedQuantity),
                                base_price_money: {
                                    amount: Math.round(ticketPrice * 100),
                                    currency: 'USD'
                                }
                            }
                        ],
                        metadata: {
                            referrer: normalizedReferrer,
                            referral: normalizedReferrer
                        }
                    },
                    checkout_options: {
                        redirect_url: `${siteDomain}/success.html?orderId=${orderId}`
                    }
                })
            });

            const squareData = await squareResponse.json();
            if (!squareResponse.ok || !squareData.payment_link?.url) {
                console.error('Square create payment link failed:', squareData);
                return res.status(500).json({ error: 'Square payment link creation failed.' });
            }

            checkoutUrl = squareData.payment_link.url;
            paymentLinkId = squareData.payment_link.id || null;

            if (squareData.payment_link.order_id) {
                await orderRef.update({ squareOrderId: squareData.payment_link.order_id });
            }
        } else if (squareBaseUrl) {
            const fallbackCheckoutUrl = new URL(squareBaseUrl);
            fallbackCheckoutUrl.searchParams.set('orderId', orderId);
            fallbackCheckoutUrl.searchParams.set('quantity', String(parsedQuantity));
            fallbackCheckoutUrl.searchParams.set('amount', totalAmount.toFixed(2));
            fallbackCheckoutUrl.searchParams.set('name', name);
            fallbackCheckoutUrl.searchParams.set('email', email);
            fallbackCheckoutUrl.searchParams.set('phone', phone);
            if (normalizedReferrer && normalizedReferrer !== 'direct') {
                fallbackCheckoutUrl.searchParams.set('ref', normalizedReferrer);
            }
            checkoutUrl = fallbackCheckoutUrl.toString();
        } else {
            return res.status(500).json({ error: 'Square is not configured. Add SQUARE_ACCESS_TOKEN and SQUARE_LOCATION_ID.' });
        }

        await orderRef.update({
            checkoutUrl,
            paymentLinkId,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        return res.status(200).json({ url: checkoutUrl });
    } catch (error) {
        console.error('Square checkout error:', error.message);
        return res.status(500).json({ error: 'Failed to create Square checkout session.' });
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