const functions = require('firebase-functions');
const admin = require('firebase-admin');
const fetch = require('node-fetch');
const cors = require('cors');
const ExcelJS = require('exceljs');

admin.initializeApp();

// IMPORTANT: Configure these using 'firebase functions:config:set paypal.client_id="YOUR_CLIENT_ID" paypal.secret="YOUR_SECRET"'
const PAYPAL_CLIENT_ID = functions.config().paypal.client_id;
const PAYPAL_SECRET = functions.config().paypal.secret;
const PAYPAL_API_BASE = 'https://api-m.paypal.com'; // Live production URL

// Define allowed origins for CORS for onRequest functions (like the webhook)
const allowedOrigins = [
  'https://torat-yosef.web.app',
  'https://www.toratyosefsummerraffle.com'
  // Add any other domains where your frontend is hosted
];

const corsHandler = cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    // or requests from allowed origins.
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
});

/**
 * Fetches an access token from PayPal.
 * @returns {Promise<string>} The PayPal access token.
 * @throws {Error} If failed to get access token.
 */
async function getPayPalAccessToken() {
  const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_SECRET}`).toString('base64');

  const response = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${auth}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: 'grant_type=client_credentials'
  });

  const data = await response.json();
  if (!response.ok) {
    console.error('PayPal access token error response:', data);
    throw new Error('Failed to get PayPal access token: ' + JSON.stringify(data));
  }

  return data.access_token;
}

/**
 * Firebase Callable Function to create a PayPal order.
 * This is invoked directly from your frontend.
 */
exports.createPayPalOrder = functions.https.onCall(async (data, context) => {
  const { amount, name, email, phone, referral } = data;

  if (!amount || !name || !email || !phone) {
    throw new new functions.https.HttpsError('invalid-argument', 'Missing required fields: amount, name, email, or phone.');
  }

  try {
    const accessToken = await getPayPalAccessToken();

    const orderResponse = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        intent: 'CAPTURE',
        purchase_units: [{
          amount: {
            currency_code: 'USD',
            value: amount.toFixed(2)
          }
        }],
        application_context: {
            shipping_preference: 'NO_SHIPPING'
        }
      })
    });

    const orderData = await orderResponse.json();

    if (!orderResponse.ok) {
      console.error('Error creating PayPal order:', orderData);
      throw new functions.https.HttpsError('internal', 'Failed to create PayPal order. Details:', orderData);
    }

    await admin.firestore().collection('paypal_orders').doc(orderData.id).set({
      name,
      email,
      phone,
      referrerRefId: referral || null,
      amount,
      status: 'CREATED',
      orderID: orderData.id,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return { orderID: orderData.id };
  } catch (err) {
    console.error('createPayPalOrder caught error:', err);
    if (err instanceof functions.https.HttpsError) {
      throw err;
    }
    throw new functions.https.HttpsError('internal', 'An unexpected error occurred during order creation.', err.message);
  }
});

/**
 * Firebase Callable Function to capture a PayPal order.
 * This is invoked from your frontend after PayPal approval.
 */
exports.capturePayPalOrder = functions.https.onCall(async (data, context) => {
  const { orderID } = data;
  if (!orderID) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing orderID for capture.');
  }

  try {
    const accessToken = await getPayPalAccessToken();

    const captureResponse = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders/${orderID}/capture`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      }
    });

    const captureData = await captureResponse.json();

    if (!captureResponse.ok) {
      console.error('Error capturing PayPal order:', captureData);
      throw new functions.https.HttpsError('internal', 'Failed to capture PayPal order. Details:', captureData);
    }

    await admin.firestore().collection('paypal_orders').doc(orderID).update({
      status: 'COMPLETED',
      captureData,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return { success: true, data: captureData };
  } catch (err) {
    console.error('capturePayPalOrder caught error:', err);
    if (err instanceof functions.https.HttpsError) {
      throw err;
    }
    throw new functions.https.HttpsError('internal', 'An unexpected error occurred during order capture.', err.message);
  }
});

/**
 * PayPal Webhook Listener (HTTP Request Function).
 * This endpoint is called by PayPal's servers, not your frontend.
 */
exports.paypalWebhook = functions.https.onRequest((req, res) => {
  corsHandler(req, res, async () => {
    if (req.method !== 'POST') {
      console.warn(`Webhook received non-POST request: ${req.method}`);
      return res.status(405).send('Method Not Allowed');
    }

    try {
      const event = req.body;
      console.log('Received PayPal webhook event type:', event.event_type);

      // --- IMPORTANT: Implement webhook signature verification in production ---

      if (event.event_type === 'CHECKOUT.ORDER.APPROVED' || event.event_type === 'PAYMENT.CAPTURE.COMPLETED') {
        const orderID = event.resource.id ||
                        event.resource.purchase_units?.[0]?.payments?.captures?.[0]?.id ||
                        event.resource.billing_agreement_id;

        if (!orderID) {
          console.error('No orderID found in PayPal webhook event:', event);
          return res.status(400).send('No orderID found in webhook event.');
        }

        const orderDocRef = admin.firestore().collection('paypal_orders').doc(orderID);
        const orderDoc = await orderDocRef.get();

        if (!orderDoc.exists) {
          console.error('Order not found in Firestore for PayPal ID:', orderID);
          return res.status(200).send('Order not found in local DB, but webhook acknowledged.');
        }

        const orderData = orderDoc.data();

        if (orderData.raffleEntryCreatedAt) {
          console.log(`Raffle entry already processed for order ${orderID}. Event type: ${event.event_type}`);
          return res.status(200).send('Raffle entry already processed.');
        }

        const ticketsBought = Math.floor(orderData.amount / 126.00);

        let referrerUid = null;
        if (orderData.referrerRefId) {
            const referrerQuerySnapshot = await admin.firestore().collection('referrers')
                .where('refId', '==', orderData.referrerRefId)
                .limit(1)
                .get();

            if (!referrerQuerySnapshot.empty) {
                referrerUid = referrerQuerySnapshot.docs[0].id;
                console.log(`Found referrer UID: ${referrerUid} for refId: ${orderData.referrerRefId}`);
            } else {
                console.warn(`Referrer with refId ${orderData.referrerRefId} not found.`);
            }
        }

        await admin.firestore().collection('raffle_entries').add({
          name: orderData.name,
          email: orderData.email,
          phone: orderData.phone,
          referrerRefId: orderData.referrerRefId || null,
          referrerUid: referrerUid,
          amount: orderData.amount,
          ticketsBought: ticketsBought,
          paymentStatus: 'completed',
          orderID: orderID,
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          webhookEventType: event.event_type,
          paypalEventId: event.id
        });

        await orderDocRef.update({
          raffleEntryCreatedAt: admin.firestore.FieldValue.serverTimestamp(),
          webhookProcessed: true,
          lastWebhookEvent: event
        });

        return res.status(200).send('Webhook processed successfully.');
      }

      res.status(200).send('Webhook event ignored (uninteresting type).');

    } catch (err) {
      console.error('paypalWebhook error:', err);
      res.status(500).send('Internal Server Error during webhook processing.');
    }
  });
});

/**
 * ONE-TIME ADMIN FUNCTION to reprocess completed PayPal orders that failed 
 * to generate a raffle entry.
 */
exports.reprocessMissingRaffleEntries = functions.https.onCall(async (data, context) => {
    if (!context.auth || !context.auth.token.superAdminReferrer) {
        throw new functions.https.HttpsError('permission-denied', 'You must be a super admin to run this operation.');
    }

    console.log('Starting reprocessing of missing raffle entries...');
    const db = admin.firestore();
    let processedCount = 0;
    const errors = [];

    const ordersToProcessSnapshot = await db.collection('paypal_orders')
        .where('status', '==', 'COMPLETED')
        .get();

    if (ordersToProcessSnapshot.empty) {
        return { success: true, message: 'No completed orders found to process.' };
    }

    const processingPromises = [];
    ordersToProcessSnapshot.forEach(doc => {
        const orderData = doc.data();
        const orderID = doc.id;

        if (orderData.raffleEntryCreatedAt) {
            return;
        }

        const processPromise = (async () => {
            try {
                const ticketsBought = Math.floor(orderData.amount / 126.00);
                let referrerUid = null;

                if (orderData.referrerRefId) {
                    const referrerQuerySnapshot = await db.collection('referrers')
                        .where('refId', '==', orderData.referrerRefId)
                        .limit(1)
                        .get();
                    
                    if (!referrerQuerySnapshot.empty) {
                        referrerUid = referrerQuerySnapshot.docs[0].id;
                    }
                }

                await db.collection('raffle_entries').add({
                    name: orderData.name,
                    email: orderData.email,
                    phone: orderData.phone,
                    referrerRefId: orderData.referrerRefId || null,
                    referrerUid: referrerUid,
                    amount: orderData.amount,
                    ticketsBought: ticketsBought,
                    paymentStatus: 'completed',
                    orderID: orderID,
                    timestamp: admin.firestore.FieldValue.serverTimestamp(),
                    reprocessingNote: 'Entry created via reprocessMissingRaffleEntries function.'
                });

                await db.collection('paypal_orders').doc(orderID).update({
                    raffleEntryCreatedAt: admin.firestore.FieldValue.serverTimestamp(),
                    webhookProcessed: true,
                    reprocessingComplete: true
                });

                processedCount++;
            } catch (error) {
                console.error(`Failed to process order ID ${orderID}:`, error);
                errors.push(`Order ${orderID}: ${error.message}`);
            }
        })();
        
        processingPromises.push(processPromise);
    });

    await Promise.all(processingPromises);

    const message = `Successfully processed ${processedCount} missing raffle entries.`;
    if (errors.length > 0) {
        return { 
            success: false, 
            message: `Completed with errors. Processed ${processedCount} entries successfully.`,
            errors: errors 
        };
    }

    return { success: true, message };
});

/**
 * Firebase Callable Function to get referrer dashboard data.
 */
exports.getReferrerDashboardData = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated to view dashboard data.');
  }

  const loggedInUid = context.auth.uid;
  let targetReferrerUid = loggedInUid;
  let dashboardTitleName = "Your";
  let isViewerAccount = false;
  let isSuperAdminReferrer = false;

  try {
    const idTokenResult = await admin.auth().getUser(loggedInUid);
    const customClaims = idTokenResult.customClaims || {};

    if (customClaims.viewer && customClaims.viewReferrerUid) {
      targetReferrerUid = customClaims.viewReferrerUid;
      isViewerAccount = true;
    } else if (customClaims.superAdminReferrer) {
      isSuperAdminReferrer = true;
    }

    let referrerData;
    if (isViewerAccount) {
      referrerData = await admin.firestore().collection('referrers').doc(targetReferrerUid).get();
      dashboardTitleName = referrerData.exists ? `${referrerData.data().name}'s` : "Unknown Referrer's";
    } else {
        referrerData = await admin.firestore().collection('referrers').doc(loggedInUid).get();
        if (referrerData.exists) {
            dashboardTitleName = referrerData.data().name;
        } else if (isSuperAdminReferrer) {
            dashboardTitleName = "Master Admin";
            referrerData = { data: () => ({ name: "Master Admin", refId: "N/A", goal: 0 }) };
        } else {
            throw new functions.https.HttpsError('not-found', 'Referrer data not found for this user.');
        }
    }

    const currentReferrerDetails = referrerData.data();
    let totalTicketsSold = 0;
    const buyerDetails = [];
    let allReferrersSummary = [];

    if (isSuperAdminReferrer) {
        const [allRaffleEntriesSnapshot, allReferrersSnapshot] = await Promise.all([
            admin.firestore().collection('raffle_entries').get(),
            admin.firestore().collection('referrers').get()
        ]);
        const aggregatedSales = {};

        allRaffleEntriesSnapshot.forEach(entryDoc => {
            const entry = entryDoc.data();
            if (entry.referrerUid) {
                if (!aggregatedSales[entry.referrerUid]) {
                    aggregatedSales[entry.referrerUid] = { totalTickets: 0, totalAmount: 0 };
                }
                aggregatedSales[entry.referrerUid].totalTickets += (entry.ticketsBought || 0);
                aggregatedSales[entry.referrerUid].totalAmount += (entry.amount || 0);
            }
        });

        allReferrersSnapshot.forEach(referrerDoc => {
            const rData = referrerDoc.data();
            const summary = {
                uid: referrerDoc.id, name: rData.name, refId: rData.refId, goal: rData.goal || 0,
                totalTicketsSold: (aggregatedSales[referrerDoc.id]?.totalTickets) || 0,
                totalAmountRaised: (aggregatedSales[referrerDoc.id]?.totalAmount) || 0,
            };
            summary.ticketsRemaining = summary.goal - summary.totalTicketsSold;
            allReferrersSummary.push(summary);
        });

        if (currentReferrerDetails.refId !== "N/A") {
             const ownSalesSnapshot = await admin.firestore().collection('raffle_entries')
                .where('referrerUid', '==', loggedInUid).orderBy('timestamp', 'desc').get();
             ownSalesSnapshot.forEach(doc => {
                 const entry = doc.data();
                 totalTicketsSold += (entry.ticketsBought || 0);
                 buyerDetails.push({ id: doc.id, name: entry.name, email: entry.email, phone: entry.phone, ticketsBought: entry.ticketsBought, timestamp: entry.timestamp?.toDate().toLocaleString('en-US', { timeZone: 'America/New_York' }) || 'N/A' });
             });
        }
    } else {
        const ticketsSoldSnapshot = await admin.firestore().collection('raffle_entries')
          .where('referrerUid', '==', targetReferrerUid).orderBy('timestamp', 'desc').get();
        ticketsSoldSnapshot.forEach(doc => {
            const entry = doc.data();
            totalTicketsSold += (entry.ticketsBought || 0);
            if (!isViewerAccount) {
                 buyerDetails.push({ id: doc.id, name: entry.name, email: entry.email, phone: entry.phone, ticketsBought: entry.ticketsBought, timestamp: entry.timestamp?.toDate().toLocaleString('en-US', { timeZone: 'America/New_York' }) || 'N/A' });
            }
        });
    }

    const referralLink = currentReferrerDetails.refId ? `https://www.toratyosefsummerraffle.com/?ref=${currentReferrerDetails.refId}` : null;
    return { name: currentReferrerDetails.name, refId: currentReferrerDetails.refId, goal: currentReferrerDetails.goal, totalTicketsSold, buyerDetails, referralLink, dashboardTitleName, isViewer: isViewerAccount, isSuperAdminReferrer, allReferrersSummary };
  } catch (error) {
    console.error('Error fetching referrer dashboard data:', error);
    throw new functions.https.HttpsError('internal', 'Failed to retrieve dashboard data.', error.message);
  }
});

/**
 * Firebase Callable Function to create a new referrer account.
 * (Currently unauthenticated)
 */
exports.createReferrerAccount = functions.https.onCall(async (data, context) => {
    const { email, password, name, refId, goal, isSuperAdminReferrer } = data;
    if (!email || !password || !name || !refId || typeof goal !== 'number' || goal < 0) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing or invalid fields.');
    }
    if (password.length < 6 || !refId.match(/^[a-zA-Z0-9]+$/)) {
        throw new functions.https.HttpsError('invalid-argument', 'Password must be 6+ chars and Ref ID must be alphanumeric.');
    }

    try {
        const existingRefId = await admin.firestore().collection('referrers').where('refId', '==', refId).limit(1).get();
        if (!existingRefId.empty) {
            throw new functions.https.HttpsError('already-exists', 'Referral ID already taken.');
        }

        const userRecord = await admin.auth().createUser({ email, password, displayName: name });
        const customClaims = { referrer: true };
        if (isSuperAdminReferrer) {
            customClaims.superAdminReferrer = true;
        }
        await admin.auth().setCustomUserClaims(userRecord.uid, customClaims);

        await admin.firestore().collection('referrers').doc(userRecord.uid).set({
            name, email, refId, goal,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        return { success: true, uid: userRecord.uid, message: 'Referrer account created.' };
    } catch (error) {
        console.error('Error creating referrer account:', error);
        throw new functions.https.HttpsError('internal', error.message, error);
    }
});

/**
 * Firebase Callable Function to create a new viewer account.
 * (Currently unauthenticated)
 */
exports.createViewerAccount = functions.https.onCall(async (data, context) => {
    const { email, password, viewerName, assignedReferrerUid } = data;
    if (!email || !password || !viewerName || !assignedReferrerUid) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields.');
    }
    if (password.length < 6) {
        throw new functions.https.HttpsError('invalid-argument', 'Password must be at least 6 characters long.');
    }

    try {
        const referrerDoc = await admin.firestore().collection('referrers').doc(assignedReferrerUid).get();
        if (!referrerDoc.exists) {
            throw new functions.https.HttpsError('not-found', 'Assigned Referrer UID does not exist.');
        }

        const userRecord = await admin.auth().createUser({ email, password, displayName: viewerName });
        await admin.auth().setCustomUserClaims(userRecord.uid, { viewer: true, viewReferrerUid: assignedReferrerUid });
        await admin.firestore().collection('viewer_configs').doc(userRecord.uid).set({
            name: viewerName, email, viewReferrerUid: assignedReferrerUid,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        return { success: true, uid: userRecord.uid, message: 'Viewer account created.' };
    } catch (error) {
        console.error('Error creating viewer account:', error);
        throw new functions.https.HttpsError('internal', error.message, error);
    }
});

/**
 * Firebase Callable Function to get a list of all existing referrers.
 */
exports.getReferrersList = functions.https.onCall(async (data, context) => {
    if (!context.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated.');
    }
    try {
        const referrersSnapshot = await admin.firestore().collection('referrers').get();
        const referrers = referrersSnapshot.docs.map(doc => ({
            uid: doc.id,
            name: doc.data().name,
            refId: doc.data().refId
        }));
        return { referrers };
    } catch (error) {
        console.error('Error fetching referrers list:', error);
        throw new functions.https.HttpsError('internal', 'Failed to retrieve referrers list.', error.message);
    }
});

/**
 * Exports all raffle entries to an XLSX file, secured for Super Admins.
 * Each ticket purchased corresponds to a single row in the spreadsheet.
 */
exports.exportRaffleEntries = functions.https.onCall(async (data, context) => {
    if (!context.auth || !context.auth.token.superAdminReferrer) {
        throw new functions.https.HttpsError('permission-denied', 'You must be a super admin to run this operation.');
    }

    console.log('Starting export of all raffle entries...');
    const db = admin.firestore();
    try {
        const entriesSnapshot = await db.collection('raffle_entries').get();

        if (entriesSnapshot.empty) {
            console.log('No raffle entries found to export.');
            return {
                success: false,
                message: 'No raffle entries found to export.'
            };
        }

        const exportRows = [];
        entriesSnapshot.forEach(doc => {
            const entry = doc.data();
            const ticketsBought = entry.ticketsBought || 0;
            for (let i = 0; i < ticketsBought; i++) {
                exportRows.push({
                    name: entry.name,
                    email: entry.email,
                    phone: entry.phone,
                    orderID: entry.orderID,
                    purchaseDate: entry.timestamp ? entry.timestamp.toDate().toISOString() : 'N/A'
                });
            }
        });
        
        console.log(`Processed ${entriesSnapshot.size} purchases, resulting in ${exportRows.length} ticket rows.`);

        const workbook = new ExcelJS.Workbook();
        const worksheet = workbook.addWorksheet('Raffle Tickets');
        worksheet.columns = [
            { header: 'Name', key: 'name', width: 30 },
            { header: 'Email', key: 'email', width: 30 },
            { header: 'Phone', key: 'phone', width: 20 },
            { header: 'PayPal Order ID', key: 'orderID', width: 35 },
            { header: 'Purchase Date', key: 'purchaseDate', width: 25 }
        ];
        worksheet.addRows(exportRows);
        
        const buffer = await workbook.xlsx.writeBuffer();
        const base64File = buffer.toString('base64');
        
        return {
            success: true,
            fileContent: base64File,
            fileName: `raffle_entries_${new Date().toISOString().split('T')[0]}.xlsx`,
            message: `Successfully generated export with ${exportRows.length} ticket entries.`
        };
    } catch (error) {
        console.error('Failed to export raffle entries:', error);
        throw new functions.https.HttpsError('internal', 'An unexpected error occurred during export.', error.message);
    }
});
exports.checkMyClaims = functions.https.onCall((data, context) => {
  // Make sure the user is authenticated.
  if (!context.auth) {
    throw new functions.https.HttpsError(
      'unauthenticated',
      'You must be logged in to check your claims.'
    );
  }

  // Return the user's UID, email, and all their custom claims.
  return {
    uid: context.auth.uid,
    email: context.auth.token.email,
    claims: context.auth.token,
  };
});