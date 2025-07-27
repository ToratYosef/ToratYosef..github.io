const functions = require('firebase-functions');
const admin = require('firebase-admin');
const fetch = require('node-fetch'); // Make sure node-fetch is installed: npm install --save node-fetch@2
const cors = require('cors');

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
  // Optional: Add authentication check here if users need to be logged in
  // if (!context.auth) {
  //   throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated to create an order.');
  // }

  const { amount, name, email, phone, referral } = data;

  if (!amount || !name || !email || !phone) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing required fields: amount, name, email, or phone.');
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
          // No need to add custom_id here, as it's optional
        }],
        // ADDED: application_context to remove shipping address requirement
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

    // Save initial order details to 'paypal_orders' collection, NOT 'raffle_entries'
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
    // Re-throw as an HttpsError for the client to handle
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
  // Optional: Add authentication check here if users need to be logged in
  // if (!context.auth) {
  //   throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated to capture an order.');
  // }

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

    // Update the order status in Firestore
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
    // PayPal webhooks always send POST requests. Reject other methods.
    if (req.method !== 'POST') {
      console.warn(`Webhook received non-POST request: ${req.method}`);
      return res.status(405).send('Method Not Allowed');
    }

    try {
      const event = req.body;
      console.log('Received PayPal webhook event type:', event.event_type);

      // --- IMPORTANT: Implement webhook signature verification in production ---
      // This step is critical for security to ensure the webhook is genuinely from PayPal.
      // Example headers to check: PayPal-Transmission-Id, PayPal-Cert-Url, PayPal-Auth-Algo,
      // PayPal-Transmission-Sig, PayPal-Transmission-Time.
      // You would typically use PayPal's SDK or manually verify the signature.
      // For development, you might skip it, but never in production.
      // -------------------------------------------------------------------------

      // Process only relevant events for raffle entries
      if (event.event_type === 'CHECKOUT.ORDER.APPROVED' || event.event_type === 'PAYMENT.CAPTURE.COMPLETED') {
        // Extract order ID, prioritizing the order ID from the event resource
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
          // Acknowledge the webhook to prevent PayPal retries, even if local record is missing.
          // You might log this as a critical alert or have a separate reconciliation process.
          return res.status(200).send('Order not found in local DB, but webhook acknowledged.');
        }

        const orderData = orderDoc.data();

        // Prevent duplicate raffle entries if webhook is received multiple times
        if (orderData.raffleEntryCreatedAt) {
          console.log(`Raffle entry already processed for order ${orderID}. Event type: ${event.event_type}`);
          return res.status(200).send('Raffle entry already processed.');
        }

        // Calculate ticketsBought based on the amount for this order.
        // Ensure $126.00 is the fixed price per ticket.
        const ticketsBought = Math.floor(orderData.amount / 126.00);

        let referrerUid = null;
        if (orderData.referrerRefId) {
            // Look up the referrer's UID from the 'referrers' collection using their refId
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

        // Pull the timestamp from paypal_orders.createdAt
        const entryTimestamp = orderData.createdAt || admin.firestore.FieldValue.serverTimestamp();

        // Add the raffle entry to a separate collection (raffle_entries)
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
          timestamp: entryTimestamp, // Use the timestamp from paypal_orders.createdAt
          webhookEventType: event.event_type,
          paypalEventId: event.id
        });

        // Mark the original PayPal order as processed by the webhook
        await orderDocRef.update({
          raffleEntryCreatedAt: admin.firestore.FieldValue.serverTimestamp(),
          webhookProcessed: true,
          lastWebhookEvent: event
        });

        return res.status(200).send('Webhook processed successfully.');
      }

      // If the webhook event type is not one we're interested in, just acknowledge it.
      res.status(200).send('Webhook event ignored (uninteresting type).');

    } catch (err) {
      console.error('paypalWebhook error:', err);
      // In case of an error during webhook processing, return 500 to signal PayPal to retry.
      res.status(500).send('Internal Server Error during webhook processing.');
    }
  });
});

/**
 * ONE-TIME ADMIN FUNCTION to reprocess completed PayPal orders that failed
 * to generate a raffle entry. This function finds orders that are 'COMPLETED'
 * but are missing the 'raffleEntryCreatedAt' field and processes them.
 * * IMPORTANT: You must be authenticated as a Super Admin Referrer to run this.
 */
exports.reprocessMissingRaffleEntries = functions.https.onCall(async (data, context) => {
    // Security Check: Ensure the caller is an authenticated super admin.
    if (!context.auth || !context.auth.token.superAdminReferrer) {
        throw new functions.https.HttpsError('permission-denied', 'You must be a super admin to run this operation.');
    }

    console.log('Starting reprocessing of missing raffle entries...');
    const db = admin.firestore();
    let processedCount = 0;
    const errors = [];

    // 1. Find all PayPal orders that are completed but were not processed by the webhook.
    // We are looking for paypal_orders documents where the raffleEntryCreatedAt field is missing.
    const ordersToProcessSnapshot = await db.collection('paypal_orders')
        .where('status', '==', 'COMPLETED')
        // Using `where('raffleEntryCreatedAt', '==', null)` or `!doc.data().raffleEntryCreatedAt` check
        // ensures we only target orders that haven't triggered a raffle entry yet.
        .get();

    if (ordersToProcessSnapshot.empty) {
        return { success: true, message: 'No completed orders found to process that are missing a raffle entry.' };
    }

    const processingPromises = [];

    ordersToProcessSnapshot.forEach(doc => {
        const orderData = doc.data();
        const orderID = doc.id;

        // Skip if a raffle entry has already been created for this order (redundant check, but safe).
        if (orderData.raffleEntryCreatedAt) {
            return;
        }

        console.log(`Processing order ID: ${orderID}`);

        // This creates a separate asynchronous task for each order.
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
                    } else {
                        console.warn(`Referrer with refId ${orderData.referrerRefId} not found for order ${orderID}.`);
                    }
                }

                // Get the timestamp from the paypal_orders document's 'createdAt' field
                const entryTimestamp = orderData.createdAt || admin.firestore.FieldValue.serverTimestamp();

                // 3. Create the missing raffle_entries document.
                await db.collection('raffle_entries').add({
                    name: orderData.name,
                    email: orderData.email,
                    phone: orderData.phone,
                    referrerRefId: orderData.referrerRefId || null,
                    referrerUid: referrerUid,
                    amount: orderData.amount,
                    ticketsBought: ticketsBought,
                    paymentStatus: 'completed', // Status from PayPal webhook context
                    orderID: orderID,
                    timestamp: entryTimestamp,
                    // Add a note that this was created via a manual reprocessing script.
                    reprocessingNote: 'Entry created via reprocessMissingRaffleEntries function.',
                    reprocessedBy: context.auth.uid // Record who ran the reprocessing
                });

                // 4. Update the original order to mark it as processed by this function.
                await db.collection('paypal_orders').doc(orderID).update({
                    raffleEntryCreatedAt: admin.firestore.FieldValue.serverTimestamp(), // Mark the PayPal order as having had its raffle entry created
                    webhookProcessed: true, // You can use this flag, or a new one specific to reprocessing
                    reprocessingComplete: true
                });

                processedCount++;
                console.log(`Successfully created raffle entry for order ID: ${orderID}`);

            } catch (error) {
                console.error(`Failed to process order ID ${orderID}:`, error);
                errors.push(`Order ${orderID}: ${error.message}`);
            }
        })();

        processingPromises.push(processPromise);
    });

    // Wait for all the individual order processing tasks to complete.
    await Promise.all(processingPromises);

    console.log(`Reprocessing complete. Processed: ${processedCount}. Errors: ${errors.length}`);

    if (errors.length > 0) {
        return {
            success: false,
            message: `Completed with errors. Processed ${processedCount} entries successfully.`,
            errors: errors
        };
    }

    return {
        success: true,
        message: `Successfully processed ${processedCount} missing raffle entries.`
    };
});

/**
 * Firebase Callable Function to get referrer dashboard data.
 * Requires authentication.
 * NOW HANDLES VIEWER ACCOUNTS.
 */
exports.getReferrerDashboardData = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated to view dashboard data.');
  }

  const loggedInUid = context.auth.uid;

  console.log('getReferrerDashboardData: Logged in UID:', loggedInUid);

  let targetReferrerUid = loggedInUid;
  let dashboardTitleName = "Your";
  let isViewerAccount = false;
  let isSuperAdminReferrer = false;

  try {
    const idTokenResult = await admin.auth().getUser(loggedInUid);
    const customClaims = idTokenResult.customClaims;

    if (customClaims && customClaims.viewer && customClaims.viewReferrerUid) {
      targetReferrerUid = customClaims.viewReferrerUid;
      isViewerAccount = true;
      console.log(`getReferrerDashboardData: Logged in user is a regular viewer (${loggedInUid}) for UID: ${targetReferrerUid}`);
    } else if (customClaims && customClaims.superAdminReferrer) {
      isSuperAdminReferrer = true;
      console.log(`getReferrerDashboardData: Logged in user is a Super Admin Referrer (${loggedInUid}).`);
    }

    let referrerData;

    if (isViewerAccount) {
      referrerData = await admin.firestore().collection('referrers').doc(targetReferrerUid).get();
      if (referrerData.exists) {
          dashboardTitleName = referrerData.data().name + "'s";
      } else {
          console.warn(`getReferrerDashboardData: Assigned referrer UID ${targetReferrerUid} not found in 'referrers' collection.`);
          throw new functions.https.HttpsError('not-found', 'Assigned referrer data not found.');
      }
    } else {
        referrerData = await admin.firestore().collection('referrers').doc(loggedInUid).get();
        if (referrerData.exists) {
            dashboardTitleName = referrerData.data().name;
        } else {
            if (!isSuperAdminReferrer) {
                 throw new functions.https.HttpsError('not-found', 'Referrer data not found for this user.');
            }
            dashboardTitleName = "Master Admin";
            // Create a dummy referrerData object for superadmins who might not have a direct referrer profile
            referrerData = {
                data: () => ({ name: "Master Admin", refId: "N/A", goal: 0 })
            };
        }
    }

    const currentReferrerDetails = referrerData.data();


    let totalTicketsSold = 0;
    const buyerDetails = [];
    let allReferrersSummary = [];

    if (isSuperAdminReferrer) {
        const allRaffleEntriesSnapshot = await admin.firestore().collection('raffle_entries').get();
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

        const allReferrersSnapshot = await admin.firestore().collection('referrers').get();
        allReferrersSnapshot.forEach(referrerDocData => {
            const rData = referrerDocData.data();
            const referrerSummary = {
                uid: referrerDocData.id,
                name: rData.name,
                refId: rData.refId,
                goal: rData.goal || 0,
                totalTicketsSold: (aggregatedSales[referrerDocData.id] && aggregatedSales[referrerDocData.id].totalTickets) || 0,
                totalAmountRaised: (aggregatedSales[referrerDocData.id] && aggregatedSales[referrerDocData.id].totalAmount) || 0
            };
            referrerSummary.ticketsRemaining = referrerSummary.goal - referrerSummary.totalTicketsSold;
            allReferrersSummary.push(referrerSummary);
        });

        // For superadmins, their "own" sales are also filtered if they have a refId
        if (currentReferrerDetails.refId && currentReferrerDetails.refId !== "N/A") { // Added check for "N/A"
            const ownSalesSnapshot = await admin.firestore().collection('raffle_entries')
                .where('referrerUid', '==', loggedInUid)
                .orderBy('timestamp', 'desc')
                .get();

            ownSalesSnapshot.forEach(doc => {
                const entry = doc.data();
                totalTicketsSold += (entry.ticketsBought || 0);

                buyerDetails.push({
                    id: doc.id,
                    name: entry.name,
                    email: entry.email,
                    phone: entry.phone,
                    ticketsBought: entry.ticketsBought,
                    timestamp: entry.timestamp ? entry.timestamp.toDate().toLocaleString('en-US', {
                        month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: true,
                        timeZone: 'America/New_York'
                    }) : 'N/A'
                });
            });
        } else {
             // If superadmin doesn't have a refId, their "Your Buyer Details" will be empty
             totalTicketsSold = 0;
             buyerDetails.length = 0; // Clear array
        }


    } else { // Not a SuperAdminReferrer
        const ticketsSoldSnapshot = await admin.firestore().collection('raffle_entries')
          .where('referrerUid', '==', targetReferrerUid)
          .orderBy('timestamp', 'desc')
          .get();

        ticketsSoldSnapshot.forEach(doc => {
            const entry = doc.data();
            totalTicketsSold += (entry.ticketsBought || 0);

            if (!isViewerAccount) { // Only show buyer details if not a viewer
                buyerDetails.push({
                    id: doc.id,
                    name: entry.name,
                    email: entry.email,
                    phone: entry.phone,
                    ticketsBought: entry.ticketsBought,
                    timestamp: entry.timestamp ? entry.timestamp.toDate().toLocaleString('en-US', {
                        month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: true,
                        timeZone: 'America/New_York'
                    }) : 'N/A'
                });
            }
        });
    }

    const referralLink = currentReferrerDetails.refId && currentReferrerDetails.refId !== "N/A" ? `https://www.toratyosefsummerraffle.com/?ref=${currentReferrerDetails.refId}` : null;

    return {
      name: currentReferrerDetails.name,
      refId: currentReferrerDetails.refId,
      goal: currentReferrerDetails.goal,
      totalTicketsSold: totalTicketsSold,
      buyerDetails: buyerDetails,
      referralLink: referralLink,
      dashboardTitleName: dashboardTitleName,
      isViewer: isViewerAccount,
      isSuperAdminReferrer: isSuperAdminReferrer,
      allReferrersSummary: allReferrersSummary
    };

  } catch (error) {
    console.error('Error fetching referrer dashboard data:', error);
    if (error instanceof functions.https.HttpsError) {
      throw error;
    }
    throw new functions.https.HttpsError('internal', 'Failed to retrieve dashboard data.', error.message);
  }
});


/**
 * Firebase Callable Function to create a new referrer account.
 * IMPORTANT: This function has NO authentication check, allowing anyone to call it.
 */
exports.createReferrerAccount = functions.https.onCall(async (data, context) => {
    // Removed: if (!context.auth) { ... } as per user request to allow unauthenticated calls.
    // WARNING: This means ANYONE can call this function if they know its endpoint.
    // This is a significant security risk for a production environment.

    // 2. Validate Input Data
    const { email, password, name, refId, goal, isSuperAdminReferrer } = data;

    if (!email || !password || !name || !refId || typeof goal !== 'number' || goal < 0) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing or invalid fields: email, password, name, refId, or goal.');
    }
    if (password.length < 6) {
        throw new functions.https.HttpsError('invalid-argument', 'Password must be at least 6 characters long.');
    }
    if (!refId.match(/^[a-zA-Z0-9]+$/)) {
        throw new functions.https.HttpsError('invalid-argument', 'Referral ID must be alphanumeric (letters and numbers only).');
    }

    try {
        // 3. Check if refId already exists to ensure uniqueness
        const existingRefId = await admin.firestore().collection('referrers')
            .where('refId', '==', refId)
            .limit(1)
            .get();

        if (!existingRefId.empty) {
            throw new functions.https.HttpsError('already-exists', 'Referral ID already taken. Please choose a different one.');
        }

        // 4. Create Firebase Authentication User
        const userRecord = await admin.auth().createUser({
            email: email,
            password: password,
            displayName: name,
            emailVerified: false
        });

        // 5. Set Custom Claims for the new user (e.g., 'referrer' role and 'superAdminReferrer')
        const customClaims = { referrer: true };
        if (isSuperAdminReferrer) {
            customClaims.superAdminReferrer = true;
        }
        await admin.auth().setCustomUserClaims(userRecord.uid, customClaims);

        // 6. Create corresponding Firestore Document for Referrer Data
        await admin.firestore().collection('referrers').doc(userRecord.uid).set({
            name: name,
            email: email,
            refId: refId,
            goal: goal,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log(`Successfully created new referrer: ${name} (${email}) with UID: ${userRecord.uid}. Is Super Admin: ${!!isSuperAdminReferrer}`);
        return { success: true, uid: userRecord.uid, message: 'Referrer account created successfully.' };

    } catch (error) {
        console.error('Error creating referrer account:', error);
        // Handle specific Firebase Auth errors
        if (error.code === 'auth/email-already-exists') {
            throw new functions.https.HttpsError('already-exists', 'The email address is already in use by another account.');
        } else if (error.code === 'auth/invalid-email') {
            throw new functions.https.HttpsError('invalid-argument', 'The email address is not valid.');
        } else if (error instanceof functions.https.HttpsError) {
            throw error;
        }
        // Generic error for unexpected issues
        throw new functions.https.HttpsError('internal', 'Failed to create referrer account.', error.message);
    }
});


/**
 * Firebase Callable Function to create a new viewer account.
 * IMPORTANT: This function should only be called by an authorized administrator
 * if you value security. Currently, it has no authentication check.
 */
exports.createViewerAccount = functions.https.onCall(async (data, context) => {
    // WARNING: This function currently has NO authentication check.
    // In a production scenario, you would typically add context.auth checks here
    // e.g., if (!context.auth || !context.auth.token.admin) { throw ... }

    const { email, password, viewerName, assignedReferrerUid } = data;

    if (!email || !password || !viewerName || !assignedReferrerUid) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing fields: email, password, viewerName, or assignedReferrerUid.');
    }
    if (password.length < 6) {
        throw new functions.https.HttpsError('invalid-argument', 'Password must be at least 6 characters long.');
    }

    try {
        // 1. Verify assignedReferrerUid exists in 'referrers' collection
        const referrerExists = await admin.firestore().collection('referrers').doc(assignedReferrerUid).get();
        if (!referrerExists.exists) {
            throw new functions.https.HttpsError('not-found', 'Assigned Referrer UID does not exist in the referrers collection.');
        }

        // 2. Create Firebase Authentication User for the viewer
        const userRecord = await admin.auth().createUser({
            email: email,
            password: password,
            displayName: viewerName,
            emailVerified: false
        });

        // 3. Set Custom Claims for the new viewer user (e.g., 'viewer' role)
        await admin.auth().setCustomUserClaims(userRecord.uid, { viewer: true, viewReferrerUid: assignedReferrerUid }); // Store assigned UID in claims

        // 4. Create corresponding Firestore Document in 'viewer_configs' (optional, claims are primary)
        await admin.firestore().collection('viewer_configs').doc(userRecord.uid).set({
            name: viewerName,
            email: email,
            viewReferrerUid: assignedReferrerUid,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log(`Successfully created new viewer account: ${viewerName} (${email}) for referrer UID: ${assignedReferrerUid}`);
        return { success: true, uid: userRecord.uid, message: 'Viewer account created successfully.' };

    } catch (error) {
        console.error('Error creating viewer account:', error);
        if (error.code === 'auth/email-already-exists') {
            throw new functions.https.HttpsError('already-exists', 'The email address is already in use by another account.');
        } else if (error instanceof functions.https.HttpsError) {
            throw error;
        }
        throw new functions.https.HttpsError('internal', 'Failed to create viewer account.', error.message);
    }
});


/**
 * Firebase Callable Function to get a list of all existing referrers.
 * This is used by the admin-create page to populate the dropdown for viewer assignment.
 * Requires authentication to call.
 */
exports.getReferrersList = functions.https.onCall(async (data, context) => {
    if (!context.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'User must be authenticated to retrieve referrer list.');
    }
    // Optional: Add admin check here if only admins should get this list
    // if (!context.auth.token.admin) {
    //   throw new functions.https.HttpsError('permission-denied', 'You do not have permission to view this list.');
    // }

    try {
        const referrersSnapshot = await admin.firestore().collection('referrers').get();
        const referrers = [];
        referrersSnapshot.forEach(doc => {
            const data = doc.data();
            referrers.push({
                uid: doc.id,
                name: data.name,
                refId: data.refId
            });
        });
        return { referrers: referrers };
    } catch (error) {
        console.error('Error fetching referrers list:', error);
        throw new functions.https.HttpsError('internal', 'Failed to retrieve referrers list.', error.message);
    }
});

/**
 * Firebase Callable Function to add a manual ticket sale entry.
 * This function should only be callable by super admins.
 */
exports.addManualSale = functions.https.onCall(async (data, context) => {
    // Security Check: Ensure the caller is an authenticated super admin.
    if (!context.auth || !context.auth.token.superAdminReferrer) {
        throw new functions.https.HttpsError('permission-denied', 'You must be a super admin to add manual entries.');
    }

    const { name, email, phone, ticketsBought, referrerRefId } = data; // referrerRefId is optional

    // Basic validation
    if (!name || !email || !phone || typeof ticketsBought !== 'number' || ticketsBought <= 0) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing or invalid fields: name, email, phone, or ticketsBought.');
    }

    const db = admin.firestore();
    let referrerUid = null;

    try {
        // If a referrerRefId is provided, try to find the corresponding referrer UID
        if (referrerRefId) {
            const referrerQuerySnapshot = await db.collection('referrers')
                .where('refId', '==', referrerRefId)
                .limit(1)
                .get();

            if (!referrerQuerySnapshot.empty) {
                referrerUid = referrerQuerySnapshot.docs[0].id;
                console.log(`Manual entry: Found referrer UID: ${referrerUid} for refId: ${referrerRefId}`);
            } else {
                console.warn(`Manual entry: Referrer with refId ${referrerRefId} not found. Entry will not be linked to a referrer.`);
            }
        }
        // If no referrerRefId, or referrer not found, it defaults to null

        // Add the manual raffle entry to the 'raffle_entries' collection
        await db.collection('raffle_entries').add({
            name: name,
            email: email,
            phone: phone,
            referrerRefId: referrerRefId || null, // Store the provided refId or null
            referrerUid: referrerUid, // Store the resolved UID or null
            amount: ticketsBought * 126.00, // Assuming $126 per ticket for manual entries
            ticketsBought: ticketsBought,
            paymentStatus: 'manual_entry', // Custom status for manual entries
            orderID: `MANUAL_${Date.now()}_${Math.random().toString(36).substr(2, 9).toUpperCase()}`, // Unique ID
            timestamp: admin.firestore.FieldValue.serverTimestamp(), // Timestamp for manual entries is current server time
            entryType: 'manual', // Explicitly mark as manual
            processedBy: context.auth.uid // Record who added it
        });

        console.log(`Successfully added manual raffle entry for ${name}. Tickets: ${ticketsBought}`);
        return { success: true, message: `Manual entry for ${ticketsBought} tickets added successfully for ${name}.` };

    } catch (error) {
        console.error('Error adding manual raffle entry:', error);
        if (error instanceof functions.https.HttpsError) {
            throw error;
        }
        throw new functions.https.HttpsError('internal', 'An unexpected error occurred while adding manual entry.', error.message);
    }
});

/**
 * Firebase Callable Function to retrieve all ticket sales,
 * with each ticket counting as a separate entry for export purposes.
 * This function should only be callable by super admins.
 */
exports.getAllTicketsSold = functions.https.onCall(async (data, context) => {
    // 1. Authenticate and authorize the user
    if (!context.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'The function must be called while authenticated.');
    }

    // IMPORTANT: Ensure your 'superAdminReferrer' custom claim is correctly set for superadmins.
    if (!context.auth.token.superAdminReferrer) {
        throw new functions.https.HttpsError('permission-denied', 'You do not have permission to view all tickets.');
    }

    const db = admin.firestore();
    const allExpandedTickets = []; // This will store the 'one by one' entries

    try {
        // Fetch all referrer names and refIds once to avoid repeated lookups in the loop
        const referrersMap = new Map(); // Map<referrerUid, { name: string, refId: string }>
        const referrersSnapshot = await db.collection('referrers').get();
        referrersSnapshot.forEach(doc => {
            referrersMap.set(doc.id, { name: doc.data().name, refId: doc.data().refId });
        });

        // Fetch all ticket sales from 'raffle_entries' collection
        const salesRef = db.collection('raffle_entries');
        const snapshot = await salesRef.orderBy('timestamp', 'desc').get();

        for (const doc of snapshot.docs) {
            const sale = doc.data();
            const ticketsBought = sale.ticketsBought || 0; // Ensure ticketsBought is a number

            let referrerInfo = 'N/A'; // Default value

            // Logic to determine referrerInfo string
            if (sale.referrerUid && referrersMap.has(sale.referrerUid)) {
                const referrer = referrersMap.get(sale.referrerUid);
                referrerInfo = `${referrer.name} (${referrer.refId})`;
            } else if (sale.referrerRefId && sale.referrerRefId !== 'N/A') { // Fallback if UID lookup fails but refId is present
                // This case handles existing entries where only referrerRefId might be present
                // or if the UID lookup from the map failed for some reason.
                referrerInfo = `(Ref ID: ${sale.referrerRefId})`;
            }
            // If neither referrerUid nor referrerRefId is present/valid, it remains 'N/A'

            const formattedTimestamp = sale.timestamp ? sale.timestamp.toDate().toLocaleString('en-US', {
                month: '2-digit', day: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true,
                timeZone: 'America/New_York' // Explicitly set timezone for consistency
            }) : 'N/A';

            // Create one entry for each ticket bought
            for (let i = 0; i < ticketsBought; i++) {
                allExpandedTickets.push({
                    buyerName: sale.name,
                    buyerEmail: sale.email,
                    buyerPhone: sale.phone,
                    ticketsBought: 1, // This column now represents a single ticket
                    referrerInfo: referrerInfo,
                    timestamp: formattedTimestamp,
                    originalOrderId: sale.orderID, // Keep original order ID for reference
                    ticketNumberInOrder: i + 1 // Which ticket it is within the original order
                });
            }
        }

        return { tickets: allExpandedTickets };

    } catch (error) {
        console.error('Error fetching all tickets sold:', error);
        if (error instanceof functions.https.HttpsError) {
            throw error;
        }
        throw new functions.https.HttpsError('internal', 'Failed to retrieve all tickets sold.', error.message);
    }
});

/**
 * DANGER ZONE: Hard Reprocesses ALL PayPal-originated raffle entries.
 * For each COMPLETED PayPal order, it will:
 * 1. Attempt to DELETE any existing raffle_entry with the same orderID.
 * 2. CREATE a new raffle_entry using data from the PayPal order,
 * setting its timestamp to paypal_orders.createdAt.
 * This is a destructive operation and should ONLY be used for data correction
 * after ensuring a full database backup. Only callable by superadmins.
 */
exports.hardReprocessAllTicketsFromPayPal = functions.https.onCall(async (data, context) => {
    console.log('HARD_REPROCESS_LOG: Function execution started.'); // <-- Added log
    // SECURITY CHECK: ABSOLUTELY ESSENTIAL
    if (!context.auth || !context.auth.token.superAdminReferrer) {
        console.error('HARD_REPROCESS_LOG: Permission denied for user:', context.auth ? context.auth.uid : 'unauthenticated'); // <-- Added log
        throw new functions.https.HttpsError('permission-denied', 'You must be a super admin to run this dangerous operation.');
    }
    console.log('HARD_REPROCESS_LOG: User is superadmin. Proceeding.'); // <-- Added log

    const db = admin.firestore();
    let entriesDeletedCount = 0;
    let entriesCreatedCount = 0;
    const errors = [];
    let batch = db.batch();
    let batchOperations = 0; // Counter for batch operations

    try {
        console.log('HARD_REPROCESS_LOG: Fetching referrers map.'); // <-- Added log
        // Fetch all referrer names and refIds once to ensure referrerUid can be resolved if needed
        const referrersMap = new Map(); // Map<referrerUid, { name: string, refId: string }>
        const referrersSnapshot = await db.collection('referrers').get();
        referrersSnapshot.forEach(doc => {
            referrersMap.set(doc.id, { name: doc.data().name, refId: doc.data().refId });
        });
        console.log(`HARD_REPROCESS_LOG: Referrers map built with ${referrersMap.size} entries.`); // <-- Added log


        console.log('HARD_REPROCESS_LOG: Fetching COMPLETED PayPal orders.'); // <-- Added log
        // Step 1: Get all COMPLETED PayPal orders
        const paypalOrdersSnapshot = await db.collection('paypal_orders')
            .where('status', '==', 'COMPLETED')
            .get();

        if (paypalOrdersSnapshot.empty) {
            console.log('HARD_REPROCESS_LOG: No COMPLETED PayPal orders found.'); // <-- Added log
            return { success: true, message: 'No COMPLETED PayPal orders found to reprocess.', deleted: 0, created: 0, errors: [] };
        }

        console.log(`HARD_REPROCESS_LOG: Found ${paypalOrdersSnapshot.size} COMPLETED PayPal orders to process.`); // <-- Added log

        const processPromises = [];

        for (const orderDoc of paypalOrdersSnapshot.docs) {
            const orderData = orderDoc.data();
            const orderID = orderDoc.id;

            // Optional: Add a very verbose log here if you want to see every order being considered.
            // console.log(`HARD_REPROCESS_LOG: Considering PayPal order: ${orderID}`);

            processPromises.push((async () => {
                try {
                    const entryTimestamp = orderData.createdAt;

                    if (!entryTimestamp || typeof entryTimestamp.toDate !== 'function') {
                        throw new Error(`PayPal order ${orderID} missing valid 'createdAt' timestamp.`);
                    }

                    // --- Step 2: Delete existing raffle_entry if it exists ---
                    const existingRaffleEntrySnapshot = await db.collection('raffle_entries')
                        .where('orderID', '==', orderID)
                        .limit(1) // Assuming one raffle_entry per orderID
                        .get();

                    if (!existingRaffleEntrySnapshot.empty) {
                        existingRaffleEntrySnapshot.forEach(docToDelete => {
                            batch.delete(docToDelete.ref);
                            batchOperations++;
                            entriesDeletedCount++;
                            console.log(`HARD_REPROCESS_LOG: Batching delete for existing raffle_entry ${docToDelete.id} (Order ID: ${orderID})`);
                        });
                    }

                    // --- Resolve referrer UID for the new entry ---
                    let referrerUidForNewEntry = null;
                    if (orderData.referrerRefId) {
                        // Find UID from the pre-fetched map or do a direct lookup if not found
                        for (const [uid, rData] of referrersMap.entries()) {
                            if (rData.refId === orderData.referrerRefId) {
                                referrerUidForNewEntry = uid;
                                break;
                            }
                        }
                        if (!referrerUidForNewEntry) {
                            // If not found in map, attempt a direct lookup (less efficient, but fallback)
                            const referrerQuerySnapshot = await db.collection('referrers')
                                .where('refId', '==', orderData.referrerRefId)
                                .limit(1)
                                .get();
                            if (!referrerQuerySnapshot.empty) {
                                referrerUidForNewEntry = referrerQuerySnapshot.docs[0].id;
                            } else {
                                console.warn(`HARD_REPROCESS_LOG: Referrer with refId ${orderData.referrerRefId} not found for order ${orderID}. New entry will not be linked to UID.`);
                            }
                        }
                    }

                    // --- Step 3: Recreate the raffle_entry ---
                    const ticketsBought = Math.floor(orderData.amount / 126.00); // Assuming $126 per ticket

                    const newRaffleEntryData = {
                        name: orderData.name,
                        email: orderData.email,
                        phone: orderData.phone,
                        referrerRefId: orderData.referrerRefId || null,
                        referrerUid: referrerUidForNewEntry, // Use the resolved UID
                        amount: orderData.amount,
                        ticketsBought: ticketsBought,
                        paymentStatus: 'completed', // Explicitly set status
                        orderID: orderID,
                        timestamp: entryTimestamp, // Use the actual PayPal order creation timestamp
                        entryType: 'paypal', // Mark as PayPal originated
                        reprocessingNote: `Recreated by hardReprocessAllTicketsFromPayPal on ${admin.firestore.FieldValue.serverTimestamp().toDate().toLocaleString('en-US', { timeZone: 'America/New_York' })}`,
                        reprocessedBy: context.auth.uid
                    };

                    batch.set(db.collection('raffle_entries').doc(), newRaffleEntryData); // Let Firestore generate new ID
                    batchOperations++;
                    entriesCreatedCount++;
                    console.log(`HARD_REPROCESS_LOG: Batching creation for new raffle_entry (Order ID: ${orderID})`);

                    // --- Commit batch if it's getting large ---
                    if (batchOperations >= 400) { // Keep well under Firestore's 500 operation limit
                        await batch.commit();
                        console.log(`HARD_REPROCESS_LOG: Batch committed. Current deleted: ${entriesDeletedCount}, created: ${entriesCreatedCount}`);
                        batch = db.batch(); // Start a new batch
                        batchOperations = 0;
                    }

                } catch (error) {
                    console.error(`HARD_REPROCESS_LOG: Error reprocessing PayPal order ${orderID}:`, error); // <-- Crucial log
                    errors.push(`Order ${orderID}: ${error.message}`);
                }
            })());
        }

        // Wait for all individual order processing tasks to complete
        await Promise.all(processPromises);

        // Commit any remaining operations in the final batch
        if (batchOperations > 0) {
            await batch.commit();
            console.log(`HARD_REPROCESS_LOG: Final batch committed. Deleted: ${entriesDeletedCount}, Created: ${entriesCreatedCount}`);
        }

        console.log('HARD_REPROCESS_LOG: --- HARD REPROCESSING COMPLETE ---'); // <-- Added log
        console.log(`HARD_REPROCESS_LOG: Total raffle entries deleted: ${entriesDeletedCount}`);
        console.log(`HARD_REPROCESS_LOG: Total raffle entries created: ${entriesCreatedCount}`);
        console.log(`HARD_REPROCESS_LOG: Total errors: ${errors.length}`);

        if (errors.length > 0) {
            return {
                success: false,
                message: `Hard reprocessing finished with errors. Deleted ${entriesDeletedCount}, Created ${entriesCreatedCount}.`,
                deleted: entriesDeletedCount,
                created: entriesCreatedCount,
                errors: errors
            };
        }

        return {
            success: true,
            message: `Hard reprocessing successful. Deleted ${entriesDeletedCount}, Created ${entriesCreatedCount} entries.`,
            deleted: entriesDeletedCount,
            created: entriesCreatedCount,
            errors: []
        };

    } catch (error) {
        console.error('HARD_REPROCESS_LOG: Top-level error in hardReprocessAllTicketsFromPayPal:', error); // <-- Crucial log
        if (error instanceof functions.https.HttpsError) {
            throw error;
        }
        throw new functions.https.HttpsError('internal', 'An unexpected top-level error occurred during hard reprocessing.', error.message);
    }
});

// Add the testLogFunction again just to be sure
exports.testLogFunction = functions.https.onCall(async (data, context) => {
    console.log("TEST LOG: testLogFunction was called successfully!");
    return { status: "success", message: "Test log generated." };
});