const functions = require('firebase-functions');
const admin = require('firebase-admin');
const fetch = require('node-fetch');
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
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
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

        if (currentReferrerDetails.refId) {
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
        }

    } else {
        const ticketsSoldSnapshot = await admin.firestore().collection('raffle_entries')
          .where('referrerUid', '==', targetReferrerUid)
          .orderBy('timestamp', 'desc')
          .get();

        ticketsSoldSnapshot.forEach(doc => {
            const entry = doc.data();
            totalTicketsSold += (entry.ticketsBought || 0);

            if (!isViewerAccount) {
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

    const referralLink = currentReferrerDetails.refId ? `https://www.toratyosefsummerraffle.com/?ref=${currentReferrerDetails.refId}` : null;

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