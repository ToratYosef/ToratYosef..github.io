const functions = require('firebase-functions');
const admin = require('firebase-admin');
const { WebhooksHelper } = require('square');

admin.initializeApp();

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

// Added this simple test function again just to be sure your environment is fully healthy
exports.testLogFunction = functions.https.onCall(async (data, context) => {
    console.log("TEST LOG: testLogFunction was called successfully!");
    return { status: "success", message: "Test log generated." };
});

/**
 * SQUARE INTEGRATION FUNCTIONS
 */

/**
 * Lazy initialization for the Square client.
 * Initialized inside functions to handle environment variables at runtime.
 */
let squareClient = null;

function useSquareTestEnvironment() {
  return String(process.env.SQUARE_TEST_ENVIRONMENT || '').toLowerCase() === 'true';
}

function getSquareAccessToken() {
  if (useSquareTestEnvironment()) {
    return process.env.SQUARE_TEST_TEST_ACCESS_TOKEN || process.env.SQUARE_TEST_ACCESS_TOKEN;
  }
  return process.env.SQUARE_ACCESS_TOKEN;
}

function getSquareClient() {
  if (!squareClient) {
    const accessToken = getSquareAccessToken();
    if (!accessToken) {
      throw new functions.https.HttpsError('internal', 'Square access token environment variable not configured for current mode');
    }
    const { Client, Environment } = require('square');
    const squareEnv = useSquareTestEnvironment() ? Environment.Sandbox : Environment.Production;
    squareClient = new Client({
      accessToken: accessToken,
      environment: squareEnv
    });
  }
  return squareClient;
}

/**
 * Firebase Callable Function to create a Square Payment Link for prize purchases.
 * This is invoked directly from your frontend.
 */
exports.createSquarePaymentLink = functions.https.onCall(async (data, context) => {
  const { prizeId, name, email, phone, referral } = data;

  if (!prizeId || !name || !email || !phone) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing required fields: prizeId, name, email, or phone.');
  }

  // Define prize details (in cents)
  const prizeDetails = {
    rolex: {
      name: 'Rolex Datejust 41 Watch',
      amount: 5000, // $50.00 in cents
      description: 'Rolex Datejust 41, Oystersteel with Jubilee bracelet'
    },
    cash: {
      name: '$1,000 Cash Prize',
      amount: 100000, // $1,000.00 in cents
      description: 'One time $1,000 cash prize'
    }
  };

  const prize = prizeDetails[prizeId];
  if (!prize) {
    throw new functions.https.HttpsError('invalid-argument', 'Invalid prize ID');
  }

  try {
    // Save initial order details to 'square_orders' collection
    const orderRef = admin.firestore().collection('square_orders').doc();
    const orderId = orderRef.id;

    await orderRef.set({
      prizeId,
      name,
      email,
      phone,
      referrerRefId: referral || null,
      amount: prize.amount,
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const locationId = process.env.SQUARE_LOCATION_ID;
    if (!locationId) {
      throw new functions.https.HttpsError('internal', 'Square location ID not configured');
    }

    // Create Square payment link
    const squareClientInstance = getSquareClient();
    const paymentLink = await squareClientInstance.checkoutApi.createPaymentLink({
      idempotencyKey: orderId,
      quickPay: {
        name: prize.name,
        priceMoney: {
          amount: prize.amount,
          currency: 'USD'
        },
        locationId: locationId
      },
      redirectUrl: `${process.env.DOMAIN || 'https://www.toratyosefsummerraffle.com'}/success.html?order_id=${orderId}&payment_method=square`,
      note: `Prize Entry - ${prizeId} | Name: ${name} | Email: ${email} | Phone: ${phone}`
    });

    if (!paymentLink?.result?.paymentLink?.url) {
      throw new functions.https.HttpsError('internal', 'Failed to generate payment link URL');
    }

    // Update the order with payment link info
    await orderRef.update({
      paymentLinkId: paymentLink.result.paymentLink.id,
      paymentLinkUrl: paymentLink.result.paymentLink.url
    });

    return { 
      paymentLinkUrl: paymentLink.result.paymentLink.url,
      orderId: orderId
    };
  } catch (err) {
    console.error('createSquarePaymentLink error:', err);
    if (err instanceof functions.https.HttpsError) {
      throw err;
    }
    throw new functions.https.HttpsError('internal', 'Failed to create Square payment link', err.message);
  }
});

/**
 * Firebase Callable Function to verify Square payment completion
 * This checks if a Square payment was completed for an order
 */
exports.verifySquarePayment = functions.https.onCall(async (data, context) => {
  const { orderId } = data;

  if (!orderId) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing orderId');
  }

  try {
    const db = admin.firestore();
    const orderDocRef = db.collection('square_orders').doc(orderId);
    const orderDoc = await orderDocRef.get();

    if (!orderDoc.exists) {
      throw new functions.https.HttpsError('not-found', 'Order not found');
    }

    const orderData = orderDoc.data();

    // If prize entry was already created, payment is confirmed
    if (orderData.prizeEntryCreatedAt) {
      return { 
        status: 'completed',
        message: 'Payment verified and prize entry created'
      };
    }

    // Otherwise, payment is still pending
    return {
      status: 'pending',
      message: 'Payment is being processed'
    };
  } catch (err) {
    console.error('verifySquarePayment error:', err);
    if (err instanceof functions.https.HttpsError) {
      throw err;
    }
    throw new functions.https.HttpsError('internal', 'Failed to verify payment', err.message);
  }
});

function getSquareWebhookConfig(mode) {
  const isTest = mode === 'test';

  return {
    environment: isTest ? 'test' : 'live',
    subscriptionId: isTest
      ? process.env.SQUARE_WEBHOOK_TEST_SUBSCRIPTION_ID
      : process.env.SQUARE_WEBHOOK_SUBSCRIPTION_ID,
    signatureKey: isTest
      ? process.env.SQUARE_WEBHOOK_TEST_SIGNATURE_KEY
      : process.env.SQUARE_WEBHOOK_SIGNATURE_KEY,
    notificationUrl: isTest
      ? process.env.SQUARE_WEBHOOK_TEST_NOTIFICATION_URL
      : process.env.SQUARE_WEBHOOK_NOTIFICATION_URL
  };
}

async function verifySquareWebhookSignature(rawBody, signature, signatureKey, notificationUrl) {
  try {
    return await WebhooksHelper.verifySignature({
      requestBody: rawBody,
      signatureHeader: signature,
      signatureKey,
      notificationUrl
    });
  } catch (error) {
    return await WebhooksHelper.verifySignature(rawBody, signature, signatureKey, notificationUrl);
  }
}

function getReferrerFromMetadata(metadata = {}) {
  return metadata.referrer || metadata.ref || metadata.referral || null;
}

async function getReferrerFromSquareOrderRecord(squareOrderId) {
  if (!squareOrderId) {
    return null;
  }

  const orderSnapshot = await admin.firestore().collection('square_orders')
    .where('squareOrderId', '==', squareOrderId)
    .limit(1)
    .get();

  if (orderSnapshot.empty) {
    return null;
  }

  const orderData = orderSnapshot.docs[0].data();
  return orderData.referrerRefId || orderData.referral || null;
}

async function saveSquarePayment(payment, event, environment) {
  const paymentId = payment.id;

  if (!paymentId) {
    console.warn('Square payment missing payment id', {
      environment,
      eventType: event.type
    });
    return;
  }

  const status = payment.status || null;
  const orderId = payment.order_id || null;
  const customerId = payment.customer_id || null;
  const amountMoney = payment.amount_money || {};
  const amountCents = amountMoney.amount || 0;
  const amount = amountCents / 100;
  const currency = amountMoney.currency || 'USD';

  const metadataReferrer = getReferrerFromMetadata(payment.metadata || {});
  const orderReferrer = await getReferrerFromSquareOrderRecord(orderId);
  const referrer = metadataReferrer || orderReferrer || 'direct';

  const saleDocId = `${environment}_square_payment_${paymentId}`;
  const saleRef = admin.firestore().collection('sales').doc(saleDocId);

  await saleRef.set({
    source: 'square',
    environment,
    type: 'payment',
    squarePaymentId: paymentId,
    squareOrderId: orderId,
    squareCustomerId: customerId,
    status,
    amount,
    amountCents,
    currency,
    referrer,
    eventType: event.type,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    rawPayment: payment
  }, { merge: true });

  console.log('Saved Square payment sale', {
    environment,
    paymentId,
    referrer,
    amount,
    status
  });
}

async function saveSquareOrder(order, event, environment) {
  const orderId = order.id;

  if (!orderId) {
    console.warn('Square order missing order id', {
      environment,
      eventType: event.type
    });
    return;
  }

  const state = order.state || null;
  const totalMoney = order.total_money || {};
  const amountCents = totalMoney.amount || 0;
  const amount = amountCents / 100;
  const currency = totalMoney.currency || 'USD';
  const referrer = getReferrerFromMetadata(order.metadata || {}) || 'direct';

  const saleDocId = `${environment}_square_order_${orderId}`;
  const saleRef = admin.firestore().collection('sales').doc(saleDocId);

  await saleRef.set({
    source: 'square',
    environment,
    type: 'order',
    squareOrderId: orderId,
    status: state,
    amount,
    amountCents,
    currency,
    referrer,
    eventType: event.type,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    rawOrder: order
  }, { merge: true });

  console.log('Saved Square order sale', {
    environment,
    orderId,
    referrer,
    amount,
    status: state
  });
}

async function handleSquareWebhook(event, environment) {
  const eventId = event.event_id;
  const eventType = event.type;

  if (!eventId) {
    console.warn('Square webhook missing event_id', {
      environment,
      eventType
    });
    return;
  }

  const eventDocId = `${environment}_${eventId}`;
  const eventRef = admin.firestore().collection('squareWebhookEvents').doc(eventDocId);
  const eventSnap = await eventRef.get();

  if (eventSnap.exists) {
    console.log('Duplicate Square webhook ignored', {
      environment,
      eventId,
      eventType
    });
    return;
  }

  await eventRef.set({
    eventId,
    eventType,
    environment,
    receivedAt: admin.firestore.FieldValue.serverTimestamp(),
    raw: event
  });

  const allowedEvents = [
    'payment.created',
    'payment.updated',
    'order.created',
    'order.updated'
  ];

  if (!allowedEvents.includes(eventType)) {
    console.log('Ignoring Square event type', {
      environment,
      eventType
    });
    return;
  }

  const object = event?.data?.object || {};

  if (object.payment) {
    await saveSquarePayment(object.payment, event, environment);
  }

  if (object.order) {
    await saveSquareOrder(object.order, event, environment);
  }
}

async function handleSquareWebhookRequest(req, res, mode) {
  try {
    if (req.method !== 'POST') {
      return res.status(405).send('Method not allowed');
    }

    const squareConfig = getSquareWebhookConfig(mode);
    if (!squareConfig.signatureKey || !squareConfig.notificationUrl) {
      console.error('Missing Square webhook config', {
        mode: squareConfig.environment,
        hasSignatureKey: Boolean(squareConfig.signatureKey),
        notificationUrl: squareConfig.notificationUrl
      });
      return res.status(500).send('Missing webhook config');
    }

    const signature = req.get('x-square-hmacsha256-signature');
    if (!signature) {
      console.error('Missing Square signature header', {
        mode: squareConfig.environment
      });
      return res.status(403).send('Missing signature');
    }

    const rawBody = req.rawBody && req.rawBody.length
      ? req.rawBody.toString('utf8')
      : null;
    if (!rawBody) {
      console.error('Missing raw body', {
        mode: squareConfig.environment
      });
      return res.status(400).send('Missing raw body');
    }

    const isValid = await verifySquareWebhookSignature(
      rawBody,
      signature,
      squareConfig.signatureKey,
      squareConfig.notificationUrl
    );

    if (!isValid) {
      console.error('Invalid Square webhook signature', {
        mode: squareConfig.environment,
        notificationUrl: squareConfig.notificationUrl
      });
      return res.status(403).send('Invalid signature');
    }

    const event = JSON.parse(rawBody);
    console.log('Square webhook verified', {
      mode: squareConfig.environment,
      eventType: event.type,
      eventId: event.event_id
    });

    await handleSquareWebhook(event, squareConfig.environment);
    return res.status(200).send('OK');
  } catch (error) {
    console.error('Square webhook error:', error);
    return res.status(500).send('Webhook error');
  }
}

/**
 * Sandbox/test Square webhook
 * URL: https://us-central1-torat-yose.cloudfunctions.net/squareWebhook
 */
exports.squareWebhook = functions.region('us-central1').https.onRequest(async (req, res) => {
  return handleSquareWebhookRequest(req, res, 'test');
});

/**
 * Live/production Square webhook
 * URL: https://us-central1-torat-yose.cloudfunctions.net/LiveSquareWebhook
 */
exports.LiveSquareWebhook = functions.region('us-central1').https.onRequest(async (req, res) => {
  return handleSquareWebhookRequest(req, res, 'live');
});