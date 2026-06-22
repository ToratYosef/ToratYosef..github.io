const functions = require('firebase-functions');
const admin = require('firebase-admin');
const crypto = require('crypto');
const { WebhooksHelper } = require('square');

admin.initializeApp();

function normalizeAliasKey(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function toRefCodeToken(value) {
  return String(value || '').replace(/[^a-zA-Z0-9]/g, '');
}

function generateRefIdFromName(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) {
    throw new functions.https.HttpsError('invalid-argument', 'Name is required to generate a referral ID.');
  }

  const first = toRefCodeToken(parts[0]);
  const last = toRefCodeToken(parts[parts.length - 1]);
  if (!first || !last) {
    throw new functions.https.HttpsError('invalid-argument', 'Name must include valid letters/numbers.');
  }

  const firstNormalized = first.charAt(0).toUpperCase() + first.slice(1).toLowerCase();
  const lastInitial = last.charAt(0).toUpperCase();
  return `${firstNormalized}${lastInitial}`;
}

function buildAdminAliasKeys(name, refId, email) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  const first = parts[0] || '';
  const last = parts[parts.length - 1] || '';
  const firstLastInitial = `${first}${last ? ' ' + last.charAt(0) : ''}`.trim();

  const candidates = [
    refId,
    name,
    firstLastInitial,
    String(email || '').split('@')[0] || ''
  ];

  return Array.from(new Set(
    candidates
      .map(normalizeAliasKey)
      .filter(Boolean)
  ));
}

async function saveAdminAliases({ uid, email, name, refId }) {
  const db = admin.firestore();
  const aliases = buildAdminAliasKeys(name, refId, email);
  const writes = aliases.map((aliasKey) => db.collection('adminLoginAliases').doc(aliasKey).set({
    uid,
    email,
    name,
    refId,
    aliasKey,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true }));
  await Promise.all(writes);
}

function sanitizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function splitNameParts(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) {
    return { firstName: '', lastName: '' };
  }
  return {
    firstName: parts[0],
    lastName: parts.length > 1 ? parts.slice(1).join(' ') : ''
  };
}

function toPositiveInt(value, fallback = 0) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  return parsed;
}

async function applyAdminTicketProgressUpdate({
  db,
  adminUid,
  refId,
  raffleEntryId,
  ticketsBought,
  amount,
  orderId,
  paymentId,
  paymentMethod,
  buyerName,
  buyerEmail,
  buyerPhone
}) {
  if (!adminUid) {
    return;
  }

  const tickets = toPositiveInt(ticketsBought, 0);
  if (tickets <= 0) {
    return;
  }

  const adminRef = db.collection('admin').doc(adminUid);
  const saleRef = adminRef.collection('ticketSales').doc(orderId || db.collection('_').doc().id);

  await db.runTransaction(async (transaction) => {
    const adminSnap = await transaction.get(adminRef);
    if (!adminSnap.exists) {
      return;
    }

    const data = adminSnap.data() || {};
    const goal = toPositiveInt(data.goal, 0);
    const revenueSoFar = Number.isFinite(Number(data.totalRevenue)) ? Number(data.totalRevenue) : 0;
    const saleAmount = Number.isFinite(Number(amount)) ? Number(amount) : 0;
    const soldSoFar = toPositiveInt(
      data.totalTicketsSold !== undefined ? data.totalTicketsSold : data.ticketsSold,
      0
    );

    const nextSold = soldSoFar + tickets;
    const nextRevenue = revenueSoFar + saleAmount;
    const nextRemaining = goal > 0 ? Math.max(goal - nextSold, 0) : Math.max(toPositiveInt(data.ticketsRemaining, 0) - tickets, 0);

    transaction.set(adminRef, {
      ref: data.ref || data.refId || refId || null,
      refId: data.refId || data.ref || refId || null,
      totalTicketsSold: nextSold,
      ticketsSold: nextSold,
      totalRevenue: nextRevenue,
      ticketsRemaining: nextRemaining,
      goalRemaining: nextRemaining,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      lastSaleAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    transaction.set(saleRef, {
      orderId: orderId || null,
      paymentId: paymentId || null,
      paymentMethod: String(paymentMethod || 'square').toLowerCase(),
      refId: refId || null,
      raffleEntryId: raffleEntryId || null,
      ticketsBought: tickets,
      amount: Number(amount) || 0,
      buyerName: String(buyerName || ''),
      buyerEmail: sanitizeEmail(buyerEmail),
      buyerPhone: String(buyerPhone || ''),
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
  });
}

/**
 * Creates or updates a super admin referrer account.
 * This callable is locked to signed-in users with superAdminReferrer claim.
 */
exports.createAdminAccount = functions.https.onCall(async (data, context) => {
  if (!context.auth || !context.auth.token.superAdminReferrer) {
    throw new functions.https.HttpsError('permission-denied', 'Only super admins can create admin accounts.');
  }

  const name = String(data?.name || '').trim();
  const firstNameInput = String(data?.firstName || '').trim();
  const lastNameInput = String(data?.lastName || '').trim();
  const email = sanitizeEmail(data?.email);
  const password = String(data?.password || '');
  const goal = toPositiveInt(data?.goal, 300);
  const role = String(data?.role || 'admin').trim() === 'superAdminReferrer' ? 'superAdminReferrer' : 'admin';
  const isActive = data?.isActive !== false;
  const generatedNameParts = splitNameParts(name);
  const firstName = firstNameInput || generatedNameParts.firstName;
  const lastName = lastNameInput || generatedNameParts.lastName;


  if (!name || !email || !password) {
    throw new functions.https.HttpsError('invalid-argument', 'Missing required fields: name, email, password.');
  }

  if (password.length < 6) {
    throw new functions.https.HttpsError('invalid-argument', 'Password must be at least 6 characters long.');
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new functions.https.HttpsError('invalid-argument', 'Email format is invalid.');
  }

  const requestedRefId = String(data?.refId || data?.ref || '').trim();
  const refId = requestedRefId || generateRefIdFromName(name);
  const db = admin.firestore();

  const existingRefId = await db.collection('admin').where('refId', '==', refId).limit(1).get();
  if (!existingRefId.empty && existingRefId.docs[0].id !== context.auth.uid) {
    const targetUid = existingRefId.docs[0].id;
    const existingByEmail = await admin.auth().getUserByEmail(email).catch(() => null);
    if (!existingByEmail || existingByEmail.uid !== targetUid) {
      throw new functions.https.HttpsError('already-exists', 'Referral ID already exists.');
    }
  }

  let userRecord;
  let operation = 'updated';
  try {
    userRecord = await admin.auth().getUserByEmail(email);
    userRecord = await admin.auth().updateUser(userRecord.uid, {
      email,
      password,
      displayName: name,
      emailVerified: true,
      disabled: !isActive
    });
  } catch (error) {
    if (error.code !== 'auth/user-not-found') {
      throw error;
    }
    operation = 'created';
    userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: name,
      emailVerified: true,
      disabled: !isActive
    });
  }

  await admin.auth().setCustomUserClaims(userRecord.uid, {
    referrer: true,
    admin: role === 'admin',
    superAdminReferrer: role === 'superAdminReferrer'
  });

  await db.collection('referrers').doc(userRecord.uid).set({
    name,
    email,
    refId,
    goal,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });

  await db.collection('admin').doc(userRecord.uid).set({
    uid: userRecord.uid,
    name,
    firstName,
    lastName,
    email,
    ref: refId,
    refId,
    goal,
    ticketsRemaining: goal,
    totalTicketsSold: 0,
    ticketsSold: 0,
    role,
    isActive,
    isSuperAdminReferrer: role === 'superAdminReferrer',
    createdByUid: context.auth.uid,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  }, { merge: true });

  await saveAdminAliases({
    uid: userRecord.uid,
    email,
    name,
    refId
  });

  return {
    success: true,
    operation,
    uid: userRecord.uid,
    email,
    refId,
    message: `Admin account ${operation} successfully.`
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
        const adminProfileDoc = await admin.firestore().collection('admin').doc(loggedInUid).get();
        if (adminProfileDoc.exists) {
          const adminProfile = adminProfileDoc.data() || {};
          const fallbackName = adminProfile.name || "Master Admin";
          const fallbackRefId = adminProfile.refId || "N/A";
          dashboardTitleName = fallbackName;
          referrerData = {
            data: () => ({
              name: fallbackName,
              refId: fallbackRefId,
              goal: adminProfile.goal || 0
            })
          };
        } else {
          dashboardTitleName = "Master Admin";
          // Create a dummy referrerData object for superadmins who might not have a direct referrer profile
          referrerData = {
            data: () => ({ name: "Master Admin", refId: "N/A", goal: 0 })
          };
        }
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
              .get();

            const ownSalesDocs = ownSalesSnapshot.docs.slice().sort((a, b) => {
              const aMs = a.data().timestamp && typeof a.data().timestamp.toMillis === 'function' ? a.data().timestamp.toMillis() : 0;
              const bMs = b.data().timestamp && typeof b.data().timestamp.toMillis === 'function' ? b.data().timestamp.toMillis() : 0;
              return bMs - aMs;
            });

            ownSalesDocs.forEach(doc => {
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
          .get();

        const sortedTicketsSoldDocs = ticketsSoldSnapshot.docs.slice().sort((a, b) => {
            const aMs = a.data().timestamp && typeof a.data().timestamp.toMillis === 'function' ? a.data().timestamp.toMillis() : 0;
            const bMs = b.data().timestamp && typeof b.data().timestamp.toMillis === 'function' ? b.data().timestamp.toMillis() : 0;
            return bMs - aMs;
        });

        sortedTicketsSoldDocs.forEach(doc => {
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

    const referralLink = currentReferrerDetails.refId && currentReferrerDetails.refId !== "N/A" ? `https://toratyosefsummerraffle.com/?ref=${currentReferrerDetails.refId}` : null;

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
 * Locked to authenticated super admins.
 */
exports.createReferrerAccount = functions.https.onCall(async (data, context) => {
    if (!context.auth || !context.auth.token.superAdminReferrer) {
      throw new functions.https.HttpsError('permission-denied', 'Only super admins can create referrer accounts.');
    }

    // 2. Validate Input Data
    const { email, password, name, goal, isSuperAdminReferrer } = data;
    const generatedRefId = generateRefIdFromName(name);

    if (!email || !password || !name || typeof goal !== 'number' || goal < 0) {
      throw new functions.https.HttpsError('invalid-argument', 'Missing or invalid fields: email, password, name, or goal.');
    }
    if (password.length < 6) {
        throw new functions.https.HttpsError('invalid-argument', 'Password must be at least 6 characters long.');
    }
    if (!generatedRefId.match(/^[a-zA-Z0-9]+$/)) {
      throw new functions.https.HttpsError('invalid-argument', 'Generated referral ID is invalid.');
    }

    try {
        // 3. Check if refId already exists to ensure uniqueness
        const existingRefId = await admin.firestore().collection('referrers')
          .where('refId', '==', generatedRefId)
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
            refId: generatedRefId,
            goal: goal,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

          await saveAdminAliases({
            uid: userRecord.uid,
            email,
            name,
            refId: generatedRefId
          });

          console.log(`Successfully created new referrer: ${name} (${email}) with UID: ${userRecord.uid}. RefId: ${generatedRefId}. Is Super Admin: ${!!isSuperAdminReferrer}`);
          return { success: true, uid: userRecord.uid, refId: generatedRefId, message: 'Referrer account created successfully.' };

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
 * Locked to authenticated super admins.
 */
exports.createViewerAccount = functions.https.onCall(async (data, context) => {
  if (!context.auth || !context.auth.token.superAdminReferrer) {
    throw new functions.https.HttpsError('permission-denied', 'Only super admins can create viewer accounts.');
  }

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
  const token = context.auth?.token || {};
  if (!context.auth || (!token.superAdminReferrer && !token.superAdmin)) {
    throw new functions.https.HttpsError('permission-denied', 'You must be a super admin to add manual entries.');
  }

  const name = String(data?.name || '').trim();
  const email = sanitizeEmail(data?.email);
  const phone = String(data?.phone || '').trim();
  const requestedTickets = Number(data?.ticketsBought);
  const ticketsBought = Number.isInteger(requestedTickets) && requestedTickets > 0 ? requestedTickets : 0;
  const requestedAdminUid = String(data?.referrerUid || '').trim();
  const requestedRefId = String(data?.referrerRefId || '').trim();
  const paymentMethod = String(data?.paymentMethod || '').trim().toLowerCase();
  const allowedPaymentMethods = new Set(['zelle', 'cash', 'venmo', 'other']);

  if (!name || !email || !phone || ticketsBought <= 0 || !requestedAdminUid) {
    throw new functions.https.HttpsError(
      'invalid-argument',
      'Name, email, phone, ticket quantity, and referring admin are required.'
    );
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new functions.https.HttpsError('invalid-argument', 'Email format is invalid.');
  }
  if (!allowedPaymentMethods.has(paymentMethod)) {
    throw new functions.https.HttpsError('invalid-argument', 'Payment method must be Zelle, cash, Venmo, or other.');
  }

  const db = admin.firestore();

  try {
    const adminSnapshot = await db.collection('admin').doc(requestedAdminUid).get();
    if (!adminSnapshot.exists || adminSnapshot.data()?.isActive === false) {
      throw new functions.https.HttpsError('not-found', 'The selected admin is missing or inactive.');
    }

    const adminData = adminSnapshot.data() || {};
    const referrerRefId = String(adminData.refId || adminData.ref || '').trim();
    if (!referrerRefId) {
      throw new functions.https.HttpsError('failed-precondition', 'The selected admin does not have a referral ID.');
    }
    if (requestedRefId && requestedRefId !== referrerRefId) {
      throw new functions.https.HttpsError('failed-precondition', 'The selected admin referral information changed. Please reload.');
    }

    const amount = ticketsBought * 126;
    const orderId = `MANUAL_${Date.now()}_${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

    const raffleEntryRef = await db.collection('raffle_entries').add({
      name,
      email,
      phone,
      referrerRefId,
      referrerUid: requestedAdminUid,
      amount,
      ticketsBought,
      paymentStatus: 'manual_entry',
      paymentMethod,
      manualPaymentMethod: paymentMethod,
      orderID: orderId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      entryType: 'manual',
      processedBy: context.auth.uid
    });

    await applyAdminTicketProgressUpdate({
      db,
      adminUid: requestedAdminUid,
      refId: referrerRefId,
      raffleEntryId: raffleEntryRef.id,
      ticketsBought,
      amount,
      orderId,
      paymentId: null,
      paymentMethod,
      buyerName: name,
      buyerEmail: email,
      buyerPhone: phone
    });

    console.log('Successfully added manual raffle entry', {
      name,
      ticketsBought,
      paymentMethod,
      referrerUid: requestedAdminUid,
      referrerRefId
    });

    return {
      success: true,
      orderId,
      referrerUid: requestedAdminUid,
      referrerRefId,
      message: `Manual entry for ${ticketsBought} ticket${ticketsBought === 1 ? '' : 's'} added successfully.`
    };
  } catch (error) {
    console.error('Error adding manual raffle entry:', error);
    if (error instanceof functions.https.HttpsError) {
      throw error;
    }
    throw new functions.https.HttpsError('internal', 'An unexpected error occurred while adding manual entry.', error.message);
  }
});

function adminProgressAfterAssignment(data, ticketsDelta, revenueDelta) {
  const goal = toPositiveInt(data.goal, 0);
  const currentSold = toPositiveInt(
    data.totalTicketsSold !== undefined ? data.totalTicketsSold : data.ticketsSold,
    0
  );
  const currentRevenue = Number.isFinite(Number(data.totalRevenue)) ? Number(data.totalRevenue) : 0;
  const nextSold = Math.max(currentSold + ticketsDelta, 0);
  const nextRevenue = Math.max(currentRevenue + revenueDelta, 0);
  const currentRemaining = toPositiveInt(data.ticketsRemaining, 0);
  const nextRemaining = goal > 0
    ? Math.max(goal - nextSold, 0)
    : Math.max(currentRemaining - ticketsDelta, 0);

  return {
    totalTicketsSold: nextSold,
    ticketsSold: nextSold,
    totalRevenue: nextRevenue,
    ticketsRemaining: nextRemaining,
    goalRemaining: nextRemaining,
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  };
}

exports.reassignTicketSale = functions.https.onCall(async (data, context) => {
  const token = context.auth?.token || {};
  if (!context.auth || (!token.superAdminReferrer && !token.superAdmin)) {
    throw new functions.https.HttpsError('permission-denied', 'Only super admins can reassign ticket sales.');
  }

  const entryId = String(data?.entryId || '').trim();
  const targetAdminUid = String(data?.targetAdminUid || '').trim();
  if (!entryId || !targetAdminUid) {
    throw new functions.https.HttpsError('invalid-argument', 'Sale entry and target admin are required.');
  }

  const db = admin.firestore();
  const entryRef = db.collection('raffle_entries').doc(entryId);
  let result;

  await db.runTransaction(async (transaction) => {
    const entrySnapshot = await transaction.get(entryRef);
    if (!entrySnapshot.exists) {
      throw new functions.https.HttpsError('not-found', 'Ticket sale not found.');
    }

    const entry = entrySnapshot.data() || {};
    const storedAdminUid = String(entry.referrerUid || '').trim();
    let currentAdminUid = storedAdminUid;
    const targetAdminRef = db.collection('admin').doc(targetAdminUid);
    const targetAdminSnapshot = await transaction.get(targetAdminRef);
    if (!targetAdminSnapshot.exists || targetAdminSnapshot.data()?.isActive === false) {
      throw new functions.https.HttpsError('not-found', 'The selected admin is missing or inactive.');
    }

    const targetAdmin = targetAdminSnapshot.data() || {};
    const targetRefId = String(targetAdmin.refId || targetAdmin.ref || '').trim();
    if (!targetRefId) {
      throw new functions.https.HttpsError('failed-precondition', 'The selected admin does not have a referral ID.');
    }

    if (!currentAdminUid && entry.referrerRefId) {
      let currentAdminQuery = await transaction.get(
        db.collection('admin').where('refId', '==', String(entry.referrerRefId)).limit(1)
      );
      if (currentAdminQuery.empty) {
        currentAdminQuery = await transaction.get(
          db.collection('admin').where('ref', '==', String(entry.referrerRefId)).limit(1)
        );
      }
      if (!currentAdminQuery.empty) {
        currentAdminUid = currentAdminQuery.docs[0].id;
      }
    }

    if (storedAdminUid === targetAdminUid && String(entry.referrerRefId || '') === targetRefId) {
      result = { changed: false, entryId, targetAdminUid, targetRefId };
      return;
    }

    let currentAdminRef = null;
    let currentAdminSnapshot = null;
    if (currentAdminUid && currentAdminUid !== targetAdminUid) {
      currentAdminRef = db.collection('admin').doc(currentAdminUid);
      currentAdminSnapshot = await transaction.get(currentAdminRef);
    }

    const tickets = Math.max(toPositiveInt(entry.ticketsBought, 0), 1);
    const amount = Number.isFinite(Number(entry.amount)) ? Number(entry.amount) : tickets * 126;
    const orderId = String(entry.orderID || entry.orderId || entryId);
    const paymentId = String(entry.squarePaymentId || entry.paymentId || '').trim() || null;
    const paymentMethod = String(
      entry.paymentMethod || entry.manualPaymentMethod || entry.entryType || 'other'
    ).toLowerCase();

    transaction.update(entryRef, {
      referrerUid: targetAdminUid,
      referrerRefId: targetRefId,
      reassignedAt: admin.firestore.FieldValue.serverTimestamp(),
      reassignedBy: context.auth.uid,
      previousReferrerUid: currentAdminUid || null,
      previousReferrerRefId: entry.referrerRefId || null
    });

    if (currentAdminRef && currentAdminSnapshot?.exists) {
      transaction.set(
        currentAdminRef,
        adminProgressAfterAssignment(currentAdminSnapshot.data() || {}, -tickets, -amount),
        { merge: true }
      );
      transaction.delete(currentAdminRef.collection('ticketSales').doc(orderId));
    }

    if (currentAdminUid !== targetAdminUid) {
      transaction.set(
        targetAdminRef,
        {
          ...adminProgressAfterAssignment(targetAdmin, tickets, amount),
          lastSaleAt: admin.firestore.FieldValue.serverTimestamp()
        },
        { merge: true }
      );
    }

    transaction.set(targetAdminRef.collection('ticketSales').doc(orderId), {
      orderId,
      paymentId,
      paymentMethod,
      refId: targetRefId,
      raffleEntryId: entryId,
      ticketsBought: tickets,
      amount,
      buyerName: String(entry.name || ''),
      buyerEmail: sanitizeEmail(entry.email),
      buyerPhone: String(entry.phone || ''),
      createdAt: entry.timestamp || admin.firestore.FieldValue.serverTimestamp(),
      reassignedAt: admin.firestore.FieldValue.serverTimestamp(),
      reassignedBy: context.auth.uid
    }, { merge: true });

    result = {
      changed: true,
      entryId,
      previousAdminUid: currentAdminUid || null,
      targetAdminUid,
      targetRefId
    };
  });

  try {
    await db.collection('adminAuditLogs').add({
      action: 'reassigned_ticket_sale',
      performedBy: context.auth.uid,
      targetAdminId: targetAdminUid,
      details: result || { entryId, targetAdminUid },
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
  } catch (error) {
    console.error('Failed to write ticket reassignment audit log:', error);
  }

  return { success: true, ...result };
});

function fcmTokenDocumentId(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

exports.registerAdminFcmToken = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Login required.');
  }

  const token = String(data?.token || '').trim();
  if (token.length < 40 || token.length > 4096) {
    throw new functions.https.HttpsError('invalid-argument', 'A valid notification token is required.');
  }

  const db = admin.firestore();
  const uid = context.auth.uid;
  const profile = await db.collection('admin').doc(uid).get();
  if (!profile.exists || profile.data()?.isActive === false) {
    throw new functions.https.HttpsError('permission-denied', 'Active admin access is required.');
  }

  const tokenId = fcmTokenDocumentId(token);
  const tokenIndexRef = db.collection('adminFcmTokens').doc(tokenId);
  const previousOwner = await tokenIndexRef.get();
  const batch = db.batch();

  if (previousOwner.exists) {
    const previousUid = String(previousOwner.data()?.uid || '');
    if (previousUid && previousUid !== uid) {
      batch.delete(db.collection('admin').doc(previousUid).collection('fcmTokens').doc(tokenId));
    }
  }

  const tokenData = {
    uid,
    token,
    userAgent: String(data?.userAgent || '').slice(0, 500),
    platform: String(data?.platform || '').slice(0, 100),
    updatedAt: admin.firestore.FieldValue.serverTimestamp()
  };

  batch.set(db.collection('admin').doc(uid).collection('fcmTokens').doc(tokenId), tokenData, { merge: true });
  batch.set(tokenIndexRef, tokenData, { merge: true });
  await batch.commit();

  return { success: true };
});

async function resolveRaffleReferrerUid(entry) {
  const directUid = String(entry.referrerUid || '').trim();
  if (directUid) {
    return directUid;
  }

  const refId = String(entry.referrerRefId || '').trim();
  if (!refId || refId.toLowerCase() === 'direct') {
    return null;
  }

  const db = admin.firestore();
  let snapshot = await db.collection('admin').where('refId', '==', refId).limit(1).get();
  if (snapshot.empty) {
    snapshot = await db.collection('admin').where('ref', '==', refId).limit(1).get();
  }
  return snapshot.empty ? null : snapshot.docs[0].id;
}

async function loadFcmTokensForAdminUids(uids) {
  const db = admin.firestore();
  const uniqueUids = Array.from(new Set(uids.filter(Boolean)));
  const snapshots = await Promise.all(
    uniqueUids.map(async (uid) => ({
      uid,
      snapshot: await db.collection('admin').doc(uid).collection('fcmTokens').get()
    }))
  );

  return snapshots.flatMap(({ uid, snapshot }) => snapshot.docs.map((doc) => ({
    uid,
    tokenId: doc.id,
    token: String(doc.data()?.token || ''),
    ref: doc.ref
  }))).filter((record) => record.token);
}

async function sendAdminSaleNotification({ recipientUids, title, body, entryId, entry, link }) {
  const tokenRecords = await loadFcmTokensForAdminUids(recipientUids);
  if (!tokenRecords.length) {
    return;
  }

  const db = admin.firestore();
  const notificationIcon = new URL('/assets/logo.png', link).toString();
  for (let offset = 0; offset < tokenRecords.length; offset += 500) {
    const batchRecords = tokenRecords.slice(offset, offset + 500);
    const response = await admin.messaging().sendEachForMulticast({
      tokens: batchRecords.map((record) => record.token),
      notification: { title, body },
      data: {
        saleId: String(entryId),
        referrerUid: String(entry.referrerUid || ''),
        referrerRefId: String(entry.referrerRefId || ''),
        ticketsBought: String(toPositiveInt(entry.ticketsBought, 0)),
        amount: String(Number(entry.amount) || 0)
      },
      webpush: {
        fcmOptions: { link },
        notification: {
          icon: notificationIcon,
          badge: notificationIcon,
          tag: `ticket-sale-${entryId}`
        }
      }
    });

    const staleTokenDeletes = [];
    response.responses.forEach((result, index) => {
      if (result.success) {
        return;
      }
      const code = result.error?.code || '';
      if (code === 'messaging/registration-token-not-registered' || code === 'messaging/invalid-registration-token') {
        const record = batchRecords[index];
        staleTokenDeletes.push(record.ref.delete());
        staleTokenDeletes.push(db.collection('adminFcmTokens').doc(record.tokenId).delete());
      } else {
        console.error('FCM notification failed', { code, message: result.error?.message });
      }
    });
    await Promise.all(staleTokenDeletes);
  }
}

exports.notifyAdminsOnRaffleEntry = functions.firestore
  .document('raffle_entries/{entryId}')
  .onCreate(async (snapshot, context) => {
    const entry = snapshot.data() || {};
    const db = admin.firestore();
    const adminsSnapshot = await db.collection('admin').get();
    const profiles = adminsSnapshot.docs.map((doc) => ({ uid: doc.id, ...(doc.data() || {}) }));
    const superAdminUids = profiles
      .filter((profile) => profile.isActive !== false && (
        profile.isSuperAdminReferrer === true ||
        profile.role === 'superAdminReferrer' ||
        profile.role === 'superAdmin'
      ))
      .map((profile) => profile.uid);

    const referrerUid = await resolveRaffleReferrerUid(entry);
    const tickets = Math.max(toPositiveInt(entry.ticketsBought, 0), 1);
    const buyerName = String(entry.name || 'A buyer').trim() || 'A buyer';
    const amount = Number(entry.amount) || 0;
    const saleSummary = `${buyerName} bought ${tickets} ticket${tickets === 1 ? '' : 's'}${amount > 0 ? ` for $${amount.toFixed(2)}` : ''}.`;
    const siteUrl = String(process.env.PUBLIC_SITE_URL || process.env.DOMAIN || 'https://toratyosefsummerraffle.com').replace(/\/$/, '');

    const notificationJobs = [];
    if (referrerUid && !superAdminUids.includes(referrerUid)) {
      notificationJobs.push(sendAdminSaleNotification({
        recipientUids: [referrerUid],
        title: 'Your referral link made a sale',
        body: saleSummary,
        entryId: context.params.entryId,
        entry,
        link: `${siteUrl}/admin-dashboard.html`
      }));
    }

    if (superAdminUids.length) {
      const referrer = profiles.find((profile) => profile.uid === referrerUid);
      const sourceName = referrer
        ? `${referrer.name || 'Admin'} (${referrer.refId || referrer.ref || 'no ref ID'})`
        : 'Direct sale';
      notificationJobs.push(sendAdminSaleNotification({
        recipientUids: superAdminUids,
        title: 'New ticket sale',
        body: `${saleSummary} Referrer: ${sourceName}.`,
        entryId: context.params.entryId,
        entry,
        link: `${siteUrl}/admin/super/sales`
      }));
    }

    await Promise.all(notificationJobs);
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

function getSquareRuntimeConfig() {
  const preferTest = useSquareTestEnvironment();
  const testAccessToken = process.env.SQUARE_TEST_TEST_ACCESS_TOKEN || process.env.SQUARE_TEST_ACCESS_TOKEN;
  const testLocationId = process.env.SQUARE_TEST_LOCATION_ID;
  const testAppId = process.env.SQUARE_TEST_APP_ID;

  const liveAccessToken = process.env.SQUARE_ACCESS_TOKEN;
  const liveLocationId = process.env.SQUARE_LOCATION_ID;
  const liveAppId = process.env.SQUARE_APP_ID;

  const canUseTest = Boolean(preferTest && testAccessToken && testLocationId && testAppId);
  const isTest = canUseTest;

  return {
    isTest,
    accessToken: isTest ? testAccessToken : liveAccessToken,
    locationId: isTest ? testLocationId : liveLocationId,
    appId: isTest ? testAppId : liveAppId,
    apiBase: isTest ? 'https://connect.squareupsandbox.com' : 'https://connect.squareup.com'
  };
}

function getSquareClient() {
  if (!squareClient) {
    const accessToken = getSquareAccessToken();
    if (!accessToken) {
      throw new functions.https.HttpsError('internal', 'Square access token environment variable not configured for current mode');
    }
    const squareSdk = require('square');
    const ClientCtor = squareSdk.Client || squareSdk.SquareClient;
    const EnvEnum = squareSdk.Environment || squareSdk.SquareEnvironment;
    const squareEnv = useSquareTestEnvironment() ? EnvEnum.Sandbox : EnvEnum.Production;
    squareClient = new ClientCtor({
      accessToken: accessToken,
      token: accessToken,
      environment: squareEnv
    });
  }
  return squareClient;
}

function applyCors(req, res) {
  const origin = req.get('origin') || '*';
  res.set('Access-Control-Allow-Origin', origin);
  res.set('Vary', 'Origin');
  res.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.status(204).send('');
    return true;
  }

  return false;
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
      redirectUrl: `${process.env.DOMAIN || 'https://toratyosefsummerraffle.com'}/success.html?order_id=${orderId}&payment_method=square`,
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

/**
 * Returns public Square card configuration for on-page checkout.
 */
exports.getSquareCardConfig = functions.region('us-central1').https.onRequest(async (req, res) => {
  try {
    if (applyCors(req, res)) {
      return;
    }

    if (req.method !== 'GET') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const squareConfig = getSquareRuntimeConfig();
    if (!squareConfig.appId || !squareConfig.locationId) {
      return res.status(500).json({ error: 'Square card config is missing.' });
    }

    return res.status(200).json({
      appId: squareConfig.appId,
      locationId: squareConfig.locationId,
      mode: squareConfig.isTest ? 'test' : 'live'
    });
  } catch (error) {
    console.error('getSquareCardConfig error:', error);
    return res.status(500).json({ error: 'Failed to load card config.' });
  }
});

/**
 * Processes Square card token from on-page checkout.
 */
exports.createSquareCardPayment = functions.region('us-central1').https.onRequest(async (req, res) => {
  if (applyCors(req, res)) {
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const { sourceId, name, email, phone, referral, quantity } = body;

    if (!sourceId || !name || !email || !phone) {
      return res.status(400).json({ error: 'Missing required fields: sourceId, name, email, phone.' });
    }

    const parsedQuantity = Math.max(1, Math.min(99, parseInt(quantity, 10) || 1));
    const ticketPrice = 126;
    const totalAmount = parsedQuantity * ticketPrice;
    const amountCents = Math.round(totalAmount * 100);
    const normalizedReferrer = (referral || 'direct').trim() || 'direct';

    const squareConfig = getSquareRuntimeConfig();
    if (!squareConfig.accessToken || !squareConfig.locationId) {
      return res.status(500).json({ error: 'Square is not configured.' });
    }

    const db = admin.firestore();
    const orderRef = db.collection('square_orders').doc();
    const orderId = orderRef.id;

    await orderRef.set({
      name,
      email,
      phone,
      referrerRefId: normalizedReferrer === 'direct' ? null : normalizedReferrer,
      quantity: parsedQuantity,
      amount: totalAmount,
      status: 'pending_card_payment',
      provider: 'square',
      squareMode: squareConfig.isTest ? 'test' : 'live',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const squareResponse = await fetch(`${squareConfig.apiBase}/v2/payments`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${squareConfig.accessToken}`,
        'Content-Type': 'application/json',
        'Square-Version': '2025-01-23'
      },
      body: JSON.stringify({
        idempotency_key: orderId,
        source_id: sourceId,
        autocomplete: true,
        location_id: squareConfig.locationId,
        amount_money: {
          amount: amountCents,
          currency: 'USD'
        },
        note: `Raffle order ${orderId} | Referrer: ${normalizedReferrer}`
      })
    });

    const squareData = await squareResponse.json();
    const payment = squareData?.payment || null;

    if (!squareResponse.ok || !payment?.id) {
      const squareErrors = squareData?.errors || [];
      const primaryError = squareErrors[0] || null;
      const errorCode = primaryError?.code || 'PAYMENT_FAILED';
      const isPaymentMethodError =
        primaryError?.category === 'PAYMENT_METHOD_ERROR' ||
        errorCode === 'PAN_FAILURE' ||
        errorCode === 'CARD_DECLINED' ||
        errorCode === 'CVV_FAILURE' ||
        errorCode === 'ADDRESS_VERIFICATION_FAILURE';

      console.error('Square create payment failed', {
        status: squareResponse.status,
        errors: squareErrors
      });

      if (isPaymentMethodError) {
        return res.status(402).json({
          error: 'Card was declined. Please use a different card or verify your card details.',
          code: errorCode,
          details: squareErrors
        });
      }

      return res.status(400).json({
        error: primaryError?.detail || 'Square payment failed.',
        code: errorCode,
        details: squareErrors
      });
    }

    let referrerUid = null;
    if (normalizedReferrer !== 'direct') {
      const refSnap = await db.collection('referrers')
        .where('refId', '==', normalizedReferrer)
        .limit(1)
        .get();
      if (!refSnap.empty) {
        referrerUid = refSnap.docs[0].id;
      }
    }

    const raffleEntryRef = await db.collection('raffle_entries').add({
      name,
      email,
      phone,
      referrerRefId: normalizedReferrer === 'direct' ? null : normalizedReferrer,
      referrerUid,
      amount: totalAmount,
      ticketsBought: parsedQuantity,
      paymentStatus: payment.status || 'COMPLETED',
      orderID: orderId,
      squarePaymentId: payment.id,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      entryType: 'square_card'
    });

    await applyAdminTicketProgressUpdate({
      db,
      adminUid: referrerUid,
      refId: normalizedReferrer === 'direct' ? null : normalizedReferrer,
      raffleEntryId: raffleEntryRef.id,
      ticketsBought: parsedQuantity,
      amount: totalAmount,
      orderId,
      paymentId: payment.id,
      paymentMethod: 'square',
      buyerName: name,
      buyerEmail: email,
      buyerPhone: phone
    });

    await orderRef.update({
      status: 'paid',
      paymentStatus: payment.status || 'COMPLETED',
      squarePaymentId: payment.id,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const cardDetails = payment.card_details || payment.cardDetails || {};
    const card = cardDetails.card || {};
    const cardBrand = card.card_brand || card.brand || null;
    const last4 = card.last_4 || card.last4 || null;

    return res.status(200).json({
      success: true,
      orderId,
      paymentId: payment.id,
      checkout: {
        name,
        email,
        phone,
        quantity: parsedQuantity,
        amount: totalAmount,
        currency: 'USD',
        paymentStatus: payment.status || 'COMPLETED',
        cardBrand,
        last4,
        referral: normalizedReferrer,
        receiptUrl: payment.receipt_url || payment.receiptUrl || null
      }
    });
  } catch (error) {
    console.error('createSquareCardPayment error:', error);
    return res.status(500).json({
      error: 'Failed to process card payment.',
      details: error?.message || null
    });
  }
});

/**
 * HTTP endpoint for web checkout pages.
 * Supports hosting rewrite from /api/square/create-checkout-session.
 */
exports.createSquareCheckoutSession = functions.region('us-central1').https.onRequest(async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const { name, email, phone, referral, quantity } = body;
    const parsedQuantity = Math.max(1, Math.min(99, parseInt(quantity, 10) || 1));
    const ticketPrice = 126;
    const totalAmount = parsedQuantity * ticketPrice;
    const normalizedReferrer = (referral || 'direct').trim() || 'direct';

    if (!name || !email || !phone) {
      return res.status(400).json({ error: 'Missing required fields: name, email, phone.' });
    }

    const db = admin.firestore();
    const orderRef = db.collection('square_orders').doc();
    const orderId = orderRef.id;

    const preferTest = useSquareTestEnvironment();
    const testAccessToken = process.env.SQUARE_TEST_TEST_ACCESS_TOKEN || process.env.SQUARE_TEST_ACCESS_TOKEN;
    const testLocationId = process.env.SQUARE_TEST_LOCATION_ID;
    const liveAccessToken = process.env.SQUARE_ACCESS_TOKEN;
    const liveLocationId = process.env.SQUARE_LOCATION_ID;
    const canUseTest = Boolean(preferTest && testAccessToken && testLocationId);
    const isTest = canUseTest;
    const squareAccessToken = isTest ? testAccessToken : liveAccessToken;
    const squareLocationId = isTest ? testLocationId : liveLocationId;
    const siteDomain = process.env.DOMAIN || 'https://toratyosefsummerraffle.com';

    await orderRef.set({
      name,
      email,
      phone,
      referrerRefId: normalizedReferrer === 'direct' ? null : normalizedReferrer,
      quantity: parsedQuantity,
      amount: totalAmount,
      status: 'pending_redirect',
      provider: 'square',
      squareMode: isTest ? 'test' : 'live',
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    if (!squareAccessToken || !squareLocationId) {
      return res.status(500).json({ error: 'Square is not configured. Add SQUARE_ACCESS_TOKEN and SQUARE_LOCATION_ID.' });
    }

    const squareApiBase = isTest ? 'https://connect.squareupsandbox.com' : 'https://connect.squareup.com';
    const squareResponse = await fetch(`${squareApiBase}/v2/online-checkout/payment-links`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${squareAccessToken}`,
        'Content-Type': 'application/json',
        'Square-Version': '2025-01-23'
      },
      body: JSON.stringify({
        idempotency_key: orderId,
        quick_pay: {
          name: `Yeshivat Torat Yosef Raffle (${parsedQuantity} ticket${parsedQuantity > 1 ? 's' : ''})`,
          price_money: {
            amount: Math.round(totalAmount * 100),
            currency: 'USD'
          },
          location_id: squareLocationId
        },
        checkout_options: {
          redirect_url: `${siteDomain}/success.html?orderId=${orderId}`
        }
      })
    });

    const squareData = await squareResponse.json();
    const paymentLinkData = squareData?.payment_link || null;
    const checkoutUrl = paymentLinkData?.url || null;

    if (!checkoutUrl) {
      const squareErrors = squareData?.errors || null;
      console.error('Square create payment link failed: missing URL', {
        status: squareResponse.status,
        hasPaymentLinkData: Boolean(paymentLinkData),
        squareErrors,
        responseKeys: Object.keys(squareData || {})
      });
      return res.status(500).json({
        error: 'Square payment link creation failed.',
        details: squareErrors || null
      });
    }

    await orderRef.update({
      checkoutUrl,
      paymentLinkId: paymentLinkData.id || null,
      squareOrderId: paymentLinkData.orderId || paymentLinkData.order_id || null,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.status(200).json({ url: checkoutUrl });
  } catch (error) {
    const squareErrors = error?.result?.errors || error?.errors || null;
    const squareMessage = error?.message || 'Failed to create Square checkout session.';
    console.error('createSquareCheckoutSession error:', {
      message: squareMessage,
      squareErrors
    });
    return res.status(500).json({
      error: 'Failed to create Square checkout session.',
      details: squareErrors || squareMessage
    });
  }
});

Object.assign(exports, require('./admin-system'));

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
