const functions = require('firebase-functions');
const admin = require('firebase-admin');

if (!admin.apps.length) {
  admin.initializeApp();
}

const db = admin.firestore();
const { FieldValue } = admin.firestore;

const ADMIN_EMAIL_DOMAIN = 'toratyosef.com';
const REF_ID_REGEX = /^[a-z0-9_-]+$/;

function now() {
  return FieldValue.serverTimestamp();
}

function normalizeRefId(value) {
  return String(value || '').trim().toLowerCase();
}

function validateRefId(value) {
  const refId = normalizeRefId(value);
  if (!refId || !REF_ID_REGEX.test(refId)) {
    throw new functions.https.HttpsError(
      'invalid-argument',
      'Referral ID can only contain lowercase letters, numbers, hyphens, and underscores.'
    );
  }
  return refId;
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function buildEmailFromRefId(refId) {
  return `${validateRefId(refId)}@${ADMIN_EMAIL_DOMAIN}`;
}

function isSuperAdminToken(token) {
  return Boolean(token && (token.superAdmin === true || token.superAdminReferrer === true));
}

function requireAuth(context) {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Login required.');
  }
  return context.auth;
}

function requireSuperAdmin(context) {
  const auth = requireAuth(context);
  if (!isSuperAdminToken(auth.token)) {
    throw new functions.https.HttpsError('permission-denied', 'Super admin access required.');
  }
  return auth;
}

function refLinkFor(refId) {
  const host = process.env.PUBLIC_SITE_URL || process.env.DOMAIN || 'https://www.toratyosefsummerraffle.com';
  return `${host}/?ref=${encodeURIComponent(refId)}`;
}

function timestampToMillis(value) {
  if (!value) {
    return 0;
  }
  if (typeof value.toMillis === 'function') {
    return value.toMillis();
  }
  if (value._seconds) {
    return (value._seconds * 1000) + Math.floor((value._nanoseconds || 0) / 1000000);
  }
  return 0;
}

function timestampToIso(value) {
  if (!value) {
    return null;
  }
  if (typeof value.toDate === 'function') {
    return value.toDate().toISOString();
  }
  if (value._seconds) {
    return new Date((value._seconds * 1000) + Math.floor((value._nanoseconds || 0) / 1000000)).toISOString();
  }
  return null;
}

function safeNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

async function getAdminDocByRefId(refId) {
  const normalized = validateRefId(refId);
  const snapshot = await db.collection('admins')
    .where('refId', '==', normalized)
    .limit(1)
    .get();

  if (snapshot.empty) {
    return null;
  }

  const doc = snapshot.docs[0];
  const data = doc.data() || {};
  if (data.isActive === false) {
    return null;
  }

  return { id: doc.id, data };
}

async function getAdminDocByUid(uid) {
  const doc = await db.collection('admins').doc(uid).get();
  if (!doc.exists) {
    return null;
  }
  return { id: doc.id, data: doc.data() || {} };
}

function buildAdminSummary(doc) {
  const data = doc.data || {};
  const clickCount = safeNumber(data.clickCount);
  const totalSales = safeNumber(data.totalSales);
  const totalRevenue = safeNumber(data.totalRevenue);
  const conversionRate = clickCount > 0 ? (totalSales / clickCount) * 100 : 0;

  return {
    uid: doc.id,
    id: doc.id,
    name: data.name || '',
    refId: data.refId || '',
    email: data.email || '',
    role: data.role || 'admin',
    isActive: data.isActive !== false,
    clickCount,
    totalSales,
    totalRevenue,
    conversionRate,
    createdAt: timestampToIso(data.createdAt),
    updatedAt: timestampToIso(data.updatedAt),
    createdBy: data.createdBy || null,
    referralLink: data.refId ? refLinkFor(data.refId) : null,
    lastLoginAt: timestampToIso(data.lastLoginAt),
    lastClickAt: timestampToIso(data.lastClickAt),
    lastSaleAt: timestampToIso(data.lastSaleAt)
  };
}

async function auditLog(action, performedBy, targetAdminId = null, details = {}) {
  await db.collection('adminAuditLogs').add({
    action,
    performedBy,
    targetAdminId,
    details,
    createdAt: now()
  });
}

async function syncAdminAuthClaims(uid, payload) {
  const existing = await admin.auth().getUser(uid);
  const currentClaims = existing.customClaims || {};
  await admin.auth().setCustomUserClaims(uid, {
    ...currentClaims,
    ...payload
  });
}

async function resolveActiveAdmin(refId) {
  const adminDoc = await getAdminDocByRefId(refId);
  if (!adminDoc) {
    return null;
  }
  return {
    id: adminDoc.id,
    ...buildAdminSummary(adminDoc)
  };
}

async function writeAdminProfile({
  uid,
  name,
  refId,
  email,
  role,
  createdBy,
  isActive = true,
  clickCount = 0,
  totalSales = 0,
  totalRevenue = 0
}) {
  const profile = {
    uid,
    name,
    refId,
    email,
    role,
    isActive,
    clickCount,
    totalSales,
    totalRevenue,
    createdBy,
    createdAt: now(),
    updatedAt: now()
  };

  await db.collection('admins').doc(uid).set(profile, { merge: true });
  return profile;
}

async function recordSaleDocument({
  refId,
  adminId,
  buyerName,
  buyerEmail,
  buyerPhone,
  amount,
  currency = 'USD',
  items = [],
  paymentProvider = 'square',
  paymentId = null,
  status = 'paid',
  source = 'direct',
  metadata = {}
}) {
  const normalizedRefId = refId ? normalizeRefId(refId) : null;
  let resolvedAdmin = null;
  if (normalizedRefId) {
    resolvedAdmin = await resolveActiveAdmin(normalizedRefId);
  }

  const saleDoc = {
    refId: normalizedRefId,
    adminId: resolvedAdmin ? resolvedAdmin.id : (adminId || null),
    buyerName: buyerName || '',
    buyerEmail: normalizeEmail(buyerEmail),
    buyerPhone: String(buyerPhone || '').trim(),
    amount: safeNumber(amount),
    currency: String(currency || 'USD').toUpperCase(),
    items: Array.isArray(items) ? items : [],
    paymentProvider,
    paymentId: paymentId || null,
    status,
    source: resolvedAdmin ? 'referral' : source,
    metadata,
    createdAt: now()
  };

  const saleRef = await db.collection('sales').add(saleDoc);

  if (resolvedAdmin) {
    await db.collection('admins').doc(resolvedAdmin.id).set({
      totalSales: FieldValue.increment(1),
      totalRevenue: FieldValue.increment(safeNumber(amount)),
      updatedAt: now(),
      lastSaleAt: now()
    }, { merge: true });
  }

  await db.collection('raffle_entries').add({
    name: saleDoc.buyerName,
    email: saleDoc.buyerEmail,
    phone: saleDoc.buyerPhone,
    referrerRefId: saleDoc.refId,
    referrerUid: saleDoc.adminId,
    amount: saleDoc.amount,
    ticketsBought: Array.isArray(items) && items.length ? items.reduce((sum, item) => sum + safeNumber(item.quantity || 1), 0) : 1,
    paymentStatus: status,
    orderID: saleRef.id,
    squarePaymentId: paymentId || null,
    timestamp: now(),
    entryType: paymentProvider === 'square' ? 'square_card' : paymentProvider
  });

  return { saleId: saleRef.id, adminId: saleDoc.adminId, refId: saleDoc.refId, source: saleDoc.source };
}

exports.resolveActiveAdminByRefId = functions.https.onCall(async (data) => {
  const refId = validateRefId(data?.refId);
  const adminDoc = await resolveActiveAdmin(refId);
  if (!adminDoc) {
    return { valid: false };
  }

  return {
    valid: true,
    admin: adminDoc,
    referralLink: refLinkFor(adminDoc.refId)
  };
});

exports.trackAdminClick = functions.https.onCall(async (data) => {
  const refId = normalizeRefId(data?.refId || data?.ref);
  if (!refId || !REF_ID_REGEX.test(refId)) {
    return { tracked: false, reason: 'invalid_ref' };
  }

  const adminDoc = await resolveActiveAdmin(refId);
  if (!adminDoc) {
    return { tracked: false, reason: 'inactive_or_missing' };
  }

  const clickRef = await db.collection('adminClicks').add({
    refId,
    adminId: adminDoc.id,
    page: String(data?.page || '').slice(0, 128),
    itemId: String(data?.itemId || '').slice(0, 128),
    itemName: String(data?.itemName || '').slice(0, 256),
    createdAt: now(),
    userAgent: String(data?.userAgent || '').slice(0, 1024),
    url: String(data?.url || '').slice(0, 1024),
    source: 'client'
  });

  await db.collection('admins').doc(adminDoc.id).set({
    clickCount: FieldValue.increment(1),
    updatedAt: now(),
    lastClickAt: now()
  }, { merge: true });

  return { tracked: true, clickId: clickRef.id, adminId: adminDoc.id, refId };
});

exports.getCurrentAdminProfile = functions.https.onCall(async (_data, context) => {
  const auth = requireAuth(context);
  const adminDoc = await getAdminDocByUid(auth.uid);
  if (!adminDoc) {
    throw new functions.https.HttpsError('not-found', 'Admin profile not found.');
  }

  const profile = buildAdminSummary(adminDoc);
  return {
    profile,
    isSuperAdmin: isSuperAdminToken(auth.token),
    redirectPath: isSuperAdminToken(auth.token) ? '/admin/super' : '/admin/dashboard'
  };
});

exports.createAdminAccountV2 = functions.https.onCall(async (data, context) => {
  const auth = requireSuperAdmin(context);
  const name = String(data?.name || '').trim();
  const refId = validateRefId(data?.refId || data?.login || data?.email);
  const password = String(data?.password || '');
  const role = String(data?.role || 'admin').trim() === 'superAdmin' ? 'superAdmin' : 'admin';
  const email = role === 'superAdmin' ? normalizeEmail(data?.email || `${refId}@${ADMIN_EMAIL_DOMAIN}`) : buildEmailFromRefId(refId);

  if (!name) {
    throw new functions.https.HttpsError('invalid-argument', 'Admin name is required.');
  }
  if (password.length < 6) {
    throw new functions.https.HttpsError('invalid-argument', 'Password must be at least 6 characters long.');
  }

  const existingRef = await db.collection('admins').where('refId', '==', refId).limit(1).get();
  if (!existingRef.empty) {
    throw new functions.https.HttpsError('already-exists', 'Referral ID already exists.');
  }

  let userRecord;
  try {
    userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: name,
      emailVerified: true,
      disabled: false
    });
  } catch (error) {
    if (error.code !== 'auth/email-already-exists') {
      throw error;
    }
    userRecord = await admin.auth().getUserByEmail(email);
    await admin.auth().updateUser(userRecord.uid, {
      email,
      password,
      displayName: name,
      disabled: false
    });
  }

  await syncAdminAuthClaims(userRecord.uid, {
    adminId: userRecord.uid,
    refId,
    role,
    admin: role === 'admin',
    superAdmin: role === 'superAdmin'
  });

  await db.collection('admins').doc(userRecord.uid).set({
    uid: userRecord.uid,
    name,
    refId,
    email,
    role,
    isActive: true,
    clickCount: 0,
    totalSales: 0,
    totalRevenue: 0,
    createdBy: auth.uid,
    createdAt: now(),
    updatedAt: now()
  }, { merge: true });

  await auditLog('created_admin', auth.uid, userRecord.uid, { name, refId, email, role });

  return {
    success: true,
    admin: {
      uid: userRecord.uid,
      name,
      refId,
      email,
      role,
      referralLink: refLinkFor(refId)
    }
  };
});

exports.updateAdminAccountV2 = functions.https.onCall(async (data, context) => {
  const auth = requireSuperAdmin(context);
  const adminId = String(data?.adminId || '').trim();
  if (!adminId) {
    throw new functions.https.HttpsError('invalid-argument', 'adminId is required.');
  }

  const existing = await getAdminDocByUid(adminId);
  if (!existing) {
    throw new functions.https.HttpsError('not-found', 'Admin not found.');
  }

  const updates = {};
  const authUpdates = {};

  if (typeof data?.name === 'string' && data.name.trim()) {
    updates.name = data.name.trim();
    authUpdates.displayName = data.name.trim();
  }

  if (typeof data?.refId === 'string' && data.refId.trim()) {
    const refId = validateRefId(data.refId);
    const refSnap = await db.collection('admins').where('refId', '==', refId).limit(1).get();
    if (!refSnap.empty && refSnap.docs[0].id !== adminId) {
      throw new functions.https.HttpsError('already-exists', 'Referral ID already exists.');
    }
    updates.refId = refId;
    updates.email = buildEmailFromRefId(refId);
    authUpdates.email = buildEmailFromRefId(refId);
  }

  if (typeof data?.isActive === 'boolean') {
    updates.isActive = data.isActive;
    authUpdates.disabled = !data.isActive;
  }

  if (typeof data?.role === 'string') {
    updates.role = data.role === 'superAdmin' ? 'superAdmin' : 'admin';
  }

  if (typeof data?.password === 'string' && data.password.length >= 6) {
    authUpdates.password = data.password;
  }

  if (Object.keys(authUpdates).length > 0) {
    await admin.auth().updateUser(adminId, authUpdates);
  }

  updates.updatedAt = now();
  await db.collection('admins').doc(adminId).set(updates, { merge: true });
  await auditLog('updated_admin', auth.uid, adminId, updates);

  return { success: true };
});

exports.deactivateAdminAccountV2 = functions.https.onCall(async (data, context) => {
  const auth = requireSuperAdmin(context);
  const adminId = String(data?.adminId || '').trim();
  if (!adminId) {
    throw new functions.https.HttpsError('invalid-argument', 'adminId is required.');
  }

  await admin.auth().updateUser(adminId, { disabled: true });
  await db.collection('admins').doc(adminId).set({ isActive: false, updatedAt: now() }, { merge: true });
  await auditLog('deactivated_admin', auth.uid, adminId, {});

  return { success: true };
});

exports.deleteAdminAccountV2 = functions.https.onCall(async (data, context) => {
  const auth = requireSuperAdmin(context);
  const adminId = String(data?.adminId || '').trim();
  if (!adminId) {
    throw new functions.https.HttpsError('invalid-argument', 'adminId is required.');
  }

  await admin.auth().deleteUser(adminId);
  await db.collection('admins').doc(adminId).delete();
  await auditLog('deleted_admin', auth.uid, adminId, {});

  return { success: true };
});

exports.resetAdminPasswordV2 = functions.https.onCall(async (data, context) => {
  const auth = requireSuperAdmin(context);
  const adminId = String(data?.adminId || '').trim();
  const newPassword = String(data?.newPassword || '').trim();
  if (!adminId) {
    throw new functions.https.HttpsError('invalid-argument', 'adminId is required.');
  }

  const user = await admin.auth().getUser(adminId);
  if (newPassword) {
    if (newPassword.length < 6) {
      throw new functions.https.HttpsError('invalid-argument', 'Password must be at least 6 characters long.');
    }
    await admin.auth().updateUser(adminId, { password: newPassword, disabled: false });
    await auditLog('reset_admin_password', auth.uid, adminId, { mode: 'set_new_password' });
    return { success: true, mode: 'updated' };
  }

  const link = await admin.auth().generatePasswordResetLink(user.email);
  await auditLog('reset_admin_password', auth.uid, adminId, { mode: 'reset_link' });
  return { success: true, mode: 'link', resetLink: link };
});

async function loadAdminsWithStats() {
  const [adminsSnapshot, salesSnapshot, clicksSnapshot] = await Promise.all([
    db.collection('admins').get(),
    db.collection('sales').get(),
    db.collection('adminClicks').get()
  ]);

  const salesByAdmin = new Map();
  const clicksByAdmin = new Map();
  const directSales = [];
  const allSales = [];
  const allClicks = [];

  salesSnapshot.forEach((doc) => {
    const data = doc.data() || {};
    const sale = {
      id: doc.id,
      ...data,
      createdAt: timestampToIso(data.createdAt)
    };
    allSales.push(sale);
    if (data.adminId) {
      const current = salesByAdmin.get(data.adminId) || { count: 0, revenue: 0 };
      current.count += 1;
      current.revenue += safeNumber(data.amount);
      salesByAdmin.set(data.adminId, current);
    } else {
      directSales.push(sale);
    }
  });

  clicksSnapshot.forEach((doc) => {
    const data = doc.data() || {};
    const click = {
      id: doc.id,
      ...data,
      createdAt: timestampToIso(data.createdAt)
    };
    allClicks.push(click);
    if (data.adminId) {
      const current = clicksByAdmin.get(data.adminId) || 0;
      clicksByAdmin.set(data.adminId, current + 1);
    }
  });

  const admins = adminsSnapshot.docs.map((doc) => {
    const data = doc.data() || {};
    const stats = {
      clicks: data.clickCount || clicksByAdmin.get(doc.id) || 0,
      sales: data.totalSales || salesByAdmin.get(doc.id)?.count || 0,
      revenue: data.totalRevenue || salesByAdmin.get(doc.id)?.revenue || 0
    };
    const conversionRate = stats.clicks > 0 ? (stats.sales / stats.clicks) * 100 : 0;
    return {
      id: doc.id,
      ...data,
      clickCount: stats.clicks,
      totalSales: stats.sales,
      totalRevenue: stats.revenue,
      conversionRate,
      createdAt: timestampToIso(data.createdAt),
      updatedAt: timestampToIso(data.updatedAt),
      referralLink: data.refId ? refLinkFor(data.refId) : null
    };
  });

  return {
    admins,
    allSales,
    allClicks,
    directSales,
    salesByAdmin,
    clicksByAdmin
  };
}

exports.listAdminsV2 = functions.https.onCall(async (_data, context) => {
  requireSuperAdmin(context);
  const { admins } = await loadAdminsWithStats();
  admins.sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
  return { admins };
});

exports.listSalesV2 = functions.https.onCall(async (data, context) => {
  const auth = requireAuth(context);
  const isSuperAdmin = isSuperAdminToken(auth.token);
  const adminId = isSuperAdmin ? null : auth.uid;
  const { allSales } = await loadAdminsWithStats();

  const filters = {
    adminId: String(data?.adminId || '').trim() || null,
    refId: normalizeRefId(data?.refId || ''),
    buyer: String(data?.buyer || '').trim().toLowerCase(),
    from: data?.from ? new Date(data.from).getTime() : null,
    to: data?.to ? new Date(data.to).getTime() : null,
    minAmount: Number.isFinite(Number(data?.minAmount)) ? Number(data.minAmount) : null,
    maxAmount: Number.isFinite(Number(data?.maxAmount)) ? Number(data.maxAmount) : null
  };

  const sales = allSales.filter((sale) => {
    if (!isSuperAdmin && sale.adminId !== adminId) {
      return false;
    }
    if (filters.adminId && sale.adminId !== filters.adminId) {
      return false;
    }
    if (filters.refId && sale.refId !== filters.refId) {
      return false;
    }
    const createdMillis = timestampToMillis(sale.createdAt);
    if (filters.from && createdMillis < filters.from) {
      return false;
    }
    if (filters.to && createdMillis > filters.to) {
      return false;
    }
    if (filters.minAmount !== null && safeNumber(sale.amount) < filters.minAmount) {
      return false;
    }
    if (filters.maxAmount !== null && safeNumber(sale.amount) > filters.maxAmount) {
      return false;
    }
    if (filters.buyer) {
      const haystack = `${sale.buyerName || ''} ${sale.buyerEmail || ''} ${sale.buyerPhone || ''}`.toLowerCase();
      if (!haystack.includes(filters.buyer)) {
        return false;
      }
    }
    return true;
  });

  sales.sort((a, b) => timestampToMillis(b.createdAt) - timestampToMillis(a.createdAt));
  return { sales };
});

exports.listClicksV2 = functions.https.onCall(async (data, context) => {
  const auth = requireAuth(context);
  const isSuperAdmin = isSuperAdminToken(auth.token);
  const adminId = isSuperAdmin ? null : auth.uid;
  const { allClicks } = await loadAdminsWithStats();
  const filters = {
    adminId: String(data?.adminId || '').trim() || null,
    refId: normalizeRefId(data?.refId || ''),
    page: String(data?.page || '').trim().toLowerCase()
  };

  const clicks = allClicks.filter((click) => {
    if (!isSuperAdmin && click.adminId !== adminId) {
      return false;
    }
    if (filters.adminId && click.adminId !== filters.adminId) {
      return false;
    }
    if (filters.refId && click.refId !== filters.refId) {
      return false;
    }
    if (filters.page && String(click.page || '').toLowerCase() !== filters.page) {
      return false;
    }
    return true;
  });

  clicks.sort((a, b) => timestampToMillis(b.createdAt) - timestampToMillis(a.createdAt));
  return { clicks };
});

exports.getAdminDashboardDataV2 = functions.https.onCall(async (_data, context) => {
  const auth = requireAuth(context);
  const profileDoc = await getAdminDocByUid(auth.uid);
  if (!profileDoc) {
    throw new functions.https.HttpsError('not-found', 'Admin profile not found.');
  }

  const profile = buildAdminSummary(profileDoc);
  if (profileDoc.data.isActive === false) {
    throw new functions.https.HttpsError('failed-precondition', 'This admin account is disabled.');
  }

  const { admins, allSales, allClicks, directSales } = await loadAdminsWithStats();
  const isSuperAdmin = isSuperAdminToken(auth.token);
  const salesForAdmin = isSuperAdmin ? allSales : allSales.filter((sale) => sale.adminId === auth.uid);
  const clicksForAdmin = isSuperAdmin ? allClicks : allClicks.filter((click) => click.adminId === auth.uid);

  const buyerCount = new Set(salesForAdmin.map((sale) => `${sale.buyerEmail || ''}-${sale.buyerPhone || ''}-${sale.buyerName || ''}`)).size;
  const recentSales = salesForAdmin.slice(0, 20);
  const recentClicks = clicksForAdmin.slice(0, 20);

  const totalClicks = isSuperAdmin
    ? allClicks.length
    : profile.clickCount;
  const totalSales = isSuperAdmin
    ? allSales.length
    : profile.totalSales;
  const totalRevenue = isSuperAdmin
    ? allSales.reduce((sum, sale) => sum + safeNumber(sale.amount), 0)
    : profile.totalRevenue;

  const summary = {
    totalRevenue,
    totalSales,
    totalBuyers: isSuperAdmin ? new Set(allSales.map((sale) => sale.buyerEmail || sale.buyerPhone || sale.buyerName || sale.id)).size : buyerCount,
    totalClicks,
    directSales: directSales.length,
    totalAdmins: admins.length,
    topByRevenue: admins.slice().sort((a, b) => safeNumber(b.totalRevenue) - safeNumber(a.totalRevenue))[0] || null,
    topBySales: admins.slice().sort((a, b) => safeNumber(b.totalSales) - safeNumber(a.totalSales))[0] || null,
    topByClicks: admins.slice().sort((a, b) => safeNumber(b.clickCount) - safeNumber(a.clickCount))[0] || null
  };

  return {
    profile,
    summary,
    referralLink: profile.refId ? refLinkFor(profile.refId) : null,
    recentSales,
    recentClicks,
    admins: isSuperAdmin ? admins.sort((a, b) => safeNumber(b.totalRevenue) - safeNumber(a.totalRevenue)) : [],
    isSuperAdmin,
    dashboardPath: isSuperAdmin ? '/admin/super' : '/admin/dashboard'
  };
});

exports.createAdminSaleRecord = async function createAdminSaleRecord(payload) {
  return recordSaleDocument(payload);
};

exports.recordAdminSale = functions.https.onCall(async (data, context) => {
  const auth = requireAuth(context);
  const isSuperAdmin = isSuperAdminToken(auth.token);
  const sale = await recordSaleDocument({
    refId: data?.refId,
    adminId: isSuperAdmin ? data?.adminId : auth.uid,
    buyerName: data?.buyerName,
    buyerEmail: data?.buyerEmail,
    buyerPhone: data?.buyerPhone,
    amount: data?.amount,
    currency: data?.currency || 'USD',
    items: data?.items || [],
    paymentProvider: data?.paymentProvider || 'manual',
    paymentId: data?.paymentId || null,
    status: data?.status || 'paid',
    source: data?.source || 'manual',
    metadata: data?.metadata || {}
  });

  return { success: true, ...sale };
});

exports.getAdminAuditLogsV2 = functions.https.onCall(async (_data, context) => {
  requireSuperAdmin(context);
  const snapshot = await db.collection('adminAuditLogs').orderBy('createdAt', 'desc').limit(200).get();
  return {
    logs: snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
      createdAt: timestampToIso(doc.data().createdAt)
    }))
  };
});
