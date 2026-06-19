const fs = require('fs');
const path = require('path');
const readline = require('readline/promises');
const { stdin: input, stdout: output } = require('process');
const admin = require('firebase-admin');

const SERVICE_ACCOUNT_PATH = '/workspaces/ToratYosef..github.io/functions/ServiceAccountKey.json';

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function toPositiveInt(value, fallback = 0) {
  const parsed = Number.parseInt(String(value || '').trim(), 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  return parsed;
}

function normalizeAliasKey(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function sanitizeRefToken(value) {
  return String(value || '').replace(/[^a-zA-Z0-9]/g, '');
}

function splitName(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) {
    return { firstName: '', lastName: '' };
  }
  return {
    firstName: parts[0],
    lastName: parts.length > 1 ? parts.slice(1).join(' ') : ''
  };
}

function generateRefIdFromName(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) {
    throw new Error('Name is required to generate a ref id.');
  }

  const first = sanitizeRefToken(parts[0]);
  const last = sanitizeRefToken(parts[parts.length - 1]);

  if (!first || !last) {
    throw new Error('Name must contain letters or numbers.');
  }

  const firstNormalized = first.charAt(0).toUpperCase() + first.slice(1).toLowerCase();
  const lastInitial = last.charAt(0).toUpperCase();
  return `${firstNormalized}${lastInitial}`;
}

function parseYesNo(inputValue, fallback = false) {
  const value = String(inputValue || '').trim().toLowerCase();
  if (!value) {
    return fallback;
  }
  return value === 'y' || value === 'yes' || value === 'true' || value === '1';
}

function buildAliasKeys(name, refId, email) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  const first = parts[0] || '';
  const lastInitial = parts.length > 1 ? parts[parts.length - 1].charAt(0) : '';

  const candidates = [
    refId,
    name,
    `${first} ${lastInitial}`.trim(),
    String(email || '').split('@')[0]
  ];

  return Array.from(new Set(candidates.map(normalizeAliasKey).filter(Boolean)));
}

async function upsertAliases(db, { uid, email, name, refId }) {
  const aliases = buildAliasKeys(name, refId, email);
  const writes = aliases.map((aliasKey) =>
    db.collection('adminLoginAliases').doc(aliasKey).set(
      {
        uid,
        email,
        name,
        refId,
        aliasKey,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      },
      { merge: true }
    )
  );

  await Promise.all(writes);
}

function initFirebaseWithServiceAccount(serviceAccountPath) {
  if (!fs.existsSync(serviceAccountPath)) {
    throw new Error(`Service account file not found: ${serviceAccountPath}`);
  }

  const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, 'utf8'));

  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
  }
}

async function run() {
  const rl = readline.createInterface({ input, output });

  try {
    initFirebaseWithServiceAccount(SERVICE_ACCOUNT_PATH);

    const fullName = String(await rl.question('Admin full name: ')).trim();
    const firstNameInput = String(await rl.question('First name (optional, press enter to derive): ')).trim();
    const lastNameInput = String(await rl.question('Last name (optional, press enter to derive): ')).trim();
    const email = normalizeEmail(await rl.question('Admin email: '));
    const password = String(await rl.question('Password (6+ chars): ')).trim();
    const refInput = String(await rl.question('Referral id / ref (optional, press enter to auto-generate): ')).trim();
    const goalInput = String(await rl.question('Goal tickets (default 300): ')).trim();
    const roleInput = String(await rl.question('Role [superAdminReferrer/admin] (default superAdminReferrer): ')).trim();
    const activeInput = String(await rl.question('Is active? [Y/n] (default Y): ')).trim();

    if (!fullName || !email || !password) {
      throw new Error('Full name, email, and password are required.');
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw new Error('Email format is invalid.');
    }

    if (password.length < 6) {
      throw new Error('Password must be at least 6 characters long.');
    }

    const derivedName = splitName(fullName);
    const firstName = firstNameInput || derivedName.firstName;
    const lastName = lastNameInput || derivedName.lastName;

    const refId = refInput || generateRefIdFromName(fullName);
    if (!/^[a-zA-Z0-9_-]+$/.test(refId)) {
      throw new Error('Ref must contain only letters, numbers, underscore, or hyphen.');
    }

    const goal = toPositiveInt(goalInput, 300);
    const isActive = parseYesNo(activeInput, true);
    const role = roleInput === 'admin' ? 'admin' : 'superAdminReferrer';
    const isSuperAdminReferrer = role === 'superAdminReferrer';

    const auth = admin.auth();
    const db = admin.firestore();

    let userRecord;
    let operation = 'updated';

    try {
      userRecord = await auth.getUserByEmail(email);
      userRecord = await auth.updateUser(userRecord.uid, {
        email,
        password,
        displayName: fullName,
        emailVerified: true,
        disabled: !isActive
      });
    } catch (error) {
      if (error.code !== 'auth/user-not-found') {
        throw error;
      }

      operation = 'created';
      userRecord = await auth.createUser({
        email,
        password,
        displayName: fullName,
        emailVerified: true,
        disabled: !isActive
      });
    }

    const existingClaims = (await auth.getUser(userRecord.uid)).customClaims || {};
    await auth.setCustomUserClaims(userRecord.uid, {
      ...existingClaims,
      referrer: true,
      superAdminReferrer: isSuperAdminReferrer
    });

    await db.collection('referrers').doc(userRecord.uid).set(
      {
        name: fullName,
        email,
        refId,
        goal,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      },
      { merge: true }
    );

    await db.collection('admin').doc(userRecord.uid).set(
      {
        uid: userRecord.uid,
        name: fullName,
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
        isSuperAdminReferrer,
        createdByUid: 'service-account-script',
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      },
      { merge: true }
    );

    await upsertAliases(db, {
      uid: userRecord.uid,
      email,
      name: fullName,
      refId
    });

    console.log('----------------------------------------');
    console.log(`Admin account ${operation} successfully.`);
    console.log(`UID: ${userRecord.uid}`);
    console.log(`Email: ${email}`);
    console.log(`Role: ${role}`);
    console.log(`Ref: ${refId}`);
    console.log(`Goal: ${goal}`);
    console.log(`Active: ${isActive}`);
    console.log(`Service Account File: ${SERVICE_ACCOUNT_PATH}`);
    console.log('----------------------------------------');
  } finally {
    rl.close();
  }
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('Bootstrap failed:', error.message || error);
    process.exit(1);
  });
