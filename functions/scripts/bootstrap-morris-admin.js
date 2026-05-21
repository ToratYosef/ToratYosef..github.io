const path = require('path');
const readline = require('readline/promises');
const { stdin: input, stdout: output } = require('process');
const admin = require('firebase-admin');

const serviceAccountPath = path.join(__dirname, '..', 'ServiceAccountKey.json');
const serviceAccount = require(serviceAccountPath);

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

function normalizeAliasKey(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function sanitizeEmailPrefix(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9._-]/g, '');
}

function generateRefIdFromName(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) {
    throw new Error('Name is required.');
  }
  const first = String(parts[0]).replace(/[^a-zA-Z0-9]/g, '');
  const last = String(parts[parts.length - 1]).replace(/[^a-zA-Z0-9]/g, '');
  if (!first || !last) {
    throw new Error('Name must include letters/numbers.');
  }
  return `${first.charAt(0).toUpperCase()}${first.slice(1).toLowerCase()}${last.charAt(0).toUpperCase()}`;
}

function buildAliasKeys(name, refId, email) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  const first = parts[0] || '';
  const lastInitial = parts.length ? parts[parts.length - 1].charAt(0) : '';

  const candidates = [
    refId,
    name,
    `${first} ${lastInitial}`.trim(),
    String(email || '').split('@')[0]
  ];

  return Array.from(new Set(candidates.map(normalizeAliasKey).filter(Boolean)));
}

async function upsertAliases({ uid, email, name, refId }) {
  const db = admin.firestore();
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

async function run() {
  const rl = readline.createInterface({ input, output });

  try {
    const name = String(await rl.question('Admin full name: ')).trim();
    const emailPrefixInput = String(await rl.question('Email prefix (before @toratyosefsummerraffle.com): ')).trim();
    const password = String(await rl.question('Password (6+ chars): ')).trim();
    const goalInput = String(await rl.question('Goal (optional, default 300): ')).trim();

    const emailPrefix = sanitizeEmailPrefix(emailPrefixInput);
    const email = `${emailPrefix}@toratyosefsummerraffle.com`;
    const refId = generateRefIdFromName(name);
    const goal = goalInput ? Number(goalInput) : 300;

    if (!name || !emailPrefix || !password) {
      throw new Error('Name, email prefix, and password are required.');
    }
    if (password.length < 6) {
      throw new Error('Password must be at least 6 characters long.');
    }
    if (!Number.isFinite(goal) || goal < 0) {
      throw new Error('Goal must be a non-negative number.');
    }

    let userRecord;
    let operation = 'updated';
    try {
      userRecord = await admin.auth().getUserByEmail(email);
      console.log(`User already exists: ${email} (${userRecord.uid})`);

      userRecord = await admin.auth().updateUser(userRecord.uid, {
        email,
        password,
        displayName: name,
        emailVerified: true,
        disabled: false
      });
      console.log(`Updated credentials/profile for existing user: ${email}`);
    } catch (error) {
      if (error.code !== 'auth/user-not-found') {
        throw error;
      }
      operation = 'created';
      userRecord = await admin.auth().createUser({
        email,
        password,
        displayName: name,
        emailVerified: true
      });
      console.log(`Created user: ${email} (${userRecord.uid})`);
    }

    await admin.auth().setCustomUserClaims(userRecord.uid, {
      referrer: true,
      superAdminReferrer: true
    });

    await admin
      .firestore()
      .collection('referrers')
      .doc(userRecord.uid)
      .set(
        {
          name,
          email,
          refId,
          goal,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        },
        { merge: true }
      );

    await admin
      .firestore()
      .collection('admin')
      .doc(userRecord.uid)
      .set(
        {
          uid: userRecord.uid,
          name,
          email,
          emailPrefix,
          refId,
          role: 'superAdminReferrer',
          isSuperAdminReferrer: true,
          createdByUid: 'service-account-script',
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        },
        { merge: true }
      );

    await upsertAliases({ uid: userRecord.uid, email, name, refId });

    console.log(`Admin ${operation} successfully.`);
    console.log(`UID: ${userRecord.uid}`);
    console.log(`Email: ${email}`);
    console.log(`Ref ID: ${refId}`);
  } finally {
    rl.close();
  }
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('Bootstrap failed:', error);
    process.exit(1);
  });
