const path = require('path');
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
  const name = 'Morris Eliyahou';
  const email = 'MorrisE@toratyosefsummerraffle.com';
  const password = 'ToratYosef12!';
  const refId = generateRefIdFromName(name); // MorrisE

  let userRecord;
  try {
    userRecord = await admin.auth().getUserByEmail(email);
    console.log(`User already exists: ${email} (${userRecord.uid})`);
  } catch (error) {
    if (error.code !== 'auth/user-not-found') {
      throw error;
    }
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
        goal: 300,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      },
      { merge: true }
    );

  await upsertAliases({ uid: userRecord.uid, email, name, refId });

  console.log('Bootstrap complete.');
  console.log(`Login aliases include: ${refId}, ${name}, Morris E (case-insensitive)`);
}

run()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('Bootstrap failed:', error);
    process.exit(1);
  });
