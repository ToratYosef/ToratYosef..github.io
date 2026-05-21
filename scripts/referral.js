import { initializeApp, getApps } from 'https://www.gstatic.com/firebasejs/11.9.0/firebase-app.js';
import { getFirestore, collection, addDoc, serverTimestamp } from 'https://www.gstatic.com/firebasejs/11.9.0/firebase-firestore.js';

const firebaseConfig = {
  apiKey: 'AIzaSyAVSkxnzvt6jJOSgQcaRFX7tfnPPPeYQvY',
  authDomain: 'torat-yose.firebaseapp.com',
  projectId: 'torat-yose',
  storageBucket: 'torat-yose.firebasestorage.app',
  messagingSenderId: '1054733969512',
  appId: '1:1054733969512:web:1437414bdad44399fd6bc1f',
  measurementId: 'G-9RYXQP6NFD'
};

function readRefFromUrl() {
  const params = new URLSearchParams(window.location.search);
  const refFromUrl = (params.get('ref') || '').trim();
  if (!refFromUrl) {
    return null;
  }
  return refFromUrl;
}

function saveReferrer(ref) {
  if (!ref) {
    return;
  }
  localStorage.setItem('referrer', ref);
  sessionStorage.setItem('referrer', ref);
}

function getSavedReferrer() {
  return (
    sessionStorage.getItem('referrer') ||
    localStorage.getItem('referrer') ||
    'direct'
  );
}

async function trackReferralClick(db) {
  const params = new URLSearchParams(window.location.search);
  const refFromUrl = params.get('ref');

  if (!refFromUrl) {
    return;
  }

  const alreadyCounted = sessionStorage.getItem('refClickCounted');
  if (alreadyCounted === 'true') {
    return;
  }

  sessionStorage.setItem('refClickCounted', 'true');

  await addDoc(collection(db, 'referralClicks'), {
    referrer: refFromUrl,
    page: window.location.pathname,
    createdAt: serverTimestamp(),
    userAgent: navigator.userAgent
  });
}

function keepRefOnInternalLinks() {
  const referrer =
    sessionStorage.getItem('referrer') ||
    localStorage.getItem('referrer');

  if (!referrer || referrer === 'direct') {
    return;
  }

  document.querySelectorAll('a[href]').forEach((link) => {
    const href = link.getAttribute('href');

    if (
      !href ||
      href.startsWith('#') ||
      href.startsWith('mailto:') ||
      href.startsWith('tel:') ||
      href.startsWith('javascript:')
    ) {
      return;
    }

    const url = new URL(href, window.location.origin);
    if (url.origin !== window.location.origin) {
      return;
    }
    url.searchParams.set('ref', referrer);
    link.href = url.pathname + url.search + url.hash;
  });
}

async function initReferralTracking() {
  const refFromUrl = readRefFromUrl();
  if (refFromUrl) {
    saveReferrer(refFromUrl);
  }

  window.__referral = {
    getReferrer: getSavedReferrer,
    keepRefOnInternalLinks
  };

  keepRefOnInternalLinks();

  try {
    const app = getApps().length ? getApps()[0] : initializeApp(firebaseConfig);
    const db = getFirestore(app);
    await trackReferralClick(db);
  } catch (error) {
    console.warn('Referral tracking initialization failed:', error);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initReferralTracking);
} else {
  initReferralTracking();
}
