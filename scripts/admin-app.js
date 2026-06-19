import { initializeApp, getApps } from 'https://www.gstatic.com/firebasejs/11.9.0/firebase-app.js';
import {
  getAuth,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  signOut
} from 'https://www.gstatic.com/firebasejs/11.9.0/firebase-auth.js';
import {
  getFirestore,
  doc,
  getDoc,
  collection,
  getDocs
} from 'https://www.gstatic.com/firebasejs/11.9.0/firebase-firestore.js';
import { firebaseConfig } from '/scripts/firebase-config.js';

const ADMIN_EMAIL_DOMAIN = 'toratyosef.com';

const app = getApps().length ? getApps()[0] : initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

function byId(id) {
  return document.getElementById(id);
}

function getPageType() {
  return document.body?.dataset?.page || '';
}

function sanitizeAlias(input) {
  return String(input || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

function normalizeIdentifier(input) {
  const value = String(input || '').trim();
  if (!value) {
    return null;
  }

  if (value.includes('@')) {
    return { email: value.toLowerCase() };
  }

  const compact = value.replace(/\s+/g, '').toLowerCase();
  return {
    email: `${compact}@${ADMIN_EMAIL_DOMAIN}`,
    alias: sanitizeAlias(value)
  };
}

function formatMoney(value) {
  const amount = Number(value) || 0;
  return `$${amount.toFixed(2)}`;
}

function formatPercent(numerator, denominator) {
  if (!denominator || denominator <= 0) {
    return '0%';
  }
  return `${((numerator / denominator) * 100).toFixed(1)}%`;
}

function isSuperAdmin(profile) {
  return Boolean(profile?.isSuperAdminReferrer || profile?.role === 'superAdmin' || profile?.role === 'superAdminReferrer');
}

async function loadAdminProfile(uid) {
  const adminSnap = await getDoc(doc(db, 'admin', uid));
  if (!adminSnap.exists()) {
    throw new Error('Admin profile not found in admin/{uid}.');
  }

  const profile = adminSnap.data() || {};
  if (profile.isActive === false) {
    throw new Error('Admin access is disabled.');
  }

  return { uid, ...profile };
}

async function resolveEmailFromAlias(alias) {
  if (!alias) {
    return null;
  }

  try {
    const aliasSnap = await getDoc(doc(db, 'adminLoginAliases', alias));
    if (!aliasSnap.exists()) {
      return null;
    }
    const data = aliasSnap.data() || {};
    return data.email || null;
  } catch (_error) {
    return null;
  }
}

function redirectToLogin() {
  const next = `${window.location.pathname}${window.location.search || ''}`;
  window.location.href = `/admin-login.html?next=${encodeURIComponent(next)}`;
}

function updateCommonActions(referralLink) {
  const copyButtons = ['copy-referral-link', 'dashboard-copy-link'];
  const openButtons = ['open-referral-link', 'dashboard-open-link'];
  const shareButtons = ['share-referral-link', 'dashboard-share-link'];

  copyButtons.forEach((id) => {
    const button = byId(id);
    if (!button) {
      return;
    }
    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(referralLink);
      } catch (_error) {
        // Clipboard is optional.
      }
    });
  });

  openButtons.forEach((id) => {
    const button = byId(id);
    if (!button) {
      return;
    }
    button.addEventListener('click', () => {
      window.open(referralLink, '_blank', 'noopener,noreferrer');
    });
  });

  shareButtons.forEach((id) => {
    const button = byId(id);
    if (!button) {
      return;
    }
    button.addEventListener('click', async () => {
      if (navigator.share) {
        try {
          await navigator.share({ title: 'My Raffle Link', url: referralLink });
          return;
        } catch (_error) {
          // Fall back to clipboard.
        }
      }
      try {
        await navigator.clipboard.writeText(referralLink);
      } catch (_error) {
        // Ignore copy failures.
      }
    });
  });
}

function renderDashboard(profile) {
  const name = String(profile?.name || [profile?.firstName, profile?.lastName].filter(Boolean).join(' ') || 'Admin');
  const ref = String(profile?.ref || profile?.refId || '').trim();
  const goal = Number(profile?.goal) || 0;
  const sold = Number(profile?.totalTicketsSold ?? profile?.ticketsSold) || 0;
  const remaining = Math.max(Number(profile?.ticketsRemaining ?? (goal - sold)) || 0, 0);
  const clicks = Number(profile?.clickCount) || 0;
  const revenue = Number(profile?.totalRevenue) || 0;

  const title = byId('page-title');
  if (title) {
    title.textContent = `Shalom ${name}`;
  }

  const subtitle = byId('page-subtitle');
  if (subtitle) {
    subtitle.textContent = `Goal: ${goal} tickets. Sold: ${sold}. Remaining: ${remaining}.`;
  }

  const statSales = byId('stat-sales');
  if (statSales) {
    statSales.textContent = String(sold);
  }

  const statClicks = byId('stat-clicks');
  if (statClicks) {
    statClicks.textContent = String(clicks);
  }

  const statRevenue = byId('stat-revenue');
  if (statRevenue) {
    statRevenue.textContent = formatMoney(revenue);
  }

  const statBuyers = byId('stat-buyers');
  if (statBuyers) {
    statBuyers.textContent = String(sold);
  }

  const conversion = byId('stat-conversion');
  if (conversion) {
    conversion.textContent = formatPercent(sold, clicks);
  }

  const referralLink = ref ? `${window.location.origin}/?ref=${encodeURIComponent(ref)}` : '';
  const referralInput = byId('referral-link');
  if (referralInput) {
    referralInput.value = referralLink;
  }

  if (referralLink) {
    updateCommonActions(referralLink);
  }

  const recentSalesEmpty = byId('recent-sales-empty');
  const recentClicksEmpty = byId('recent-clicks-empty');
  if (recentSalesEmpty) {
    recentSalesEmpty.textContent = sold > 0 ? 'Sales are being tracked in Firestore under admin/{uid}/ticketSales.' : 'No sales yet.';
  }
  if (recentClicksEmpty) {
    recentClicksEmpty.textContent = clicks > 0 ? 'Clicks are tracked server-side and reflected in your counters.' : 'No clicks yet.';
  }
}

function renderSuperDashboard(profiles) {
  const totalRevenue = profiles.reduce((sum, p) => sum + (Number(p.totalRevenue) || 0), 0);
  const totalSales = profiles.reduce((sum, p) => sum + (Number(p.totalTicketsSold ?? p.ticketsSold) || 0), 0);
  const totalClicks = profiles.reduce((sum, p) => sum + (Number(p.clickCount) || 0), 0);

  const byRevenue = [...profiles].sort((a, b) => (Number(b.totalRevenue) || 0) - (Number(a.totalRevenue) || 0));
  const bySales = [...profiles].sort((a, b) => (Number(b.totalTicketsSold ?? b.ticketsSold) || 0) - (Number(a.totalTicketsSold ?? a.ticketsSold) || 0));
  const byClicks = [...profiles].sort((a, b) => (Number(b.clickCount) || 0) - (Number(a.clickCount) || 0));

  const setText = (id, value) => {
    const el = byId(id);
    if (el) {
      el.textContent = value;
    }
  };

  setText('page-title', 'Super Admin Dashboard');
  setText('page-subtitle', 'All admin performance and goals are protected behind Firebase Auth.');
  setText('stat-total-revenue', formatMoney(totalRevenue));
  setText('stat-total-sales', String(totalSales));
  setText('stat-total-buyers', String(totalSales));
  setText('stat-total-clicks', String(totalClicks));
  setText('stat-total-admins', String(profiles.length));
  setText('top-revenue', byRevenue[0] ? `${byRevenue[0].name || 'Admin'} (${formatMoney(byRevenue[0].totalRevenue || 0)})` : '-');
  setText('top-sales', bySales[0] ? `${bySales[0].name || 'Admin'} (${Number(bySales[0].totalTicketsSold ?? bySales[0].ticketsSold) || 0})` : '-');
  setText('top-clicks', byClicks[0] ? `${byClicks[0].name || 'Admin'} (${Number(byClicks[0].clickCount) || 0})` : '-');

  const body = byId('admins-body');
  const empty = byId('admins-empty');
  if (!body) {
    return;
  }

  body.innerHTML = '';
  if (!profiles.length) {
    if (empty) {
      empty.style.display = 'block';
    }
    return;
  }

  if (empty) {
    empty.style.display = 'none';
  }

  profiles.forEach((profile) => {
    const sold = Number(profile.totalTicketsSold ?? profile.ticketsSold) || 0;
    const clicks = Number(profile.clickCount) || 0;
    const revenue = Number(profile.totalRevenue) || 0;
    const ref = profile.ref || profile.refId || '';
    const link = ref ? `${window.location.origin}/?ref=${encodeURIComponent(ref)}` : '';
    const conversion = formatPercent(sold, clicks);
    const status = profile.isActive === false ? 'Inactive' : 'Active';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${profile.name || '-'}</td>
      <td>${ref || '-'}</td>
      <td>${profile.email || '-'}</td>
      <td>${link ? `<a href="${link}" target="_blank" rel="noopener noreferrer">Open</a>` : '-'}</td>
      <td>${clicks}</td>
      <td>${sold}</td>
      <td>${formatMoney(revenue)}</td>
      <td>${conversion}</td>
      <td>${status}</td>
      <td>-</td>
    `;
    body.appendChild(tr);
  });
}

async function ensureAuthorizedAndRender(currentUser) {
  const pageType = getPageType();

  try {
    const profile = await loadAdminProfile(currentUser.uid);

    if (pageType === 'super' && !isSuperAdmin(profile)) {
      window.location.href = '/admin-dashboard.html';
      return;
    }

    if (pageType === 'dashboard') {
      renderDashboard(profile);
      return;
    }

    if (pageType === 'super') {
      const allAdminsSnap = await getDocs(collection(db, 'admin'));
      const profiles = allAdminsSnap.docs.map((snap) => ({ uid: snap.id, ...(snap.data() || {}) }));
      renderSuperDashboard(profiles);
      return;
    }
  } catch (_error) {
    await signOut(auth);
    redirectToLogin();
  }
}

async function handleLoginPage() {
  const form = byId('login-form');
  if (!form) {
    return;
  }

  const identifierInput = byId('login-identifier');
  const passwordInput = byId('login-password');
  const status = byId('login-status');

  const setStatus = (message, isError = false) => {
    if (!status) {
      return;
    }
    status.textContent = message;
    status.style.color = isError ? '#c02626' : '#334155';
  };

  const nextPath = new URLSearchParams(window.location.search).get('next') || '/admin-dashboard.html';

  onAuthStateChanged(auth, async (user) => {
    if (!user) {
      return;
    }

    try {
      const profile = await loadAdminProfile(user.uid);
      const target = isSuperAdmin(profile) ? '/admin-super.html' : nextPath;
      window.location.replace(target);
    } catch (_error) {
      await signOut(auth);
    }
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    const identifier = normalizeIdentifier(identifierInput?.value || '');
    const password = String(passwordInput?.value || '');

    if (!identifier || !password) {
      setStatus('Please enter your login and password.', true);
      return;
    }

    setStatus('Signing in...');

    let signedIn = null;

    try {
      signedIn = await signInWithEmailAndPassword(auth, identifier.email, password);
    } catch (_error) {
      if (identifier.alias) {
        const aliasEmail = await resolveEmailFromAlias(identifier.alias);
        if (aliasEmail) {
          try {
            signedIn = await signInWithEmailAndPassword(auth, aliasEmail, password);
          } catch (_retryError) {
            signedIn = null;
          }
        }
      }
    }

    if (!signedIn || !signedIn.user) {
      setStatus('Login failed. Check your ID/email and password.', true);
      return;
    }

    try {
      const profile = await loadAdminProfile(signedIn.user.uid);
      const target = isSuperAdmin(profile) ? '/admin-super.html' : nextPath;
      window.location.replace(target);
    } catch (_error) {
      await signOut(auth);
      setStatus('This account is not allowed to access admin pages.', true);
    }
  });
}

function handleProtectedPage() {
  onAuthStateChanged(auth, async (user) => {
    if (!user) {
      redirectToLogin();
      return;
    }
    await ensureAuthorizedAndRender(user);
  });
}

(function initAdminApp() {
  const pageType = getPageType();
  if (pageType === 'login') {
    handleLoginPage();
    return;
  }
  handleProtectedPage();
})();
