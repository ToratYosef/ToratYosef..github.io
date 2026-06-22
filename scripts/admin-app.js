import { initializeApp, getApps } from 'https://www.gstatic.com/firebasejs/11.9.0/firebase-app.js';
import {
  getAuth,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  signOut
} from 'https://www.gstatic.com/firebasejs/11.9.0/firebase-auth.js';
import {
  getFunctions,
  httpsCallable
} from 'https://www.gstatic.com/firebasejs/11.9.0/firebase-functions.js';
import {
  getFirestore,
  doc,
  getDoc,
  collection,
  getDocs,
  query,
  where
} from 'https://www.gstatic.com/firebasejs/11.9.0/firebase-firestore.js';
import {
  getMessaging,
  getToken,
  isSupported as isMessagingSupported,
  onMessage
} from 'https://www.gstatic.com/firebasejs/11.9.0/firebase-messaging.js';
import { firebaseConfig, firebaseMessagingVapidKey } from '/scripts/firebase-config.js';

const ADMIN_EMAIL_DOMAIN = 'toratyosef.com';
const TICKET_PRICE = 126;

const app = getApps().length ? getApps()[0] : initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
const functions = getFunctions(app, 'us-central1');
let foregroundMessagingBound = false;

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

function formatPaymentMethod(value) {
  const normalized = String(value || '').trim().toLowerCase();
  const labels = {
    cash: 'Cash',
    other: 'Other',
    square: 'Square',
    square_card: 'Square',
    venmo: 'Venmo',
    zelle: 'Zelle'
  };
  return labels[normalized] || (normalized ? normalized.replace(/_/g, ' ') : '-');
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  }[character]));
}

function formatPercent(numerator, denominator) {
  if (!denominator || denominator <= 0) {
    return '0%';
  }
  return `${((numerator / denominator) * 100).toFixed(1)}%`;
}

function formatDateValue(value) {
  if (!value) {
    return '-';
  }

  try {
    if (typeof value.toDate === 'function') {
      return value.toDate().toLocaleString();
    }
    if (value.seconds) {
      return new Date((value.seconds * 1000) + Math.floor((value.nanoseconds || 0) / 1000000)).toLocaleString();
    }
  } catch (_error) {
    return '-';
  }

  return '-';
}

function timestampToMillis(value) {
  if (!value) {
    return 0;
  }
  if (typeof value.toMillis === 'function') {
    return value.toMillis();
  }
  if (value.seconds) {
    return (value.seconds * 1000) + Math.floor((value.nanoseconds || 0) / 1000000);
  }
  return 0;
}

function isSuperAdmin(profile) {
  return Boolean(profile?.isSuperAdminReferrer || profile?.role === 'superAdmin' || profile?.role === 'superAdminReferrer');
}

function wireAdminHeader(profile) {
  const headerName = byId('admin-header-name');
  if (headerName) {
    headerName.textContent = profile?.name || 'Admin';
  }

  const headerRole = byId('admin-header-role');
  if (headerRole) {
    headerRole.textContent = isSuperAdmin(profile) ? 'Super Admin' : 'Admin';
  }

  const logoutButton = byId('admin-logout-button');
  if (logoutButton && !logoutButton.dataset.bound) {
    logoutButton.dataset.bound = 'true';
    logoutButton.addEventListener('click', async () => {
      await signOut(auth);
      redirectToLogin();
    });
  }
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
  window.location.href = `/admin?next=${encodeURIComponent(next)}`;
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

function setStatusText(id, message, isError = false) {
  const node = byId(id);
  if (!node) {
    return;
  }
  node.textContent = message;
  node.className = isError ? 'self-center text-sm text-red-600' : 'self-center text-sm text-slate-600';
}

async function setupSaleNotifications() {
  const button = byId('enable-sale-notifications');
  const status = byId('sale-notification-status');
  if (!button || button.dataset.bound === 'true') {
    return;
  }

  const setStatus = (message, isError = false) => {
    if (!status) {
      return;
    }
    status.textContent = message;
    status.className = isError ? 'self-center text-xs text-red-600' : 'self-center text-xs text-slate-500';
  };

  if (!window.isSecureContext || !('serviceWorker' in navigator) || !('Notification' in window)) {
    button.disabled = true;
    button.classList.add('opacity-50', 'cursor-not-allowed');
    setStatus('Push notifications are not supported in this browser.', true);
    return;
  }

  if (!(await isMessagingSupported())) {
    button.disabled = true;
    button.classList.add('opacity-50', 'cursor-not-allowed');
    setStatus('Firebase notifications are not supported in this browser.', true);
    return;
  }

  const messaging = getMessaging(app);

  const registerToken = async (requestPermission) => {
    try {
      let permission = Notification.permission;
      if (requestPermission && permission === 'default') {
        permission = await Notification.requestPermission();
      }

      if (permission !== 'granted') {
        setStatus(
          permission === 'denied'
            ? 'Notifications are blocked in your browser settings.'
            : 'Click Enable Notifications to receive sale alerts.',
          permission === 'denied'
        );
        return;
      }

      setStatus('Connecting sale notifications...');
      const serviceWorkerRegistration = await navigator.serviceWorker.register('/firebase-messaging-sw.js');
      const tokenOptions = { serviceWorkerRegistration };
      if (firebaseMessagingVapidKey) {
        tokenOptions.vapidKey = firebaseMessagingVapidKey;
      }

      const token = await getToken(messaging, tokenOptions);
      if (!token) {
        throw new Error('Firebase did not return a notification token.');
      }

      const registerAdminFcmToken = httpsCallable(functions, 'registerAdminFcmToken');
      await registerAdminFcmToken({
        token,
        userAgent: navigator.userAgent,
        platform: navigator.userAgentData?.platform || navigator.platform || ''
      });

      button.textContent = 'Notifications Enabled';
      button.disabled = true;
      button.classList.add('opacity-70', 'cursor-default');
      setStatus('This browser will receive ticket sale alerts.');

      if (!foregroundMessagingBound) {
        foregroundMessagingBound = true;
        onMessage(messaging, (payload) => {
          const title = payload.notification?.title || 'New ticket sale';
          const body = payload.notification?.body || 'A new raffle sale was recorded.';
          setStatus(body);
          if (Notification.permission === 'granted') {
            try {
              new Notification(title, {
                body,
                icon: '/assets/logo.png',
                tag: payload.data?.saleId ? `ticket-sale-${payload.data.saleId}` : 'ticket-sale'
              });
            } catch (_error) {
              // Some mobile browsers only display notifications from the service worker.
            }
          }
        });
      }
    } catch (error) {
      console.error('Sale notification registration failed:', error);
      setStatus('Could not enable notifications. Check the Firebase Web Push key and browser permissions.', true);
    }
  };

  button.dataset.bound = 'true';
  button.addEventListener('click', () => registerToken(true));

  if (Notification.permission === 'granted') {
    await registerToken(false);
  } else if (Notification.permission === 'denied') {
    setStatus('Notifications are blocked in your browser settings.', true);
  } else {
    setStatus('Enable alerts to be notified when tickets are sold.');
  }
}

function wireAddAdminForm() {
  const panel = byId('add-admin-panel');
  const showButton = byId('show-add-admin-form');
  const hideButton = byId('hide-add-admin-form');
  const form = byId('add-admin-form');

  if (!panel || !showButton || !hideButton || !form || form.dataset.bound === 'true') {
    return;
  }

  const togglePanel = (visible) => {
    panel.classList.toggle('hidden', !visible);
  };

  showButton.addEventListener('click', () => togglePanel(true));
  hideButton.addEventListener('click', () => togglePanel(false));

  form.dataset.bound = 'true';
  form.addEventListener('submit', async (event) => {
    event.preventDefault();

    const payload = {
      name: String(byId('admin-name')?.value || '').trim(),
      firstName: String(byId('admin-first-name')?.value || '').trim(),
      lastName: String(byId('admin-last-name')?.value || '').trim(),
      email: String(byId('admin-email')?.value || '').trim(),
      password: String(byId('admin-password')?.value || ''),
      refId: String(byId('admin-ref-id')?.value || '').trim(),
      goal: Number(byId('admin-goal')?.value || 300),
      role: String(byId('admin-role')?.value || 'admin'),
      isActive: Boolean(byId('admin-active')?.checked)
    };

    if (!payload.name || !payload.email || !payload.password) {
      setStatusText('add-admin-status', 'Name, email, and password are required.', true);
      return;
    }

    setStatusText('add-admin-status', 'Creating admin...');

    try {
      const createAdminAccount = httpsCallable(functions, 'createAdminAccount');
      await createAdminAccount(payload);
      setStatusText('add-admin-status', 'Admin created successfully. Reloading...');
      window.location.reload();
    } catch (error) {
      const message = error?.message || 'Failed to create admin.';
      setStatusText('add-admin-status', message, true);
    }
  });
}

function wireManualSaleForm(profiles) {
  const panel = byId('manual-sale-panel');
  const showButton = byId('show-manual-sale-form');
  const hideButton = byId('hide-manual-sale-form');
  const form = byId('manual-sale-form');
  const referrerSelect = byId('manual-sale-referrer');
  const assignment = byId('manual-sale-assignment');
  const ticketInput = byId('manual-sale-tickets');
  const amountPreview = byId('manual-sale-amount');

  if (!panel || !showButton || !hideButton || !form || !referrerSelect) {
    return;
  }

  const activeProfiles = profiles
    .filter((profile) => profile.isActive !== false && (profile.refId || profile.ref))
    .sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
  const profilesByUid = new Map(activeProfiles.map((profile) => [profile.uid, profile]));

  referrerSelect.innerHTML = '<option value="">Select an admin</option>';
  activeProfiles.forEach((profile) => {
    const option = document.createElement('option');
    option.value = profile.uid;
    option.textContent = `${profile.name || 'Admin'} — ${profile.refId || profile.ref}`;
    referrerSelect.appendChild(option);
  });

  const updateAssignment = () => {
    const profile = profilesByUid.get(referrerSelect.value);
    if (assignment) {
      assignment.textContent = profile
        ? `UID: ${profile.uid} · Ref ID: ${profile.refId || profile.ref}`
        : 'Choose an admin to assign both UID and Ref ID automatically.';
    }
  };

  const updateAmount = () => {
    if (amountPreview) {
      const tickets = Math.max(Number(ticketInput?.value) || 0, 0);
      amountPreview.textContent = formatMoney(tickets * TICKET_PRICE);
    }
  };

  referrerSelect.addEventListener('change', updateAssignment);
  ticketInput?.addEventListener('input', updateAmount);
  updateAssignment();
  updateAmount();

  if (form.dataset.bound === 'true') {
    return;
  }

  const togglePanel = (visible) => {
    panel.classList.toggle('hidden', !visible);
    if (visible) {
      byId('manual-sale-name')?.focus();
    }
  };

  showButton.addEventListener('click', () => togglePanel(true));
  hideButton.addEventListener('click', () => togglePanel(false));

  form.dataset.bound = 'true';
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const selectedProfile = profilesByUid.get(referrerSelect.value);
    const submitButton = byId('submit-manual-sale');
    const payload = {
      name: String(byId('manual-sale-name')?.value || '').trim(),
      email: String(byId('manual-sale-email')?.value || '').trim(),
      phone: String(byId('manual-sale-phone')?.value || '').trim(),
      ticketsBought: Number(byId('manual-sale-tickets')?.value || 0),
      paymentMethod: String(byId('manual-sale-payment-method')?.value || '').trim(),
      referrerUid: selectedProfile?.uid || '',
      referrerRefId: selectedProfile?.refId || selectedProfile?.ref || ''
    };

    if (!payload.name || !payload.email || !payload.phone || payload.ticketsBought <= 0 || !selectedProfile || !payload.paymentMethod) {
      setStatusText('manual-sale-status', 'Complete every field and select the referring admin.', true);
      return;
    }

    submitButton.disabled = true;
    submitButton.classList.add('opacity-60', 'cursor-not-allowed');
    setStatusText('manual-sale-status', 'Saving manual ticket entry...');

    try {
      const addManualSale = httpsCallable(functions, 'addManualSale');
      const result = await addManualSale(payload);
      setStatusText('manual-sale-status', result.data?.message || 'Manual ticket entry saved.');
      form.reset();
      updateAssignment();
      updateAmount();
      window.setTimeout(() => window.location.reload(), 800);
    } catch (error) {
      setStatusText('manual-sale-status', error?.message || 'Failed to save the manual ticket entry.', true);
      submitButton.disabled = false;
      submitButton.classList.remove('opacity-60', 'cursor-not-allowed');
    }
  });
}

async function renderDashboard(profile) {
  wireAdminHeader(profile);
  const name = String(profile?.name || [profile?.firstName, profile?.lastName].filter(Boolean).join(' ') || 'Admin');
  const ref = String(profile?.ref || profile?.refId || '').trim();
  const goal = Number(profile?.goal) || 0;
  const ticketSales = await loadAllSalesForAdmin(profile);
  const trackedTickets = ticketSales.reduce((sum, sale) => sum + (Number(sale.ticketsBought) || 0), 0);
  const trackedRevenue = ticketSales.reduce((sum, sale) => sum + (Number(sale.amount) || 0), 0);

  const sold = trackedTickets > 0
    ? trackedTickets
    : (Number(profile?.totalTicketsSold ?? profile?.ticketsSold) || 0);
  const remaining = Math.max(Number(profile?.ticketsRemaining ?? (goal - sold)) || 0, 0);
  const clicks = Number(profile?.clickCount) || 0;
  const storedRevenue = Number(profile?.totalRevenue) || 0;
  const revenueFromSalesCount = sold > 0 ? sold * TICKET_PRICE : 0;
  const revenue = trackedRevenue > 0
    ? trackedRevenue
    : (storedRevenue > 0 ? storedRevenue : revenueFromSalesCount);

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

  const remainingStat = byId('stat-remaining');
  if (remainingStat) {
    remainingStat.textContent = String(remaining);
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
  const recentSalesBody = byId('recent-sales-body');

  const sortedSales = [...ticketSales].sort((a, b) => timestampToMillis(b.createdAt) - timestampToMillis(a.createdAt));
  if (recentSalesBody) {
    recentSalesBody.innerHTML = '';
    sortedSales.forEach((sale) => {
      const tr = document.createElement('tr');
      tr.className = 'border-b border-slate-100';
      tr.innerHTML = `
        <td class="px-2 py-2">${escapeHtml(sale.buyerName || '-')}</td>
        <td class="px-2 py-2">${escapeHtml(sale.buyerPhone || '-')}</td>
        <td class="px-2 py-2">${sale.ticketsBought || 0}</td>
        <td class="px-2 py-2">${formatMoney(sale.amount || 0)}</td>
        <td class="px-2 py-2">${escapeHtml(formatPaymentMethod(sale.paymentMethod))}</td>
      `;
      recentSalesBody.appendChild(tr);
    });
  }

  if (recentSalesEmpty) {
    recentSalesEmpty.style.display = sortedSales.length ? 'none' : 'block';
  }
}

async function renderSuperDashboard(profiles) {
  wireAddAdminForm();
  wireManualSaleForm(profiles);
  const salesByAdmin = await Promise.all(profiles.map((profile) => loadAllSalesForAdmin(profile)));
  const normalizedProfiles = profiles.map((profile, index) => {
    const sales = salesByAdmin[index] || [];
    const trackedRevenue = sales.reduce((sum, sale) => sum + (Number(sale.amount) || 0), 0);
    const trackedTickets = sales.reduce((sum, sale) => sum + (Number(sale.ticketsBought) || 0), 0);

    const fallbackRevenue = Number(profile.totalRevenue) || 0;
    const fallbackTickets = Number(profile.totalTicketsSold ?? profile.ticketsSold) || 0;
    const fallbackRevenueFromTickets = fallbackTickets > 0 ? fallbackTickets * TICKET_PRICE : 0;

    return {
      ...profile,
      totalRevenue: trackedRevenue > 0
        ? trackedRevenue
        : (fallbackRevenue > 0 ? fallbackRevenue : fallbackRevenueFromTickets),
      totalTicketsSold: trackedTickets > 0 ? trackedTickets : fallbackTickets,
      ticketsSold: trackedTickets > 0 ? trackedTickets : fallbackTickets
    };
  });

  const totalRevenue = normalizedProfiles.reduce((sum, p) => sum + (Number(p.totalRevenue) || 0), 0);
  const totalSales = normalizedProfiles.reduce((sum, p) => sum + (Number(p.totalTicketsSold ?? p.ticketsSold) || 0), 0);

  const byRevenue = [...normalizedProfiles].sort((a, b) => (Number(b.totalRevenue) || 0) - (Number(a.totalRevenue) || 0));
  const bySales = [...normalizedProfiles].sort((a, b) => (Number(b.totalTicketsSold ?? b.ticketsSold) || 0) - (Number(a.totalTicketsSold ?? a.ticketsSold) || 0));

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
  setText('stat-total-admins', String(normalizedProfiles.length));
  setText('top-revenue', byRevenue[0] ? `${byRevenue[0].name || 'Admin'} (${formatMoney(byRevenue[0].totalRevenue || 0)})` : '-');
  setText('top-sales', bySales[0] ? `${bySales[0].name || 'Admin'} (${Number(bySales[0].totalTicketsSold ?? bySales[0].ticketsSold) || 0})` : '-');

  const body = byId('admins-body');
  const empty = byId('admins-empty');
  if (!body) {
    return;
  }

  body.innerHTML = '';
  if (!normalizedProfiles.length) {
    if (empty) {
      empty.style.display = 'block';
    }
    return;
  }

  if (empty) {
    empty.style.display = 'none';
  }

  normalizedProfiles.forEach((profile, index) => {
    const sold = Number(profile.totalTicketsSold ?? profile.ticketsSold) || 0;
    const revenue = Number(profile.totalRevenue) || 0;
    const ref = profile.ref || profile.refId || '';
    const link = ref ? `${window.location.origin}/?ref=${encodeURIComponent(ref)}` : '';
    const status = profile.isActive === false ? 'Inactive' : 'Active';
    const isEvenRow = index % 2 === 0;

    const tr = document.createElement('tr');
    tr.className = `border-b border-slate-100 ${isEvenRow ? 'bg-slate-50/40' : 'bg-white'} hover:bg-rose-50/30 transition-colors`;
    tr.innerHTML = `
      <td class="px-4 py-3 font-medium text-slate-900">${profile.name || '-'}</td>
      <td class="px-4 py-3 text-slate-600">${ref || '-'}</td>
      <td class="px-4 py-3 text-slate-600">${profile.email || '-'}</td>
      <td class="px-4 py-3">${link ? `<a href="${link}" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 rounded px-2 py-1 text-rose-700 hover:bg-rose-100 hover:text-rose-800 transition-colors">Open ↗</a>` : '-'}</td>
      <td class="px-4 py-3 text-center font-semibold text-slate-900">${sold}</td>
      <td class="px-4 py-3 text-center font-semibold text-slate-900">${formatMoney(revenue)}</td>
      <td class="px-4 py-3"><span class="inline-flex rounded-full ${status === 'Active' ? 'bg-emerald-100 text-emerald-800 border border-emerald-300' : 'bg-slate-200 text-slate-700 border border-slate-300'} px-3 py-1 text-xs font-bold uppercase tracking-wide">${status}</span></td>
      <td class="px-4 py-3 text-slate-400">-</td>
    `;
    body.appendChild(tr);
  });
}

async function loadTicketSalesForAdmin(adminProfile) {
  const uid = adminProfile.uid;
  const salesSnap = await getDocs(collection(db, 'admin', uid, 'ticketSales'));
  return salesSnap.docs.map((snap) => {
    const data = snap.data() || {};
    const amountValue = Number(data.amount);
    const amount = Number.isFinite(amountValue) ? amountValue : 0;

    const rawTickets = Number(data.ticketsBought);
    const derivedTickets = amount > 0 ? Math.max(Math.round(amount / TICKET_PRICE), 1) : 0;
    const ticketsBought = Number.isFinite(rawTickets) && rawTickets > 0 ? rawTickets : derivedTickets;

    return {
      id: snap.id,
      adminUid: uid,
      adminName: adminProfile.name || '-',
      adminRef: adminProfile.ref || adminProfile.refId || '-',
      refId: data.refId || adminProfile.ref || adminProfile.refId || '-',
      buyerName: data.buyerName || '-',
      buyerEmail: data.buyerEmail || '-',
      buyerPhone: data.buyerPhone || '-',
      ticketsBought,
      amount,
      orderId: data.orderId || snap.id || '-',
      paymentId: data.paymentId || '-',
      paymentMethod: data.paymentMethod || (data.paymentId ? 'square' : '-'),
      createdAt: data.createdAt || null,
      createdAtText: formatDateValue(data.createdAt)
    };
  });
}

async function loadLegacyEntriesForAdmin(adminProfile) {
  const uid = adminProfile.uid;
  const ref = adminProfile.ref || adminProfile.refId || null;
  const all = [];

  try {
    const byUidSnap = await getDocs(query(collection(db, 'raffle_entries'), where('referrerUid', '==', uid)));
    byUidSnap.docs.forEach((snap) => {
      const data = snap.data() || {};
      all.push({
        id: snap.id,
        adminUid: uid,
        adminName: adminProfile.name || '-',
        adminRef: ref || '-',
        buyerName: data.name || '-',
        buyerEmail: data.email || '-',
        buyerPhone: data.phone || '-',
        ticketsBought: Number(data.ticketsBought) || 0,
        amount: Number(data.amount) || ((Number(data.ticketsBought) || 0) * TICKET_PRICE),
        orderId: data.orderID || data.orderId || '-',
        paymentId: data.squarePaymentId || '-',
        paymentMethod: data.paymentMethod || data.manualPaymentMethod || data.entryType || '-',
        createdAt: data.timestamp || null,
        createdAtText: formatDateValue(data.timestamp)
      });
    });
  } catch (_error) {
    // Ignore query failures and continue.
  }

  if (all.length === 0 && ref) {
    try {
      const byRefSnap = await getDocs(query(collection(db, 'raffle_entries'), where('referrerRefId', '==', ref)));
      byRefSnap.docs.forEach((snap) => {
        const data = snap.data() || {};
        all.push({
          id: snap.id,
          adminUid: uid,
          adminName: adminProfile.name || '-',
          adminRef: ref || '-',
          buyerName: data.name || '-',
          buyerEmail: data.email || '-',
          buyerPhone: data.phone || '-',
          ticketsBought: Number(data.ticketsBought) || 0,
          amount: Number(data.amount) || ((Number(data.ticketsBought) || 0) * TICKET_PRICE),
          orderId: data.orderID || data.orderId || '-',
          paymentId: data.squarePaymentId || '-',
          paymentMethod: data.paymentMethod || data.manualPaymentMethod || data.entryType || '-',
          createdAt: data.timestamp || null,
          createdAtText: formatDateValue(data.timestamp)
        });
      });
    } catch (_error) {
      // Ignore query failures.
    }
  }

  return all;
}

async function loadAllSalesForAdmin(adminProfile) {
  const ticketSales = await loadTicketSalesForAdmin(adminProfile);
  if (ticketSales.length > 0) {
    return ticketSales;
  }
  return loadLegacyEntriesForAdmin(adminProfile);
}

async function loadUnreferredSalesForSuper(adminProfiles) {
  const knownRefIds = new Set(
    adminProfiles
      .map((profile) => String(profile.ref || profile.refId || '').trim().toLowerCase())
      .filter(Boolean)
  );

  let entriesSnap;
  try {
    entriesSnap = await getDocs(collection(db, 'raffle_entries'));
  } catch (_error) {
    return [];
  }

  return entriesSnap.docs.map((snap) => {
    const data = snap.data() || {};
    const referrerUid = String(data.referrerUid || '').trim();
    const referrerRefId = String(data.referrerRefId || '').trim().toLowerCase();
    const isDirect = !referrerUid || !referrerRefId || referrerRefId === 'direct';

    if (!isDirect || (referrerRefId && referrerRefId !== 'direct' && knownRefIds.has(referrerRefId))) {
      return null;
    }

    const amountValue = Number(data.amount);
    const amount = Number.isFinite(amountValue) ? amountValue : 0;

    const rawTickets = Number(data.ticketsBought);
    const derivedTickets = amount > 0 ? Math.max(Math.round(amount / TICKET_PRICE), 1) : 0;
    const ticketsBought = Number.isFinite(rawTickets) && rawTickets > 0 ? rawTickets : derivedTickets;

    return {
      id: snap.id,
      adminUid: 'direct',
      adminName: 'Direct',
      adminRef: 'direct',
      refId: 'direct',
      buyerName: data.name || '-',
      buyerEmail: data.email || '-',
      buyerPhone: data.phone || '-',
      ticketsBought,
      amount,
      orderId: data.orderID || data.orderId || snap.id || '-',
      paymentId: data.squarePaymentId || '-',
      paymentMethod: data.paymentMethod || data.manualPaymentMethod || data.entryType || '-',
      createdAt: data.timestamp || null,
      createdAtText: formatDateValue(data.timestamp)
    };
  }).filter(Boolean);
}

function renderSalesRows(tbody, sales) {
  if (!tbody) {
    return;
  }

  tbody.innerHTML = '';

  sales.forEach((sale, index) => {
    const isEvenRow = index % 2 === 0;
    const tr = document.createElement('tr');
    tr.className = `border-b border-slate-100 ${isEvenRow ? 'bg-slate-50/40' : 'bg-white'} hover:bg-rose-50/30 transition-colors`;
    const referrerDisplay = sale.adminRef ? `${sale.adminName} (${sale.adminRef})` : sale.adminName || '-';
    tr.innerHTML = `
      <td class="px-4 py-3 font-medium text-slate-900">${escapeHtml(sale.buyerName)}</td>
      <td class="px-4 py-3 text-center font-semibold text-slate-900">${sale.ticketsBought}</td>
      <td class="px-4 py-3 text-center font-semibold text-slate-900">${formatMoney(sale.amount)}</td>
      <td class="px-4 py-3 text-slate-600">${escapeHtml(formatPaymentMethod(sale.paymentMethod))}</td>
      <td class="px-4 py-3 text-slate-600">${sale.createdAtText}</td>
      <td class="px-4 py-3 font-medium text-slate-900">${escapeHtml(referrerDisplay)}</td>
    `;
    tbody.appendChild(tr);
  });
}

function csvEscape(value) {
  const text = String(value ?? '');
  if (text.includes(',') || text.includes('"') || text.includes('\n')) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

function downloadCsv(filename, rows) {
  const csvContent = rows.map((row) => row.map(csvEscape).join(',')).join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function exportSalesPerTicketCsv(sales) {
  const headers = [
    'Ticket #',
    'Buyer Name',
    'Buyer Email',
    'Buyer Phone',
    'Referrer Name',
    'Referrer ID',
    'Sale Amount',
    'Ticket Amount',
    'Order ID',
    'Payment ID',
    'Payment Method',
    'Sale Time'
  ];

  const rows = [headers];
  let ticketCounter = 0;

  sales.forEach((sale) => {
    const ticketCount = Math.max(Number(sale.ticketsBought) || 0, 0);
    if (!ticketCount) {
      return;
    }

    const saleAmount = Number(sale.amount) || 0;
    const perTicketAmount = saleAmount / ticketCount;

    for (let i = 0; i < ticketCount; i += 1) {
      ticketCounter += 1;
      rows.push([
        ticketCounter,
        sale.buyerName || '-',
        sale.buyerEmail || '-',
        sale.buyerPhone || '-',
        sale.adminName || '-',
        sale.adminRef || '-',
        saleAmount.toFixed(2),
        perTicketAmount.toFixed(2),
        sale.orderId || '-',
        sale.paymentId || '-',
        formatPaymentMethod(sale.paymentMethod),
        sale.createdAtText || '-'
      ]);
    }
  });

  if (ticketCounter === 0) {
    return 0;
  }

  const stamp = new Date().toISOString().slice(0, 10);
  downloadCsv(`all-sales-per-ticket-${stamp}.csv`, rows);
  return ticketCounter;
}

async function renderSuperSalesPage(currentProfile) {
  if (!isSuperAdmin(currentProfile)) {
    window.location.href = '/admin-dashboard.html';
    return;
  }

  wireAdminHeader(currentProfile);

  const adminsSnap = await getDocs(collection(db, 'admin'));
  const admins = adminsSnap.docs.map((snap) => ({ uid: snap.id, ...(snap.data() || {}) }));

  const salesByAdmin = await Promise.all(admins.map((profile) => loadAllSalesForAdmin(profile)));
  const unreferredSales = await loadUnreferredSalesForSuper(admins);
  const allSales = salesByAdmin
    .flat()
    .concat(unreferredSales)
    .sort((a, b) => timestampToMillis(b.createdAt) - timestampToMillis(a.createdAt));
  const ownSales = allSales.filter((sale) => sale.adminUid === currentProfile.uid);

  const totalTickets = allSales.reduce((sum, sale) => sum + sale.ticketsBought, 0);
  const totalAmount = allSales.reduce((sum, sale) => sum + sale.amount, 0);
  const ownTickets = ownSales.reduce((sum, sale) => sum + sale.ticketsBought, 0);
  const ownAmount = ownSales.reduce((sum, sale) => sum + sale.amount, 0);

  const setText = (id, value) => {
    const el = byId(id);
    if (el) {
      el.textContent = value;
    }
  };

  setText('super-sales-total-count', String(allSales.length));
  setText('super-sales-total-tickets', String(totalTickets));
  setText('super-sales-total-amount', formatMoney(totalAmount));
  setText('super-sales-own-count', String(ownSales.length));
  setText('super-sales-own-tickets', String(ownTickets));
  setText('super-sales-own-amount', formatMoney(ownAmount));

  const exportButton = byId('export-all-sales-button');
  const exportStatus = byId('export-all-sales-status');
  if (exportButton) {
    exportButton.disabled = allSales.length === 0;
    exportButton.classList.toggle('opacity-50', allSales.length === 0);
    exportButton.classList.toggle('cursor-not-allowed', allSales.length === 0);
    exportButton.onclick = () => {
      const count = exportSalesPerTicketCsv(allSales);
      if (exportStatus) {
        exportStatus.textContent = count > 0
          ? `Exported ${count} ticket rows.`
          : 'No ticket data to export.';
      }
    };
  }

  renderSalesRows(byId('all-sales-body'), allSales);
  renderSalesRows(byId('own-sales-body'), ownSales);

  const allEmpty = byId('all-sales-empty');
  if (allEmpty) {
    allEmpty.style.display = allSales.length ? 'none' : 'block';
  }

  const ownEmpty = byId('own-sales-empty');
  if (ownEmpty) {
    ownEmpty.style.display = ownSales.length ? 'none' : 'block';
  }
}

async function ensureAuthorizedAndRender(currentUser) {
  const pageType = getPageType();

  try {
    const profile = await loadAdminProfile(currentUser.uid);
    wireAdminHeader(profile);
    setupSaleNotifications().catch((error) => {
      console.error('Notification setup failed:', error);
    });

    if (pageType === 'super' && !isSuperAdmin(profile)) {
      window.location.href = '/admin-dashboard.html';
      return;
    }

    if (pageType === 'dashboard') {
      await renderDashboard(profile);
      return;
    }

    if (pageType === 'super') {
      const allAdminsSnap = await getDocs(collection(db, 'admin'));
      const profiles = allAdminsSnap.docs.map((snap) => ({ uid: snap.id, ...(snap.data() || {}) }));
      await renderSuperDashboard(profiles);
      return;
    }

    if (pageType === 'super-sales') {
      await renderSuperSalesPage(profile);
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
