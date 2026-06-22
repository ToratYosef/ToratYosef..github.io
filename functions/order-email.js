const nodemailer = require('nodemailer');

const ADMIN_SALE_EMAIL = 'morriselliott@icloud.com';
const SITE_URL = 'https://toratyosefsummerraffle.com';
const LOGO_URL = `${SITE_URL}/logo.png`;

let gmailTransporter = null;

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function formatCurrency(amount, currency = 'USD') {
  const numericAmount = Number(amount);
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency || 'USD'
  }).format(Number.isFinite(numericAmount) ? numericAmount : 0);
}

function formatOrderDate(value) {
  const date = value instanceof Date ? value : new Date(value || Date.now());
  return new Intl.DateTimeFormat('en-US', {
    dateStyle: 'long',
    timeStyle: 'short',
    timeZone: 'America/New_York'
  }).format(date);
}

function formatPaymentMethod(value) {
  const normalized = String(value || '').trim().toLowerCase();
  const labels = {
    apple_pay: 'Apple Pay',
    card: 'Card',
    google_pay: 'Google Pay'
  };
  return labels[normalized] || 'Square';
}

function ticketLabel(quantity) {
  const tickets = Math.max(1, Number.parseInt(quantity, 10) || 1);
  return `${tickets} raffle ticket${tickets === 1 ? '' : 's'}`;
}

function emailShell(content) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Torat Yosef Email</title>
</head>

<body style="margin:0; padding:0; background-color:#f3f4f6; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; color:#111111;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f3f4f6; margin:0; padding:32px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:640px; background:#ffffff; border-radius:28px; overflow:hidden; border:1px solid #e5e7eb; box-shadow:0 12px 40px rgba(0,0,0,0.04);">
          <tr>
            <td style="padding:20px 24px 16px 24px; background:#ffffff; border-bottom:1px solid #f1f1f1;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td align="center" valign="middle">
                    <a href="${SITE_URL}" style="text-decoration:none; display:inline-block;">
                      <img src="${LOGO_URL}" alt="Torat Yosef" style="height:56px; display:block; margin:0 auto;" />
                    </a>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <tr>
            <td style="padding:42px 36px 24px 36px; font-size:16px; line-height:26px; color:#3f3f46;">
              ${content}
            </td>
          </tr>

          <tr>
            <td style="padding:34px 36px 34px 36px;">
              <div style="border-top:1px solid #eeeeee; padding-top:22px; text-align:center; font-size:12px; line-height:20px; color:#9ca3af;">
                <div style="font-weight:600; color:#6b7280; margin-bottom:4px;">ToratYosefSummerRaffle.com</div>
                <div>
                  <a href="${SITE_URL}" style="color:#8b8b8f; text-decoration:none;">ToratYosefSummerRaffle.com</a>
                  &nbsp;&nbsp;&bull;&nbsp;&nbsp;
                  <a href="mailto:${ADMIN_SALE_EMAIL}" style="color:#8b8b8f; text-decoration:none;">Morriselliott@icloud.com</a>
                </div>
                <div style="margin-top:6px;">© 2026 Torat Yosef. All rights reserved.</div>
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

function detailRow(label, value, options = {}) {
  const isTotal = options.total === true;
  const valueColor = isTotal ? '#be123c' : '#18181b';
  const valueSize = isTotal ? '20px' : '15px';
  return `
    <tr>
      <td style="padding:11px 0; color:#71717a; font-size:14px; border-bottom:1px solid #f4f4f5;">${escapeHtml(label)}</td>
      <td align="right" style="padding:11px 0; color:${valueColor}; font-size:${valueSize}; font-weight:700; border-bottom:1px solid #f4f4f5;">${escapeHtml(value)}</td>
    </tr>`;
}

function buildCustomerReceiptMessage(order, senderEmail) {
  const quantity = Math.max(1, Number.parseInt(order.quantity, 10) || 1);
  const name = String(order.name || 'Supporter').trim();
  const firstName = name.split(/\s+/)[0] || 'Supporter';
  const amount = formatCurrency(order.amount, order.currency);
  const paymentMethod = formatPaymentMethod(order.paymentMethod);
  const orderId = String(order.orderId || 'Unavailable');
  const orderDate = formatOrderDate(order.completedAt);
  const receiptLink = order.receiptUrl
    ? `<div style="margin-top:24px; text-align:center;">
        <a href="${escapeHtml(order.receiptUrl)}" style="display:inline-block; padding:13px 22px; border-radius:14px; background:#be123c; color:#ffffff; font-weight:700; text-decoration:none;">View Square Receipt</a>
      </div>`
    : '';
  const testPrefix = order.isTest ? '[TEST] ' : '';

  const content = `
    <div style="display:inline-block; padding:6px 12px; border-radius:999px; background:#fff1f2; color:#be123c; font-size:12px; line-height:18px; font-weight:800; letter-spacing:0.04em; text-transform:uppercase;">Order confirmed</div>
    <h1 style="margin:18px 0 12px 0; color:#18181b; font-size:30px; line-height:38px;">Thank you, ${escapeHtml(firstName)}!</h1>
    <p style="margin:0 0 24px 0;">Your Torat Yosef Summer Raffle order is complete. Your ${escapeHtml(ticketLabel(quantity))} ${quantity === 1 ? 'has' : 'have'} been entered into the raffle.</p>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="padding:8px 22px; background:#fafafa; border:1px solid #eeeeee; border-radius:18px;">
      ${detailRow('Order number', orderId)}
      ${detailRow('Order date', orderDate)}
      ${detailRow('Tickets', String(quantity))}
      ${detailRow('Payment method', paymentMethod)}
      ${detailRow('Total paid', amount, { total: true })}
    </table>

    <div style="margin-top:24px; padding:18px 20px; border-radius:16px; background:#f8fafc; color:#52525b;">
      Please keep this email as your receipt. The raffle team will contact the winner using the information submitted with the order.
    </div>
    ${receiptLink}
    <p style="margin:24px 0 0 0; font-size:13px; line-height:21px; color:#9ca3af;">Questions? Reply to this email or contact <a href="mailto:${ADMIN_SALE_EMAIL}" style="color:#71717a;">${ADMIN_SALE_EMAIL}</a>.</p>`;

  return {
    from: `"Torat Yosef Summer Raffle" <${senderEmail}>`,
    replyTo: ADMIN_SALE_EMAIL,
    to: normalizeEmail(order.email),
    subject: `${testPrefix}Your Torat Yosef raffle receipt — ${ticketLabel(quantity)}`,
    text: [
      `Thank you, ${firstName}!`,
      '',
      `Your ${ticketLabel(quantity)} has been entered into the Torat Yosef Summer Raffle.`,
      `Order number: ${orderId}`,
      `Order date: ${orderDate}`,
      `Payment method: ${paymentMethod}`,
      `Total paid: ${amount}`,
      order.receiptUrl ? `Square receipt: ${order.receiptUrl}` : '',
      '',
      `Questions: ${ADMIN_SALE_EMAIL}`
    ].filter(Boolean).join('\n'),
    html: emailShell(content)
  };
}

function buildAdminSaleMessage(order, senderEmail) {
  const quantity = Math.max(1, Number.parseInt(order.quantity, 10) || 1);
  const amount = formatCurrency(order.amount, order.currency);
  const paymentMethod = formatPaymentMethod(order.paymentMethod);
  const orderId = String(order.orderId || 'Unavailable');
  const paymentId = String(order.paymentId || 'Unavailable');
  const referral = String(order.referral || 'direct');
  const orderDate = formatOrderDate(order.completedAt);
  const testPrefix = order.isTest ? '[TEST] ' : '';

  const content = `
    <div style="display:inline-block; padding:6px 12px; border-radius:999px; background:#ecfdf5; color:#047857; font-size:12px; line-height:18px; font-weight:800; letter-spacing:0.04em; text-transform:uppercase;">Ticket sold</div>
    <h1 style="margin:18px 0 12px 0; color:#18181b; font-size:30px; line-height:38px;">A raffle order was completed</h1>
    <p style="margin:0 0 24px 0;">${escapeHtml(order.name)} purchased ${escapeHtml(ticketLabel(quantity))} for ${escapeHtml(amount)}.</p>

    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="padding:8px 22px; background:#fafafa; border:1px solid #eeeeee; border-radius:18px;">
      ${detailRow('Buyer', order.name || 'Unavailable')}
      ${detailRow('Email', normalizeEmail(order.email) || 'Unavailable')}
      ${detailRow('Phone', order.phone || 'Unavailable')}
      ${detailRow('Tickets', String(quantity))}
      ${detailRow('Payment method', paymentMethod)}
      ${detailRow('Referral', referral)}
      ${detailRow('Order number', orderId)}
      ${detailRow('Square payment ID', paymentId)}
      ${detailRow('Completed', orderDate)}
      ${detailRow('Total paid', amount, { total: true })}
    </table>`;

  return {
    from: `"Torat Yosef Summer Raffle" <${senderEmail}>`,
    replyTo: normalizeEmail(order.email) || ADMIN_SALE_EMAIL,
    to: ADMIN_SALE_EMAIL,
    subject: `${testPrefix}Ticket sold: ${ticketLabel(quantity)} — ${String(order.name || 'Buyer')}`,
    text: [
      'A Torat Yosef Summer Raffle order was completed.',
      '',
      `Buyer: ${order.name || 'Unavailable'}`,
      `Email: ${normalizeEmail(order.email) || 'Unavailable'}`,
      `Phone: ${order.phone || 'Unavailable'}`,
      `Tickets: ${quantity}`,
      `Payment method: ${paymentMethod}`,
      `Referral: ${referral}`,
      `Order number: ${orderId}`,
      `Square payment ID: ${paymentId}`,
      `Completed: ${orderDate}`,
      `Total paid: ${amount}`
    ].join('\n'),
    html: emailShell(content)
  };
}

function getGmailTransporter(smtpUser, smtpAppPassword) {
  const user = normalizeEmail(smtpUser);
  const pass = String(smtpAppPassword || '').replace(/\s+/g, '');

  if (!user || !pass) {
    throw new Error('SMTP_USER and SMTP_APP_PASSWORD must be configured.');
  }

  if (!gmailTransporter) {
    gmailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user,
        pass
      }
    });
  }

  return {
    transporter: gmailTransporter,
    senderEmail: user
  };
}

function serializeDeliveryResult(result) {
  if (result.status === 'fulfilled') {
    return {
      status: 'sent',
      messageId: result.value?.messageId || null
    };
  }

  return {
    status: 'failed',
    errorCode: result.reason?.code || null,
    errorMessage: String(result.reason?.message || 'Email delivery failed.').slice(0, 500)
  };
}

async function sendCompletedOrderEmails(order, credentials, options = {}) {
  const configuredTransport = options.transporter
    ? {
        transporter: options.transporter,
        senderEmail: normalizeEmail(credentials.smtpUser)
      }
    : getGmailTransporter(
      credentials.smtpUser,
      credentials.smtpAppPassword
    );

  const customerMessage = buildCustomerReceiptMessage(
    order,
    configuredTransport.senderEmail
  );
  const adminMessage = buildAdminSaleMessage(
    order,
    configuredTransport.senderEmail
  );

  const [customerResult, adminResult] = await Promise.allSettled([
    configuredTransport.transporter.sendMail(customerMessage),
    configuredTransport.transporter.sendMail(adminMessage)
  ]);

  const customer = serializeDeliveryResult(customerResult);
  const admin = serializeDeliveryResult(adminResult);
  const sentCount = [customer, admin]
    .filter((delivery) => delivery.status === 'sent').length;

  return {
    status: sentCount === 2 ? 'sent' : sentCount === 1 ? 'partial' : 'failed',
    customer,
    admin
  };
}

module.exports = {
  ADMIN_SALE_EMAIL,
  buildAdminSaleMessage,
  buildCustomerReceiptMessage,
  sendCompletedOrderEmails
};
