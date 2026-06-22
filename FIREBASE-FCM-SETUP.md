# Firebase Admin Sale Notifications

The website code includes Firebase Cloud Messaging registration and sale
notification functions. Complete these external setup steps before testing.

## 1. Firebase Authentication domain

In Firebase Console:

1. Open **Authentication**.
2. Open **Settings**.
3. Open **Authorized domains**.
4. Add:
   - `toratyosefsummerraffle.com`
   - `www.toratyosefsummerraffle.com`

## 2. Web Push certificate

In **Project Settings > Cloud Messaging > Web Push certificates**, confirm the
public key matches `firebaseMessagingVapidKey` in
`scripts/firebase-config.js`.

Never commit or expose the matching private key. Rotate the key pair if the
private key is shared outside Firebase.

## 3. Network and DNS filters

Browsers must be able to reach Firebase Installations and FCM. If NextDNS,
Pi-hole, a firewall, antivirus HTTPS inspection, or another security filter is
enabled, allow:

- `firebaseinstallations.googleapis.com`
- `fcmregistrations.googleapis.com`

An `ERR_CERT_AUTHORITY_INVALID` response whose certificate mentions a block
page indicates that a DNS/security filter intercepted the Firebase request.

## 4. Deploy Cloud Functions

From the repository root:

```bash
firebase login
firebase deploy \
  --only functions:registerAdminFcmToken,functions:notifyAdminsOnRaffleEntry,functions:addManualSale \
  --project torat-yose
```

## 5. Test

1. Sign in to an admin dashboard on the production domain.
2. Click **Enable Notifications** and allow browser notifications.
3. Record a test sale.
4. Confirm the referring admin receives an alert.
5. Confirm every super admin with notifications enabled receives an alert.
