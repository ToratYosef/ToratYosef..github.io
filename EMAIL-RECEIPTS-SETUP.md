# Order receipt email setup

Completed Square card, Apple Pay, and Google Pay orders send:

1. A receipt to the email address submitted by the buyer.
2. A ticket-sold notification to `morriselliott@icloud.com`.

Email is sent through Gmail with Nodemailer. The Gmail username and app
password are stored in Firebase Secret Manager and are available only to the
`createSquareCardPayment` function.

> Important: revoke any app password that has been pasted into chat or another
> shared location, generate a new Gmail app password, and store only the new
> value in Firebase Secret Manager.

## Configure Firebase secrets

From the repository root, run:

```bash
firebase functions:secrets:set SMTP_USER --project torat-yose
firebase functions:secrets:set SMTP_APP_PASSWORD --project torat-yose
```

Enter the Gmail address at the first prompt and the 16-character Gmail app
password at the second prompt. Do not put either value in GitHub, source code,
or a committed `.env` file.

Spaces in the displayed Gmail app password are accepted; the function removes
them before authenticating.

## Deploy

After setting both secrets:

```bash
firebase deploy --only functions:createSquareCardPayment --project torat-yose
```

Whenever either secret is changed, deploy the function again so it receives
the new secret version.

## Local emulator

For local-only testing, create `functions/.secret.local`:

```dotenv
SMTP_USER=your-gmail-address
SMTP_APP_PASSWORD=your-gmail-app-password
```

The file is ignored by Git. Never use real customer information when testing
email locally.
