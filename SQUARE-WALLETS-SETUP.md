# Square Apple Pay and Google Pay Setup

The checkout initializes Apple Pay, Google Pay, and card payments through
Square's Web Payments SDK. It displays only the wallet methods supported by
the buyer's current browser and device.

## Required Square configuration

1. Open the Square Developer Console.
2. Select the Square application used by this website.
3. In **Production** mode, open **Apple Pay**.
4. Add `toratyosefsummerraffle.com` as a production Apple Pay domain.
5. Confirm this URL returns the Square-provided file without redirects or a
   file extension:

   `https://toratyosefsummerraffle.com/.well-known/apple-developer-merchantid-domain-association`

6. Confirm the production application ID, location ID, and access token all
   belong to the same Square application and seller location.

## Deployment

Deploy the updated payment function after merging:

```bash
firebase deploy --only functions:createSquareCardPayment --project torat-yose
```

The Square access token remains server-side. Never add it to website HTML or
JavaScript.

## Testing

- Apple Pay requires Safari, HTTPS, a supported Apple device, and a card in
  Apple Wallet.
- Google Pay appears only when Square and the browser report it as available.
- Unsupported wallets stay hidden, while card checkout remains available.
- Test production wallet payments with a low-risk controlled transaction and
  verify the payment in the Square Dashboard.
