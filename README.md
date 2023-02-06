# A Reverse-Analysis of the Austrian "ID Wallet" (eAusweise / Digitales Amt)

This is an ongoing effort for documenting and understanding the Austrian "ID Wallet" apps:
- [*Digitales Amt*](https://play.google.com/store/apps/details?id=at.gv.oe.app&hl=en&gl=US)
- [*eAusweise*](https://play.google.com/store/apps/details?id=at.gv.oe.awp.eausweise&hl=de&gl=US)

First, the user logs in at the *Digitales Amt* app. Then, the *eAusweise* app is set-up, which sends an intent to the first app.

Based on a reverse-analysis, the `./demo.py` script re-implements this procedure. After a successfull run, it provides you with **TLS Client Certificates** (and keys) for use with:
- The *Digitales Amt* backend API endpoints
- The *eAusweise* backend API endpoints

You will need some eIDAS compliant identity token during the process, such as the german national identity card.

## Handysignatur

Need a Handysignatur test account? [Here](https://www.a-trust.at/testidentitaetenmanagement) you can get a test account on the production infrastructure using an eIDAS identity token (such as the german ID card). On an iPhone, I logged into the *Digitales Amt* app using the "EU-Login" and then accessed the test identity management on my phone.
