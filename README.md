Code for the mail server component of maskr.app. This application handles incoming email and forwards it accordingly. Currently we are outsourcing outgoing emails due to bad IP reputation with our hosting provider.

### Checks

The following checks are being performed on incoming emails to ensure their validity:

- SPF
- DKIM
- DMARC
- PTR record check
- DNSBL

### Installation

TODO
