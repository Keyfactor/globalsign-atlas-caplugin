## Overview

The GlobalSign Atlas AnyCA Gateway REST plugin extends the capabilities of GlobalSign Atlas to Keyfactor Command via the Keyfactor AnyCA Gateway REST. The plugin has the following capabilities:
* SSl Certificate Synchronization
* SSL Certificate Enrollment
* SSL Certificate Revocation

## Requirements

To use the GlobalSign Atlas AnyCA Gateway, you must generate a set of API Credentials (key/secret) within the Atlas portal, as well as an mTLS certificate linked to those credentials.

## Gateway Registration

In order to enroll for certificates the Keyfactor Command server must trust the trust chain. Once you configure your Root and/or Subordinate CA in your Atlas account, make sure to download and import the certificate chain into the Command Server certificate store

## Certificate Template Creation Step

When defining templates, the product ID should just be defined as "certificate".