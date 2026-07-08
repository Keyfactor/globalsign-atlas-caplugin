<h1 align="center" style="border-bottom: none">
    GlobalSign Atlas AnyCA Gateway REST Plugin
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
<a href="https://github.com/Keyfactor/globalsign-atlas-caplugin/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/globalsign-atlas-caplugin?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/globalsign-atlas-caplugin?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/globalsign-atlas-caplugin/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a>
  ·
  <a href="#requirements">
    <b>Requirements</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=anycagateway">
    <b>Related Integrations</b>
  </a>
</p>

The GlobalSign Atlas AnyCA Gateway REST plugin extends the capabilities of GlobalSign Atlas to Keyfactor Command via the Keyfactor AnyCA Gateway REST. The plugin has the following capabilities:
* SSl Certificate Synchronization
* SSL Certificate Enrollment
* SSL Certificate Revocation

## Compatibility

The GlobalSign Atlas AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2.0 and later.

## Support
The GlobalSign Atlas AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com.

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

To use the GlobalSign Atlas AnyCA Gateway, you must generate a set of API Credentials (key/secret) within the Atlas portal, as well as an mTLS certificate linked to those credentials.

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [GlobalSign Atlas AnyCA Gateway REST plugin](https://github.com/Keyfactor/globalsign-atlas-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net8.0` or `net10.0`) to the Extensions directory:


    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net10.0\Extensions
    ```

    > The directory containing the GlobalSign Atlas AnyCA Gateway REST plugin DLLs (`net8.0` or `net10.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the GlobalSign Atlas plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

        In order to enroll for certificates the Keyfactor Command server must trust the trust chain. Once you configure your Root and/or Subordinate CA in your Atlas account, make sure to download and import the certificate chain into the Command Server certificate store

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **ApiKey** - The API key for the Atlas credentials the gateway will use.
        * **ApiSecret** - The corresponding API secret value that matches with the ApiKey.
        * **ClientCertificate** - The client auth certificate to use with the Atlas API
        * **SyncStartDate** - The earliest date to go back when doing a full sync.

2. When defining templates, the product ID should just be defined as "certificate".

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.

4. In Keyfactor Command (v12.3+), for each imported Certificate Template, follow the [official documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Configuring%20Template%20Options.htm) to define enrollment fields for each of the following parameters:

    * **Lifetime** - The term length (in days) to use for enrollment.
    * **KeyUsage** - The key usage to use for enrolled certs. Valid values are 'client', 'server', and 'clientserver'.

## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).
