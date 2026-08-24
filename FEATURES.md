# Unicorn --- Detailed Features

This document provides a technical feature overview of the Unichorn
project.

## 1. Public Key Infrastructure

### Certificate Handling

-   Creation and handling of X.509 certificates
-   Certificate-related cryptographic operations
-   Support for private and public key material
-   Attribute-certificate functionality
-   Certificate-chain and trust-related processing
-   Certificate Signing Request (CSR) workflows

### Trust and Validation

-   Certificate Revocation List (CRL) processing
-   OCSP-related certificate-status processing
-   OCSP responder component
-   Trust-list processing
-   Private-certificate and trust-store related functionality
-   Models derived from ETSI trust-service-list schemas

## 2. Digital Signatures

### CMS

-   CMS-based cryptographic signature functionality
-   Signed-content processing
-   Integration with certificate and key infrastructure

### CAdES

-   CAdES-related signature functionality
-   Integration with CMS and certificate infrastructure
-   Timestamp and validation-related building blocks

### PAdES / PDF Signatures

-   PDF signing functionality
-   PAdES-related capabilities
-   Integration with iText-based PDF processing
-   Certificate-based PDF signature workflows

### XML Signatures / XAdES

-   XML Digital Signature-related models and functionality
-   XAdES-related support
-   JAXB-generated models based on XML signature and XAdES schemas
-   XML-security integration

### Timestamping

-   Timestamp-protocol related functionality
-   Cryptographic timestamp integration for signature workflows

## 3. PKCS#11 and Hardware Cryptography

The dedicated `unichorn-pkcs11` module provides a separation layer for
cryptographic-device integration.

Features include:

-   PKCS#11-oriented integration
-   Smart-card/token interaction
-   Hardware-backed key access
-   Separation of device-specific concerns from the PKI core

This architecture allows private-key operations to be integrated with
cryptographic hardware instead of requiring all keys to reside in
software key stores.

## 4. Trust-Service Infrastructure

Unichorn contains models or functionality related to trust-service and
digital-signature standards, including:

-   ETSI TS 119 612 Trust Service Lists
-   ETSI TS 102 231-related schemas
-   OASIS Digital Signature Services
-   DSS-X verification reports
-   SAML 1.1/2.0 schemas
-   ASiC-related schemas
-   XMLDSig
-   XAdES

These models provide a foundation for standards-oriented
interoperability and trust-information processing.

**Important:** inclusion or implementation of standards-related
functionality is not equivalent to formal conformity assessment or
certification.

## 5. Responder and Server Components

The `unichorn-responder` module separates server-side functionality from
the core library and GUI.

The project includes service-oriented functionality for areas such as:

-   signing content,
-   CSR-related operations,
-   OCSP response handling,
-   certificate-status processing, and
-   trust-related services.

The original project architecture targets deployment of service
components in a servlet container such as Tomcat.

## 6. Desktop Application

The `unichorn-gui-fx` module provides the JavaFX-based
client/user-interface layer.

Its separation from `unichorn-core` allows the cryptographic
implementation to remain reusable independently of the desktop
interface.

## 7. Secure E-Mail

Unichorn includes a lightweight e-mail client with support for:

-   plain e-mail,
-   digitally signed e-mail, and
-   encrypted e-mail.

This demonstrates integration of PKI functionality into an end-user
communication workflow rather than limiting the project to standalone
cryptographic primitives.

## 8. Browser Component

A lightweight browser component is included as part of the
desktop/client functionality.

Together with the mail client, it demonstrates how certificate and trust
functionality can be integrated into user-facing applications.

## 9. Modular Architecture

The project is divided into four principal Maven modules:

  -----------------------------------------------------------------------
  Module                              Responsibility
  ----------------------------------- -----------------------------------
  `unichorn-core`                     Core cryptography, PKI,
                                      certificates, signatures, trust and
                                      validation

  `unichorn-pkcs11`                   PKCS#11 and cryptographic-device
                                      integration

  `unichorn-responder`                Server-side responder/services

  `unichorn-gui-fx`                   JavaFX desktop/client functionality
  -----------------------------------------------------------------------

The parent Maven project manages the modules and shared dependency
configuration.

## 10. Cryptographic and Supporting Libraries

The codebase integrates or references technologies including:

-   Bouncy Castle
-   IAIK JCE
-   IAIK CMS
-   IAIK timestamping
-   IAIK PAdES-related components
-   IAIK ECCelerate
-   IAIK XML/XAdES components
-   iText
-   JAXB
-   Apache HTTP Components
-   Apache Commons
-   Java EE / servlet APIs
-   JavaFX

Third-party components remain subject to their respective licenses. The
MIT license of Unichorn does not relicense third-party dependencies.

## 11. XML Schema-Based Models

The Maven build contains JAXB code-generation configuration for schemas
including:

-   e-mail client configuration
-   XAdES
-   XML Digital Signature
-   ASiC
-   OpenDocument manifest
-   ETSI TS 119 612
-   ETSI TS 102 231
-   OASIS DSS
-   SAML
-   DSS-X verification reports

Schema-driven generation reduces the need for hand-written
representations of complex standards documents and provides a basis for
standards-oriented message processing.

## 12. Engineering Characteristics

Unichorn demonstrates several architecture and engineering concerns in
one project:

-   separation between core, device, service, and GUI layers,
-   integration of multiple signature formats,
-   certificate lifecycle operations,
-   online and offline certificate-status mechanisms,
-   trust-list processing,
-   hardware-token integration,
-   client/server PKI workflows,
-   XML schema interoperability, and
-   integration of cryptography into practical applications such as
    e-mail and PDF signing.

## 13. Suitable Areas of Use

The project is particularly relevant for:

-   PKI experimentation,
-   applied-cryptography education,
-   digital-signature research,
-   security architecture demonstrations,
-   certificate-validation experiments,
-   trust-list processing,
-   interoperability prototyping,
-   PKCS#11 integration experiments, and
-   software-architecture studies involving security-sensitive systems.

## 14. Production and Compliance Boundary

Before production deployment, users should perform an independent
security and interoperability review.

In particular, this project does **not** claim solely by virtue of its
feature set to be:

-   a qualified trust service,
-   an eIDAS-certified product,
-   a certified signature-creation device,
-   a formally ETSI-conformant implementation, or
-   a replacement for an audited production PKI.

Such claims require specific conformity assessments, operational
controls, policies, audits, and---in some cases---certified hardware and
organizational processes beyond source-code functionality.
