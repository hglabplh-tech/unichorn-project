# Unicorn Project

**Unicorn** is a modular Java-based PKI and digital-signature platform
for working with certificates, cryptographic signatures, trust
infrastructure, validation services, secure e-mail, and PKCS#11 devices.

The project combines desktop and server-side components and provides
functionality around certificate creation and management,
CMS/CAdES/PAdES/XAdES signatures, certificate signing requests,
timestamping, OCSP/CRL-based validation, ETSI Trust Service Lists, and
hardware-backed cryptographic operations.

> Unichorn is an engineering and research-oriented open-source project.
> Support for a standard or format does not by itself imply formal
> certification, qualified trust-service status, or audited regulatory
> compliance.

## Highlights

-   X.509 certificate and attribute-certificate handling
-   Certificate Signing Request (CSR) workflows
-   CMS / CAdES digital signatures
-   PDF signatures and PAdES-related functionality
-   XML signatures and XAdES-related functionality
-   Timestamping support
-   OCSP responder functionality
-   Certificate Revocation List (CRL) processing
-   Trust-list processing, including ETSI Trust Service List schemas
-   PKCS#11 integration for cryptographic tokens and smart cards
-   JavaFX desktop application
-   Server-side responder/services suitable for servlet-container
    deployment
-   Secure e-mail functionality with signing and encryption
-   Lightweight browser and mail-client components
-   Maven multi-module architecture

For a more detailed feature overview, see [FEATURES.md](FEATURES.md).

## Architecture

Unichorn is organized as a Maven multi-module project:

``` text
unichorn-project
├── unichorn-core
│   └── Core PKI, certificate, signature, validation and trust functionality
├── unichorn-pkcs11
│   └── PKCS#11 / cryptographic-device integration
├── unichorn-responder
│   └── Server-side responder and PKI-related services
└── unichorn-gui-fx
    └── JavaFX desktop user interface and client functionality
```

This separation keeps cryptographic and PKI functionality independent
from user-interface, hardware-token, and service-layer concerns.

## Standards and Formats

The project contains functionality or data models related to a broad set
of PKI and electronic-signature technologies, including:

-   X.509 certificates
-   CMS
-   CAdES
-   PAdES
-   XAdES
-   XML Digital Signature
-   ASiC-related schemas
-   OCSP
-   CRLs
-   PKCS#10 / certificate signing requests
-   PKCS#11
-   Time-Stamp Protocol/timestamping
-   ETSI TS 119 612 Trust Service Lists
-   ETSI TS 102 231-related schemas
-   OASIS Digital Signature Services
-   SAML schemas
-   DSS-X verification-report schemas

The inclusion of standards and schemas documents the interoperability
targets of the project. It should not be interpreted as a claim of
formal certification against every referenced specification.

## Core Technology

The project is primarily Java-based and built with Maven. Depending on
the module and feature, it integrates technologies and libraries such
as:

-   Java / JavaFX
-   Java Cryptography Architecture
-   Bouncy Castle
-   IAIK cryptographic libraries
-   iText
-   JAXB / XML Schema code generation
-   Apache HTTP components
-   Java EE / servlet technologies
-   PKCS#11

Some dependencies are third-party components with their own licenses and
distribution terms. In particular, users must verify the licensing
conditions of cryptographic and PDF libraries before redistributing
derived binaries.

## Typical Use Cases

Unichorn can be used as an implementation and experimentation platform
for:

1.  Creating and handling certificates.
2.  Generating and processing certificate signing requests.
3.  Digitally signing documents and arbitrary content.
4.  Working with CMS/CAdES, PAdES, and XAdES signature formats.
5.  Validating certificates through CRLs, OCSP, and trust information.
6.  Experimenting with trust-service-list processing.
7.  Integrating smart cards, tokens, or other PKCS#11 cryptographic
    devices.
8.  Running PKI-related responder or signing services.
9.  Sending signed or encrypted e-mail.
10. Studying practical PKI and electronic-signature architectures.

## Building

The repository is structured as a Maven parent project.

A conventional build starts from the repository root:

``` bash
mvn clean install
```

The project currently references several older and/or externally
licensed dependencies. A successful build can therefore require
appropriate dependency availability, compatible JDK tooling, and locally
configured third-party libraries.

The parent POM currently targets Java 14.

## Security Notice

Cryptographic software should be reviewed carefully before production
use.

Users deploying Unichorn in security-critical or regulated environments
should independently verify:

-   cryptographic algorithms and key sizes,
-   certificate profiles and validation policy,
-   trust-anchor management,
-   revocation handling,
-   timestamp validation,
-   private-key protection,
-   PKCS#11 device configuration,
-   dependency security,
-   interoperability with target systems, and
-   applicable legal or regulatory requirements.

No statement in this repository should be interpreted as certification
for eIDAS, ETSI, qualified electronic signatures, qualified seals, or
another regulated trust-service regime.

## Project Status

Unichorn is an open-source engineering project with a substantial
implementation history. The repository combines PKI infrastructure,
signature formats, trust validation, cryptographic-device integration,
desktop functionality, and service components.

Contributions, technical reviews, interoperability testing,
documentation improvements, and security-focused feedback.

## Contributing

You can contribute via GitHub issues and pull requests.

Useful contribution areas include:

-   automated tests,
-   interoperability tests,
-   modernization of dependencies,
-   additional signature profiles,
-   documentation,
-   PKCS#11 device compatibility,
-   certificate-validation test cases,
-   security review, and
-   build/CI improvements.

When contributing cryptographic functionality, please include tests and
describe the standards or profiles on which the implementation is based.

## Sponsoring

If Unichorn is useful to your work, research, teaching, or
experimentation, you can support continued maintenance and development.

See [SPONSORING.md](SPONSORING.md) for details.

GitHub's sponsorship button can be configured through
[`.github/FUNDING.yml`](.github/FUNDING.yml).

## License

The Unichorn project source code is licensed under the **MIT License**,
unless an individual file or third-party component states otherwise.

Copyright © 2020--2026 Harald Glab-Plhak.

See [LICENSE](LICENSE).

## Author

**Harald Glab-Plhak**

GitHub organization: `hglabplh-tech`
