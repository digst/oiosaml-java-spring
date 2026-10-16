# Security policy

This repository is a demo of a SAML 2.0 Service Provider
federating with NemLog-in. It is not a supported product, use it as a starting point and review
it before running anything derived from it in production.

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately through
GitHub's [private vulnerability reporting](https://github.com/digst/oiosaml-java-spring/security/advisories/new)
("Report a vulnerability" under the repository's *Security* tab).

Include what you found, how to reproduce it, and the affected commit. We aim to acknowledge
reports within a few working days.

## Scope

In scope: the code in this repository, notably the SAML response handling in
`EncryptedAssertionDecryptingConverter` and the security configuration in `SamlSecurityConfig`.

Out of scope: the bundled demo keystores and their passwords (`keystore.p12` is published
deliberately for the NemLog-in DevTest4 test environment and is not trusted anywhere else,
`tls.p12` is a self-signed localhost certificate), and vulnerabilities in
Spring Security or OpenSAML — report those upstream.
