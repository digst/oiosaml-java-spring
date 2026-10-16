# OIOSAML Spring Security demo SP

[![CI](https://github.com/digst/oiosaml-java-spring/actions/workflows/ci.yml/badge.svg)](https://github.com/digst/oiosaml-java-spring/actions/workflows/ci.yml)
[![CodeQL](https://github.com/digst/oiosaml-java-spring/actions/workflows/codeql.yml/badge.svg)](https://github.com/digst/oiosaml-java-spring/actions/workflows/codeql.yml)

A minimal SAML 2.0 Service Provider for the integration test leg of
[NemLog-in DevTest4](https://www.nemlog-in.dk/om-nemlog-in/miljoer-i-nemlog-in/), the pre-production
environment (`https://saml.test-devtest4-nemlog-in.dk`), built on Spring Security's own SAML support.

> **Disclaimer:** this is not a complete example or a production-ready Service Provider. It only shows
> how Spring Security's SAML support can be adapted to work with NemLog-in. Hardening, session
> handling, error handling, logging and certificate management are left to the integrating application.

Java 25, Maven, Spring Boot 4.1.1, Spring Security 7.1 (`spring-security-saml2-service-provider`,
OpenSAML 5), Thymeleaf. OpenSAML 5 is not on Maven Central, so `pom.xml` adds the Shibboleth repository.

## Run

```sh
mvn spring-boot:run
```

Open <https://localhost:8443/secure> and accept the certificate warning. For demo purposes the SP
(entity ID `https://oiosaml.java-spring`) is already registered in the DevTest4 integration test leg,
so login works out of the box.

## Why Spring's defaults are not enough

NemLog-in encrypts the assertion but leaves the enclosing `<saml2p:Response>` unsigned. The
signature is on the assertion inside the encrypted blob. Spring Security's
`BaseOpenSamlAuthenticationProvider` only decrypts when the response itself is signed, in a private
method no hook can reach, so every NemLog-in login with Spring SAML defaults fails with
*"Did not decrypt response […] since it is not signed"*.

`EncryptedAssertionDecryptingConverter` decrypts one step earlier, in the `AuthenticationConverter`,
and hands the provider a response whose assertion is already decrypted. The provider still verifies
the assertion signature against the IdP metadata so no signature check is skipped.
`EncryptedAssertionDecryptingConverterTests` shows the provider rejecting the NemLog-in message shape
alone and accepting it after the converter.

Sample includes copy of own metadata as well as pre-production inttest metadata.

## Endpoints

| URL | Purpose |
| --- | --- |
| `/secure` | protected page, triggers login |
| `/saml2/metadata` | SP metadata |
| `/saml2/login` | assertion consumer service |
| `/saml2/logout` | single logout |
| `/logout` | SP-initiated logout (POST) |

## Notes

- ACS and SLO are moved from Spring's defaults to `/saml2/login` and `/saml2/logout`, so the metadata
  URLs carry no registration id. `SamlSecurityConfig` sets this on the registration, the
  `saml2Login`/`saml2Logout` configurers and the converter's request matcher.
- The `AuthnRequest` is signed with `rsa-sha256` and requests the NSIS level from
  `nemlogin.nsis-level` (`Comparison="minimum"`).
- `/secure` shows the NameID and raw attributes without interpreting them. For a full OIOSAML 3
  profile implementation, see [OIOSAML.Java](https://github.com/digst/OIOSAML.Java).

## License

[Apache License 2.0](LICENSE). Security issues: see [SECURITY.md](SECURITY.md).
