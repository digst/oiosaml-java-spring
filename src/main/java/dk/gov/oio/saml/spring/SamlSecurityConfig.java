/*
 * Copyright 2026 Digitaliseringsstyrelsen (Danish Agency for Digital Government)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dk.gov.oio.saml.spring;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.jspecify.annotations.NonNull;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.metadata.OpenSaml5MetadataResolver;
import org.springframework.security.saml2.provider.service.web.metadata.RequestMatcherMetadataResponseResolver;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.OpenSaml5AuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml5AuthenticationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

@Configuration
@EnableWebSecurity
public class SamlSecurityConfig {

    private static final String NSIS_LOA_PREFIX = "https://data.gov.dk/concept/core/nsis/loa/";

    /**
     * Assertion consumer service and single logout service paths, as published in the SP metadata.
     * Spring Security's default ACS path carries the registration id
     * ({@code /login/saml2/sso/{registrationId}}); these do not.
     */
    private static final String ACS_PATH = "/saml2/login";

    private static final String SLO_PATH = "/saml2/logout";

    /**
     * Spring Security needs an id for the relying party registration, but with fixed endpoint paths it no
     * longer appears in any URL published to NemLog-in - only in the internal
     * {@code /saml2/authenticate?registrationId=...} redirect and the optional
     * {@code /saml2/metadata/{registrationId}} alias.
     */
    private static final String REGISTRATION_ID = "nemlogin";

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrations(Properties properties) throws Exception {
        var credential = credential(properties);
        try (var metadata = new ClassPathResource(properties.idpMetadata()).getInputStream()) {
            var registration = RelyingPartyRegistrations.fromMetadata(metadata)
                    .registrationId(REGISTRATION_ID)
                    .entityId(properties.entityId())
                    .assertionConsumerServiceLocation(properties.baseUrl() + ACS_PATH)
                    .singleLogoutServiceLocation(properties.baseUrl() + SLO_PATH)
                    .singleLogoutServiceResponseLocation(properties.baseUrl() + SLO_PATH)
                    // NemLog-in sends the LogoutRequest over either binding; the default accepts POST only.
                    .singleLogoutServiceBindings((bindings) -> {
                        bindings.add(Saml2MessageBinding.REDIRECT);
                        bindings.add(Saml2MessageBinding.POST);
                    })
                    // OIOSAML 3 uses a persistent NameID; declaring it also puts a NameIDPolicy on the AuthnRequest.
                    .nameIdFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
                    .signingX509Credentials((credentials) -> credentials.add(credential))
                    .decryptionX509Credentials((credentials) -> credentials.add(credential))
                    .build();
            return new InMemoryRelyingPartyRegistrationRepository(registration);
        }
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, RelyingPartyRegistrationRepository registrations, Properties properties) {
        http
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/", "/error", "/saml2/**").permitAll()
                        .anyRequest().authenticated())
                .saml2Login((saml2) -> saml2
                        .loginProcessingUrl(ACS_PATH)
                        .authenticationConverter(getEncryptedAssertionDecryptingConverter(registrations))
                        .authenticationRequestResolver(getAssuranceLevelAuthenticationRequestResolver(registrations, properties)))
                .saml2Logout((saml2) -> saml2
                        .logoutRequest((request) -> request.logoutUrl(SLO_PATH))
                        .logoutResponse((response) -> response.logoutUrl(SLO_PATH)))
                // Saml2LogoutConfigurer picks up this handler for the LogoutResponse from NemLog-in;
                // without it the user ends on Spring Security's generated /login?logout page.
                .logout((logout) -> logout.logoutSuccessUrl("/"))
                .saml2Metadata((metadata) -> metadata.metadataResponseResolver(
                        new RequestMatcherMetadataResponseResolver(registrations, metadataResolver())));
        return http.build();
    }

    private static @NonNull OpenSaml5AuthenticationRequestResolver getAssuranceLevelAuthenticationRequestResolver(RelyingPartyRegistrationRepository registrations, Properties properties) {
        // NemLog-in requires the requested NSIS level of assurance on the AuthnRequest, and reads the
        // signing order from its own <nl:SigningContext> extension.
        var authenticationRequestResolver =
                new OpenSaml5AuthenticationRequestResolver(new DefaultRelyingPartyRegistrationResolver(registrations));
        authenticationRequestResolver.setAuthnRequestCustomizer((context) -> {
            var authnRequest = context.getAuthnRequest();
            authnRequest.setRequestedAuthnContext(requestedAuthnContext(properties.nsisLevel()));
        });
        return authenticationRequestResolver;
    }

    private static @NonNull EncryptedAssertionDecryptingConverter getEncryptedAssertionDecryptingConverter(RelyingPartyRegistrationRepository registrations) {
        // Decrypt NemLog-in's EncryptedAssertion before the stock authentication provider runs.
        var converter = new OpenSaml5AuthenticationTokenConverter(registrations);
        // Saml2LoginConfigurer only applies loginProcessingUrl to the converter it creates itself.
        converter.setRequestMatcher(pathPattern(ACS_PATH));
        return new EncryptedAssertionDecryptingConverter(converter);
    }

    /**
     * OIOSAML 3 requires the SP to declare that it signs its requests and wants signed assertions.
     */
    private static OpenSaml5MetadataResolver metadataResolver() {
        var metadataResolver = new OpenSaml5MetadataResolver();
        metadataResolver.setEntityDescriptorCustomizer((parameters) -> {
            var descriptor = parameters.getEntityDescriptor().getSPSSODescriptor(SAMLConstants.SAML20P_NS);
            descriptor.setAuthnRequestsSigned(true);
            descriptor.setWantAssertionsSigned(true);
        });
        return metadataResolver;
    }

    private static RequestedAuthnContext requestedAuthnContext(String nsisLevel) {
        var classRef =
                (AuthnContextClassRef) XMLObjectSupport.buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        classRef.setURI(NSIS_LOA_PREFIX + nsisLevel);
        var requestedAuthnContext =
                (RequestedAuthnContext) XMLObjectSupport.buildXMLObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
        requestedAuthnContext.getAuthnContextClassRefs().add(classRef);
        return requestedAuthnContext;
    }

    private static Saml2X509Credential credential(Properties properties) throws Exception {
        var password = properties.keystorePassword().toCharArray();
        var keyStore = KeyStore.getInstance("PKCS12");
        try (var store = new ClassPathResource(properties.keystore()).getInputStream()) {
            keyStore.load(store, password);
        }
        var privateKey = (PrivateKey) keyStore.getKey(properties.keystoreAlias(), password);
        var certificate = (X509Certificate) keyStore.getCertificate(properties.keystoreAlias());
        return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING,
                Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);
    }

}

