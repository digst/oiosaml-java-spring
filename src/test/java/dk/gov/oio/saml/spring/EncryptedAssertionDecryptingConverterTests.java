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
import java.time.Duration;
import java.time.Instant;

import javax.xml.namespace.QName;

import net.shibboleth.shared.xml.SerializeSupport;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.authentication.AuthenticationConverter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Reproduces the NemLog-in shape - an unsigned {@code <Response>} wrapping an
 * {@code <EncryptedAssertion>} whose assertion is signed - and shows that Spring Security accepts it
 * only when {@link EncryptedAssertionDecryptingConverter} decrypts it first.
 */
class EncryptedAssertionDecryptingConverterTests {

    private static final String SP_ENTITY_ID = "https://saml.oiosaml3-spring-demo";

    private static final String ACS = "https://localhost:8443/saml2/login";

    private static final String IDP_ENTITY_ID = "https://saml.test-devtest4-nemlog-in.dk";

    private static final String NAME_ID = "https://data.gov.dk/model/core/eid/person/uuid/1234";

    private static PrivateKey privateKey;

    private static X509Certificate certificate;

    @BeforeAll
    static void loadKeyMaterial() throws Exception {
        OpenSamlInitializationService.initialize();
        var password = "dYTEc;Gc1ut:".toCharArray();
        var keyStore = KeyStore.getInstance("PKCS12");
        try (var store = new ClassPathResource("keystore.p12").getInputStream()) {
            keyStore.load(store, password);
        }
        privateKey = (PrivateKey) keyStore.getKey("oiosaml.java sp and wsc", password);
        certificate = (X509Certificate) keyStore.getCertificate("oiosaml.java sp and wsc");
    }

    @Test
    void authenticatesWhenAssertionIsDecryptedBeforeTheProvider() {
        var token = token();
        // A lambda has no standalone type, so `delegate` cannot be a var.
        AuthenticationConverter delegate = (request) -> token;
        var converted = new EncryptedAssertionDecryptingConverter(delegate).convert(null);

        var authentication = new OpenSaml5AuthenticationProvider().authenticate(converted);

        assertThat(authentication.getName()).isEqualTo(NAME_ID);
    }

    @Test
    void providerAloneRejectsTheEncryptedAssertionOfAnUnsignedResponse() {
        assertThatExceptionOfType(Saml2AuthenticationException.class)
            .isThrownBy(() -> new OpenSaml5AuthenticationProvider().authenticate(token()))
            .withMessageContaining("since it is not signed");
    }

    private Saml2AuthenticationToken token() {
        var registration = RelyingPartyRegistration.withRegistrationId("nemlogin")
            .entityId(SP_ENTITY_ID)
            .assertionConsumerServiceLocation(ACS)
            .decryptionX509Credentials((credentials) -> credentials
                .add(Saml2X509Credential.decryption(privateKey, certificate)))
            .assertingPartyMetadata((party) -> party
                .entityId(IDP_ENTITY_ID)
                .singleSignOnServiceLocation("https://test-devtest4-nemlog-in.dk/idp/saml/3.0/")
                .verificationX509Credentials(
                        (credentials) -> credentials.add(Saml2X509Credential.verification(certificate))))
            .build();
        return new Saml2AuthenticationToken(registration, serializedResponse());
    }

    private String serializedResponse() {
        try {
            Response response = build(Response.DEFAULT_ELEMENT_NAME);
            response.setID("_response");
            response.setIssueInstant(Instant.now());
            response.setDestination(ACS);
            response.setIssuer(issuer());
            response.setStatus(successStatus());
            response.getEncryptedAssertions().add(encrypt(signedAssertion()));
            return SerializeSupport.nodeToString(XMLObjectSupport.marshall(response));
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private Assertion signedAssertion() throws Exception {
        var now = Instant.now();
        Assertion assertion = build(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.setID("_assertion");
        assertion.setIssueInstant(now);
        assertion.setIssuer(issuer());
        assertion.setSubject(subject(now));
        assertion.setConditions(conditions(now));
        assertion.getAuthnStatements().add(authnStatement(now));

        Signature signature = build(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(new BasicX509Credential(certificate, privateKey));
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        assertion.setSignature(signature);
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        Signer.signObject(signature);
        return assertion;
    }

    private EncryptedAssertion encrypt(Assertion assertion) throws Exception {
        var dataParameters = new DataEncryptionParameters();
        dataParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);
        var keyParameters = new KeyEncryptionParameters();
        keyParameters.setEncryptionCredential(new BasicX509Credential(certificate));
        keyParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        var encrypter = new Encrypter(dataParameters, keyParameters);
        encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);
        return encrypter.encrypt(assertion);
    }

    private Issuer issuer() {
        Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(IDP_ENTITY_ID);
        return issuer;
    }

    private Status successStatus() {
        StatusCode code = build(StatusCode.DEFAULT_ELEMENT_NAME);
        code.setValue(StatusCode.SUCCESS);
        Status status = build(Status.DEFAULT_ELEMENT_NAME);
        status.setStatusCode(code);
        return status;
    }

    private Subject subject(Instant now) {
        NameID nameId = build(NameID.DEFAULT_ELEMENT_NAME);
        nameId.setValue(NAME_ID);
        nameId.setFormat(NameID.PERSISTENT);
        SubjectConfirmationData data = build(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        data.setRecipient(ACS);
        data.setNotOnOrAfter(now.plus(Duration.ofMinutes(5)));
        SubjectConfirmation confirmation = build(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        confirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        confirmation.setSubjectConfirmationData(data);
        Subject subject = build(Subject.DEFAULT_ELEMENT_NAME);
        subject.setNameID(nameId);
        subject.getSubjectConfirmations().add(confirmation);
        return subject;
    }

    private Conditions conditions(Instant now) {
        Audience audience = build(Audience.DEFAULT_ELEMENT_NAME);
        audience.setURI(SP_ENTITY_ID);
        AudienceRestriction restriction = build(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        restriction.getAudiences().add(audience);
        Conditions conditions = build(Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore(now.minus(Duration.ofMinutes(5)));
        conditions.setNotOnOrAfter(now.plus(Duration.ofMinutes(5)));
        conditions.getAudienceRestrictions().add(restriction);
        return conditions;
    }

    private AuthnStatement authnStatement(Instant now) {
        AuthnContextClassRef classRef = build(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        classRef.setURI("https://data.gov.dk/concept/core/nsis/loa/Substantial");
        AuthnContext context = build(AuthnContext.DEFAULT_ELEMENT_NAME);
        context.setAuthnContextClassRef(classRef);
        AuthnStatement statement = build(AuthnStatement.DEFAULT_ELEMENT_NAME);
        statement.setAuthnInstant(now);
        statement.setSessionIndex("_session");
        statement.setAuthnContext(context);
        return statement;
    }

    /**
     * Locals assigned from this helper keep an explicit type: {@code var} would infer {@code T} as
     * {@link XMLObject} and lose the SAML API.
     */
    @SuppressWarnings("unchecked")
    private static <T extends XMLObject> T build(QName elementName) {
        return (T) XMLObjectSupport.buildXMLObject(elementName);
    }
}
