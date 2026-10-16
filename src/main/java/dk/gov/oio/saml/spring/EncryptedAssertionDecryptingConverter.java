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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.CollectionKeyInfoCredentialResolver;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * Decrypts the {@code <saml2:EncryptedAssertion>} of an incoming SAML response before Spring
 * Security's authentication provider sees it.
 * <p>
 * NemLog-in encrypts the assertion but leaves the enclosing {@code <saml2p:Response>} unsigned,
 * instead the assertion inside the encrypted blob is signed.
 * {@code BaseOpenSamlAuthenticationProvider} only runs its decrypter when the response itself is
 * signed, and otherwise rejects the response with
 * {@code "Did not decrypt response [...] since it is not signed"}.
 * <p>
 * That branch is private, so no  * combination of its
 * {@code setResponseElementsDecrypter}/{@code setResponseValidator} hooks can
 * make it accept a NemLog-in response.
 * <p>
 * So we decrypt one step earlier - in the {@link AuthenticationConverter} that turns the HTTP request
 * into a {@link Saml2AuthenticationToken} - hands the provider a response whose assertion is
 * already decrypted.
 * <p>
 * The decrypted assertion is placed in a document of its own ({@code rootInNewDocument}) so that it
 * carries its own namespace declarations, and its signature therefore still verifies after the
 * response has been re-serialized.
 */
public final class EncryptedAssertionDecryptingConverter implements AuthenticationConverter {

    static {
        OpenSamlInitializationService.initialize();
    }

    private static final EncryptedKeyResolver ENCRYPTED_KEY_RESOLVER = new ChainingEncryptedKeyResolver(
            Arrays.asList(new InlineEncryptedKeyResolver(), new EncryptedElementTypeEncryptedKeyResolver(),
                    new SimpleRetrievalMethodEncryptedKeyResolver()));

    private final AuthenticationConverter delegate;

    public EncryptedAssertionDecryptingConverter(AuthenticationConverter delegate) {
        this.delegate = delegate;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        var authentication = this.delegate.convert(request);
        if (!(authentication instanceof Saml2AuthenticationToken token)) {
            return authentication;
        }
        var registration = token.getRelyingPartyRegistration();
        var response = token.getSaml2Response();
        var decrypted = decryptAssertions(response, registration);
        if (decrypted.equals(response)) {
            return token;
        }
        return new Saml2AuthenticationToken(registration, decrypted, token.getAuthenticationRequest());
    }

    private String decryptAssertions(String serializedResponse, RelyingPartyRegistration registration) {
        var response = deserialize(serializedResponse);
        if (response.getEncryptedAssertions().isEmpty()) {
            return serializedResponse;
        }
        var decrypter = decrypter(registration);
        var assertions = new ArrayList<Assertion>();
        try {
            for (var encrypted : List.copyOf(response.getEncryptedAssertions())) {
                assertions.add(decrypter.decrypt(encrypted));
            }
        } catch (Exception ex) {
            throw new Saml2AuthenticationException(Saml2Error.decryptionError(ex.getMessage()), ex);
        }
        response.getEncryptedAssertions().clear();
        response.getAssertions().addAll(assertions);
        return serialize(response);
    }

    private static Decrypter decrypter(RelyingPartyRegistration registration) {
        var credentials = new ArrayList<Credential>();
        registration.getDecryptionX509Credentials()
                .forEach((key) -> credentials
                        .add(CredentialSupport.getSimpleCredential(key.getCertificate(), key.getPrivateKey())));
        var resolver = new CollectionKeyInfoCredentialResolver(credentials);
        var decrypter = new Decrypter(null, resolver, ENCRYPTED_KEY_RESOLVER);
        decrypter.setRootInNewDocument(true);
        return decrypter;
    }

    private static Response deserialize(String serializedResponse) {
        var parserPool = XMLObjectProviderRegistrySupport.getParserPool();
        try (var source = new ByteArrayInputStream(serializedResponse.getBytes(StandardCharsets.UTF_8))) {
            return (Response) XMLObjectSupport.unmarshallFromInputStream(parserPool, source);
        } catch (Exception ex) {
            throw new Saml2AuthenticationException(Saml2Error.malformedResponseData(ex.getMessage()), ex);
        }
    }

    private static String serialize(Response response) {
        try {
            var element = XMLObjectSupport.marshall(response);
            return SerializeSupport.nodeToString(element);
        } catch (Exception ex) {
            throw new Saml2AuthenticationException(Saml2Error.internalValidationError(ex.getMessage()), ex);
        }
    }
}
