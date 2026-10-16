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

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Settings for the relying party (this SP) and the NemLog-in IdP.
 *
 * @param entityId          the SP entity id registered in the NemLog-in administration portal
 * @param baseUrl           externally reachable base URL of this application
 * @param idpMetadata       classpath location of the NemLog-in IdP metadata
 * @param keystore          classpath location of the PKCS#12 holding the SP's OCES3 certificate
 * @param keystorePassword  password for both the keystore and the private key
 * @param keystoreAlias     alias of the private key entry to use
 * @param nsisLevel         requested NSIS level of assurance: None, Low, Substantial or High
 */
@ConfigurationProperties(prefix = "nemlogin")
public record Properties(
        String entityId,
        String baseUrl,
        String idpMetadata,
        String keystore,
        String keystorePassword,
        String keystoreAlias,
        String nsisLevel) {
}
