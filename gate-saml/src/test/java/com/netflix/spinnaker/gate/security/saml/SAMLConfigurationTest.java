/*
 * Copyright 2025 Harness, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package com.netflix.spinnaker.gate.security.saml;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

public class SAMLConfigurationTest {

    @Mock
    private SecuritySamlProperties properties;

    private SAMLConfiguration.WebSecurityConfig webSecurityConfig;

    @BeforeEach
    public void setUp() throws GeneralSecurityException, IOException {
        MockitoAnnotations.openMocks(this);

        // Configure the mock SecuritySamlProperties
        when(properties.getMetadataUrl()).thenReturn("classpath:complex-metadata.xml");
        when(properties.getRegistrationId()).thenReturn("test-registration");
        when(properties.getIssuerId()).thenReturn("test-issuer");
        when(properties.getAssertionConsumerServiceLocation()).thenReturn("https://test.acs.location");
        when(properties.isSignRequests()).thenReturn(false);
        when(properties.getDecryptionCredential()).thenReturn(null);
        when(properties.getSigningCredentials()).thenReturn(java.util.Collections.emptyList());

        // Create the configuration instance
        webSecurityConfig = new SAMLConfiguration.WebSecurityConfig(
            properties, null, null, null, null
        );
    }

    @Test
    public void testRelyingPartyRegistrationRepository() throws Exception {
        // When
        RelyingPartyRegistrationRepository repository = webSecurityConfig.relyingPartyRegistrationRepository();
        RelyingPartyRegistration registration = repository.findByRegistrationId("test-registration");

        // Then
        assertNotNull(registration, "RelyingPartyRegistration should not be null");
        assertEquals("test-issuer", registration.getEntityId(), "Entity ID should match configuration");
        assertNotNull(registration.getAssertingPartyDetails(), "Asserting party details should be set");
        assertEquals("https://ida.dummy.com",
                   registration.getAssertingPartyDetails().getEntityId(),
                   "Should parse entity ID from complex metadata");
    }


    @Test
    public void testMetadataFileExists() {
        // Given
        ClassPathResource resource = new ClassPathResource("complex-metadata.xml");

        // Then
        assertTrue(resource.exists(), "Complex metadata file should exist in test resources");
    }    @Test
    public void testMetadataWithoutPrefixes() throws Exception {
        // Given - configure properties for no-prefix metadata
        when(properties.getMetadataUrl()).thenReturn("classpath:idp-metadata-no-prefix.xml");
        when(properties.getRegistrationId()).thenReturn("test-registration-no-prefix");

        // When
        RelyingPartyRegistrationRepository repository = webSecurityConfig.relyingPartyRegistrationRepository();
        RelyingPartyRegistration registration = repository.findByRegistrationId("test-registration-no-prefix");

        // Then
        assertNotNull(registration, "RelyingPartyRegistration should be created from metadata without prefixes");
        assertEquals("https://idp.example.com/no-prefix-metadata",
                   registration.getAssertingPartyDetails().getEntityId(),
                   "Should correctly parse entity ID from metadata without prefixes");

        // Verify SSO endpoints are correctly parsed
        assertFalse(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation().isEmpty(),
                  "Should have SSO location from metadata without prefixes");
        assertTrue(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation()
                   .contains("sso-no-prefix"),
                   "Should use SSO location from metadata without prefixes");
    }

    @Test
    public void testSPSigningDisabled() throws Exception {
        // Given - signing is disabled (default)
        when(properties.isSignRequests()).thenReturn(false);
        when(properties.getSigningCredentials()).thenReturn(java.util.Collections.emptyList());

        // When
        RelyingPartyRegistrationRepository repository = webSecurityConfig.relyingPartyRegistrationRepository();
        RelyingPartyRegistration registration = repository.findByRegistrationId("test-registration");

        // Then
        assertNotNull(registration, "RelyingPartyRegistration should be created");
        assertTrue(registration.getSigningX509Credentials().isEmpty(),
                  "Should have no signing credentials when signing is disabled");
    }

    @Test
    public void testSPSigningEnabled() throws Exception {
        // Given - configure signing to be enabled with mock credentials
        when(properties.isSignRequests()).thenReturn(true);

        // Create a mock signing credential using the test certificate
        org.springframework.security.saml2.core.Saml2X509Credential mockCredential =
            org.springframework.security.saml2.core.Saml2X509Credential.signing(
                loadTestPrivateKey(), loadTestCertificate());

        when(properties.getSigningCredentials()).thenReturn(java.util.List.of(mockCredential));

        // When
        RelyingPartyRegistrationRepository repository = webSecurityConfig.relyingPartyRegistrationRepository();
        RelyingPartyRegistration registration = repository.findByRegistrationId("test-registration");

        // Then
        assertNotNull(registration, "RelyingPartyRegistration should be created");
        assertFalse(registration.getSigningX509Credentials().isEmpty(),
                   "Should have signing credentials when signing is enabled");
        assertEquals(1, registration.getSigningX509Credentials().size(),
                    "Should have exactly one signing credential");

        // Verify the credential is properly configured for signing
        org.springframework.security.saml2.core.Saml2X509Credential credential =
            registration.getSigningX509Credentials().iterator().next();
        assertTrue(credential.isSigningCredential(),
                  "Credential should be configured for signing");
        assertNotNull(credential.getPrivateKey(),
                     "Signing credential should have a private key");
        assertNotNull(credential.getCertificate(),
                     "Signing credential should have a certificate");
    }

    private java.security.PrivateKey loadTestPrivateKey() throws Exception {
        // Load the test private key from resources
        ClassPathResource resource = new ClassPathResource("private_key.pem");
        String keyContent = new String(resource.getInputStream().readAllBytes());

        // Remove PEM headers and decode
        keyContent = keyContent.replace("-----BEGIN PRIVATE KEY-----", "")
                              .replace("-----END PRIVATE KEY-----", "")
                              .replaceAll("\\s", "");

        byte[] keyBytes = java.util.Base64.getDecoder().decode(keyContent);
        java.security.spec.PKCS8EncodedKeySpec keySpec = new java.security.spec.PKCS8EncodedKeySpec(keyBytes);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private java.security.cert.X509Certificate loadTestCertificate() throws Exception {
        // Load the test certificate from resources
        ClassPathResource resource = new ClassPathResource("certificate.pem");
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        return (java.security.cert.X509Certificate) cf.generateCertificate(resource.getInputStream());
    }

    @Test
    public void testSPSigningWithPrefixedMetadata() throws Exception {
        // Given - configure signing enabled with prefixed metadata
        when(properties.getMetadataUrl()).thenReturn("classpath:idp-metadata.xml");
        when(properties.getRegistrationId()).thenReturn("test-registration-prefixed");
        when(properties.isSignRequests()).thenReturn(true);

        // Create signing credential
        org.springframework.security.saml2.core.Saml2X509Credential mockCredential =
            org.springframework.security.saml2.core.Saml2X509Credential.signing(
                loadTestPrivateKey(), loadTestCertificate());
        when(properties.getSigningCredentials()).thenReturn(java.util.List.of(mockCredential));

        // When
        RelyingPartyRegistrationRepository repository = webSecurityConfig.relyingPartyRegistrationRepository();
        RelyingPartyRegistration registration = repository.findByRegistrationId("test-registration-prefixed");

        // Then
        assertNotNull(registration, "RelyingPartyRegistration should be created with prefixed metadata");

        // Verify IdP metadata was parsed correctly (prefixed metadata)
        assertEquals("https://idp.example.com/metadata",
                   registration.getAssertingPartyDetails().getEntityId(),
                   "Should correctly parse entity ID from prefixed metadata");

        // Verify SP signing is configured
        assertFalse(registration.getSigningX509Credentials().isEmpty(),
                   "Should have signing credentials when signing is enabled with prefixed metadata");
        assertEquals(1, registration.getSigningX509Credentials().size(),
                    "Should have exactly one signing credential with prefixed metadata");

        // Verify the credential works with prefixed metadata
        org.springframework.security.saml2.core.Saml2X509Credential credential =
            registration.getSigningX509Credentials().iterator().next();
        assertTrue(credential.isSigningCredential(),
                  "Credential should be configured for signing with prefixed metadata");
        assertEquals("CN=Spinnaker", credential.getCertificate().getSubjectX500Principal().getName(),
                    "Should have correct certificate subject with prefixed metadata");
    }

    @Test
    public void testSPSigningWithNonPrefixedMetadata() throws Exception {
        // Given - configure signing enabled with non-prefixed metadata
        when(properties.getMetadataUrl()).thenReturn("classpath:idp-metadata-no-prefix.xml");
        when(properties.getRegistrationId()).thenReturn("test-registration-no-prefix");
        when(properties.isSignRequests()).thenReturn(true);

        // Create signing credential
        org.springframework.security.saml2.core.Saml2X509Credential mockCredential =
            org.springframework.security.saml2.core.Saml2X509Credential.signing(
                loadTestPrivateKey(), loadTestCertificate());
        when(properties.getSigningCredentials()).thenReturn(java.util.List.of(mockCredential));

        // When
        RelyingPartyRegistrationRepository repository = webSecurityConfig.relyingPartyRegistrationRepository();
        RelyingPartyRegistration registration = repository.findByRegistrationId("test-registration-no-prefix");

        // Then
        assertNotNull(registration, "RelyingPartyRegistration should be created with non-prefixed metadata");

        // Verify IdP metadata was parsed correctly (non-prefixed metadata)
        assertEquals("https://idp.example.com/no-prefix-metadata",
                   registration.getAssertingPartyDetails().getEntityId(),
                   "Should correctly parse entity ID from non-prefixed metadata");

        // Verify SP signing is configured
        assertFalse(registration.getSigningX509Credentials().isEmpty(),
                   "Should have signing credentials when signing is enabled with non-prefixed metadata");
        assertEquals(1, registration.getSigningX509Credentials().size(),
                    "Should have exactly one signing credential with non-prefixed metadata");

        // Verify the credential works with non-prefixed metadata
        org.springframework.security.saml2.core.Saml2X509Credential credential =
            registration.getSigningX509Credentials().iterator().next();
        assertTrue(credential.isSigningCredential(),
                  "Credential should be configured for signing with non-prefixed metadata");
        assertEquals("CN=Spinnaker", credential.getCertificate().getSubjectX500Principal().getName(),
                    "Should have correct certificate subject with non-prefixed metadata");
    }

    @Test
    public void testSPSigningConsistencyBetweenMetadataFormats() throws Exception {
        // This test verifies that SP signing behavior is consistent regardless of metadata namespace prefixes

        // Test with prefixed metadata
        when(properties.getMetadataUrl()).thenReturn("classpath:idp-metadata.xml");
        when(properties.getRegistrationId()).thenReturn("test-prefixed");
        when(properties.isSignRequests()).thenReturn(true);

        org.springframework.security.saml2.core.Saml2X509Credential mockCredential =
            org.springframework.security.saml2.core.Saml2X509Credential.signing(
                loadTestPrivateKey(), loadTestCertificate());
        when(properties.getSigningCredentials()).thenReturn(java.util.List.of(mockCredential));

        RelyingPartyRegistrationRepository prefixedRepo = webSecurityConfig.relyingPartyRegistrationRepository();
        RelyingPartyRegistration prefixedRegistration = prefixedRepo.findByRegistrationId("test-prefixed");

        // Test with non-prefixed metadata
        when(properties.getMetadataUrl()).thenReturn("classpath:idp-metadata-no-prefix.xml");
        when(properties.getRegistrationId()).thenReturn("test-no-prefix");

        RelyingPartyRegistrationRepository noPrefixRepo = webSecurityConfig.relyingPartyRegistrationRepository();
        RelyingPartyRegistration noPrefixRegistration = noPrefixRepo.findByRegistrationId("test-no-prefix");

        // Verify both configurations have identical signing setup
        assertEquals(prefixedRegistration.getSigningX509Credentials().size(),
                    noPrefixRegistration.getSigningX509Credentials().size(),
                    "Both metadata formats should result in same number of signing credentials");

        // Verify both have signing enabled
        assertFalse(prefixedRegistration.getSigningX509Credentials().isEmpty(),
                   "Prefixed metadata should have signing credentials");
        assertFalse(noPrefixRegistration.getSigningX509Credentials().isEmpty(),
                   "Non-prefixed metadata should have signing credentials");

        // Verify certificate subjects are identical
        String prefixedSubject = prefixedRegistration.getSigningX509Credentials()
            .iterator().next().getCertificate().getSubjectX500Principal().getName();
        String noPrefixSubject = noPrefixRegistration.getSigningX509Credentials()
            .iterator().next().getCertificate().getSubjectX500Principal().getName();

        assertEquals(prefixedSubject, noPrefixSubject,
                    "Certificate subjects should be identical regardless of metadata namespace prefixes");
    }

    public void testAssertionSignatureVerificationConfiguration() throws Exception {
        // Given - configure for assertion signature verification
        when(properties.getMetadataUrl()).thenReturn("classpath:complex-metadata.xml");
        when(properties.getRegistrationId()).thenReturn("test-assertion-verification");
        when(properties.isSignRequests()).thenReturn(false); // Focus on assertion verification

        // When
        RelyingPartyRegistrationRepository repository = webSecurityConfig.relyingPartyRegistrationRepository();
        RelyingPartyRegistration registration = repository.findByRegistrationId("test-assertion-verification");

        // Then - Verify IdP verification certificates are configured
        assertNotNull(registration, "RelyingPartyRegistration should be created");
        assertNotNull(registration.getAssertingPartyDetails(), "Asserting party details should be set");

        // Verify IdP verification certificates from metadata are available
        assertFalse(registration.getAssertingPartyDetails().getVerificationX509Credentials().isEmpty(),
                   "Should have verification credentials from IdP metadata for assertion signature verification");

        // Verify the verification credential is properly configured
        org.springframework.security.saml2.core.Saml2X509Credential verificationCredential =
            registration.getAssertingPartyDetails().getVerificationX509Credentials().iterator().next();
        assertTrue(verificationCredential.isVerificationCredential(),
                  "Credential should be configured for verification");
        assertNotNull(verificationCredential.getCertificate(),
                     "Verification credential should have a certificate");
        assertEquals("CN=Spinnaker", verificationCredential.getCertificate().getSubjectX500Principal().getName(),
                     "Should have correct certificate subject for verification");
    }

    @Test
    public void testSPSigningOnlyConfiguration() throws Exception {
        // This test verifies SP signing configuration in isolation
        // Note: IdP verification certificates are still loaded from metadata, but we focus on SP signing

        // Given - configure only SP signing, no explicit verification setup
        when(properties.getMetadataUrl()).thenReturn("classpath:complex-metadata.xml");
        when(properties.getRegistrationId()).thenReturn("test-sp-signing-only");
        when(properties.isSignRequests()).thenReturn(true); // Enable SP request signing

        // Create ONLY SP signing credential (no separate verification credential setup)
        org.springframework.security.saml2.core.Saml2X509Credential spSigningCredential =
            org.springframework.security.saml2.core.Saml2X509Credential.signing(
                loadTestPrivateKey(), loadTestCertificate());
        when(properties.getSigningCredentials()).thenReturn(java.util.List.of(spSigningCredential));

        // When
        RelyingPartyRegistrationRepository repository = webSecurityConfig.relyingPartyRegistrationRepository();
        RelyingPartyRegistration registration = repository.findByRegistrationId("test-sp-signing-only");

        // Then - Verify SP signing is configured
        assertNotNull(registration, "RelyingPartyRegistration should be created");

        // Verify SP has signing credentials for outgoing requests
        assertFalse(registration.getSigningX509Credentials().isEmpty(),
                   "Should have SP signing credentials for request signing");
        assertEquals(1, registration.getSigningX509Credentials().size(),
                    "Should have exactly one SP signing credential");

        // Verify SP signing credential is properly configured
        org.springframework.security.saml2.core.Saml2X509Credential actualSpCredential =
            registration.getSigningX509Credentials().iterator().next();
        assertTrue(actualSpCredential.isSigningCredential(),
                  "SP credential should be configured for signing requests");
        assertNotNull(actualSpCredential.getPrivateKey(),
                     "SP signing credential should have private key for signing");
        assertNotNull(actualSpCredential.getCertificate(),
                     "SP signing credential should have certificate");

        // Verify IdP verification certificates are STILL loaded from metadata
        // (This is automatic when parsing IdP metadata - we can't prevent it)
        assertFalse(registration.getAssertingPartyDetails().getVerificationX509Credentials().isEmpty(),
                   "IdP verification credentials are automatically loaded from metadata");

        // Verify the SP and IdP credentials are distinct in purpose
        org.springframework.security.saml2.core.Saml2X509Credential idpVerificationCredential =
            registration.getAssertingPartyDetails().getVerificationX509Credentials().iterator().next();
        assertTrue(idpVerificationCredential.isVerificationCredential(),
                  "IdP credential should be configured for verification only");
        assertNull(idpVerificationCredential.getPrivateKey(),
                  "IdP verification credential should NOT have private key");

        // Verify SP signing credential has private key but IdP verification doesn't
        assertNotNull(actualSpCredential.getPrivateKey(),
                     "SP signing credential should have private key");
        assertNull(idpVerificationCredential.getPrivateKey(),
                  "IdP verification credential should not have private key");
    }

}
