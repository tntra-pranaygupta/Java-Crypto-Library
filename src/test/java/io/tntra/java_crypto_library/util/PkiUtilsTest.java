package io.tntra.java_crypto_library.util;

import io.tntra.java_crypto_library.exception.CryptoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.*;

import static org.junit.jupiter.api.Assertions.*;

class PkiUtilsTest {

    private PkiUtils pkiUtils;

    // Valid certificate from your application.yml
    private static final String VALID_CERT = """
-----BEGIN CERTIFICATE-----
MIIDQzCCAiugAwIBAgIUaLj6rlHU5Z9SLe82Sj0lbAT+frswDQYJKoZIhvcNAQEL
BQAwMTEUMBIGA1UEAwwLcG9jLXNlcnZpY2UxDDAKBgNVBAoMA1BPQzELMAkGA1UE
BhMCVVMwHhcNMjYwMzA1MDcxODAwWhcNMjcwMzA1MDcxODAwWjAxMRQwEgYDVQQD
DAtwb2Mtc2VydmljZTEMMAoGA1UECgwDUE9DMQswCQYDVQQGEwJVUzCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAM2naVv+Tqo7u3Y1n3Bq3/98z3Gg9tUH
HsNiNVUdPR0FAw++NdJ26qtzj6A71z96f0G9BgiiaSbOOtDlulEqpWxDe9iPMjhN
Q3i3Y+0lK/RB4aY7lZ/Z43Yg/n8VLvKkbUoa4RdRiwu8pMIurbSKhuULdt/ifoGR
CxrJelLA2VLiveKFJAvr02ehhFEF+W9r6OmejHkfs6Rf1AHBy1Y6kIkUzDegJVeu
jtCCxF4FnjwpgrhM3JbvGBi+ZbghMNLbM3laKyrmlbNsRHjd7c7dFPuCFhfIIaLm
sdByVZaqyf3etsMKqsnfuXPUZF0EVYrP+cRFuB3SYSPAcP3iIxmaghMCAwEAAaNT
MFEwHQYDVR0OBBYEFAwZrGv4dXGguIU+ODoKwJalUQBoMB8GA1UdIwQYMBaAFAwZ
rGv4dXGguIU+ODoKwJalUQBoMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAIkJGC5N4JbE2mreDhT9Z34KpdtrHIaRqSdSkJzdoBuhSqKGuLVvHHPc
zeMafrDO2I2EKkCBT+Kmt3759Ns9SkAFkmJSxPKD82SzNatPinzdnjrVAAYIxiIh
ZXzeZMgqBlLtO3nu3mEQb9SEeVTWWd1HvfoLX+JziqQqOoaou1vThfK3QnW7tTMs
8aRzYWRXZSTqX0pPcHo153vySetIAkYxqDgBZa2b4TO/La1ZDG/yGOliHdJQeLCS
qv5L9t9npFnKXHyFgIdh13cW+Bvn1sOkEApq6p9C80iVGJBvk8sGw9ZgvF9MFsIS
HSdSbFMum2GBaaQKyyGiFgyDK6synjs=
-----END CERTIFICATE-----
""";

    @BeforeEach
    void setup() {
        pkiUtils = new PkiUtils();
    }

    /** Loads a PEM-formatted certificate successfully */
    @Test
    void loadPemCertificateTest() {

        X509Certificate cert = pkiUtils.loadCertificate(VALID_CERT);

        assertNotNull(cert);
        assertNotNull(cert.getSubjectX500Principal());
    }

    /** Loads a Base64 DER certificate string successfully */
    @Test
    void loadBase64DerCertificateTest() {

        String base64 = VALID_CERT
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");

        X509Certificate cert = pkiUtils.loadCertificate(base64);

        assertNotNull(cert);
    }

    /** Throws when certificate source is null */
    @Test
    void loadCertificateNullSourceTest() {

        CryptoException.PkiException ex =
                assertThrows(CryptoException.PkiException.class,
                        () -> pkiUtils.loadCertificate(null));

        assertEquals("Certificate source must not be null or blank", ex.getMessage());
    }

    /** Throws when certificate data is invalid */
    @Test
    void loadCertificateInvalidTest() {

        CryptoException.PkiException ex =
                assertThrows(CryptoException.PkiException.class,
                        () -> pkiUtils.loadCertificate("invalid-cert"));

        assertEquals("Failed to load certificate", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    /** Returns true for a valid certificate */
    @Test
    void validateCertificateValidTest() {

        X509Certificate cert = pkiUtils.loadCertificate(VALID_CERT);

        boolean valid = pkiUtils.validateCertificate(cert);

        assertTrue(valid);
    }

    /** Throws when validateCertificate is called with null */
    @Test
    void validateCertificateNullTest() {

        assertThrows(NullPointerException.class,
                () -> pkiUtils.validateCertificate(null));
    }

    /** Generates an RSA key pair using the provider */
    @Test
    void generateRsaKeyPairTest() {

        KeyPair keyPair = pkiUtils.generateKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());

        assertEquals("RSA", keyPair.getPrivate().getAlgorithm());
    }

    /** Constructor throws when CertificateFactory initialization fails */
    @Test
    void constructorCertificateFactoryFailTest() {

        try (MockedStatic<CertificateFactory> mocked =
                     Mockito.mockStatic(CertificateFactory.class)) {

            mocked.when(() -> CertificateFactory.getInstance("X.509"))
                    .thenThrow(new CertificateException("factory error"));

            CryptoException.PkiException ex =
                    assertThrows(CryptoException.PkiException.class, PkiUtils::new);

            assertEquals(
                    "Failed to initialise X.509 CertificateFactory",
                    ex.getMessage()
            );
        }
    }

    /** Returns false when certificate is expired */
    @Test
    void validateCertificateExpiredTest() throws Exception {

        PkiUtils utils = new PkiUtils();

        X509Certificate cert = Mockito.mock(X509Certificate.class);

        Mockito.doThrow(new CertificateExpiredException("expired"))
                .when(cert).checkValidity(Mockito.any());

        boolean result = utils.validateCertificate(cert);

        assertFalse(result);
    }

    /** Returns false when certificate is not yet valid (future) */
    @Test
    void validateCertificateNotYetValidTest() throws Exception {

        PkiUtils utils = new PkiUtils();

        X509Certificate cert = Mockito.mock(X509Certificate.class);

        Mockito.doThrow(new CertificateNotYetValidException("future"))
                .when(cert).checkValidity(Mockito.any());

        boolean result = utils.validateCertificate(cert);

        assertFalse(result);
    }

    /** Throws when KeyPairGenerator initialization fails */
    @Test
    void generateKeyPairGeneratorFailTest() {

        try (MockedStatic<KeyPairGenerator> mocked =
                     Mockito.mockStatic(KeyPairGenerator.class)) {

            mocked.when(() -> KeyPairGenerator.getInstance("RSA", "BC"))
                    .thenThrow(new RuntimeException("generator error"));

            PkiUtils utils = new PkiUtils();

            CryptoException.PkiException ex =
                    assertThrows(CryptoException.PkiException.class,
                            utils::generateKeyPair);

            assertEquals("Failed to generate RSA key pair", ex.getMessage());
        }
    }

    /** Throws when loadCertificate is called with null on instance */
    @Test
    void loadCertificateSourceNullTest() {

        PkiUtils utils = new PkiUtils();

        CryptoException.PkiException ex =
                assertThrows(CryptoException.PkiException.class,
                        () -> utils.loadCertificate(null));

        assertEquals(
                "Certificate source must not be null or blank",
                ex.getMessage()
        );
    }

    /** Throws when loadCertificate is called with blank string */
    @Test
    void loadCertificateSourceBlankTest() {

        PkiUtils utils = new PkiUtils();

        CryptoException.PkiException ex =
                assertThrows(CryptoException.PkiException.class,
                        () -> utils.loadCertificate("   "));

        assertEquals(
                "Certificate source must not be null or blank",
                ex.getMessage()
        );
    }
}

