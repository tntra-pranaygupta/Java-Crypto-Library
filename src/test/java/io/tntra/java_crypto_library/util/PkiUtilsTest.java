//package io.tntra.java_crypto_library.util;
//
//import io.tntra.java_crypto_library.exception.CryptoException;
//import org.bouncycastle.asn1.x500.X500Name;
//import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
//import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
//import org.junit.jupiter.api.*;
//import org.junit.jupiter.params.ParameterizedTest;
//import org.junit.jupiter.params.provider.NullAndEmptySource;
//import org.junit.jupiter.params.provider.ValueSource;
//
//import java.math.BigInteger;
//import java.security.*;
//import java.security.cert.X509Certificate;
//import java.time.Instant;
//import java.time.temporal.ChronoUnit;
//import java.util.Base64;
//import java.util.Date;
//
//import static org.assertj.core.api.Assertions.*;
//
///**
// * Unit tests for {@link PkiUtils}.
// *
// * <p>Self-signed certificates are generated inline using Bouncy Castle so no
// * external keystores or fixtures are required.</p>
// */
//@DisplayName("PkiUtils")
//class PkiUtilsTest {
//
//    private PkiUtils pkiUtils;
//
//    @BeforeAll
//    static void registerProvider() {
//        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
//            Security.addProvider(new BouncyCastleProvider());
//        }
//    }
//
//    @BeforeEach
//    void setUp() {
//        pkiUtils = new PkiUtils();
//    }
//
//    // =========================================================================
//    // generateKeyPair()
//    // =========================================================================
//    @Nested
//    @DisplayName("generateKeyPair()")
//    class GenerateKeyPair {
//
//        @Test
//        @DisplayName("returns a non-null RSA key pair")
//        void notNull() {
//            var kp = pkiUtils.generateKeyPair();
//            assertThat(kp).isNotNull();
//            assertThat(kp.getPublic()).isNotNull();
//            assertThat(kp.getPrivate()).isNotNull();
//        }
//
//        @Test
//        @DisplayName("returns RSA algorithm for both keys")
//        void algorithm() {
//            var kp = pkiUtils.generateKeyPair();
//            assertThat(kp.getPublic().getAlgorithm()).isEqualTo("RSA");
//            assertThat(kp.getPrivate().getAlgorithm()).isEqualTo("RSA");
//        }
//
//        @Test
//        @DisplayName("each call returns a distinct key pair")
//        void uniqueness() {
//            assertThat(pkiUtils.generateKeyPair().getPublic().getEncoded())
//                    .isNotEqualTo(pkiUtils.generateKeyPair().getPublic().getEncoded());
//        }
//    }
//
//    // =========================================================================
//    // loadCertificate()
//    // =========================================================================
//    @Nested
//    @DisplayName("loadCertificate()")
//    class LoadCertificate {
//
//        @Test
//        @DisplayName("loads a valid PEM certificate")
//        void validPem() throws Exception {
//            var pem  = toPem(selfSigned(yesterday(), tomorrow()));
//            var cert = pkiUtils.loadCertificate(pem);
//            assertThat(cert).isNotNull();
//            assertThat(cert.getSubjectX500Principal().getName()).contains("CN=test");
//        }
//
//        @Test
//        @DisplayName("loads a Base64-encoded DER certificate")
//        void base64Der() throws Exception {
//            var original = selfSigned(yesterday(), tomorrow());
//            var b64Der   = Base64.getEncoder().encodeToString(original.getEncoded());
//            var loaded   = pkiUtils.loadCertificate(b64Der);
//            assertThat(loaded.getSerialNumber()).isEqualTo(original.getSerialNumber());
//        }
//
//        @ParameterizedTest
//        @NullAndEmptySource
//        @ValueSource(strings = {"   "})
//        @DisplayName("throws PkiException for null/blank source")
//        void nullOrBlank(String src) {
//            assertThatThrownBy(() -> pkiUtils.loadCertificate(src))
//                    .isInstanceOf(CryptoException.PkiException.class)
//                    .hasMessageContaining("Certificate source must not be null or blank");
//        }
//
//        @Test
//        @DisplayName("throws PkiException for invalid certificate data")
//        void invalid() {
//            assertThatThrownBy(() -> pkiUtils.loadCertificate("not-a-certificate"))
//                    .isInstanceOf(CryptoException.PkiException.class);
//        }
//    }
//
//    // =========================================================================
//    // validateCertificate()
//    // =========================================================================
//    @Nested
//    @DisplayName("validateCertificate()")
//    class ValidateCertificate {
//
//        @Test
//        @DisplayName("returns true for a currently valid certificate")
//        void currentlyValid() throws Exception {
//            assertThat(pkiUtils.validateCertificate(selfSigned(yesterday(), tomorrow()))).isTrue();
//        }
//
//        @Test
//        @DisplayName("returns false for an expired certificate")
//        void expired() throws Exception {
//            var notBefore = Date.from(Instant.now().minus(2, ChronoUnit.DAYS));
//            var notAfter  = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
//            assertThat(pkiUtils.validateCertificate(selfSigned(notBefore, notAfter))).isFalse();
//        }
//
//        @Test
//        @DisplayName("returns false for a not-yet-valid certificate")
//        void notYetValid() throws Exception {
//            var notBefore = Date.from(Instant.now().plus(1, ChronoUnit.DAYS));
//            var notAfter  = Date.from(Instant.now().plus(2, ChronoUnit.DAYS));
//            assertThat(pkiUtils.validateCertificate(selfSigned(notBefore, notAfter))).isFalse();
//        }
//
//        @Test
//        @DisplayName("throws PkiException for null certificate")
//        void nullCert() {
//            assertThatThrownBy(() -> pkiUtils.validateCertificate(null))
//                    .isInstanceOf(CryptoException.PkiException.class)
//                    .hasMessageContaining("Certificate must not be null");
//        }
//    }
//
//    // =========================================================================
//    // Test helpers
//    // =========================================================================
//
//    private static Date yesterday() {
//        return Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
//    }
//
//    private static Date tomorrow() {
//        return Date.from(Instant.now().plus(1, ChronoUnit.DAYS));
//    }
//
//    /** Generates a minimal self-signed RSA-2048 X.509 certificate. */
//    private static X509Certificate selfSigned(Date notBefore, Date notAfter) throws Exception {
//        var kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
//        kpg.initialize(2048);
//        var kp = kpg.generateKeyPair();
//
//        var subject     = new X500Name("CN=test");
//        var certBuilder = new JcaX509v3CertificateBuilder(
//                subject,
//                BigInteger.valueOf(Instant.now().toEpochMilli()),
//                notBefore, notAfter,
//                subject,
//                kp.getPublic());
//
//        var signer = new JcaContentSignerBuilder("SHA256WithRSA")
//                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
//                .build(kp.getPrivate());
//
//        return new JcaX509CertificateConverter()
//                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
//                .getCertificate(certBuilder.build(signer));
//    }
//
//    /** Encodes an X.509 certificate as a PEM string. */
//    private static String toPem(X509Certificate cert) throws Exception {
//        return """
//               -----BEGIN CERTIFICATE-----
//               %s
//               -----END CERTIFICATE-----
//               """.formatted(
//                Base64.getMimeEncoder(64, new byte[]{'\n'})
//                        .encodeToString(cert.getEncoded()));
//    }
//}
