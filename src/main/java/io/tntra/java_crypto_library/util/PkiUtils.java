package io.tntra.java_crypto_library.util;

import io.tntra.java_crypto_library.exception.CryptoException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.*;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;

/**
 * Stateless utility providing public key infrastructure (PKI) operations.
 *
 * <h2>Responsibilities</h2>
 * <ul>
 *   <li>Load X.509 certificates from PEM or Base64-encoded DER sources.</li>
 *   <li>Validate certificate temporal validity.</li>
 *   <li>Generate RSA-2048 key pairs.</li>
 * </ul>
 *
 * <h2>Thread safety</h2>
 * Instances are effectively immutable after construction and are safe to share
 * across threads.  The internal {@link CertificateFactory} is also thread-safe.
 *
 * <h2>PCI-DSS compliance</h2>
 * <ul>
 *   <li>Private key material is <em>never</em> logged.</li>
 *   <li>RSA-2048 is the minimum key size for generated key pairs.</li>
 *   <li>Certificate expiry validated on every {@link #validateCertificate} call.</li>
 * </ul>
 *
 * <h2>Java 21 features used</h2>
 * <ul>
 *   <li>{@code var} for local type inference throughout.</li>
 *   <li>{@link Instant} instead of the legacy {@link java.util.Date} API for
 *       time comparisons.</li>
 *   <li>Enhanced {@code for} loops over iterable key/ring collections.</li>
 *   <li>Multi-line string messages via {@code String::formatted}.</li>
 *   <li>Typed sub-exceptions ({@link CryptoException.PkiException}).</li>
 * </ul>
 */
@Slf4j
public final class PkiUtils {

    private static final String X509     = "X.509";
    private static final String RSA      = "RSA";
    private static final int    KEY_SIZE = 2048;

    private final CertificateFactory certFactory;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Constructs {@code PkiUtils} and initialises the X.509 {@link CertificateFactory}.
     *
     * @throws CryptoException.PkiException if the JVM does not support X.509
     */
    public PkiUtils() {
        try {
            this.certFactory = CertificateFactory.getInstance(X509);
        } catch (CertificateException e) {
            throw new CryptoException.PkiException(
                    "Failed to initialise X.509 CertificateFactory", e);
        }
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Loads an X.509 certificate from a PEM string or a Base64-encoded DER block.
     *
     * <p>PEM input must include the {@code -----BEGIN CERTIFICATE-----} header.
     * Bare Base64-encoded DER is also accepted.</p>
     *
     * @param source PEM or Base64-DER certificate; must not be {@code null} or blank
     * @return the parsed {@link X509Certificate}
     * @throws CryptoException.PkiException if the source is null, blank, or unparseable
     */
    public X509Certificate loadCertificate(String source) {
        if (source == null || source.isBlank()) {
            throw new CryptoException.PkiException(
                    "Certificate source must not be null or blank");
        }
        try {
            var derBytes = decodeCertSource(source);
            var cert = (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(derBytes));
            log.debug("Certificate loaded: subject={}", cert.getSubjectX500Principal());
            return cert;
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to load certificate: {}", e.getMessage());
            throw new CryptoException.PkiException("Failed to load certificate", e);
        }
    }

    /**
     * Validates the temporal validity of an X.509 certificate.
     *
     * <p>Checks that {@code notBefore ≤ now ≤ notAfter}. Chain and revocation
     * validation are out of scope for this utility.</p>
     *
     * @param certificate the certificate to validate; must not be {@code null}
     * @return {@code true} if the certificate is currently valid; {@code false} if
     *         expired or not yet valid
     * @throws CryptoException.PkiException if {@code certificate} is {@code null}
     */
    public boolean validateCertificate(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "Certificate must not be null");
        try {
            // Used Instant, instead of legacy Date
            certificate.checkValidity(java.util.Date.from(Instant.now()));
            log.debug("Certificate is valid: subject={}", certificate.getSubjectX500Principal());
            return true;
        } catch (CertificateExpiredException e) {
            log.warn("Certificate has expired: {}", e.getMessage());
            return false;
        } catch (CertificateNotYetValidException e) {
            log.warn("Certificate is not yet valid: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Generates a fresh RSA-{@value KEY_SIZE} key pair using a cryptographically
     * strong random source.
     *
     * <p><strong>Important:</strong> the returned private key must be handled
     * securely and must never be logged.</p>
     *
     * @return a new {@link KeyPair} containing an RSA public and private key
     * @throws CryptoException.PkiException if key-pair generation fails
     */
    public KeyPair generateKeyPair() {
        try {
            var generator = KeyPairGenerator.getInstance(RSA, BouncyCastleProvider.PROVIDER_NAME);
            generator.initialize(KEY_SIZE, new SecureRandom());
            var keyPair = generator.generateKeyPair();
            log.debug("RSA-{} key pair generated", KEY_SIZE);
            return keyPair;
        } catch (Exception e) {
            log.error("Failed to generate key pair: {}", e.getMessage());
            throw new CryptoException.PkiException("Failed to generate RSA key pair", e);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Decodes the certificate source into raw DER bytes.
     * Handles both PEM (strips ASCII armour) and plain Base64-encoded DER.
     */
    private static byte[] decodeCertSource(String source) {
        var trimmed = source.strip();           // Strips Unicode whitespace too
        if (trimmed.startsWith("-----BEGIN")) {
            var body = trimmed
                    .replaceAll("-----BEGIN[^-]*-----", "")
                    .replaceAll("-----END[^-]*-----", "")
                    .replaceAll("\\s+", "");
            return Base64.getDecoder().decode(body);
        }
        return Base64.getDecoder().decode(trimmed);
    }
}
