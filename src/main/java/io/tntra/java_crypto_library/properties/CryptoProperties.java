package io.tntra.java_crypto_library.properties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Immutable Spring Boot configuration properties for the crypto module.
 *
 * <p>Uses a Java 21 {@code record} to enforce immutability at the language level.
 * Values are bound from {@code application.yml} under the {@code crypto} prefix.
 * Keys are <strong>never</strong> hardcoded; they must be supplied via external
 * configuration (environment variables, secrets manager, etc.) to comply with
 * PCI-DSS key management requirements.</p>
 *
 * <p>Example {@code application.yml}:</p>
 * <pre>{@code
 * crypto:
 *   aes-key: ${CRYPTO_AES_KEY}
 *   pgp:
 *     private-key-passphrase: ${CRYPTO_PGP_PASSPHRASE}
 * }</pre>
 *
 * @param aesKey Base64-encoded 256-bit (32-byte) AES key
 * @param pgp    PGP-specific key configuration
 */
@ConfigurationProperties(prefix = "crypto")
public record CryptoProperties(
        String aesKey,
        @DefaultValue Pgp pgp
) {

    /**
     * Immutable PGP key configuration.
     *
     * @param privateKeyPassphrase Passphrase protecting the private key
     */
    public record Pgp(
            String privateKeyPassphrase
    ) {
        /** Canonical empty-passphrase sentinel. */
        public static final Pgp EMPTY = new Pgp(null);

        /**
         * Returns the passphrase as a {@code char[]}, never {@code null}.
         * Callers should zero-fill the array after use.
         */
        public char[] passphraseChars() {
            return privateKeyPassphrase != null ? privateKeyPassphrase.toCharArray() : new char[0];
        }
    }

    /**
     * Returns a safe non-null {@link Pgp} instance.
     */
    public Pgp pgpOrEmpty() {
        return pgp != null ? pgp : Pgp.EMPTY;
    }
}
