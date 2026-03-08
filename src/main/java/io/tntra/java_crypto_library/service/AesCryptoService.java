package io.tntra.java_crypto_library.service;

import io.tntra.java_crypto_library.exception.CryptoException;
import io.tntra.java_crypto_library.properties.CryptoProperties;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Service providing AES-256-CBC encryption and decryption.
 *
 * <h2>Output format</h2>
 * <pre>Base64( IV[16 bytes] || CipherText )</pre>
 * A fresh, cryptographically random IV is generated for every {@link #encrypt}
 * call to ensure semantic security (IND-CPA).
 *
 * <h2>PCI-DSS compliance</h2>
 * <ul>
 *   <li>Plaintext and key material are <em>never</em> logged.</li>
 *   <li>AES-256-CBC with a random IV per operation.</li>
 *   <li>Key loaded from external {@link CryptoProperties}, never hardcoded.</li>
 * </ul>
 *
 * <p>This class is thread-safe; the {@link SecretKeySpec} and
 * {@link SecureRandom} are immutable / thread-safe respectively.</p>
 */
@Slf4j
public final class AesCryptoService {


    private static final String ALGORITHM      = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int    IV_BYTES        = 16;
    private static final int    KEY_BYTES        = 32; // 256-bit

    private final SecretKeySpec keySpec;
    private final SecureRandom  random;

    /**
     * Constructs the service and validates the configured AES key.
     *
     * @param properties Spring-bound crypto configuration; must not be {@code null}
     * @throws CryptoException.AesException if the key is missing or not 256 bits
     */
    public AesCryptoService(CryptoProperties properties) {
        Objects.requireNonNull(properties, "CryptoProperties must not be null");
        this.keySpec = buildKeySpec(properties.aesKey());
        this.random  = new SecureRandom();
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Encrypts {@code plaintext} with AES-256-CBC.
     *
     * @param plaintext value to encrypt; must not be {@code null}
     * @return {@code Base64( IV || CipherText )}
     * @throws CryptoException.AesException if encryption fails
     */
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            throw new CryptoException.AesException("Plaintext must not be null");
        }
        try {
            var iv     = generateIv();
            var cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));

            var encrypted  = cipher.doFinal(plaintext.getBytes(UTF_8));
            var ivAndCipher = concat(iv, encrypted);

            log.debug("AES encryption completed");
            return Base64.getEncoder().encodeToString(ivAndCipher);

        } catch (Exception e) {
            log.error("AES encryption failed: {}", e.getMessage());
            throw new CryptoException.AesException("AES encryption failed", e);
        }
    }

    /**
     * Decrypts a {@code Base64( IV || CipherText )} string produced by {@link #encrypt}.
     *
     * @param ciphertext Base64-encoded ciphertext with prepended IV; must not be {@code null}
     * @return the original plaintext
     * @throws CryptoException.AesException if decryption fails or the input is malformed
     */
    public String decrypt(String ciphertext) {
        if (ciphertext == null) {
            throw new CryptoException.AesException("Ciphertext must not be null");
        }
        try {
            var ivAndCipher = Base64.getDecoder().decode(ciphertext);
            if (ivAndCipher.length <= IV_BYTES) {
                throw new CryptoException.AesException(
                        "Ciphertext is too short to contain a valid IV");
            }

            var iv            = slice(ivAndCipher, 0, IV_BYTES);
            var encryptedBytes = slice(ivAndCipher, IV_BYTES, ivAndCipher.length);

            var cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

            var plain = cipher.doFinal(encryptedBytes);
            log.debug("AES decryption completed");
            return new String(plain, UTF_8);

        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            log.error("AES decryption failed: {}", e.getMessage());
            throw new CryptoException.AesException("AES decryption failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static SecretKeySpec buildKeySpec(String aesKey) {
        if (aesKey == null || aesKey.isBlank()) {
            throw new CryptoException.AesException(
                    "AES key must not be null or blank; check 'crypto.aes-key' in configuration");
        }
        var keyBytes = Base64.getDecoder().decode(aesKey);
        if (keyBytes.length != KEY_BYTES) {
            throw new CryptoException.AesException(
                    "AES key must be exactly 256 bits (32 bytes) when Base64-decoded; "
                            + "actual length: %d bytes".formatted(keyBytes.length));
        }
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    private byte[] generateIv() {
        var iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        return iv;
    }

    /** Concatenates two byte arrays into a new array. */
    private static byte[] concat(byte[] a, byte[] b) {
        var result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0,        a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /** Returns a copy of {@code src[from..to)}. */
    private static byte[] slice(byte[] src, int from, int to) {
        var slice = new byte[to - from];
        System.arraycopy(src, from, slice, 0, slice.length);
        return slice;
    }
}
