package io.tntra.java_crypto_library.helper;

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
 * AES-256-CBC encryption/decryption utilities.
 * <p>Provides structured (Go-compatible) payload handling, a legacy zero-IV mode
 * for interoperability, and helpers for key/IV generation. Implementation is
 * thread-safe and does not log secrets.
 */
@Slf4j
public final class AesCryptoHelper {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int IV_BYTES = 16;
    private static final int KEY_BYTES = 32; // 256-bit

    /** Fixed all-zero IV for legacy BuyPass interop (zero-IV mode). */
    private static final byte[] ZERO_IV         = new byte[IV_BYTES];

    private final SecretKeySpec keySpec;
    private final SecureRandom  random;

    /**
     * Constructs the service and validates the configured AES key.
     *
     * @param properties Spring-bound crypto configuration; must not be {@code null}
     * @throws CryptoException.AesException if the key is missing or not 256 bits
     */
    public AesCryptoHelper(CryptoProperties properties) {
        Objects.requireNonNull(properties, "CryptoProperties must not be null");
        this.keySpec = buildKeySpec(properties.aesKey());
        this.random  = new SecureRandom();
    }

    /**
     * Go-style AES payload with structured header.
     *
     * @param keyIndex logical key index used by the caller
     * @param iv raw IV bytes
     * @param ciphertext raw AES ciphertext bytes
     */
    public record AesPayload(int keyIndex, byte[] iv, byte[] ciphertext) {}

    public AesPayload encryptStructured(String plaintext, int keyIndex) {
        if (plaintext == null) {
            throw new CryptoException.AesException("Plaintext must not be null");
        }
        try {
            var iv     = generateIv();
            var cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
            var cipherBytes = cipher.doFinal(plaintext.getBytes(UTF_8));
            return new AesPayload(keyIndex, iv, cipherBytes);
        } catch (Exception e) {
            log.error("AES structured encryption failed: {}", e.getMessage());
            throw new CryptoException.AesException("AES structured encryption failed", e);
        }
    }

    /**
     * Serialises an {@link AesPayload} into the Go-style header format.
     *
     * @param payload structured payload
     * @return binary representation: keyIndex || ivLen || ivBase64 || ciphertextBase64
     */
    public byte[] toStructuredBytes(AesPayload payload) {
        Objects.requireNonNull(payload, "payload must not be null");
        var encoder = Base64.getEncoder();
        var ivB64 = encoder.encodeToString(payload.iv()).getBytes(UTF_8);
        var ctB64 = encoder.encodeToString(payload.ciphertext()).getBytes(UTF_8);
        var result = new byte[8 + ivB64.length + ctB64.length];

        writeIntBigEndian(result, 0, payload.keyIndex());
        writeIntBigEndian(result, 4, ivB64.length);

        System.arraycopy(ivB64, 0, result, 8, ivB64.length);
        System.arraycopy(ctB64, 0, result, 8 + ivB64.length, ctB64.length);
        return result;
    }

    /**
     * Convenience helper: encrypts and returns the structured payload as a Base64 string.
     *
     * @param plaintext value to encrypt
     * @param keyIndex  key index to embed
     * @return Base64-encoded structured payload bytes
     */
    public String encryptStructuredBase64(String plaintext, int keyIndex) {
        var payload = encryptStructured(plaintext, keyIndex);
        var bytes   = toStructuredBytes(payload);
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Parses a binary Go-style structured payload into {@link AesPayload}.
     *
     * @param payloadBytes keyIndex || ivLen || ivBase64 || ciphertextBase64
     * @return parsed {@link AesPayload}
     */
    public AesPayload fromStructuredBytes(byte[] payloadBytes) {
        if (payloadBytes == null || payloadBytes.length < 8) {
            throw new CryptoException.AesException("Structured AES payload is too short");
        }
        try {
            var keyIndex = readIntBigEndian(payloadBytes, 0);
            var ivLen    = readIntBigEndian(payloadBytes, 4);
            if (ivLen < 0 || 8 + ivLen > payloadBytes.length) {
                throw new CryptoException.AesException("Invalid IV length in structured AES payload");
            }

            var ivB64Bytes = slice(payloadBytes, 8, 8 + ivLen);
            var ctB64Bytes = slice(payloadBytes, 8 + ivLen, payloadBytes.length);

            var decoder    = Base64.getDecoder();
            var iv         = decoder.decode(ivB64Bytes);
            var ciphertext = decoder.decode(ctB64Bytes);

            return new AesPayload(keyIndex, iv, ciphertext);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to parse structured AES payload: {}", e.getMessage());
            throw new CryptoException.AesException("Failed to parse structured AES payload", e);
        }
    }

    /**
     * Convenience helper: decodes Base64-encoded structured payload bytes.
     *
     * @param base64Payload Base64-encoded structured payload
     * @return parsed {@link AesPayload}
     */
    public AesPayload fromStructuredBase64(String base64Payload) {
        if (base64Payload == null) {
            throw new CryptoException.AesException("Structured AES payload must not be null");
        }
        var bytes = Base64.getDecoder().decode(base64Payload);
        return fromStructuredBytes(bytes);
    }

    /**
     * Decrypts a Go-style structured payload into plaintext.
     *
     * @param payloadBytes binary structured payload
     * @return decrypted plaintext
     */
    public String decryptStructured(byte[] payloadBytes) {
        var payload = fromStructuredBytes(payloadBytes);
        try {
            var cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(payload.iv()));
            var plain = cipher.doFinal(payload.ciphertext());
            log.debug("AES structured decryption completed");
            return new String(plain, UTF_8);
        } catch (Exception e) {
            log.error("AES structured decryption failed: {}", e.getMessage());
            throw new CryptoException.AesException("AES structured decryption failed", e);
        }
    }

    /**
     * Decrypts a Base64-encoded structured payload into plaintext.
     *
     * @param base64Payload Base64-encoded structured payload
     * @return plaintext
     */
    public String decryptStructuredBase64(String base64Payload) {
        var bytes = Base64.getDecoder().decode(base64Payload);
        return decryptStructured(bytes);
    }

    // -------------------------------------------------------------------------
    // Public API — Legacy zero-IV mode (BuyPass interop)
    // -------------------------------------------------------------------------

    /**
     * Encrypts {@code plaintext} with AES-256-CBC using an all-zero IV.
     *
     * <p>Wire format: {@code Base64(ciphertext)} (no IV included).</p>
     *
     * <p><strong>Warning:</strong> this mode is not semantically secure and must
     * only be used for interoperability with legacy systems that require a
     * zero-IV.</p>
     */
    public String encryptZeroIv(String plaintext) {
        if (plaintext == null) {
            throw new CryptoException.AesException("Plaintext must not be null");
        }
        try {
            var cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(ZERO_IV));
            var encrypted = cipher.doFinal(plaintext.getBytes(UTF_8));
            log.debug("AES zero-IV encryption completed");
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            log.error("AES zero-IV encryption failed: {}", e.getMessage());
            throw new CryptoException.AesException("AES zero-IV encryption failed", e);
        }
    }

    /**
     * Decrypts a {@code Base64(ciphertext)} string encrypted with {@link #encryptZeroIv(String)}.
     */
    public String decryptZeroIv(String ciphertext) {
        if (ciphertext == null) {
            throw new CryptoException.AesException("Ciphertext must not be null");
        }
        try {
            var encryptedBytes = Base64.getDecoder().decode(ciphertext);
            var cipher         = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ZERO_IV));
            var plain = cipher.doFinal(encryptedBytes);
            log.debug("AES zero-IV decryption completed");
            return new String(plain, UTF_8);
        } catch (Exception e) {
            log.error("AES zero-IV decryption failed: {}", e.getMessage());
            throw new CryptoException.AesException("AES zero-IV decryption failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // Public API — Key and IV generation helpers
    // -------------------------------------------------------------------------

    /**
     * Generates a fresh 256-bit AES key and returns it as Base64.
     */
    public static String generateRandomKeyBase64() {
        var random   = new SecureRandom();
        var keyBytes = new byte[KEY_BYTES];
        random.nextBytes(keyBytes);
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    /**
     * Generates a fresh random IV (16 bytes).
     */
    public static byte[] generateRandomIv() {
        var random = new SecureRandom();
        var iv     = new byte[IV_BYTES];
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Generates a fresh random IV (16 bytes) and returns it as Base64.
     */
    public static String generateRandomIvBase64() {
        return Base64.getEncoder().encodeToString(generateRandomIv());
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

    private static void writeIntBigEndian(byte[] dest, int offset, int value) {
        dest[offset]     = (byte) ((value >>> 24) & 0xFF);
        dest[offset + 1] = (byte) ((value >>> 16) & 0xFF);
        dest[offset + 2] = (byte) ((value >>> 8)  & 0xFF);
        dest[offset + 3] = (byte) (value & 0xFF);
    }

    private static int readIntBigEndian(byte[] src, int offset) {
        return ((src[offset] & 0xFF) << 24)
                | ((src[offset + 1] & 0xFF) << 16)
                | ((src[offset + 2] & 0xFF) << 8)
                | (src[offset + 3] & 0xFF);
    }
}
