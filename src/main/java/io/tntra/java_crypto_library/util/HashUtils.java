package io.tntra.java_crypto_library.util;

import io.tntra.java_crypto_library.exception.CryptoException;

import java.security.MessageDigest;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Hashing utilities shared across services.
 *
 * <p>Provides BIM-API-compatible helpers:</p>
 * <ul>
 *   <li>{@link #sha256Hex(String)}</li>
 *   <li>{@link #sha256Hex(byte[])}</li>
 *   <li>{@link #sha256Salted(String, String)}</li>
 *   <li>{@link #sha256Salted(byte[], byte[])}</li>
 * </ul>
 *
 * <p>By convention, salted hashing is defined as:</p>
 * <pre>
 *   SHA256Salted(data, salt) = hex( SHA-256( salt || data ) )
 * </pre>
 */
public final class HashUtils {

    private HashUtils() {
        // Utility class
    }

    // -------------------------------------------------------------------------
    // SHA-256 (hex)
    // -------------------------------------------------------------------------

    public static String sha256Hex(String value) {
        if (value == null) {
            throw new CryptoException("Value for SHA-256 must not be null");
        }
        return sha256Hex(value.getBytes(UTF_8));
    }

    public static String sha256Hex(byte[] data) {
        if (data == null) {
            throw new CryptoException("Data for SHA-256 must not be null");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest    = md.digest(data);
            return toHex(digest);
        } catch (Exception e) {
            throw new CryptoException("SHA-256 hashing failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // SHA-256 salted (hex)
    // -------------------------------------------------------------------------

    /**
     * Computes {@code hex(SHA-256(salt || value))} using UTF-8 encoding.
     */
    public static String sha256Salted(String value, String salt) {
        if (value == null || salt == null) {
            throw new CryptoException("Value and salt for SHA-256 salted must not be null");
        }
        return sha256Salted(value.getBytes(UTF_8), salt.getBytes(UTF_8));
    }

    /**
     * Computes {@code hex(SHA-256(salt || data))}.
     */
    public static String sha256Salted(byte[] data, byte[] salt) {
        if (data == null || salt == null) {
            throw new CryptoException("Data and salt for SHA-256 salted must not be null");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            md.update(data);
            byte[] digest = md.digest();
            return toHex(digest);
        } catch (Exception e) {
            throw new CryptoException("SHA-256 salted hashing failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private static String toHex(byte[] bytes) {
        var sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}

