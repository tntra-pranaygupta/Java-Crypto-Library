package io.tntra.java_crypto_library.helper;

import io.tntra.java_crypto_library.exception.CryptoException;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Service providing RSA-OAEP encryption and decryption.
 *
 * <p>Supports both SHA-256 and SHA-1 variants to mirror the Go implementation:</p>
 * <ul>
 *   <li>{@link #encryptSha256(byte[], PublicKey)}</li>
 *   <li>{@link #decryptSha256(byte[], PrivateKey)}</li>
 *   <li>{@link #encryptSha1(byte[], PublicKey)}</li>
 *   <li>{@link #decryptSha1(byte[], PrivateKey)}</li>
 * </ul>
 *
 * <p>Labelled OAEP is supported via overloads that accept a {@code label} byte array.
 * The label is optional and defaults to empty when {@code null}.</p>
 */
@Slf4j
public final class RsaOaepHelper {

    // -------------------------------------------------------------------------
    // Public API — SHA-256 OAEP
    // -------------------------------------------------------------------------

    public byte[] encryptSha256(byte[] plaintext, PublicKey publicKey) {
        return encryptSha256(plaintext, publicKey, null);
    }

    public byte[] encryptSha256(byte[] plaintext, PublicKey publicKey, byte[] label) {
        return doOaepEncrypt(plaintext, publicKey, "SHA-256", "SHA-256", label);
    }

    public byte[] decryptSha256(byte[] ciphertext, PrivateKey privateKey) {
        return decryptSha256(ciphertext, privateKey, null);
    }

    public byte[] decryptSha256(byte[] ciphertext, PrivateKey privateKey, byte[] label) {
        return doOaepDecrypt(ciphertext, privateKey, "SHA-256", "SHA-256", label);
    }

    // -------------------------------------------------------------------------
    // Public API — SHA-1 OAEP (legacy interop)
    // -------------------------------------------------------------------------

    public byte[] encryptSha1(byte[] plaintext, PublicKey publicKey) {
        return encryptSha1(plaintext, publicKey, null);
    }

    public byte[] encryptSha1(byte[] plaintext, PublicKey publicKey, byte[] label) {
        return doOaepEncrypt(plaintext, publicKey, "SHA-1", "SHA-1", label);
    }

    public byte[] decryptSha1(byte[] ciphertext, PrivateKey privateKey) {
        return decryptSha1(ciphertext, privateKey, null);
    }

    public byte[] decryptSha1(byte[] ciphertext, PrivateKey privateKey, byte[] label) {
        return doOaepDecrypt(ciphertext, privateKey, "SHA-1", "SHA-1", label);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private byte[] doOaepEncrypt(
            byte[] plaintext,
            PublicKey publicKey,
            String digest,
            String mgfDigest,
            byte[] label
    ) {
        if (plaintext == null) {
            throw new CryptoException.PkiException("RSA-OAEP plaintext must not be null");
        }
        if (publicKey == null) {
            throw new CryptoException.PkiException("RSA-OAEP public key must not be null");
        }
        try {
            var cipher = Cipher.getInstance("RSA/ECB/OAEPWith" + digest + "AndMGF1Padding");
            var oaepParams = buildOaepParams(digest, mgfDigest, label);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
            var result = cipher.doFinal(plaintext);
            log.debug("RSA-OAEP({}) encryption completed", digest);
            return result;
        } catch (Exception e) {
            log.error("RSA-OAEP({}) encryption failed: {}", digest, e.getMessage());
            throw new CryptoException.PkiException("RSA-OAEP encryption failed", e);
        }
    }

    private byte[] doOaepDecrypt(
            byte[] ciphertext,
            PrivateKey privateKey,
            String digest,
            String mgfDigest,
            byte[] label
    ) {
        if (ciphertext == null) {
            throw new CryptoException.PkiException("RSA-OAEP ciphertext must not be null");
        }
        if (privateKey == null) {
            throw new CryptoException.PkiException("RSA-OAEP private key must not be null");
        }
        try {
            var cipher = Cipher.getInstance("RSA/ECB/OAEPWith" + digest + "AndMGF1Padding");
            var oaepParams = buildOaepParams(digest, mgfDigest, label);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
            var result = cipher.doFinal(ciphertext);
            log.debug("RSA-OAEP({}) decryption completed", digest);
            return result;
        } catch (Exception e) {
            log.error("RSA-OAEP({}) decryption failed: {}", digest, e.getMessage());
            throw new CryptoException.PkiException("RSA-OAEP decryption failed", e);
        }
    }

    private static OAEPParameterSpec buildOaepParams(
            String digest,
            String mgfDigest,
            byte[] label
    ) {
        var pSource = label != null
                ? new PSource.PSpecified(label)
                : PSource.PSpecified.DEFAULT;

        return new OAEPParameterSpec(
                digest,
                "MGF1",
                new MGF1ParameterSpec(mgfDigest),
                pSource
        );
    }
}

