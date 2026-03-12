package io.tntra.java_crypto_library.helper;

import io.tntra.java_crypto_library.exception.CryptoException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RsaOaepHelper")
class RsaOaepHelperTest {

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    /** Round-trip RSA OAEP encryption/decryption using SHA-256 */
    @Test
    void encryptDecryptSha256RoundTripTest() throws Exception {
        KeyPair kp = generateKeyPair();
        RsaOaepHelper service = new RsaOaepHelper();

        byte[] plaintext = "rsa-oaep-sha256".getBytes();

        byte[] cipher = service.encryptSha256(plaintext, kp.getPublic());
        assertNotNull(cipher);

        byte[] decrypted = service.decryptSha256(cipher, kp.getPrivate());
        assertArrayEquals(plaintext, decrypted);
    }

    /** Round-trip RSA OAEP encryption/decryption using SHA-1 */
    @Test
    void encryptDecryptSha1RoundTripTest() throws Exception {
        KeyPair kp = generateKeyPair();
        RsaOaepHelper service = new RsaOaepHelper();

        byte[] plaintext = "rsa-oaep-sha1".getBytes();

        byte[] cipher = service.encryptSha1(plaintext, kp.getPublic());
        assertNotNull(cipher);

        byte[] decrypted = service.decryptSha1(cipher, kp.getPrivate());
        assertArrayEquals(plaintext, decrypted);
    }

    /** Encrypting null plaintext should throw a PkiException */
    @Test
    void encryptNullPlaintextThrowsTest() throws Exception {
        KeyPair kp = generateKeyPair();
        RsaOaepHelper service = new RsaOaepHelper();

        assertThrows(CryptoException.PkiException.class,
                () -> service.encryptSha256(null, kp.getPublic()));
    }

    /** Round-trip RSA OAEP SHA-256 encryption/decryption with label (context) */
    @Test
    void encryptDecryptSha256WithLabelRoundTripTest() throws Exception {
        KeyPair kp = generateKeyPair();
        RsaOaepHelper service = new RsaOaepHelper();

        byte[] plaintext = "rsa-oaep-sha256-label".getBytes();
        byte[] label     = "context-label".getBytes();

        byte[] cipher = service.encryptSha256(plaintext, kp.getPublic(), label);
        assertNotNull(cipher);

        byte[] decrypted = service.decryptSha256(cipher, kp.getPrivate(), label);
        assertArrayEquals(plaintext, decrypted);
    }

    /** Decrypting null ciphertext should throw a PkiException */
    @Test
    void decryptNullCiphertextThrowsTest() throws Exception {
        KeyPair kp = generateKeyPair();
        RsaOaepHelper service = new RsaOaepHelper();

        assertThrows(CryptoException.PkiException.class,
                () -> service.decryptSha256(null, kp.getPrivate()));
    }

    /** Encrypting with a null public key should throw a PkiException */
    @Test
    void encryptNullPublicKeyThrowsTest() {
        RsaOaepHelper service = new RsaOaepHelper();
        byte[] data = "data".getBytes();

        assertThrows(CryptoException.PkiException.class,
                () -> service.encryptSha1(data, null));
    }

    /** Decrypting with a null private key should throw a PkiException */
    @Test
    void decryptNullPrivateKeyThrowsTest() {
        RsaOaepHelper service = new RsaOaepHelper();
        byte[] cipher = "cipher".getBytes();

        assertThrows(CryptoException.PkiException.class,
                () -> service.decryptSha1(cipher, null));
    }
}

