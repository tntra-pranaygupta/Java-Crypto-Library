package io.tntra.java_crypto_library.service;

import io.tntra.java_crypto_library.exception.CryptoException;
import io.tntra.java_crypto_library.properties.CryptoProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;


@DisplayName("AesCryptoService")
class AesCryptoServiceTest {

    private AesCryptoService aesCryptoService;

    private static final String VALID_AES_KEY = Base64.getEncoder().encodeToString(new byte[32]);

    @BeforeEach
    void setUp() {
        CryptoProperties properties = new CryptoProperties(VALID_AES_KEY, CryptoProperties.Pgp.EMPTY);
        aesCryptoService = new AesCryptoService(properties);
    }

    @Test
    void shouldEncryptAndDecryptSuccessfullyTest() {
        String plaintext = "SensitiveInfo123";
        String encrypted = aesCryptoService.encrypt(plaintext);
        assertNotNull(encrypted);
        String decrypted = aesCryptoService.decrypt(encrypted);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldGenerateDifferentCiphertextForSamePlaintextTest() {
        String plaintext = "SensitiveInfo123";
        String encrypted1 = aesCryptoService.encrypt(plaintext);
        String encrypted2 = aesCryptoService.encrypt(plaintext);
        assertNotEquals(encrypted1, encrypted2);
    }

    @Test
    void shouldThrowExceptionWhenPlaintextIsNullTest() {
        CryptoException.AesException exception = assertThrows(CryptoException.AesException.class,
                () -> aesCryptoService.encrypt(null));
        assertEquals("Plaintext must not be null", exception.getMessage());
    }

    @Test
    void decryptShouldThrowExceptionWhenCiphertextNullTest() {
        CryptoException.AesException exception = assertThrows(CryptoException.AesException.class,
                () -> aesCryptoService.decrypt(null));
        assertEquals("Ciphertext must not be null", exception.getMessage());
    }

    @Test
    void decryptShouldThrowExceptionWhenCiphertextTooShortTest() {
        String invalidCiphertext = Base64.getEncoder().encodeToString(new byte[15]); // Less than IV + 1 byte
        CryptoException.AesException exception = assertThrows(CryptoException.AesException.class,
                () -> aesCryptoService.decrypt(invalidCiphertext));
        assertTrue(exception.getMessage().contains("Ciphertext is too short to contain a valid IV"));
    }

    @Test
    void decryptShouldThrowExceptionWhenBase64InvalidTest() {
        String invalidBase64 = "ThisIsNotBase64!";
        CryptoException.AesException exception = assertThrows(CryptoException.AesException.class,
                () -> aesCryptoService.decrypt(invalidBase64));
        assertTrue(exception.getMessage().contains("AES decryption failed"));
    }

    @Test
    void constructorShouldThrowExceptionWhenKeyNullTest() {
        CryptoProperties properties =
                new CryptoProperties(null, CryptoProperties.Pgp.EMPTY);
        CryptoException.AesException exception = assertThrows(CryptoException.AesException.class,
                () -> new AesCryptoService(properties));
        assertTrue(exception.getMessage().contains("AES key must not be null or blank"));
    }

    @Test
    void constructorShouldThrowExceptionWhenKeyInvalidLengthTest() {
        String shortKey = Base64.getEncoder().encodeToString(new byte[10]);
        CryptoProperties properties =
                new CryptoProperties(shortKey, CryptoProperties.Pgp.EMPTY);
        CryptoException.AesException exception = assertThrows(CryptoException.AesException.class,
                () -> new AesCryptoService(properties));
        assertTrue(exception.getMessage().contains("AES key must be exactly 256 bits"));
    }
}
