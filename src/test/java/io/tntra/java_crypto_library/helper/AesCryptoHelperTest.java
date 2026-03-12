package io.tntra.java_crypto_library.helper;

import io.tntra.java_crypto_library.exception.CryptoException;
import io.tntra.java_crypto_library.properties.CryptoProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import javax.crypto.Cipher;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;


@DisplayName("AesCryptoHelper")
class AesCryptoHelperTest {

    private AesCryptoHelper aesCryptoHelper;

    private static final String VALID_AES_KEY = Base64.getEncoder().encodeToString(new byte[32]);

    @BeforeEach
    void setUp() {
        CryptoProperties properties = new CryptoProperties(VALID_AES_KEY, CryptoProperties.Pgp.EMPTY);
        aesCryptoHelper = new AesCryptoHelper(properties);
    }

    /** Fails when structured payload bytes are too short */
    @Test
    void fromStructuredBytesTooShortTest() {
        byte[] tooShort = new byte[4];
        CryptoException.AesException ex = assertThrows(
                CryptoException.AesException.class,
                () -> aesCryptoHelper.fromStructuredBytes(tooShort)
        );
        assertTrue(ex.getMessage().contains("Structured AES payload is too short"));
    }

    /** Fails when IV length header is inconsistent with payload length */
    @Test
    void fromStructuredBytesInvalidIvLengthTest() {
        byte[] payload = new byte[8];
        payload[3] = 1;
        payload[7] = (byte) 0xE8;

        CryptoException.AesException ex = assertThrows(
                CryptoException.AesException.class,
                () -> aesCryptoHelper.fromStructuredBytes(payload)
        );
        assertTrue(ex.getMessage().contains("Invalid IV length"));
    }

    /** Fails when structured Base64 payload is null */
    @Test
    void fromStructuredBase64NullTest() {
        CryptoException.AesException ex = assertThrows(
                CryptoException.AesException.class,
                () -> aesCryptoHelper.fromStructuredBase64(null)
        );
        assertTrue(ex.getMessage().contains("must not be null"));
    }

    /** Encrypts/decrypts using Go-style structured payload (Base64 wrapper) */
    @Test
    void structuredEncryptDecryptBase64Test() {
        String plaintext = "StructuredPayload123";
        int keyIndex = 7;

        String structured = aesCryptoHelper.encryptStructuredBase64(plaintext, keyIndex);
        assertNotNull(structured);

        String decrypted = aesCryptoHelper.decryptStructuredBase64(structured);
        assertEquals(plaintext, decrypted);

        AesCryptoHelper.AesPayload payload = aesCryptoHelper.fromStructuredBase64(structured);
        assertEquals(keyIndex, payload.keyIndex());
        assertNotNull(payload.iv());
        assertNotNull(payload.ciphertext());
    }

    /** Zero-IV mode is deterministic (same plaintext -> same ciphertext) */
    @Test
    void zeroIvModeDeterministicTest() {
        String plaintext = "ZeroIvMode";

        String c1 = aesCryptoHelper.encryptZeroIv(plaintext);
        String c2 = aesCryptoHelper.encryptZeroIv(plaintext);

        assertEquals(c1, c2);

        String decrypted = aesCryptoHelper.decryptZeroIv(c1);
        assertEquals(plaintext, decrypted);
    }

    /** Key and IV generation helpers produce correctly sized material */
    @Test
    void keyAndIvGenerationHelpersTest() {
        String keyB64 = AesCryptoHelper.generateRandomKeyBase64();
        assertNotNull(keyB64);
        byte[] keyBytes = Base64.getDecoder().decode(keyB64);
        assertEquals(32, keyBytes.length);

        byte[] iv = AesCryptoHelper.generateRandomIv();
        assertNotNull(iv);
        assertEquals(16, iv.length);

        String ivB64 = AesCryptoHelper.generateRandomIvBase64();
        assertNotNull(ivB64);
        assertEquals(16, Base64.getDecoder().decode(ivB64).length);
    }

    /** Throws when structured encryption plaintext is null */
    @Test
    void encryptStructuredNullPlaintextTest() {
        CryptoException.AesException ex = assertThrows(
                CryptoException.AesException.class,
                () -> aesCryptoHelper.encryptStructured(null, 1)
        );
        assertEquals("Plaintext must not be null", ex.getMessage());
    }

    /** Triggers AES structured encryption failure catch block via mocked Cipher */
    @Test
    void encryptStructuredCipherFailureTest() {
        try (MockedStatic<Cipher> mocked = Mockito.mockStatic(Cipher.class)) {
            mocked.when(() -> Cipher.getInstance(anyString()))
                    .thenThrow(new RuntimeException("cipher-error"));

            CryptoException.AesException ex = assertThrows(
                    CryptoException.AesException.class,
                    () -> aesCryptoHelper.encryptStructured("data", 1)
            );

            assertEquals("AES structured encryption failed", ex.getMessage());
            assertNotNull(ex.getCause());
        }
    }

    /** Triggers parse failure in fromStructuredBytes when Base64 decode fails */
    @Test
    void fromStructuredBytesDecodeFailureTest() {
        byte[] payload = new byte[11];
        payload[4] = 0;
        payload[5] = 0;
        payload[6] = 0;
        payload[7] = 3;
        payload[8] = '?';
        payload[9] = '?';
        payload[10] = '?';

        CryptoException.AesException ex = assertThrows(
                CryptoException.AesException.class,
                () -> aesCryptoHelper.fromStructuredBytes(payload)
        );

        assertTrue(ex.getMessage().contains("Failed to parse structured AES payload"));
        assertNotNull(ex.getCause());
    }

    /** Triggers AES structured decryption failure catch block via mocked Cipher */
    @Test
    void decryptStructuredCipherFailureTest() {
        String plaintext = "fail-decrypt";
        String structuredB64 = aesCryptoHelper.encryptStructuredBase64(plaintext, 5);
        byte[] structuredBytes = Base64.getDecoder().decode(structuredB64);

        try (MockedStatic<Cipher> mocked = Mockito.mockStatic(Cipher.class)) {
            mocked.when(() -> Cipher.getInstance(anyString()))
                    .thenThrow(new RuntimeException("cipher-error"));

            CryptoException.AesException ex = assertThrows(
                    CryptoException.AesException.class,
                    () -> aesCryptoHelper.decryptStructured(structuredBytes)
            );

            assertEquals("AES structured decryption failed", ex.getMessage());
            assertNotNull(ex.getCause());
        }
    }

    /** Throws when zero-IV encryption plaintext is null */
    @Test
    void encryptZeroIvNullPlaintextTest() {
        CryptoException.AesException ex = assertThrows(
                CryptoException.AesException.class,
                () -> aesCryptoHelper.encryptZeroIv(null)
        );
        assertEquals("Plaintext must not be null", ex.getMessage());
    }

    /** Triggers AES zero-IV encryption failure catch block via mocked Cipher */
    @Test
    void encryptZeroIvCipherFailureTest() {
        try (MockedStatic<Cipher> mocked = Mockito.mockStatic(Cipher.class)) {
            mocked.when(() -> Cipher.getInstance(anyString()))
                    .thenThrow(new RuntimeException("cipher-error"));

            CryptoException.AesException ex = assertThrows(
                    CryptoException.AesException.class,
                    () -> aesCryptoHelper.encryptZeroIv("data")
            );

            assertEquals("AES zero-IV encryption failed", ex.getMessage());
            assertNotNull(ex.getCause());
        }
    }

    /** Throws when zero-IV decryption ciphertext is null */
    @Test
    void decryptZeroIvNullCiphertextTest() {
        CryptoException.AesException ex = assertThrows(
                CryptoException.AesException.class,
                () -> aesCryptoHelper.decryptZeroIv(null)
        );
        assertEquals("Ciphertext must not be null", ex.getMessage());
    }

    /** Triggers AES zero-IV decryption failure catch block via mocked Cipher */
    @Test
    void decryptZeroIvCipherFailureTest() {
        String someCiphertext = Base64.getEncoder().encodeToString("abc".getBytes());

        try (MockedStatic<Cipher> mocked = Mockito.mockStatic(Cipher.class)) {
            mocked.when(() -> Cipher.getInstance(anyString()))
                    .thenThrow(new RuntimeException("cipher-error"));

            CryptoException.AesException ex = assertThrows(
                    CryptoException.AesException.class,
                    () -> aesCryptoHelper.decryptZeroIv(someCiphertext)
            );

            assertEquals("AES zero-IV decryption failed", ex.getMessage());
            assertNotNull(ex.getCause());
        }
    }

    /** Constructor triggers buildKeySpec null/blank AES key branch */
    @Test
    void constructorNullAesKeyBuildKeySpecTest() {
        CryptoProperties props =
                new CryptoProperties(null, CryptoProperties.Pgp.EMPTY);

        CryptoException.AesException ex = assertThrows(
                CryptoException.AesException.class,
                () -> new AesCryptoHelper(props)
        );

        assertTrue(ex.getMessage().contains("AES key must not be null or blank"));
    }

    /** Constructor triggers buildKeySpec invalid length branch */
    @Test
    void constructorInvalidAesKeyLengthBuildKeySpecTest() {
        // 10 bytes instead of 32
        String shortKeyB64 = Base64.getEncoder().encodeToString(new byte[10]);
        CryptoProperties props =
                new CryptoProperties(shortKeyB64, CryptoProperties.Pgp.EMPTY);

        CryptoException.AesException ex = assertThrows(
                CryptoException.AesException.class,
                () -> new AesCryptoHelper(props)
        );

        assertTrue(ex.getMessage().contains("AES key must be exactly 256 bits"));
    }


}
