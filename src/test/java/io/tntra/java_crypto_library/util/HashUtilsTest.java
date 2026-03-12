package io.tntra.java_crypto_library.util;

import io.tntra.java_crypto_library.exception.CryptoException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;

@DisplayName("HashUtils")
class HashUtilsTest {

    /** Known SHA-256 hex for input "abc" */
    @Test
    void sha256HexKnownValueTest() {
        String expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        String actual = HashUtils.sha256Hex("abc");

        assertEquals(expected, actual);
    }

    /** Salted SHA-256 changes when salt value changes */
    @Test
    void sha256SaltedChangesWithSaltTest() {
        String value = "data";
        String salt1 = "salt1";
        String salt2 = "salt2";

        String h1 = HashUtils.sha256Salted(value, salt1);
        String h2 = HashUtils.sha256Salted(value, salt2);

        assertNotEquals(h1, h2);
    }

    /** Calling sha256Hex with null String should throw CryptoException */
    @Test
    void sha256NullValueThrowsTest() {
        assertThrows(CryptoException.class, () -> HashUtils.sha256Hex((String) null));
    }

    /** Calling sha256Salted with null arguments should throw CryptoException */
    @Test
    void sha256SaltedNullThrowsTest() {
        assertThrows(CryptoException.class, () -> HashUtils.sha256Salted(null, "salt"));
        assertThrows(CryptoException.class, () -> HashUtils.sha256Salted("data", null));
    }

    /** Throws when sha256Hex(byte[]) is called with null data */
    @Test
    void sha256HexByteArrayNullDataThrowsTest() {
        assertThrows(CryptoException.class, () -> HashUtils.sha256Hex((byte[]) null));
    }

    /** Triggers SHA-256 hashing failure catch block via mocked MessageDigest */
    @Test
    void sha256HexHashingFailureTest() {
        byte[] data = "abc".getBytes();

        try (MockedStatic<MessageDigest> mocked = Mockito.mockStatic(MessageDigest.class)) {
            mocked.when(() -> MessageDigest.getInstance(anyString()))
                    .thenThrow(new RuntimeException("md-error"));

            CryptoException ex = assertThrows(
                    CryptoException.class,
                    () -> HashUtils.sha256Hex(data)
            );

            assertTrue(ex.getMessage().contains("SHA-256 hashing failed"));
            assertNotNull(ex.getCause());
        }
    }

    /** Throws when sha256Salted(byte[], byte[]) is called with null data or salt */
    @Test
    void sha256SaltedByteArrayNullArgumentsThrowTest() {
        byte[] data = "data".getBytes();
        byte[] salt = "salt".getBytes();

        assertThrows(CryptoException.class, () -> HashUtils.sha256Salted(null, salt));
        assertThrows(CryptoException.class, () -> HashUtils.sha256Salted(data, null));
    }

    /** Triggers SHA-256 salted hashing failure catch block via mocked MessageDigest */
    @Test
    void sha256SaltedHashingFailureTest() {
        byte[] data = "data".getBytes();
        byte[] salt = "salt".getBytes();

        try (MockedStatic<MessageDigest> mocked = Mockito.mockStatic(MessageDigest.class)) {
            mocked.when(() -> MessageDigest.getInstance(anyString()))
                    .thenThrow(new RuntimeException("md-error"));

            CryptoException ex = assertThrows(
                    CryptoException.class,
                    () -> HashUtils.sha256Salted(data, salt)
            );

            assertTrue(ex.getMessage().contains("SHA-256 salted hashing failed"));
            assertNotNull(ex.getCause());
        }
    }
}

