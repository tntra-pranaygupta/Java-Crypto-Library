package io.tntra.java_crypto_library.exception;

/**
 * Runtime exception representing any cryptographic operation failure.
 *
 * <p>Thrown by AES, PGP, and PKI operations when keys are invalid, data is
 * malformed, or an underlying algorithm error occurs.  Sensitive material
 * (keys, plaintext) must <em>never</em> appear in the exception message to
 * satisfy PCI-DSS logging requirements.</p>
 *
 * <p>This class is {@code sealed} so that only the intended subtype hierarchy
 * may extend it, preventing accidental misuse in consuming services.</p>
 *
 * @since 1.0.0
 */
public sealed class CryptoException extends RuntimeException
        permits CryptoException.AesException,
        CryptoException.PgpException,
        CryptoException.PkiException {

    /**
     * Constructs a {@code CryptoException} with the given non-sensitive message.
     *
     * @param message a non-sensitive description of the failure
     */
    public CryptoException(String message) {
        super(message);
    }

    /**
     * Constructs a {@code CryptoException} with the given message and root cause.
     *
     * @param message a non-sensitive description of the failure
     * @param cause   the underlying exception that triggered this error
     */
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    // Typed sub-exceptions - one per crypto domain

    /** Thrown when an AES encrypt or decrypt operation fails. */
    public static final class AesException extends CryptoException {
        public AesException(String message)                  { super(message); }
        public AesException(String message, Throwable cause) { super(message, cause); }
    }

    /** Thrown when a PGP encrypt, decrypt, sign, or verify operation fails. */
    public static final class PgpException extends CryptoException {
        public PgpException(String message)                  { super(message); }
        public PgpException(String message, Throwable cause) { super(message, cause); }
    }

    /** Thrown when a PKI certificate or key-pair operation fails. */
    public static final class PkiException extends CryptoException {
        public PkiException(String message)                  { super(message); }
        public PkiException(String message, Throwable cause) { super(message, cause); }
    }
}
