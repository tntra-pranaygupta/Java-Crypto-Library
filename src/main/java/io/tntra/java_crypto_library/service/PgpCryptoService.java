package io.tntra.java_crypto_library.service;

import io.tntra.java_crypto_library.exception.CryptoException;
import io.tntra.java_crypto_library.properties.CryptoProperties;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Service providing PGP encryption, decryption, digital signing, and
 * signature verification.
 *
 * <p>Uses Bouncy Castle as the JCE provider. All keys are loaded from
 * {@link CryptoProperties} — never hardcoded.</p>
 *
 * <h2>PCI-DSS compliance</h2>
 * <ul>
 *   <li>Plaintext and private-key material are <em>never</em> logged.</li>
 *   <li>AES-256 session key inside each PGP message.</li>
 *   <li>SHA-256 for digital signatures.</li>
 * </ul>
 *
 * <h2>Java 21 features used</h2>
 * <ul>
 *   <li>{@code var} for local type inference.</li>
 *   <li>Pattern-matching {@code instanceof} (e.g. in {@link #resolveEncryptedDataList}).</li>
 *   <li>Switch expressions for object dispatch.</li>
 *   <li>Text-block-style error messages via {@code String::formatted}.</li>
 *   <li>Typed sub-exceptions from the sealed {@code CryptoException} hierarchy.</li>
 * </ul>
 */
@Slf4j
public final class PgpCryptoService {


    private static final int BUFFER_SIZE = 1 << 16;

    private final CryptoProperties properties;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Constructs the service with the supplied configuration.
     *
     * @param properties Spring-bound crypto configuration; must not be {@code null}
     */
    public PgpCryptoService(CryptoProperties properties) {
        this.properties = Objects.requireNonNull(properties, "CryptoProperties must not be null");
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Encrypts {@code data} using the given ASCII-armored PGP public key.
     *
     * @param data      plaintext bytes; must not be {@code null}
     * @param publicKey ASCII-armored PGP public key of the recipient
     * @return Base64-encoded PGP-encrypted payload
     * @throws CryptoException.PgpException if encryption fails
     */
    public String encrypt(byte[] data, String publicKey) {
        if (data == null) {
            throw new CryptoException.PgpException("Data must not be null");
        }
        try {
            if (publicKey == null || publicKey.isBlank()) {
                throw new CryptoException.PgpException("Public key must not be null or blank");
            }
            var pgpKey = readPublicKey(publicKey);
            var encryptedBytes = encryptData(data, pgpKey);
            log.debug("PGP encryption completed");
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            log.error("PGP encryption failed: {}", e.getMessage());
            throw new CryptoException.PgpException("PGP encryption failed", e);
        }
    }

    /**
     * Decrypts a Base64-encoded PGP payload using the given ASCII-armored private key.
     *
     * @param encryptedData Base64-encoded PGP payload; must not be {@code null} or blank
     * @param privateKey    ASCII-armored PGP private key
     * @return decrypted plaintext bytes
     * @throws CryptoException.PgpException if decryption fails
     */
    public byte[] decrypt(String encryptedData, String privateKey) {
        try {
            var encryptedBytes  = Base64.getDecoder().decode(encryptedData);
            var secretKeyRings  = readSecretKeyRingCollection(privateKey);
            var passphrase       = properties.pgpOrEmpty().passphraseChars();
            var plaintext        = decryptData(encryptedBytes, secretKeyRings, passphrase);
            log.debug("PGP decryption completed");
            return plaintext;
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            log.error("PGP decryption failed: {}", e.getMessage());
            throw new CryptoException.PgpException("PGP decryption failed", e);
        }
    }

    /**
     * Creates a detached PGP signature over {@code data}.
     *
     * @param data       bytes to sign; must not be {@code null}
     * @param privateKey ASCII-armored PGP private key
     * @return Base64-encoded detached PGP signature
     * @throws CryptoException.PgpException if signing fails
     */
    public String sign(byte[] data, String privateKey) {
        if (data == null) {
            throw new CryptoException.PgpException("Data must not be null");
        }
        try {
            var secretKey   = readFirstSecretKey(privateKey);
            var passphrase   = properties.pgpOrEmpty().passphraseChars();
            var pgpPrivKey   = secretKey.extractPrivateKey(
                    new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                            .build(passphrase));

            var sigGen = new PGPSignatureGenerator(
                    new BcPGPContentSignerBuilder(
                            secretKey.getPublicKey().getAlgorithm(),
                            HashAlgorithmTags.SHA256));
            sigGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
            sigGen.update(data);

            var baos = new ByteArrayOutputStream();
            try (var aos = new ArmoredOutputStream(baos)) {
                sigGen.generate().encode(aos);
            }

            log.debug("PGP signing completed");
            return Base64.getEncoder().encodeToString(baos.toByteArray());

        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            log.error("PGP signing failed: {}", e.getMessage());
            throw new CryptoException.PgpException("PGP signing failed", e);
        }
    }

    /**
     * Verifies a detached PGP signature.
     *
     * @param data      original signed bytes; must not be {@code null}
     * @param signature Base64-encoded detached PGP signature
     * @param publicKey ASCII-armored PGP public key of the signer
     * @return {@code true} if the signature is valid; {@code false} otherwise
     * @throws CryptoException.PgpException if verification cannot be performed
     */
    public boolean verify(byte[] data, String signature, String publicKey) {
        if (data == null) {
            throw new CryptoException.PgpException("Data must not be null");
        }
        try {
            var sigBytes   = Base64.getDecoder().decode(signature);
            var pgpPublicKey = readPublicKey(publicKey);

            var sigStream = PGPUtil.getDecoderStream(new ByteArrayInputStream(sigBytes));
            var factory   = new PGPObjectFactory(sigStream, new BcKeyFingerprintCalculator());

            // Pattern-matching switch to locate the PGPSignatureList
            var sigList = switch (factory.nextObject()) {
                case PGPSignatureList list -> list;
                case Object ignored       -> (PGPSignatureList) factory.nextObject();
            };

            var pgpSig = sigList.get(0);
            pgpSig.init(new BcPGPContentVerifierBuilderProvider(), pgpPublicKey);
            pgpSig.update(data);

            var valid = pgpSig.verify();
            log.debug("PGP signature verification result: {}", valid);
            return valid;

        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            log.error("PGP signature verification failed: {}", e.getMessage());
            throw new CryptoException.PgpException("PGP signature verification failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers — encryption
    // -------------------------------------------------------------------------

    private byte[] encryptData(byte[] data, PGPPublicKey publicKey) throws Exception {
        var baos   = new ByteArrayOutputStream();
        var encGen = new PGPEncryptedDataGenerator(
                new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setWithIntegrityPacket(true));
        encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));

        try (var encOut = encGen.open(baos, new byte[BUFFER_SIZE])) {
            var compressGen = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
            try (var compOut = compressGen.open(encOut)) {
                var litGen = new PGPLiteralDataGenerator();
                try (var litOut = litGen.open(
                        compOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE,
                        data.length, new Date())) {
                    litOut.write(data);
                }
            }
        }
        return baos.toByteArray();
    }

    // -------------------------------------------------------------------------
    // Private helpers — decryption
    // -------------------------------------------------------------------------

    private byte[] decryptData(
            byte[] encryptedBytes,
            PGPSecretKeyRingCollection secretKeyRings,
            char[] passphrase) throws Exception {

        var decIn      = PGPUtil.getDecoderStream(new ByteArrayInputStream(encryptedBytes));
        var pgpFactory = new PGPObjectFactory(decIn, new BcKeyFingerprintCalculator());
        var encDataList = resolveEncryptedDataList(pgpFactory);

        PGPPrivateKey            privateKey = null;
        PGPPublicKeyEncryptedData encData    = null;

        for (var candidate : encDataList) {
            // Pattern-matching instanceof to find the first PGPPublicKeyEncryptedData and extract the private key
            if (candidate instanceof PGPPublicKeyEncryptedData pkEncData) {
                var secretKey = secretKeyRings.getSecretKey(pkEncData.getKeyID());
                if (secretKey != null) {
                    privateKey = secretKey.extractPrivateKey(
                            new BcPBESecretKeyDecryptorBuilder(
                                    new BcPGPDigestCalculatorProvider()).build(passphrase));
                    encData = pkEncData;
                    break;
                }
            }
        }

        if (privateKey == null || encData == null) {
            throw new CryptoException.PgpException(
                    "No matching private key found for decryption");
        }

        var clear        = encData.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
        var plainFactory = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());
        return extractLiteralData(plainFactory);
    }

    private PGPEncryptedDataList resolveEncryptedDataList(PGPObjectFactory factory)
            throws IOException {
        // Switch expression with pattern matching (Java 21)
        return switch (factory.nextObject()) {
            case PGPEncryptedDataList list -> list;
            case Object ignored -> switch (factory.nextObject()) {
                case PGPEncryptedDataList list -> list;
                case Object o -> throw new CryptoException.PgpException(
                        "No PGP encrypted data found in stream; got: %s"
                                .formatted(o == null ? "null" : o.getClass().getSimpleName()));
            };
        };
    }

    private byte[] extractLiteralData(PGPObjectFactory factory) throws IOException, PGPException {
        var message = factory.nextObject();

        // Unwrap compression layer if present
        if (message instanceof PGPCompressedData compressed) {
            var compFactory = new PGPObjectFactory(
                    compressed.getDataStream(), new BcKeyFingerprintCalculator());
            message = compFactory.nextObject();
        }

        if (message instanceof PGPLiteralData literalData) {
            try (var in   = literalData.getInputStream();
                 var baos = new ByteArrayOutputStream()) {
                in.transferTo(baos);
                return baos.toByteArray();
            }
        }

        throw new CryptoException.PgpException(
                "Unexpected PGP object type during decryption: %s"
                        .formatted(message == null ? "null" : message.getClass().getSimpleName()));
    }

    private PGPPublicKey readPublicKey(String armoredKey) throws IOException, PGPException {

        try (var keyIn = PGPUtil.getDecoderStream(
                new ByteArrayInputStream(armoredKey.getBytes(UTF_8)))) {

            var factory = new PGPObjectFactory(keyIn, new BcKeyFingerprintCalculator());

            Object obj;
            while ((obj = factory.nextObject()) != null) {

                if (obj instanceof PGPPublicKeyRing ring) {
                    for (var key : ring) {
                        if (key.isEncryptionKey()) {
                            return key;
                        }
                    }
                }
            }
        }

        throw new CryptoException.PgpException(
                "No encryption-capable public key found in provided key material");
    }

    private PGPSecretKey readFirstSecretKey(String armoredKey) throws IOException, PGPException {
        for (var ring : readSecretKeyRingCollection(armoredKey)) {
            for (var key : ring) {
                if (key.isSigningKey()) return key;
            }
        }
        throw new CryptoException.PgpException(
                "No signing-capable secret key found in provided key material");
    }

    private PGPSecretKeyRingCollection readSecretKeyRingCollection(String armoredKey)
            throws IOException, PGPException {
        try (var keyIn = PGPUtil.getDecoderStream(
                new ByteArrayInputStream(armoredKey.getBytes(UTF_8)))) {
            return new PGPSecretKeyRingCollection(keyIn, new BcKeyFingerprintCalculator());
        }
    }
}
