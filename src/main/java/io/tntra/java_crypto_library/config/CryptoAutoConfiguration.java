package io.tntra.java_crypto_library.config;

import io.tntra.java_crypto_library.helper.AesCryptoHelper;
import io.tntra.java_crypto_library.helper.PgpCryptoHelper;
import io.tntra.java_crypto_library.helper.RsaOaepHelper;
import io.tntra.java_crypto_library.util.PkiUtils;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import io.tntra.java_crypto_library.properties.CryptoProperties;

/**
 * Spring Boot auto-configuration for the common crypto module.
 *
 * <p>Registers {@link AesCryptoHelper}, {@link PgpCryptoHelper},
 * {@link RsaOaepHelper}, and {@link PkiUtils} as singleton Spring beans wired
 * from {@link CryptoProperties}.
 * Consuming services only need to add this module as a Maven dependency — no
 * {@code @Import} or {@code @ComponentScan} is required.</p>
 */
@AutoConfiguration
@EnableConfigurationProperties(CryptoProperties.class)
public class CryptoAutoConfiguration {

    /**
     * Creates the {@link AesCryptoHelper} bean.
     *
     * @param properties bound crypto configuration
     * @return configured AES service
     */
    @Bean
    public AesCryptoHelper aesCryptoService(CryptoProperties properties) {
        return new AesCryptoHelper(properties);
    }

    /**
     * Creates the {@link PgpCryptoHelper} bean.
     *
     * @param properties bound crypto configuration
     * @return configured PGP service
     */
    @Bean
    public PgpCryptoHelper pgpCryptoService(CryptoProperties properties) {
        return new PgpCryptoHelper(properties);
    }

    /**
     * Creates the {@link RsaOaepHelper} bean.
     *
     * <p>Keys are supplied directly to the service methods; they are not
     * injected from configuration.</p>
     *
     * @return configured RSA-OAEP service
     */
    @Bean
    public RsaOaepHelper rsaOaepService() {
        return new RsaOaepHelper();
    }

    /**
     * Creates the {@link PkiUtils} bean.
     *
     * @return PKI utilities instance
     */
    @Bean
    public PkiUtils pkiUtils() {
        return new PkiUtils();
    }
}
