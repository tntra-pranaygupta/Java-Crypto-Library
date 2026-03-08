package io.tntra.java_crypto_library.config;

import io.tntra.java_crypto_library.service.AesCryptoService;
import io.tntra.java_crypto_library.service.PgpCryptoService;
import io.tntra.java_crypto_library.util.PkiUtils;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import io.tntra.java_crypto_library.properties.CryptoProperties;

/**
 * Spring Boot auto-configuration for the common crypto module.
 *
 * <p>Registers {@link AesCryptoService}, {@link PgpCryptoService}, and
 * {@link PkiUtils} as singleton Spring beans wired from {@link CryptoProperties}.
 * Consuming services only need to add this module as a Maven dependency — no
 * {@code @Import} or {@code @ComponentScan} is required.</p>
 */
@AutoConfiguration
@EnableConfigurationProperties(CryptoProperties.class)
public class CryptoAutoConfiguration {

    /**
     * Creates the {@link AesCryptoService} bean.
     *
     * @param properties bound crypto configuration
     * @return configured AES service
     */
    @Bean
    public AesCryptoService aesCryptoService(CryptoProperties properties) {
        return new AesCryptoService(properties);
    }

    /**
     * Creates the {@link PgpCryptoService} bean.
     *
     * @param properties bound crypto configuration
     * @return configured PGP service
     */
    @Bean
    public PgpCryptoService pgpCryptoService(CryptoProperties properties) {
        return new PgpCryptoService(properties);
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
