package com.haufe.spring.cloud.vault.config.tls;

import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.vault.config.VaultSecretBackendDescriptor;

/**
 * Type-safe representation of the TLS client configuration.
 */
@ConfigurationProperties("haufe.client.ssl")
@Data
public class ServiceClientTLSProperties {

    private String protocol = "TLSv1.2";
    private FilesystemServiceClientTLSProperties filesystem = new FilesystemServiceClientTLSProperties();
    private VaultServiceClientTLSProperties vault = new VaultServiceClientTLSProperties();

    @Data
    public static class FilesystemServiceClientTLSProperties {
        private String keyStore;
        private String trustStore;
        private String keyStorePassword;
        private String trustStorePassword;
        private String keyStoreType = "JCEKS";

        /**
         * Getter for property 'keyStore'. If empty, then the client won't support TLS client authentication.
         *
         * @return Value for property 'keyStore'.
         */
        public String getKeyStore() {
            return StringUtils.defaultString(keyStore);
        }

        /**
         * Getter for property 'trustStore'. If empty, then the JVM's default truststore settings will be used.
         *
         * @return Value for property 'trustStore'.
         */
        public String getTrustStore() {
            return StringUtils.defaultString(trustStore);
        }

        /**
         * Getter for property 'keyStorePassword'.
         *
         * @return Value for property 'keyStorePassword'.
         */
        public String getKeyStorePassword() {
            return StringUtils.defaultString(keyStorePassword);
        }

        /**
         * Getter for property 'trustStorePassword'.
         *
         * @return Value for property 'trustStorePassword'.
         */
        public String getTrustStorePassword() {
            return StringUtils.defaultString(trustStorePassword);
        }

        /**
         * Getter for property 'keyStoreType'.
         *
         * @return Value for property 'keyStoreType'.
         */
        public String getKeyStoreType() {
            return StringUtils.defaultString(keyStoreType);
        }
    }

    @Data
    public static class VaultServiceClientTLSProperties implements VaultSecretBackendDescriptor {

        /**
         * The default value of {@link #getKeyStorePath()}
         */
        public static final String DEFAULT_KEYSTORE_PATH = "${spring.application.name}/client/keystore";

        /**
         * The default value of {@link #getTrustStorePath()}
         */
        public static final String DEFAULT_TRUSTSTORE_PATH = "${spring.application.name}/client/truststore";

        /**
         * The name of the vault backend where the key material is read from.
         * Must not be {@link StringUtils#isBlank(CharSequence) blank} if {@link #enabled} is {@literal true}.
         */
        private String backend;

        /**
         * Whether fetching the TLS key material from vault is enabled at all.
         */
        private boolean enabled = true;

        /**
         * The path in vault (relative to {@code backend}) where a JSON document with the private key material is stored.
         * Default is {@value DEFAULT_KEYSTORE_PATH}.
         * <p>
         * If empty, then no client key material is set and the TLS client won't support client authentication.
         *
         * @see org.springframework.vault.support.CertificateBundle
         */
        private String keyStorePath = DEFAULT_KEYSTORE_PATH;

        /**
         * The path in vault (relative to {@code backend}) where a JSON document with entries of
         * trusted certificate chains is stored. Default is {@value DEFAULT_TRUSTSTORE_PATH}.
         * <p>
         * If empty, then no explicit trust store is configured and the JRE's default trust settings apply.
         *
         * @see TrustedCertificates
         */
        private String trustStorePath = DEFAULT_TRUSTSTORE_PATH;

    }
}
