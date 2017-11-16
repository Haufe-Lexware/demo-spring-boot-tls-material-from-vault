/*
 * Copyright 2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * This file was originally copied from
 * https://github.com/mp911de/spring-cloud-vault-config/commit/29680b75b270e551f5b6b684e00f1107f039ec46 .
 * It should be reviewed again once PKI support makes it into a release version of
 * spring-cloud-vault-config.
 */
package com.haufe.spring.cloud.vault.config.tls;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.embedded.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.vault.config.VaultProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ResourceUtils;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.CertificateBundle;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

/**
 * {@link Configuration} to request SSL certificates and register a
 * {@link org.springframework.beans.factory.config.BeanPostProcessor} to configure SSL
 * certificates in the
 * {@link org.springframework.boot.context.embedded.EmbeddedServletContainer}.
 * <p>
 * This class is meant to adapt the configuration in {@code server.ssl}. If you have additional
 * TLS configurations for, say, client connections to other services, then you have to provide additional
 * bean factories.
 * <p>
 * You can disable this adaption by setting {@code haufe.cloud.vault.pki.enabled=false}.
 *
 * @author Mark Paluch
 * @author Christoph Ludwig (adaptions)
 */
@Configuration
@ConditionalOnWebApplication
@ConditionalOnProperty(prefix = "haufe.cloud.vault.pki", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(VaultPkiProperties.class)
public class VaultPkiConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(VaultPkiConfiguration.class);

    /**
     * Create an {@link EmbeddedServletContainerCustomizer} that fetches the TLS key and trust material from vault.
     * <p>
     * More precisely, this bean factory fetches the {@link KeyStore key store} with
     * the server certificate and the corresponding private key from the vault according to the supplied
     * {@link VaultPkiProperties pkiProperties}. If these properties include a
     * {@link StringUtils#isNotBlank(CharSequence) non-blank} {@code trustStorePath} property, then an attempt is made
     * to read the container's trust store from said path in the vault as well.
     * <p>
     * If, for whatever reasons, the trust store cannot be fetched from the vault, then it is loaded as specified in
     * the server's {@link ServerProperties#getSsl() SSL properties}.
     *
     * @param vaultProperties  {@link ConfigurationProperties} of the vault client, typically specified in the application's
     *                         bootstrap configuration
     * @param vaultOperations  facade for interactions with the vault instance
     * @param pkiProperties    {@link ConfigurationProperties} of the vault PKI backend client. Also includes information on the
     *                         required server certificate, path (within the vault) of the trusted certificates etc.
     * @param serverProperties {@link ConfigurationProperties} of the embedded web container.
     * @return a customizer bean, never {@code null}
     */
    @Bean
    @ConditionalOnProperty(prefix = "server.ssl", name = "enabled", havingValue = "true")
    public SslCertificateEmbeddedServletContainerCustomizer sslCertificateRequestingPostProcessor(
            VaultProperties vaultProperties, VaultOperations vaultOperations,
            VaultPkiProperties pkiProperties, ServerProperties serverProperties) {

        CertificateBundle certificateBundle = CertificateUtil
                .getOrRequestCertificate(vaultProperties, vaultOperations, pkiProperties);

        TrustedCertificates trustedCertificates = getTrustedCertificates(vaultOperations, pkiProperties);

        Ssl ssl = serverProperties.getSsl();

        if (ssl != null) {
            ssl.setKeyAlias("vault");
            ssl.setKeyPassword("");
            ssl.setKeyStorePassword("");
        }

        return new SslCertificateEmbeddedServletContainerCustomizer(certificateBundle, trustedCertificates, ssl);
    }

    private static TrustedCertificates getTrustedCertificates(VaultOperations vaultOperations,
                                                              VaultPkiProperties pkiProperties) {

        String trustStorePath = pkiProperties.getTrustStorePath();
        return StringUtils.isNotBlank(trustStorePath) ?
                CertificateUtil.readTrustedCertificates(vaultOperations, trustStorePath) :
                null;
    }

    private static class SslCertificateEmbeddedServletContainerCustomizer
            implements EmbeddedServletContainerCustomizer {

        private final CertificateBundle certificateBundle;
        private final TrustedCertificates trustedCertificates;
        private final Ssl sslServerConfig;

        SslCertificateEmbeddedServletContainerCustomizer(
                CertificateBundle certificateBundle, TrustedCertificates trustedCertificates, Ssl ssl) {
            this.certificateBundle = certificateBundle;
            this.trustedCertificates = trustedCertificates;
            this.sslServerConfig = ssl;
        }

        @Override
        public void customize(ConfigurableEmbeddedServletContainer container) {

            try {

                final KeyStore keyStore = certificateBundle.createKeyStore("vault");
                final KeyStore trustStore = buildTrustStore();

                container.setSslStoreProvider(new SslStoreProvider() {
                    @Override
                    public KeyStore getKeyStore() throws Exception {
                        return keyStore;
                    }

                    @Override
                    public KeyStore getTrustStore() throws Exception {
                        return trustStore;
                    }
                });
            } catch (RuntimeException e) {
                throw new IllegalStateException(
                        "Cannot configure Vault SSL certificate in ConfigurableEmbeddedServletContainer",
                        e);
            }
        }

        private KeyStore buildTrustStore() {
            if (trustedCertificates == null) {
                LOG.info("no trusted certificate information from vault, falling back to server.ssl config");
                return getTrustStoreFromSslConfig();
            }
            LOG.info("using trusted certificates information from vault");
            return trustedCertificates.createTrustStore();
        }

        private KeyStore getTrustStoreFromSslConfig() {

            String trustStoreLocation = sslServerConfig != null ? sslServerConfig.getTrustStore() : null;
            if (StringUtils.isNotBlank(trustStoreLocation)) {
                try {
                    KeyStore instance = getTrustStoreInstance(sslServerConfig.getKeyStoreType(),
                            sslServerConfig.getTrustStoreProvider());
                    return readTrustStore(instance, trustStoreLocation, sslServerConfig.getTrustStorePassword());
                } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException |
                        CertificateException | IOException ex) {
                    throw new EmbeddedServletContainerException(
                            "Could not load trust store: " + ex.getMessage(), ex);
                }
            }

            LOG.info("no trust store location configured in the container's SSL properties, " +
                    "falling back to the default x509 trust manager");
            return getDefaultTrustStore();
        }

        private KeyStore getDefaultTrustStore() {
            TrustedCertificates defaultTrustedCertificates = TrustedCertificates.getDefaultTrustedCertificates();
            return defaultTrustedCertificates.createTrustStore();
        }

        private KeyStore getTrustStoreInstance(String keyStoreType, String trustStoreProvider)
                throws KeyStoreException, NoSuchProviderException {

            String type = keyStoreType == null ? "JCEKS" : keyStoreType;
            return StringUtils.isNotBlank(trustStoreProvider) ?
                    KeyStore.getInstance(type, trustStoreProvider) :
                    KeyStore.getInstance(type);
        }

        private KeyStore readTrustStore(KeyStore trustStoreInstance, String trustStoreLocation,
                                        String trustStorePassword)
                throws IOException, CertificateException, NoSuchAlgorithmException {

            File trustStoreFile = ResourceUtils.getFile(trustStoreLocation);
            try (FileInputStream trustStoreInputStream = new FileInputStream(trustStoreFile)) {
                char[] trustStorePw = StringUtils.isNotEmpty(trustStorePassword) ?
                        trustStorePassword.toCharArray() :
                        null;
                trustStoreInstance.load(trustStoreInputStream, trustStorePw);
            }
            return trustStoreInstance;
        }
    }
}
