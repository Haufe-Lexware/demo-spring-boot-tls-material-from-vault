package com.haufe.spring.cloud.vault.config.tls;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.vault.config.VaultBootstrapConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.CertificateBundle;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Optional;

import static com.google.common.base.Throwables.propagate;

/**
 * Spring configuration class that creates the beans that control the TLS setup of the client services.
 */
@Configuration
@EnableConfigurationProperties(ServiceClientTLSProperties.class)
@Import(VaultBootstrapConfiguration.class)
public class ServiceClientTLSConfig {

    private static final Logger LOG = LoggerFactory.getLogger(ServiceClientTLSConfig.class);

    private static final char[] EMPTY_PASSWORD = new char[]{};

    /**
     * Factory for {@link TLSClientKeyMaterial} that fetches the necessary data from the vault as specified in
     * the properties {@code haufe.client.ssl.vault}.
     *
     * @param serviceClientTLSProperties the properties with the prefix {@code haufe.client.ssl}, must not be {@code null}
     * @param vaultOperations      facade for interactions with the vault instance
     * @return key material required to set up the {@link javax.net.ssl.SSLContext} for the client access
     */
    @Bean
    @ConditionalOnBean(VaultOperations.class)
    @ConditionalOnExpression(
        "${spring.cloud.vault.enabled:true} and " +
            "${haufe.client.ssl.vault.enabled:true}")
    public TLSClientKeyMaterial tlsClientKeyMaterialFromVault(
            ServiceClientTLSProperties serviceClientTLSProperties, VaultOperations vaultOperations) {

        ServiceClientTLSProperties.VaultServiceClientTLSProperties vaultServiceClientTLSProperties = serviceClientTLSProperties.getVault();
        String vaulSecretBackend = vaultServiceClientTLSProperties.getBackend();
        if (StringUtils.isBlank(vaulSecretBackend)) {
            throw new IllegalStateException("backend must not be blank");
        }

        LOG.info("creating TLSClientKayMaterial from data in the vault backend {}", vaulSecretBackend);

        Optional<TLSClientKeyMaterial.PrivateKeyMaterial> privateKeyMaterial =
            fetchPrivateKeyMaterial(vaultServiceClientTLSProperties, vaultOperations);
        Optional<TLSClientKeyMaterial.TrustMaterial> trustMaterial =
            fetchTrustMaterial(vaultServiceClientTLSProperties, vaultOperations);

        return ImmutableTLSClientKeyMaterial.builder()
            .privateKeyMaterial(privateKeyMaterial)
            .trustMaterial(trustMaterial)
            .build();

    }

    /**
     * Fetch TLS private key material from the vault secret backend specified in {@code haufe.client.ssl.vault.backend}.
     *
     * @param vaultServiceClientTLSProperties the properties with the prefix {@code haufe.client.ssl.vault},
     *                                  must not be {@code null}
     * @param vaultOperations           facade for interactions with the vault instance
     * @return private key material required to set up the {@link javax.net.ssl.SSLContext}
     * for the client access
     */
    private Optional<TLSClientKeyMaterial.PrivateKeyMaterial> fetchPrivateKeyMaterial(
            ServiceClientTLSProperties.VaultServiceClientTLSProperties vaultServiceClientTLSProperties, VaultOperations vaultOperations) {

        String relPath = vaultServiceClientTLSProperties.getKeyStorePath();
        String fullKeyStorePath = StringUtils.isNotBlank(relPath) ?
            vaultServiceClientTLSProperties.getBackend() + "/" + relPath :
            "";
        Optional<CertificateBundle> certificateBundle =
            CertificateUtil.readCertificateBundle(vaultOperations, fullKeyStorePath);

        if (certificateBundle.isPresent()) {
            LOG.info("Fetched client key material for {} from vault for the client HTTP acces",
                certificateBundle.get().getX509Certificate().getSubjectDN());
        } else {
            LOG.warn("No client key material found in vault for the client HTTP acces");
        }

        return certificateBundle
            .map(bundle -> ImmutablePrivateKeyMaterial.builder()
                .keyStore(bundle.createKeyStore("http-client"))
                .keyPassword(EMPTY_PASSWORD)
                .keyStorePassword(EMPTY_PASSWORD)
                .build());

    }

    /**
     * Fetch TLS trusted certificates from the vault secret backend specified in {@code haufe.client.ssl.vault.backend}.
     *
     * @param vaultServiceClientTLSProperties the properties with the prefix {@code haufe.client.ssl.vault},
     *                                  must not be {@code null}
     * @param vaultOperations           facade for interactions with the vault instance
     * @return trust material required to set up the {@link javax.net.ssl.SSLContext}
     * for tthe client HTTP acces
     */
    private Optional<TLSClientKeyMaterial.TrustMaterial> fetchTrustMaterial(
            ServiceClientTLSProperties.VaultServiceClientTLSProperties vaultServiceClientTLSProperties, VaultOperations vaultOperations) {

        String relPath = vaultServiceClientTLSProperties.getTrustStorePath();
        String fullTrustStorePath = StringUtils.isNotBlank(relPath) ?
            vaultServiceClientTLSProperties.getBackend() + "/" + relPath :
            "";
        Optional<TrustedCertificates> trustedCertificates =
            StringUtils.isNotBlank(fullTrustStorePath) ?
                Optional.of(CertificateUtil.readTrustedCertificates(vaultOperations, fullTrustStorePath)) :
                Optional.empty();

        LOG.info("Fetched {} trusted certificates from vault as TLS client configuration " +
                "for the client HTTP acces. ",
            trustedCertificates.map(certs -> certs.getEntries().size()).orElse(0));

        return trustedCertificates
            .map(trustedCerts -> ImmutableTrustMaterial.builder()
                .trustStore(trustedCerts.createTrustStore())
                .trustStorePassword(EMPTY_PASSWORD)
                .build());

    }

    /**
     * Factory for {@link TLSClientKeyMaterial} that fetches the necessary data from the filesystem as specified in
     * the properties {@code haufe.client.ssl.filesystem}.
     *
     * @param serviceClientTLSProperties the properties with the prefix {@code haufe.client.ssl}, must not be {@code null}
     * @return key material required to set up the {@link javax.net.ssl.SSLContext} for the client HTTP acces
     */
    @Bean
    @ConditionalOnMissingBean(TLSClientKeyMaterial.class)
    public TLSClientKeyMaterial tlsClientKeyMaterialFromFilesystem(
        ServiceClientTLSProperties serviceClientTLSProperties) {

        final ServiceClientTLSProperties.FilesystemServiceClientTLSProperties filesystemServiceClientTLSProperties =
            serviceClientTLSProperties.getFilesystem();

        LOG.info("creating TLSClientKeyMaterial from data in the filesystem");

        Optional<TLSClientKeyMaterial.PrivateKeyMaterial> privateKeyMaterial =
            readPrivateKeyMaterial(filesystemServiceClientTLSProperties);
        Optional<TLSClientKeyMaterial.TrustMaterial> trustMaterial =
            readTrustMaterial(filesystemServiceClientTLSProperties);

        return ImmutableTLSClientKeyMaterial.builder()
            .privateKeyMaterial(privateKeyMaterial)
            .trustMaterial(trustMaterial)
            .build();

    }

    /**
     * Fetch TLS private key material from the key store in the file system specified in
     * {@code haufe.client.ssl.filesystem.keyStore}.
     *
     * @param filesystemServiceClientTLSProperties the properties with the prefix {@code haufe.client.ssl.filesystem},
     *                                       must not be {@code null}
     * @return private key material required to set up the {@link javax.net.ssl.SSLContext}
     * for the client HTTP acces
     */
    private Optional<TLSClientKeyMaterial.PrivateKeyMaterial> readPrivateKeyMaterial(
        ServiceClientTLSProperties.FilesystemServiceClientTLSProperties filesystemServiceClientTLSProperties) {

        final String keyStoreFileName = filesystemServiceClientTLSProperties.getKeyStore();
        final char[] keyStorePassword = filesystemServiceClientTLSProperties.getKeyStorePassword().toCharArray();
        final String keyStoreType = filesystemServiceClientTLSProperties.getKeyStoreType();

        if (StringUtils.isNotBlank(keyStoreFileName)) {

            LOG.info("loading client key material from {} for the client HTTP acces",
                keyStoreFileName);
            return Optional.of(ImmutablePrivateKeyMaterial.builder()
                .keyStore(getFilesystemStore(keyStoreFileName, keyStorePassword, keyStoreType))
                .keyStorePassword(keyStorePassword)
                .keyPassword(keyStorePassword)
                .build());

        }

        LOG.warn("No key store configured for the client HTTP acces");
        return Optional.empty();

    }

    /**
     * Fetch TLS trusted certificates from the trust store in the file system specified in
     * {@code haufe.client.ssl.filesystem.trustStore}.
     *
     * @param filesystemServiceClientTLSProperties the properties with the prefix {@code haufe.client.ssl.filesystem},
     *                                       must not be {@code null}
     * @return trust material required to set up the {@link javax.net.ssl.SSLContext}
     * for the client HTTP acces
     */
    private Optional<TLSClientKeyMaterial.TrustMaterial> readTrustMaterial(
        ServiceClientTLSProperties.FilesystemServiceClientTLSProperties filesystemServiceClientTLSProperties) {

        final String trustStoreFileName = filesystemServiceClientTLSProperties.getTrustStore();
        final char[] trustStorePassword = filesystemServiceClientTLSProperties.getTrustStorePassword().toCharArray();
        final String keyStoreType = filesystemServiceClientTLSProperties.getKeyStoreType();

        if (StringUtils.isNotBlank(trustStoreFileName)) {
            LOG.info("loading trusted certificates from {} for the client HTTP acces",
                trustStoreFileName);
            return Optional.of(ImmutableTrustMaterial.builder()
                .trustStore(getFilesystemStore(trustStoreFileName, trustStorePassword, keyStoreType))
                .trustStorePassword(trustStorePassword)
                .build());
        }

        LOG.warn("No trust store configured for the client HTTP acces");
        return Optional.empty();

    }


    /**
     * Load a Java {@link KeyStore} from the file syste.
     *
     * @param storeFileName the (relative or absolute) path to the key store
     * @param password      the password required to {@link KeyStore#load(InputStream, char[]) load} the key store
     * @param keyStoreType  the {@link KeyStore#getInstance(String) type} of the key store
     * @return a key store object with the content of the specified key store
     */
    private KeyStore getFilesystemStore(final String storeFileName, final char[] password, String keyStoreType) {

        try (InputStream inputStream = new FileInputStream(new File(storeFileName))) {

            final KeyStore store = KeyStore.getInstance(keyStoreType);
            store.load(inputStream, password);

            return store;

        } catch (Exception ex) {

            throw propagate(ex);

        }

    }


}
