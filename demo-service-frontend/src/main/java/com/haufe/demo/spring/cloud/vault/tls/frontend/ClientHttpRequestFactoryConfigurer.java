package com.haufe.demo.spring.cloud.vault.tls.frontend;

import com.haufe.spring.cloud.vault.config.tls.ServiceClientTLSProperties;
import com.haufe.spring.cloud.vault.config.tls.TLSClientKeyMaterial;
import com.haufe.spring.cloud.vault.config.tls.TLSClientKeyMaterial.PrivateKeyMaterial;
import com.haufe.spring.cloud.vault.config.tls.TLSClientKeyMaterial.TrustMaterial;
import com.haufe.spring.cloud.vault.config.tls.TlsInitializationException;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLContext;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

/**
 * A service component that configures the HTTP client for backend access.
 */
@Component
@ComponentScan(basePackages = "com.haufe.spring.cloud.vault.config.tls")
@EnableConfigurationProperties(ServiceClientTLSProperties.class)
public class ClientHttpRequestFactoryConfigurer {

    private static final Logger LOG = LoggerFactory.getLogger(ClientHttpRequestFactoryConfigurer.class);

    private final ServiceClientTLSProperties serviceClientTLSProperties;
    private final TLSClientKeyMaterial tlsClientKeyMaterial;

    /**
     * Create a service component that configures the HTTP client for backend access.
     * <p>
     * The TLS client key material is fetched from vault if and only if all of the properties
     * {@code spring.cloud.vault.enabled}, {@code spring.cloud.vault.generic.enabled}, and
     * {@code haufe.client.ssl.vault.enabled} are {@code true}.
     *
     * @param serviceClientTLSProperties the properties with the prefix {@code haufe.client.ssl}, must not be {@code null}
     * @param tlsClientKeyMaterial       the key material required to set up the client connection's {@link SSLContext}
     */
    public ClientHttpRequestFactoryConfigurer(ServiceClientTLSProperties serviceClientTLSProperties, TLSClientKeyMaterial tlsClientKeyMaterial) {
        this.serviceClientTLSProperties = serviceClientTLSProperties;
        this.tlsClientKeyMaterial = tlsClientKeyMaterial;
    }

    /**
     * Construct a factory for HTTP client requests that respects the {@link ServiceClientTLSProperties} and
     * {@link TLSClientKeyMaterial} injected into this configurer's constructor.
     *
     * @return a HTTP client request factory, never {@code null}
     */
    @Bean
    public ClientHttpRequestFactory clientHttpRequestFactory() {
        SSLContext sslContext = getSSLContext();

        SSLConnectionSocketFactory sslConnectionSocketFactory =
                new SSLConnectionSocketFactory(sslContext,
                        new DefaultHostnameVerifier());

        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", new PlainConnectionSocketFactory())
                .register("https", sslConnectionSocketFactory)
                .build();

        HttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(registry);

        CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(connectionManager).build();
        return new HttpComponentsClientHttpRequestFactory(httpClient);
    }

    private SSLContext getSSLContext() {

        try {

            final SSLContextBuilder contextBuilder = SSLContexts.custom();
            tlsClientKeyMaterial.getPrivateKeyMaterial().ifPresent(material ->
                    loadKeyMaterial(contextBuilder, material));
            tlsClientKeyMaterial.getTrustMaterial().ifPresent(material ->
                    loadTrustMaterial(contextBuilder, material));

            String protocol = serviceClientTLSProperties.getProtocol();
            LOG.info("building an SSLContext based on the {} protocol for backend access", protocol);

            return contextBuilder
                    .useProtocol(protocol)
                    .build();

        } catch (Exception ex) {

            throw new TlsInitializationException("could not construct an SSLContext for the HTTP client", ex);

        }
    }

    private void loadTrustMaterial(SSLContextBuilder contextBuilder, TrustMaterial material) {
        try {
            contextBuilder.loadTrustMaterial(material.getTrustStore(), null);
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new TlsInitializationException("could not load trust material", e);
        }
    }

    private void loadKeyMaterial(SSLContextBuilder contextBuilder, PrivateKeyMaterial material) {
        try {
            contextBuilder.loadKeyMaterial(material.getKeyStore(), material.getKeyStorePassword());
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
            throw new TlsInitializationException("could not load key material", e);
        }
    }

}
