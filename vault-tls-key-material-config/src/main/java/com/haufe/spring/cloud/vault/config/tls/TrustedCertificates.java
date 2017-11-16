package com.haufe.spring.cloud.vault.config.tls;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.common.base.Preconditions;
import javaslang.collection.Stream;
import javaslang.control.Try;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.*;
import java.util.*;

/**
 * A set of trusted certificates.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class TrustedCertificates {
    private static final Logger LOG = LoggerFactory.getLogger(TrustedCertificates.class);

    private static final String PEM_CERTIFICATE_PREFIX = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_CERTIFICATE_SUFFIX = "-----END CERTIFICATE-----";

    /**
     * The collection of trusted certificate entries.
     */
    private List<TrustedCertificateEntry> entries = Collections.emptyList();

    /**
     * Static constructor that returns the certificates trusted by the Java runtime's
     * default X509 trust manager.
     *
     * @return the set of certificates trusted by default
     * @throws TlsInitializationException access to the default trust manager failed
     */
    public static TrustedCertificates getDefaultTrustedCertificates() {
        X509TrustManager trustManager = getDefaultX509TrustManager();
        List<TrustedCertificateEntry> entries = Stream.of(trustManager.getAcceptedIssuers())
                .map(TrustedCertificates::toBase64DER)
                .filter(Objects::nonNull)
                .zipWithIndex() // t._1: entry; t._2: index
                .map(t -> TrustedCertificateEntry.createdIndexedEntry(t._2(), t._1()))
                .toJavaList();
        TrustedCertificates trustedCertificates = new TrustedCertificates();
        trustedCertificates.setEntries(entries);
        return trustedCertificates;
    }

    private static String toBase64DER(X509Certificate trustedCert) {
        try {
            byte[] derEncodedCertificate = trustedCert.getEncoded();
            return Base64.getMimeEncoder().encodeToString(derEncodedCertificate);
        } catch (CertificateEncodingException encodingException) {
            Principal subjectDN = trustedCert.getSubjectDN();
            String name = subjectDN != null ? subjectDN.getName() : "<unknown subject DN>";
            LOG.warn("cannot encode certificate for {} and omitted it from the trust store",
                    name, encodingException);
            return null;
        }
    }

    private static X509TrustManager getDefaultX509TrustManager() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null); // null means default truststore

            return java.util.stream.Stream.of(tmf.getTrustManagers())
                    .filter(tm -> tm instanceof X509TrustManager)
                    .map(tm -> (X509TrustManager) tm)
                    .findFirst()
                    .orElseThrow(() -> new TlsInitializationException("no default X509TrustManager found"));
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new TlsInitializationException("cannot access the JVM's default trust managers", e);
        }
    }


    /**
     * Construct an in-memory trust store from the trusted certificates.
     * <p>
     * Certificates that, for whatever reason, cannot be added to the trust store are omitted with a log entry at
     * ERROR level.
     *
     * @return an {@link KeyStore#load(InputStream, char[]) initialized} key store that contains a
     * {@link KeyStore.TrustedCertificateEntry} for every item in {@link #entries}.
     * @throws TlsInitializationException the trust store could not be set up
     */
    public KeyStore createTrustStore() {
        Try<KeyStore> trustStoreResult = Try.of(() -> {
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null); // required to initialize the trust store

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Stream.ofAll(getEntries())
                    .zipWithIndex() // t._1: entry; t._2: index
                    .forEach(t -> addTrustedCertificateToStore(t._1, trustStore, t._2, certificateFactory));

            return trustStore;
        });

        return trustStoreResult.getOrElseThrow(
                throwable -> new TlsInitializationException("failed to build trust store", throwable));
    }

    private void addTrustedCertificateToStore(TrustedCertificateEntry entry, KeyStore trustStore,
                                              long idx,
                                              CertificateFactory certificateFactory) {
        Try<String> aliasResult = Try.of(() -> {
            String alias = StringUtils.trimToEmpty(entry.getAlias());
            String certificateString = StringUtils.trimToEmpty(entry.getCertificate());
            Certificate certificate =
                    parseCertificateString(certificateString, alias, certificateFactory);
            trustStore.setCertificateEntry(alias, certificate);
            return alias;
        });
        aliasResult.onFailure(
                throwable ->
                        LOG.error("could not parse or add certificate of entry at index {}: ",
                                idx, throwable));
        aliasResult.onSuccess(
                alias -> LOG.debug("added certificate with alias {} to trust store for entry at index {}",
                        alias, idx));
    }

    private Certificate parseCertificateString(String certificateString, String alias,
                                               CertificateFactory certificateFactory)
            throws CertificateException, KeyStoreException, IOException {

        Preconditions.checkArgument(StringUtils.isNotEmpty(alias),
                "certificate alias must not be empty");
        Preconditions.checkArgument(StringUtils.isNotEmpty(certificateString),
                "certificateString must not be empty");

        try (ByteArrayInputStream bis = certificateAsByteArrayInputStream(certificateString)) {

            return certificateFactory.generateCertificate(bis);
        }
    }

    private ByteArrayInputStream certificateAsByteArrayInputStream(String certificateString) {

        // strip off PEM markers, if any, so the certificate is in Base64-encoded DER format
        // (possibly with extraneous whitespace)
        String base64DER = certificateString.replaceAll(PEM_CERTIFICATE_PREFIX + "|" + PEM_CERTIFICATE_SUFFIX, "");
        return new ByteArrayInputStream(Base64.getMimeDecoder().decode(base64DER));
    }

    /**
     * An entry in the set of trusted certificates.
     * <p>
     * Java key (or trust) stores require every certificate to have a label or alias used to reference the
     * certificate. This class makes the coupling explicit.
     *
     * @see TrustedCertificates
     */
    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class TrustedCertificateEntry {

        /**
         * An alias under which the entry can be referenced, must not be empty.
         * <p>
         * It depends on the JCE trust store implementation whether the alias is case sensitive. It is therefore
         * best to always specify and use the alias in lower-case form.
         */
        private String alias;

        /**
         * An X.509 certificate that is part of a trusted certificate chain.
         */
        private String certificate;

        static TrustedCertificateEntry createdIndexedEntry(long idx, String certificate) {
            TrustedCertificateEntry entry = new TrustedCertificateEntry();
            entry.setAlias("alias_" + Long.toString(idx));
            entry.setCertificate(certificate);
            return entry;
        }
    }
}
