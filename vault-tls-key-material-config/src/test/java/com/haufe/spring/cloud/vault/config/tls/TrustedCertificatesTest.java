package com.haufe.spring.cloud.vault.config.tls;

import org.junit.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.Collections;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * Unit tests for {@link TrustedCertificates}
 */
public class TrustedCertificatesTest {

    private static final Charset UTF8 = Charset.forName("UTF-8");

    @Test
    public void testThatCreateTrustStoreHandlesPEMCertificates()
            throws IOException, URISyntaxException, KeyStoreException {
        String caCertPEM = readCaCert();
        String alias = "ca";
        TrustedCertificates trustedCertificates = buildTrustedCertificates(alias, caCertPEM);

        KeyStore trustStore = trustedCertificates.createTrustStore();
        assertThat(trustStore, notNullValue());
        assertThat(trustStore.getCertificate(alias),
                   hasProperty("type", equalToIgnoringCase("x.509")));
    }

    @Test
    public void testThatCreateTrustStoreHandlesPEMCertificatesWithoutLinebreaks()
            throws IOException, URISyntaxException, KeyStoreException {
        String caCertPEM = readCaCert();
        String caCertPEMWithoutLinebreaks = caCertPEM.replaceAll("\n|\r", "");
        String alias = "ca";
        TrustedCertificates trustedCertificates = buildTrustedCertificates(alias, caCertPEMWithoutLinebreaks);

        KeyStore trustStore = trustedCertificates.createTrustStore();
        assertThat(trustStore, notNullValue());
        assertThat(trustStore.getCertificate(alias),
                   hasProperty("type", equalToIgnoringCase("x.509")));
    }

    @Test
    public void testThatCreateTrustStoreHandlesBase64EncodedDER()
            throws IOException, URISyntaxException, KeyStoreException {
        String caCertPEM = readCaCert();
        String caCertBase64DER = caCertPEM.replaceAll("-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\\s+", "");
        String alias = "ca";
        TrustedCertificates trustedCertificates = buildTrustedCertificates(alias, caCertBase64DER);

        KeyStore trustStore = trustedCertificates.createTrustStore();
        assertThat(trustStore, notNullValue());
        assertThat(trustStore.getCertificate(alias),
                   hasProperty("type", equalToIgnoringCase("x.509")));
    }

    @Test
    public void testThatCreateTrustStoreHandlesBase64EncodedDERWithWhitespace()
            throws IOException, URISyntaxException, KeyStoreException {
        String caCertPEM = readCaCert();
        String caCertBase64DER = caCertPEM.replaceAll("-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----", "");
        String alias = "ca";
        TrustedCertificates trustedCertificates = buildTrustedCertificates(alias, caCertBase64DER);

        KeyStore trustStore = trustedCertificates.createTrustStore();
        assertThat(trustStore, notNullValue());
        assertThat(trustStore.getCertificate(alias),
                   hasProperty("type", equalToIgnoringCase("x.509")));
    }

    @Test
    public void testThatEntriesWithNullAliasAreIgnored()
            throws IOException, URISyntaxException, KeyStoreException {
        String caCertPEM = readCaCert();
        TrustedCertificates trustedCertificates = buildTrustedCertificates(
                "alias1", caCertPEM, null, caCertPEM, "alias3", caCertPEM);

        KeyStore trustStore = trustedCertificates.createTrustStore();
        assertThatTrustStoreContainsAliases(trustStore, "alias1", "alias3");
    }

    @Test
    public void testThatEntriesWithBlankAliasAreIgnored()
            throws IOException, URISyntaxException, KeyStoreException {
        String caCertPEM = readCaCert();
        TrustedCertificates trustedCertificates = buildTrustedCertificates(
                "alias1", caCertPEM, "  ", caCertPEM, "alias3", caCertPEM);

        KeyStore trustStore = trustedCertificates.createTrustStore();
        assertThatTrustStoreContainsAliases(trustStore, "alias1", "alias3");
        assertThatTrustStoreDoesNotContainAliases(trustStore, "  ");
    }

    @Test
    public void testThatEntriesWithNullCertificateAreIgnored()
            throws IOException, URISyntaxException, KeyStoreException {
        String caCertPEM = readCaCert();
        TrustedCertificates trustedCertificates = buildTrustedCertificates(
                "alias1", caCertPEM, "alias2", null, "alias3", caCertPEM);

        KeyStore trustStore = trustedCertificates.createTrustStore();
        assertThatTrustStoreContainsAliases(trustStore, "alias1", "alias3");
        assertThatTrustStoreDoesNotContainAliases(trustStore, "alias2");
    }

    @Test
    public void testThatEntriesWithCorruptedCertificatesAreIgnored()
            throws IOException, URISyntaxException, KeyStoreException {
        String caCertPEM = readCaCert();
        String brokenCertificate = caCertPEM.replaceAll("\\s+", "");
        TrustedCertificates trustedCertificates = buildTrustedCertificates(
                "alias1", caCertPEM, "alias2", brokenCertificate, "alias3", caCertPEM);

        KeyStore trustStore = trustedCertificates.createTrustStore();
        assertThatTrustStoreContainsAliases(trustStore, "alias1", "alias3");
        assertThatTrustStoreDoesNotContainAliases(trustStore, "alias2");
    }

    private void assertThatTrustStoreContainsAliases(KeyStore trustStore, String ... aliases) throws KeyStoreException {
        assertThat(trustStore, notNullValue());
        for(String alias : aliases) {
            assertThat(trustStore.containsAlias(alias), is(true));
        }
    }

    private void assertThatTrustStoreDoesNotContainAliases(KeyStore trustStore, String ... aliases)
            throws KeyStoreException {
        assertThat(trustStore, notNullValue());
        for(String alias : aliases) {
            assertThat(trustStore.containsAlias(alias), is(false));
        }
    }

    private String readCaCert() throws URISyntaxException, IOException {
        Path caCertPath = Paths.get(getClass().getClassLoader().getResource("testpki-ca.pem").toURI());
        return new String(Files.readAllBytes(caCertPath), UTF8);
    }

    // takes alias1, cert1, alias2, cert2, ...
    private TrustedCertificates buildTrustedCertificates(String... aliasesAndCerts) {
        ArrayList<TrustedCertificates.TrustedCertificateEntry> trustedCertificateEntries = new ArrayList<>();
        for(int idx = 0; idx < aliasesAndCerts.length; idx += 2) {
            TrustedCertificates.TrustedCertificateEntry entry = new TrustedCertificates.TrustedCertificateEntry();
            entry.setAlias(aliasesAndCerts[idx]);
            entry.setCertificate(idx < aliasesAndCerts.length - 1 ? aliasesAndCerts[idx+1] : null);
            trustedCertificateEntries.add(entry);
        }
        TrustedCertificates trustedCertificates = new TrustedCertificates();
        trustedCertificates.setEntries(Collections.unmodifiableList(trustedCertificateEntries));
        return trustedCertificates;
    }

}
