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
package com.haufe.spring.cloud.vault.config.tls;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.vault.config.VaultProperties;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.core.VaultPkiOperations;
import org.springframework.vault.support.*;

import java.util.Collections;
import java.util.Optional;

/**
 * Utility class to store and retrieve Certificates from Vault.
 * <p>
 * <b>Remark:</b> The original implementation of this class was copied from Mark Paluch's sample repository
 * and adapted. In particular, {@link #readTrustedCertificates(VaultOperations, String)} was added.
 * <p>
 * If PKI support it added to a release version of Spring Cloud Vault, then most likely a revision of this class
 * becomes necessary.
 *
 * @author Mark Paluch
 * @author Christoph Ludwig (adaptions)
 * @see <a href="https://github.com/mp911de/spring-cloud-vault-config/commit/29680b75b270e551f5b6b684e00f1107f039ec46">Mark Paluch's original version</a>
 */
public final class CertificateUtil {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateUtil.class);

    // Refresh period in seconds before certificate expires.
    private static final long REFRESH_PERIOD_BEFORE_EXPIRY = 60;

    /**
     * Hidden default constructor
     */
    private CertificateUtil() {
        throw new UnsupportedOperationException(CertificateUtil.class.getCanonicalName() +
            " is a utility class and must not be instantiated");
    }

    /**
     * Request SSL Certificate from Vault or retrieve cached certificate.
     * <p>
     * If {@code reuseValidCertificate} in {@link VaultPkiProperties} is {@literal true},
     * then this method attempts to read a cached Certificate from Vault at
     * {@code secret/${spring.application.name}/cert/${spring.cloud.vault.pki.commonName}}.
     * Valid certificates will be reused until they expire. A new certificate is requested
     * and cached if no valid certificate is found.
     *
     * @param vaultProperties configuration how to access the vault instance
     * @param vaultOperations vault API client implementation
     * @param pkiProperties   PKI specific configurations
     * @return the {@link CertificateBundle}.
     */
    public static CertificateBundle getOrRequestCertificate(VaultProperties vaultProperties,
                                                            VaultOperations vaultOperations,
                                                            VaultPkiProperties pkiProperties) {

        if (!pkiProperties.isReuseValidCertificate()) {
            return requestCertificate(vaultOperations, pkiProperties).getData();
        }

        String cacheKey = createCacheKey(vaultProperties, pkiProperties);

        VaultHealth health = vaultOperations.opsForSys().health();
        Optional<CertificateBundle> certBundle = readCertificateBundle(vaultOperations, cacheKey, health);

        return certBundle.orElseGet(() ->
            updateCachedCertificate(vaultOperations, pkiProperties, cacheKey, health));
    }

    /**
     * Read a SSL certificate with private key from the specified path in the vault.
     * <p>
     * The data must be stored as a JSON representation of {@link CachedCertificateBundle}.
     *
     * @param vaultOperations vault API client implementation, must not be {@literal null}
     * @param vaultPath       the path in vault where to read the data from, must not be {@literal null}
     * @return an optional certificate bundle; {@link Optional#empty() empty} if no valid
     * certificate bundle could be read.
     */
    public static Optional<CertificateBundle> readCertificateBundle(VaultOperations vaultOperations,
                                                                    String vaultPath) {
        if(StringUtils.isBlank(vaultPath)) {
            return Optional.empty();
        }

        VaultHealth health = vaultOperations.opsForSys().health();
        return readCertificateBundle(vaultOperations, vaultPath, health);
    }

    private static CertificateBundle updateCachedCertificate(VaultOperations vaultOperations,
                                                             VaultPkiProperties pkiProperties,
                                                             String cacheKey, VaultHealth health) {
        vaultOperations.delete(cacheKey);
        VaultCertificateResponse certificateResponse = requestCertificate(vaultOperations,
            pkiProperties);

        storeCertificate(cacheKey, vaultOperations, health, certificateResponse);

        return certificateResponse.getData();
    }

    private static Optional<CertificateBundle> readCertificateBundle(VaultOperations vaultOperations,
                                                                     String path, VaultHealth health) {

        VaultResponseSupport<CachedCertificateBundle> readResponse = vaultOperations
            .read(path, CachedCertificateBundle.class);
        if (isValid(health, readResponse)) {

            CertificateBundle value = getCertificateBundle(readResponse);
            LOG.info("Found valid SSL certificate in Vault at {}", path);
            return Optional.of(value);

        }
        LOG.info("no valid certificate bundle at {}", path);
        return Optional.empty();
    }

    /**
     * Read a set of trusted SSL certificates from the specified path in the vault.
     * <p>
     * The data must be stored as a JSON representation of {@link TrustedCertificates}.
     *
     * @param vaultOperations vault API client implementation, must not be {@literal null}
     * @param vaultPath       the path in vault where to read the data from, must not be {@literal null}
     * @return a trusted certificates object, never {@literal null}; it's {@code entries} property
     * might be empty, though.
     */
    public static TrustedCertificates readTrustedCertificates(VaultOperations vaultOperations,
                                                              String vaultPath) {

        VaultResponseSupport<TrustedCertificates> readResponse =
            vaultOperations.read(vaultPath, TrustedCertificates.class);
        if (readResponse == null) {
            LOG.warn("no trust-chain data found in the vault at {}, assuming an empty collection", vaultPath);
            return new TrustedCertificates();
        }

        TrustedCertificates trustedCertificates = readResponse.getData();
        LOG.info("found {} trust chain entries in the vault document at {}",
            trustedCertificates.getEntries().size(), vaultPath);

        return trustedCertificates;
    }


    private static void storeCertificate(String cacheKey, VaultOperations vaultOperations,
                                         VaultHealth health, VaultCertificateResponse certificateResponse) {

        CertificateBundle certificateBundle = certificateResponse.getData();
        long expires = (health.getServerTimeUtc()
            + certificateResponse.getLeaseDuration()) - REFRESH_PERIOD_BEFORE_EXPIRY;

        CachedCertificateBundle cachedCertificateBundle = new CachedCertificateBundle();

        cachedCertificateBundle.setExpires(expires);
        cachedCertificateBundle.setTimeRequested(health.getServerTimeUtc());
        cachedCertificateBundle.setPrivateKey(certificateBundle.getPrivateKey());
        cachedCertificateBundle.setCertificate(certificateBundle.getCertificate());
        cachedCertificateBundle
            .setIssuingCaCertificate(certificateBundle.getIssuingCaCertificate());
        cachedCertificateBundle.setSerialNumber(certificateBundle.getSerialNumber());

        vaultOperations.write(cacheKey, cachedCertificateBundle);
    }

    private static String createCacheKey(VaultProperties vaultProperties,
                                         VaultPkiProperties pkiProperties) {

        return String.format("%s/%s/cert/%s",
            pkiProperties.getCacheBackend(),
            vaultProperties.getApplicationName(),
            pkiProperties.getCommonName());
    }

    private static CertificateBundle getCertificateBundle(
        VaultResponseSupport<CachedCertificateBundle> readResponse) {

        CachedCertificateBundle cachedCertificateBundle = readResponse.getData();

        return CertificateBundle.of(cachedCertificateBundle.getSerialNumber(),
            cachedCertificateBundle.getCertificate(),
            cachedCertificateBundle.getIssuingCaCertificate(),
            cachedCertificateBundle.getPrivateKey());
    }

    private static boolean isValid(VaultHealth health,
                                   VaultResponseSupport<CachedCertificateBundle> readResponse) {

        if (readResponse != null) {

            CachedCertificateBundle cachedCertificateBundle = readResponse.getData();
            if (health.getServerTimeUtc() < cachedCertificateBundle.getExpires()) {
                return true;
            }
        }

        return false;
    }

    private static VaultCertificateResponse requestCertificate(
        VaultOperations vaultOperations, VaultPkiProperties pkiProperties) {

        LOG.info("Requesting SSL certificate from Vault for: {}",
            pkiProperties.getCommonName());

        VaultCertificateRequest certificateRequest = VaultCertificateRequest.builder()
            .commonName(pkiProperties.getCommonName())
            .altNames(pkiProperties.getAltNames() != null
                ? pkiProperties.getAltNames() : Collections.emptyList())
            .build();

        VaultPkiOperations vaultPkiOperations = vaultOperations.opsForPki(pkiProperties.getBackend());

        return vaultPkiOperations.issueCertificate(pkiProperties.getRole(), certificateRequest);
    }
}
