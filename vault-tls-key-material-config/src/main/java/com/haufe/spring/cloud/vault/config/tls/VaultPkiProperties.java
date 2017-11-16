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
 * It has to be reviewed again once PKI support makes it into a release version of
 * spring-cloud-vault-config.
 */
package com.haufe.spring.cloud.vault.config.tls;

import lombok.Data;
import org.hibernate.validator.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.vault.config.VaultSecretBackendDescriptor;

import java.util.List;

/**
 * Configuration properties for Vault using the PKI integration.
 * <p>
 * <b>Note:</b> We added some fields compared with Mark Paluch's original version. In order to avoid
 * future conflicts if the PKI support is added to Spring Cloud Vault, we moved the configuration prefix
 * from {@code spring.cloud.vault.pki} to {@code haufe.cloud.vault.pki}.
 *
 * @author Mark Paluch
 * @author Christoph Ludwig (adaptions)
 */
@ConfigurationProperties("haufe.cloud.vault.pki")
@Data
public class VaultPkiProperties implements VaultSecretBackendDescriptor {

    private static final long ONE_DAY_IN_SECONDS = 24L * 3600;

    /**
     * Enable pki backend usage.
     */
    private boolean enabled = false;

    /**
     * Role name for credentials.
     */
    @NotEmpty
    private String role;

    /**
     * pki backend path.
     */
    @NotEmpty
    private String backend = "pki";

    /**
     * The CN of the certificate. Should match the host name.
     */
    @NotEmpty
    private String commonName;

    /**
     * Alternate CN names for additional host names.
     */
    private List<String> altNames;

    /**
     * Prevent certificate re-creation by storing the Valid certificate inside Vault.
     */
    private boolean reuseValidCertificate = true;

    /**
     * The generic secret backend used to store cached certificates.
     */
    @NotEmpty
    private String cacheBackend = "secret";

    /**
     * The minimum remaining TTL (in seconds) of a certificate accepted from the cache. Default is 21 days.
     */
    private long minCachedTimeToLive = 21 * ONE_DAY_IN_SECONDS;

    /**
     * The path in vault where a JSON document with entries of trusted certificate chains is stored.
     * <p>
     * If empty, then the embedded container's default trust store settings are kept as specified by
     * the {@link org.springframework.boot.context.embedded.Ssl external properties}.
     *
     * @see TrustedCertificates
     */
    private String trustStorePath;
}
