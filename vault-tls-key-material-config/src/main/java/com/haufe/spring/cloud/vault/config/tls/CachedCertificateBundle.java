package com.haufe.spring.cloud.vault.config.tls;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.springframework.vault.support.VaultCertificateRequest;

/**
 * Aggregation of an X.509 private RSA key, the corresponding certificate chain, as well as management information.
 * <p>
 * When the structure is filled by a POST request to the Vault endpoint {@code /pki/issue/}, then one should set
 * {@code format=der} to get the certificates and the key in a Base64 presentation of their respective DER format.
 *
 * @see org.springframework.vault.core.VaultPkiOperations#issueCertificate(String, VaultCertificateRequest)
 */
@Data
class CachedCertificateBundle {

    /**
     * Base64 of the DER-encoded certificate
     */
    private String certificate;

    /**
     * Serial number of the certificate
     */
    @JsonProperty("serial_number")
    private String serialNumber;

    /**
     * Base64 of the DER-encoded certificate of the issuing CA
     */
    @JsonProperty("issuing_ca")
    private String issuingCaCertificate;

    /**
     * Base64 of the DER encoded, unencrypted private RSA key
     */
    @JsonProperty("private_key")
    private String privateKey;

    /**
     * Timestamp (in Posix time) when the certificate was requested
     */
    @JsonProperty("time_requested")
    private long timeRequested;

    /**
     * Timestamp (in Posix time) when the certificate will expire
     */
    @JsonProperty("expires")
    private long expires;
}
