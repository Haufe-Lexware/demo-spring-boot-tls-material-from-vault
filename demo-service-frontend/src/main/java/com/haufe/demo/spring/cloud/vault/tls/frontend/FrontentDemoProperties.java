package com.haufe.demo.spring.cloud.vault.tls.frontend;

import lombok.Data;
import org.hibernate.validator.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for the frontend demo application
 */
@ConfigurationProperties("haufe.demo.frontend")
@Component
@Data
public class FrontentDemoProperties {

    /**
     * The {@link org.springframework.boot.web.client.RestTemplateBuilder#rootUri(String) root URI} of the
     * backend service.
     */
    @NotEmpty
    private String backendRootUri = "http://localhost:8080/";

}
