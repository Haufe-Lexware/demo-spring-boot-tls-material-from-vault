package com.haufe.demo.spring.cloud.vault.tls.frontend;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.Map;

/**
 * Spring MVC Controller for the demo backend application.
 */
@RestController
@RequestMapping("/")
public class DemoFrontendController {

    private final RestTemplate restTemplate;


    public DemoFrontendController(RestTemplateBuilder builder,
                                  FrontentDemoProperties frontentDemoProperties,
                                  ClientHttpRequestFactory clientHttpRequestFactory) {
        RestTemplateBuilder backendTemplateBuilder = builder.rootUri(frontentDemoProperties.getBackendRootUri());

        this.restTemplate = backendTemplateBuilder.build();
        this.restTemplate.setRequestFactory(clientHttpRequestFactory);
    }

    @GetMapping(path = "/data", produces = "application/json")
    public Map<String, Object> displayTimeUTC() {
        BackendUTC backendUTC = restTemplate.getForObject("/utc", BackendUTC.class);

        return Collections.singletonMap("data", "Received from backend: " + backendUTC.getUtc());
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class BackendUTC {

        @JsonProperty("UTC")
        private String utc;

        public String getUtc() {
            return utc;
        }

        public void setUtc(String utc) {
            this.utc = utc;
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder("BackendUTC{");
            sb.append("utc='").append(utc).append('\'');
            sb.append('}');
            return sb.toString();
        }
    }

}
