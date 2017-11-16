package com.haufe.demo.spring.cloud.vault.tls.backend;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.Map;

/**
 * Spring MVC Controller for the demo backend application.
 */
@RestController
@RequestMapping("/")
public class DemoBackendController {

    private final ZoneId UTC_ZONE_ID = ZoneId.of("UTC");

    @GetMapping(path = "/utc", produces = "application/json")
    public Map<String, Object> displayTimeUTC() {
        ZonedDateTime nowInUTC = ZonedDateTime.now(UTC_ZONE_ID);
        String isoFormattedUTC = nowInUTC.format(DateTimeFormatter.ISO_INSTANT);
        return Collections.singletonMap("UTC", isoFormattedUTC);
    }

}
