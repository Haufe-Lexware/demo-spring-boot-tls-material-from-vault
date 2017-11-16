package com.haufe.demo.spring.cloud.vault.tls.backend;

import com.haufe.demo.spring.cloud.vault.tls.backend.DemoBackendController;
import org.junit.Test;

import java.util.Map;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * Unit tests for {@link DemoBackendController}
 */
public class DemoBackendControllerTest {

    @Test
    public void testThatDisplayTimeUTCProducesISOFormattedUTCTime() {
        DemoBackendController demoBackendController = new DemoBackendController();
        Map<String, Object> stringObjectMap = demoBackendController.displayTimeUTC();

        String expectedUTCKey = "UTC";
        assertThat(stringObjectMap, hasKey(expectedUTCKey));

        // Unfortunately, the version of Hamcrest selected by the Spring dependency management (version 1.3)
        // does not include a regexp matcher. It is not worth the hassle to force Hamcrest 2.0 and risk
        // incompatibilities, though.
        assertThat(stringObjectMap, hasValue(instanceOf(String.class)));
        String utcValue = (String) stringObjectMap.get(expectedUTCKey);
        assertThat(utcValue.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z"), is(true));
    }

}