package com.haufe.demo.spring.cloud.vault.tls.frontend;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * Unit tests for {@link DemoFrontendController}
 */
@RunWith(SpringRunner.class)
@ActiveProfiles({"no-vault"})
@SpringBootTest(properties = {
        "FRONTEND_TLS_KEYSTORE=",
        "FRONTEND_TLS_TRUSTSTORE="})
public class DemoFrontendControllerTest {

    @Test
    public void contextLoads() {
        // we only check the service comes up...
    }

}