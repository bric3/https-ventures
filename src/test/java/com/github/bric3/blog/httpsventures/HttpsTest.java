package com.github.bric3.blog.httpsventures;

import java.io.IOException;
import com.github.bric3.blog.httpsventures.tools.HttpClients;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.Rule;
import org.junit.Test;

import static java.lang.String.format;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

public class HttpsTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort()
                                                                        .dynamicHttpsPort()
                                                                        .disableRequestJournal());

    @Test
    public void connect_ssl_server_with_custom_certificate() {
        try (Response response = HttpClients.simpleHttpClient()
                                            .newCall(new Request.Builder().get().url(
                                                    format("https://%s:%d",
                                                           "localhost",
                                                           wireMockRule.httpsPort()
                                                    )).build())
                                            .execute()) {
            // won't work anyway
        } catch (IOException e) {
            fail(e.toString());
        }
    }

    @Test
    public void connect_ssl_server_with_custom_certificate_using_trust_all() {
        try (Response response = HttpClients.trustAllHttpClient()
                                            .newCall(new Request.Builder().get().url(
                                                    format("https://%s:%d",
                                                           "localhost",
                                                           wireMockRule.httpsPort()
                                                    )).build())
                                            .execute()) {
            assertThat(response.code()).isEqualTo(200);
        } catch (IOException e) {
            fail(e.toString());
        }
    }
}
