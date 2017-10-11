package com.github.bric3.blog.httpsventures;

import com.github.bric3.blog.httpsventures.tools.HttpClients;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.assertj.core.api.Assertions;
import org.junit.Rule;
import org.junit.Test;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.nio.file.Paths;

import static com.github.bric3.blog.httpsventures.tools.HttpClients.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static java.lang.String.format;

public class HttpsTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort()
                                                                        .dynamicHttpsPort());

    @Test
    public void connect_ssl_server_with_self_signed_certificate_will_fail() {
        try (Response response = simpleHttpClient().newCall(new Request.Builder().get()
                                                                                 .url(format("https://%s:%d",
                                                                                             "localhost",
                                                                                             wireMockRule.httpsPort()))
                                                                                 .build())
                                                   .execute()) {
            // won't work anyway
        } catch (IOException e) {
            Assertions.assertThat(e).isInstanceOf(SSLHandshakeException.class);
        }

    }

    @Test
    public void connect_ssl_server_with_self_signed_certificate_using_trust_all() throws IOException {
        try (Response response = trustAllHttpClient().newBuilder()
                                                     .hostnameVerifier(HttpClients.allowAllHostname())
                                                     .build()
                                                     .newCall(new Request.Builder().get()
                                                                                   .url(format("https://%s:%d",
                                                                                               "localhost",
                                                                                               wireMockRule.httpsPort()
                                                                                              ))
                                                                                   .build())
                                                     .execute()) {
            // successfully established connection
        }
    }

    @Test
    public void connect_ssl_server_with_self_signed_certificate_loading_an_external_truststore() throws IOException {
        X509TrustManager customTrustManager = AlternateTrustManager.trustManagerFor(AlternateTrustManager.readJavaKeyStore(Paths.get("./wiremock-truststore.jks"), "changeit"));
        try (Response response = httpClient(sslContext(null,
                                                       new TrustManager[]{customTrustManager}),
                                            customTrustManager)
                .newBuilder()
                .hostnameVerifier(HttpClients.allowAllHostname())
                .build()
                .newCall(new Request.Builder().get()
                                              .url(format("https://%s:%d",
                                                          "localhost",
                                                          wireMockRule.httpsPort()
                                                         ))
                                              .build())
                .execute()) {
            // successfully established connection
        }
    }


    @Test
    public void connect_ssl_server_with_self_signed_certificate_loading_an_external_certificate() throws IOException {
        X509TrustManager customTrustManager = AlternateTrustManager.trustManagerFor(AlternateTrustManager.makeJavaKeyStore(Paths.get("./wiremock.pem")));
        try (Response response = httpClient(sslContext(null,
                                                       new TrustManager[]{customTrustManager}),
                                            customTrustManager)
                .newBuilder()
                .hostnameVerifier(HttpClients.allowAllHostname())
                .build()
                .newCall(new Request.Builder().get()
                                              .url(format("https://%s:%d",
                                                          "localhost",
                                                          wireMockRule.httpsPort()))
                                              .build())
                .execute()) {
            // successfully established connection
        }
    }

    @Test
    public void connect_ssl_server_with_composite_trust_manager_for_self_signed_certificate_and_system_certificates() throws IOException {
        X509TrustManager compositeTrustManager = new HttpClients.CompositeX509TrustManager(
                AlternateTrustManager.trustManagerFor(AlternateTrustManager.makeJavaKeyStore(Paths.get("./wiremock.pem"))),
                systemTrustManager());
        OkHttpClient okHttpClient = httpClient(sslContext(null,
                                                          new TrustManager[]{compositeTrustManager}),
                                               compositeTrustManager)
                .newBuilder()
                .hostnameVerifier(HttpClients.allowAllHostname())
                .build();
        try (Response response = okHttpClient.newCall(new Request.Builder().get()
                                                                           .url(format("https://%s:%d",
                                                                                       "localhost",
                                                                                       wireMockRule.httpsPort()))
                                                                           .build())
                                             .execute()) {
            // successfully established connection
        }
        try (Response response = okHttpClient.newCall(new Request.Builder().get()
                                                                           .url("https://google.com")
                                                                           .build())
                                             .execute()) {
            // successfully established connection
        }
    }
}
