package com.github.bric3.blog.httpsventures;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.Rule;
import org.junit.Test;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.nio.file.Paths;

import static com.github.bric3.blog.httpsventures.tools.HttpClients.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static java.lang.String.format;

public class HttpsCustomCertificateJKSTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort()
                                                                        .keystorePath("./bric3-openssl.jks")
                                                                        .keystorePassword("the_password")
                                                                        .dynamicHttpsPort());

    @Test
    public void connect_ssl_server_with_composite_trust_manager_for_self_signed_certificate_and_system_certificates() throws IOException {
        X509TrustManager compositeTrustManager = new CompositeX509TrustManager(
                AlternateTrustManager.trustManagerFor(AlternateTrustManager.readJavaKeyStore(Paths.get("./bric3-openssl.jks"), "the_password")),
                systemTrustManager());
        OkHttpClient okHttpClient = httpClient(sslContext(null,
                                                          new TrustManager[]{compositeTrustManager}),
                                               compositeTrustManager)
                .newBuilder()
                .build();
        try (Response response = okHttpClient.newCall(new Request.Builder().get()
                                                                           .url(format("https://%s:%d",
                                                                                       "localhost",
                                                                                       wireMockRule.httpsPort()))
                                                                           .build())
                                             .execute()) {
            // successfully established connection
        }
//        try (Response response = okHttpClient.newCall(new Request.Builder().get()
//                                                                           .url("https://google.com")
//                                                                           .build())
//                                             .execute()) {
//            // successfully established connection
//        }
    }
}
