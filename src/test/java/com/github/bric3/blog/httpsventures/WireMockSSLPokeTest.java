package com.github.bric3.blog.httpsventures;

import com.github.bric3.blog.httpsventures.tools.HttpClients.TrustAllX509TrustManager;
import com.github.bric3.blog.httpsventures.tools.HttpClients.TrustSelfSignedX509TrustManager;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.junit.Rule;
import org.junit.Test;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URL;

import static com.github.bric3.blog.httpsventures.tools.HttpClients.allowAllHostname;
import static com.github.bric3.blog.httpsventures.tools.HttpClients.sslContext;
import static com.github.bric3.blog.httpsventures.tools.HttpClients.systemTrustManager;
import static com.github.bric3.blog.httpsventures.tools.HttpClients.trustAllSslContext;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

public class WireMockSSLPokeTest {

    @Rule
    public WireMockRule wireMock = new WireMockRule(wireMockConfig().dynamicPort()
                                                                    .dynamicHttpsPort());

    @Test
    public void ssl_poke_fails() throws IOException {
        new OkHttpClient.Builder().build()
                                  .newCall(new Request.Builder().get()
                                                                .url("https://localhost:" + wireMock.httpsPort())
                                                                .build())
                                  .execute();
    }

    @Test
    public void ssl_poke_using_trust_all_ssl_context() throws IOException {
        new OkHttpClient.Builder().sslSocketFactory(trustAllSslContext().getSocketFactory(),
                                                    TrustAllX509TrustManager.INSTANCE)
                                  .build()
                                  .newCall(new Request.Builder().get()
                                                                .url("https://localhost:" + wireMock.httpsPort())
                                                                .build())
                                  .execute();
    }

    @Test
    public void ssl_poke_using_trust_all_ssl_context_and_allow_all_hostname() throws IOException {
        new OkHttpClient.Builder().sslSocketFactory(trustAllSslContext().getSocketFactory(),
                                                    TrustAllX509TrustManager.INSTANCE)
                                  .hostnameVerifier(allowAllHostname())
                                  .build()
                                  .newCall(new Request.Builder().get()
                                                                .url("https://localhost:" + wireMock.httpsPort())
                                                                .build())
                                  .execute();
    }


    @Test
    public void ssl_poke_using_trust_self_signed_ssl_context_and_allow_all_hostname() throws IOException {
        X509TrustManager trustManager = TrustSelfSignedX509TrustManager.wrap(systemTrustManager());
        new OkHttpClient.Builder().sslSocketFactory(sslContext(null, new X509TrustManager[] {trustManager}).getSocketFactory(),
                                                    trustManager)
                                  .hostnameVerifier(allowAllHostname())
                                  .build()
                                  .newCall(new Request.Builder().get()
                                                                .url("https://localhost:" + wireMock.httpsPort())
                                                                .build())
                                  .execute();
    }


    @Test
    public void ssl_poke_using_trust_all_ssl_context_allow_all_hostname_with_url_connection() throws IOException {
        HostnameVerifier allHostsValid = (hostname, session) -> true;
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        HttpsURLConnection.setDefaultSSLSocketFactory(trustAllSslContext().getSocketFactory());
        new URL("https://localhost:" + wireMock.httpsPort()).openConnection().connect();
    }
}
