package com.github.bric3.blog.httpsventures;

import com.github.tomakehurst.wiremock.WireMockServer;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

/*
echo -n | \
        /usr/local/opt/libressl/bin/openssl s_client -prexit -connect localhost:8443 2>&1 | \
        /usr/local/opt/libressl/bin/openssl x509
*/
public class HttpsServer {
    public static void main(String[] args) {
        WireMockServer wireMockServer = new WireMockServer(wireMockConfig().httpsPort(8443)
                                                                           .disableRequestJournal());
        wireMockServer.start();
    }
}
