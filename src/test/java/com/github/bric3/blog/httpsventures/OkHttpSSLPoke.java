package com.github.bric3.blog.httpsventures;

import com.github.bric3.blog.httpsventures.tools.HttpClients.AlternateTrustManager;
import okhttp3.OkHttpClient;
import okhttp3.Request;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.nio.file.Paths;

import static com.github.bric3.blog.httpsventures.tools.HttpClients.sslContext;

public class OkHttpSSLPoke {

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: " + SSLPoke.class.getName() + " <host> <port>");
            System.exit(1);
        }
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        System.out.println(host + ":" + port);
        okhttp_poke(args[0], Integer.parseInt(args[1]));
    }

    private static void okhttp_poke(String host, int port) {
        try {
            X509TrustManager trustManager = AlternateTrustManager.trustManagerFor(AlternateTrustManager.readJavaKeyStore(Paths.get("./wiremock-truststore.jks"), "changeit"));
            new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext(null, new TrustManager[]{trustManager}).getSocketFactory(),
                                      trustManager)
                    .hostnameVerifier((hostname, sslSession) -> true)
                    .build()
                    .newCall(new Request.Builder().get()
                                                  .url("https://" + host + ":" + port)
                                                  .build())
                    .execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
