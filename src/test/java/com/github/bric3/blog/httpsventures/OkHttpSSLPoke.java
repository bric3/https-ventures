package com.github.bric3.blog.httpsventures;

import com.github.bric3.blog.httpsventures.tools.HttpClients.AlternateTrustManager;
import okhttp3.OkHttpClient;
import okhttp3.Request;

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

        okhttp_poke(args[0], Integer.parseInt(args[1]));
        okhttp_poke_load_keystore(args[0], Integer.parseInt(args[1]));
        okhttp_poke_load_certificate(args[0], Integer.parseInt(args[1]));
    }

    private static void okhttp_poke(String host, int port) {
        try {
            new OkHttpClient.Builder().hostnameVerifier((hostname, sslSession) -> true)
                    .build()
                    .newCall(new Request.Builder().get()
                                                  .url("https://" + host + ":" + port)
                                                  .build())
                    .execute();
            System.out.println("basic : " + host + ":" + port + " => OK");
        } catch (IOException e) {
            System.err.println("basic : " + host + ":" + port + " => ERROR");
            e.printStackTrace(System.err);
        }
    }


    private static void okhttp_poke_load_keystore(String host, int port) {
        try {
            X509TrustManager trustManager = AlternateTrustManager.trustManagerFor(AlternateTrustManager.readJavaKeyStore(Paths.get("./wiremock-truststore.jks"), "changeit"));
            new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext(null, new X509TrustManager[]{trustManager}).getSocketFactory(),
                                      trustManager)
                    .hostnameVerifier((hostname, sslSession) -> true)
                    .build()
                    .newCall(new Request.Builder().get()
                                                  .url("https://" + host + ":" + port)
                                                  .build())
                    .execute();
            System.out.println("loading keystore : " + host + ":" + port + " => OK");
        } catch (IOException e) {
            System.err.println("loading keystore : " + host + ":" + port + " => ERROR");
            e.printStackTrace(System.err);
        }
    }

    private static void okhttp_poke_load_certificate(String host, int port) {
        try {
            X509TrustManager trustManager = AlternateTrustManager.trustManagerFor(AlternateTrustManager.makeJavaKeyStore(Paths.get("./wiremock.der")));
            new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext(null, new X509TrustManager[]{trustManager}).getSocketFactory(),
                                      trustManager)
                    .hostnameVerifier((hostname, sslSession) -> true)
                    .build()
                    .newCall(new Request.Builder().get()
                                                  .url("https://" + host + ":" + port)
                                                  .build())
                    .execute();
            System.out.println("loading certificate : " + host + ":" + port + " => OK");
        } catch (IOException e) {
            System.err.println("loading certificate : " + host + ":" + port + " => ERROR");
            e.printStackTrace(System.err);
        }
    }
}
