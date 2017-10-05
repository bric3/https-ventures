package com.github.bric3.blog.httpsventures;

import okhttp3.OkHttpClient;
import okhttp3.Request;

import java.io.IOException;

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
            new OkHttpClient().newCall(new Request.Builder().get().url("https://" + host + ":" + port).build()).execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
