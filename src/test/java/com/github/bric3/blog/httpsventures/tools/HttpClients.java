package com.github.bric3.blog.httpsventures.tools;

import okhttp3.Authenticator;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import javax.net.ssl.*;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

import static com.github.bric3.blog.httpsventures.tools.DebugDetector.debugging;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

public class HttpClients {

    public static final String BEARER_PREFIX = "Bearer ";
    public static final String AUTHORIZATION_HEADER = "Authorization";

    public static OkHttpClient trustAllHttpClient() {
        // Create an ssl socket context with our all-trusting manager
        return httpClient(sslContext(null,
                                     TrustAllX509TrustManager.ARRAY_INSTANCE),
                          TrustAllX509TrustManager.INSTANCE);
    }

    public static OkHttpClient httpClient(SSLContext sslContext, X509TrustManager trustManager) {
        return new OkHttpClient.Builder()
                .sslSocketFactory(sslContext.getSocketFactory(), trustManager)
                .connectTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .readTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .writeTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .build();
    }

    public static SSLContext sslContext(KeyManager[] keyManagers, TrustManager[] trustManagers) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers,
                            trustManagers,
                            null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException("Couldn't init TLS context", e);
        }
    }


//    private static X509KeyManager jksKeyManager(Path path, char[] pazzwort) {
//        try (InputStream fis = Files.newInputStream(path)) {
//            KeyStore jks = KeyStore.getInstance("JKS");
//            jks.load(fis, pazzwort);
//
//            KeyManagerFactory sunX509keyManager = KeyManagerFactory.getInstance("SunX509");
//            sunX509keyManager.init(jks, pazzwort);
//
//            KeyManager[] keyManagers = sunX509keyManager.getKeyManagers();
//            if (keyManagers.length != 1 || !(keyManagers[0] instanceof X509KeyManager)) {
//                throw new IllegalStateException("Unexpected default key managers:"
//                                                + Arrays.toString(keyManagers));
//            }
//            return (X509KeyManager) keyManagers[0];
//        } catch (IOException e) {
//            throw new UncheckedIOException(e);
//        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException e) {
//            throw new IllegalStateException("Couldn't init TLS with custom trust store '"
//                                            + path + "' and system trust manager", e);
//        }
//    }

    public static SSLContext trustAllSslContext() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null,
                            TrustAllX509TrustManager.ARRAY_INSTANCE,
                            null);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException("Couldn't init TLS with trust all X509 manager", e);
        }
    }


    public static X509TrustManager systemTrustManager() {
        TrustManager[] trustManagers = systemTrustManagerFactory().getTrustManagers();
        if (trustManagers.length != 1) {
            throw new IllegalStateException("Unexpected default trust managers:"
                                                    + Arrays.toString(trustManagers));
        }
        TrustManager trustManager = trustManagers[0];
        if (trustManager instanceof X509TrustManager) {
            return (X509TrustManager) trustManager;
        }
        throw new IllegalStateException("'" + trustManager + "' is not a X509TrustManager");
    }

    private static TrustManagerFactory systemTrustManagerFactory() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            return tmf;
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new IllegalStateException("Can't load default trust manager", e);
        }
    }

    public static OkHttpClient simpleHttpClient() {
        return new OkHttpClient.Builder()
                .connectTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .readTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .writeTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .build();
    }

    public static OkHttpClient trustAllAuthenticatingClient(Authenticator authenticator) {
        return new OkHttpClient.Builder()
                .sslSocketFactory(trustAllSslContext().getSocketFactory(), TrustAllX509TrustManager.INSTANCE)
                .hostnameVerifier(allowAllHostname())
                .authenticator(authenticator)
                .connectTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .readTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .writeTimeout(debugging() ? 0 : 10_000, MILLISECONDS)
                .build();
    }

    public static HostnameVerifier allowAllHostname() {
        return (hostname, sslSession) -> true;
    }

    public static X509TrustManager from(Path javaKeyStore, char[] password) {
        // Read the given trustStore (stored in a Java KeyStore format, JKS)
        try (InputStream inputStream = new BufferedInputStream(Files.newInputStream(javaKeyStore))) {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(inputStream, password);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());

            trustManagerFactory.init(ks);


            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            if (trustManagers.length != 1) {
                throw new IllegalStateException("Unexpected number of trust managers:"
                                                        + Arrays.toString(trustManagers));
            }
            return (X509TrustManager) trustManagers[0];
        } catch (IOException e) {
            throw new IllegalStateException("Couldn't init load key store", e);
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            throw new IllegalStateException("Couldn't init trust store", e);
        }
    }

    public abstract static class AlternateTrustManager implements X509TrustManager {
        public static X509TrustManager trustManagerFor(Path javaKeyStorePath, String password) {
            return trustManagerFor(readJavaKeyStore(javaKeyStorePath, password));
        }

        public static X509TrustManager trustManagerFor(KeyStore keyStore) {
            TrustManagerFactory tmf = trustManagerFactoryFor(keyStore);

            TrustManager[] trustManagers = tmf.getTrustManagers();
            if (trustManagers.length != 1) {
                throw new IllegalStateException("Unexpected number of trust managers:"
                                                        + Arrays.toString(trustManagers));
            }
            TrustManager trustManager = trustManagers[0];
            if (trustManager instanceof X509TrustManager) {
                return (X509TrustManager) trustManager;
            }
            throw new IllegalStateException("'" + trustManager + "' is not a X509TrustManager");
        }

        private static TrustManagerFactory trustManagerFactoryFor(KeyStore keyStore) {
            try {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(keyStore);
                return tmf;
            } catch (KeyStoreException | NoSuchAlgorithmException e) {
                throw new IllegalStateException("Can't load trust manager for keystore : " + keyStore, e);
            }
        }

        public static KeyStore readJavaKeyStore(Path javaKeyStorePath, String password) {
            try (InputStream inputStream = new BufferedInputStream(Files.newInputStream(javaKeyStorePath))) {
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(inputStream, password.toCharArray());
                return ks;
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
                throw new IllegalStateException(e);
            }
        }

    }

    public static class TrustAllX509TrustManager implements X509TrustManager {
        public static final X509TrustManager INSTANCE = new TrustAllX509TrustManager();
        public static final X509TrustManager[] ARRAY_INSTANCE = new X509TrustManager[]{INSTANCE};

        private TrustAllX509TrustManager() {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    public static class TrustSelfSignedX509TrustManager implements X509TrustManager {
        private X509TrustManager delegate;

        private TrustSelfSignedX509TrustManager(X509TrustManager delegate) {
            this.delegate = delegate;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            if (isSelfSigned(chain)) {
                return;
            }
            delegate.checkServerTrusted(chain, authType);
        }

        private boolean isSelfSigned(X509Certificate[] chain) {
            return chain.length == 1;
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }

        public static X509TrustManager wrap(X509TrustManager trustManager) {
            return new TrustSelfSignedX509TrustManager(trustManager);
        }
    }

    public interface OAuthAuthenticator extends Authenticator {
        Optional<String> acquireAccessToken();

        static String toBearer(String token) {
            return BEARER_PREFIX + token;
        }

        default int responseCount(Response response) {
            int result = 1;
            while ((response = response.priorResponse()) != null) {
                result++;
            }
            return result;
        }
    }
}
