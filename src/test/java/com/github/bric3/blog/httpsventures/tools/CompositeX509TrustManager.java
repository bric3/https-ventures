package com.github.bric3.blog.httpsventures.tools;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import com.google.common.collect.ImmutableList;

/**
 * Represents an ordered list of {@link X509TrustManager}s with additive trust. If any one of the composed managers
 * trusts a certificate chain, then it is trusted by the composite manager.
 *
 * This is necessary because of the fine-print on {@link SSLContext#init}: Only the first instance of a particular key
 * and/or trust manager implementation type in the array is used. (For example, only the first
 * javax.net.ssl.X509KeyManager in the array will be used.)
 *
 * <pre><code>
 * try {
 *     KeyStore keystore; // Get your own keystore here
 *     SSLContext sslContext = SSLContext.getInstance("TLS");
 *     TrustManager[] tm = CompositeX509TrustManager.getTrustManagers(keystore);
 *     sslContext.init(null, tm, null);
 * } catch (NoSuchAlgorithmException | KeyManagementException e) {
 *     e.printStackTrace();
 * }
 * </code></pre>
 *
 *
 * @author codyaray
 * @since 4/22/2013
 * @see <a href="http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm">
 *     http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm
 *     </a>
 */
@SuppressWarnings("unused")
public class CompositeX509TrustManager implements X509TrustManager {

    private final List<X509TrustManager> trustManagers;

    public CompositeX509TrustManager(List<X509TrustManager> trustManagers) {
        this.trustManagers = ImmutableList.copyOf(trustManagers);
    }

    public CompositeX509TrustManager(KeyStore keystore) {

        this.trustManagers = ImmutableList.of(getDefaultTrustManager(), getTrustManager(keystore));

    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        for (X509TrustManager trustManager : trustManagers) {
            try {
                trustManager.checkClientTrusted(chain, authType);
                return; // someone trusts them. success!
            } catch (CertificateException e) {
                // maybe someone else will trust them
            }
        }
        throw new CertificateException("None of the TrustManagers trust this certificate chain");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        for (X509TrustManager trustManager : trustManagers) {
            try {
                trustManager.checkServerTrusted(chain, authType);
                return; // someone trusts them. success!
            } catch (CertificateException e) {
                // maybe someone else will trust them
            }
        }
        throw new CertificateException("None of the TrustManagers trust this certificate chain");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        ImmutableList.Builder<X509Certificate> certificates = ImmutableList.builder();
        for (X509TrustManager trustManager : trustManagers) {
            for (X509Certificate cert : trustManager.getAcceptedIssuers()) {
                certificates.add(cert);
            }
        }
        return  certificates.build().toArray(new X509Certificate[0]);
    }

    public static TrustManager[] getTrustManagers(KeyStore keyStore) {

        return new TrustManager[] { new CompositeX509TrustManager(keyStore) };

    }

    public static X509TrustManager getDefaultTrustManager() {

        return getTrustManager(null);

    }

    public static X509TrustManager getTrustManager(KeyStore keystore) {
        return getTrustManager(TrustManagerFactory.getDefaultAlgorithm(), keystore);

    }

    public static X509TrustManager getTrustManager(String algorithm, KeyStore keystore) {

        TrustManagerFactory factory;

        try {
            factory = TrustManagerFactory.getInstance(algorithm);
            factory.init(keystore);
            return (X509TrustManager) Arrays.stream(factory.getTrustManagers())
                                            .filter((X509TrustManager.class)::isInstance)
                                            .findFirst()
                                            .orElse(null);
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            e.printStackTrace();
        }

        return null;
    }

}
