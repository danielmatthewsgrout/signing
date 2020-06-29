package dev.dmg.signing.httpsign.service.impl;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import dev.dmg.signing.httpsign.service.HTTPSigner;
import dev.dmg.signing.httpsign.service.SignData;

public class BasicHTTPSignerImpl implements HTTPSigner {
    private static HTTPSigner httpSigner;
    private final SignData signData;
    private static final String ENCODING = StandardCharsets.UTF_8.toString();

    private BasicHTTPSignerImpl(SignData signData) {
        this.signData = signData;
    }

    /*
     * @param signData and instance of SignData interface
     * 
     * @return an instance of HTTPSigner
     */
    public static HTTPSigner getHttpSigner(final SignData signData) {
        if (httpSigner == null) {
            httpSigner = new BasicHTTPSignerImpl(signData);
        }
        return httpSigner;
    }

    @Override
    public HttpResponse<String> signAndSend(String url, HTTPMethod method, byte[] data, PrivateKey signingKey,
            SignatureType signatureType, final Map<String, String> headers, boolean disableSSLValidation, boolean verbose)
            throws IOException, GeneralSecurityException, InterruptedException {

        final String signature = Base64.getUrlEncoder()
                .encodeToString(signData.sign(data, signingKey, signatureType.getAlgo(),verbose));
         
       if (verbose) System.out.println("signature b64: " + signature);

        HttpClient client;
        if (disableSSLValidation) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());

            client = HttpClient.newBuilder().version(Version.HTTP_1_1).sslContext(sslContext).build();
        } else {
            client = HttpClient.newBuilder().version(Version.HTTP_1_1).build();
        }
       if (verbose) System.out.println("payload is " + data.length + " body is: " + new String(data, ENCODING));
       if (verbose) System.out.println("using encoding: " + ENCODING);
        Builder build = HttpRequest.newBuilder().uri(URI.create(url)).setHeader("Signature", signature)
                .method(method.toString(), BodyPublishers.ofString(new String(data, ENCODING)));

       if (verbose) System.out.println("setting headers");
        for (String k : headers.keySet()) {
            String v = headers.get(k);
           if (verbose) System.out.println("header key: " + k + " value:" + v);
            build.setHeader(k, v);
        }

       if (verbose) System.out.println("sending");
        return client.send(build.build(), BodyHandlers.ofString());
    }

    private static TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
        }
    } };
}