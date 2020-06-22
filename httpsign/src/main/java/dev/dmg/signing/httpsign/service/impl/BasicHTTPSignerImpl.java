package dev.dmg.signing.httpsign.service.impl;

import java.io.IOException;
import java.net.Authenticator;
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
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import java.util.logging.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import dev.dmg.signing.httpsign.service.HTTPSigner;
import dev.dmg.signing.httpsign.service.SignData;

public class BasicHTTPSignerImpl implements HTTPSigner {
    private static HTTPSigner httpSigner;
    private final SignData signData;
    private static final String ENCODING= StandardCharsets.UTF_8.toString();
    private static final Logger logger = Logger.getLogger(BasicHTTPSignerImpl.class.getName());

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
    public HttpResponse<String> signAndSend(final String url, final HTTPMethod method, final byte[] data, final PrivateKey privateKey,
    final SignatureType signatureType, final Map<String,X509Certificate> clientCertificates, final Map<String,String> headers)
            throws IOException, GeneralSecurityException, InterruptedException {
                        
        final String signature =  Base64.getUrlEncoder().encodeToString(signData.sign(data, privateKey, signatureType.getAlgo()));
     
        SSLContext ctx =SSLContext.getDefault();

        if (clientCertificates!=null&&clientCertificates.size()>0) {  //Build an SSL context to use our pinned certificate
            TrustManagerFactory tmf = TrustManagerFactory
            .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore ks = KeyStore.getInstance("SunX509");
            ks.load(null); 
             for (String certName:clientCertificates.keySet()) {
                ks.setCertificateEntry(certName,clientCertificates.get(certName));
            }
            tmf.init(ks);
            ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
        }

        final HttpClient 
        client = HttpClient.newBuilder()
        .version(Version.HTTP_1_1)
        .authenticator(Authenticator.getDefault())
        .sslContext(ctx) 
        .build();

        Builder build = HttpRequest.newBuilder()
        .uri(URI.create(url))
        .setHeader("Signature", signature)
        .method(method.toString(),BodyPublishers.ofString(new String(data,ENCODING)));

        for(String k:headers.keySet()){
            build.setHeader(k, headers.get(k));
        }

        final HttpRequest req = build.build();

        return  client.send(req,  BodyHandlers.ofString());
    }
}