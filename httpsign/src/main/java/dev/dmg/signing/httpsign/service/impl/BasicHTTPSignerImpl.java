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
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Map;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;

import dev.dmg.signing.httpsign.service.HTTPSigner;
import dev.dmg.signing.httpsign.service.SignData;

public class BasicHTTPSignerImpl implements HTTPSigner {
    private static HTTPSigner httpSigner;
    private final SignData signData;
    private static final String ENCODING = StandardCharsets.UTF_8.toString();
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
    public HttpResponse<String> signAndSend(String url, HTTPMethod method, byte[] data, PrivateKey signingKey,
            SignatureType signatureType, final Map<String, String> headers)
            throws IOException, GeneralSecurityException, InterruptedException {

        final String signature = Base64.getUrlEncoder()
                .encodeToString(signData.sign(data, signingKey, signatureType.getAlgo()));
        logger.fine("signature b64: " + signature);

        logger.fine("setting up http client");
        final HttpClient client = HttpClient.newBuilder().version(Version.HTTP_1_1)
                .authenticator(Authenticator.getDefault()).sslContext(SSLContext.getDefault()).build();

        logger.fine("payload is " + data.length + " body is: " + new String(data, ENCODING));
        logger.fine("using encoding: " + ENCODING);
        Builder build = HttpRequest.newBuilder().uri(URI.create(url)).setHeader("Signature", signature)
                .method(method.toString(), BodyPublishers.ofString(new String(data, ENCODING)));

        logger.fine("setting headers");
        for (String k : headers.keySet()) {
            String v = headers.get(k);
            logger.fine("header key: " + k + " value:" + v);
            build.setHeader(k, v);
        }

        logger.fine("sending");
        return client.send(build.build(), BodyHandlers.ofString());
    }
}