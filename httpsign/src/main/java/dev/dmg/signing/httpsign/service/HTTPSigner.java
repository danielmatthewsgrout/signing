package dev.dmg.signing.httpsign.service;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Map;

public interface HTTPSigner {

    public enum HTTPMethod {
        POST, PUT
    }

    public enum SignatureType {
        SHA26RSA("SHA256withRSA");

        private String algo;

        private SignatureType(String algo) {
            this.algo = algo;
        }

        public String getAlgo() {
            return algo;
        }
    }

    /*
     * @param URL the url to send - not null
     * 
     * @param HTTPMethod method to use - not null
     * 
     * @param data - body of request - this will be signed - not null
     * 
     * @param privateKey the pk to sign with - not null
     * 
     * @param signatureType the type of signature algo - not null
     * 
     * @param clientCertificates - if request requires extra certs - map of name and value of X509Certificate, else send null or empty map
     * 
     * @return an HTTP Response
     */
    public HttpResponse<String> signAndSend(String URL, HTTPMethod method, byte[] data, PrivateKey privateKey,
            SignatureType signatureType, Map<String, X509Certificate> clientCertificates, final Map<String,String> headers)
            throws IOException, GeneralSecurityException, InterruptedException;

}