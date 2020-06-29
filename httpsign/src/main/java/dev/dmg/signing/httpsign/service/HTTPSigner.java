package dev.dmg.signing.httpsign.service;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Map;

public interface HTTPSigner {

    public enum HTTPMethod {
        POST, PUT
    }

    public enum SignatureType {
        SHA1("SHA1withRSA"), SHA256("SHA256withRSA"), SHA384("SHA384withRSA"), SHA512("SHA512withRSA");

        private String algo;

        private SignatureType(String algo) {
            this.algo = algo;
        }

        public String getAlgo() {
            return algo;
        }
    }

    /*
     * @param url the url to send - not null
     * 
     * @param HTTPMethod method to use - not null
     * 
     * @param data - body of request - this will be signed - not null
     * 
     * @param signingKey the pk to sign with - not null
     * 
     * @param signatureType the type of signature algo - not null
     * 
     * @param headers - map of key/value of headers to send in the request.
     * 
     * @parameter disableSSLValidation ronseal
     * 
     * @parameter verbose use verbose logging
     * 
     * @return an HTTP Response
     */
    public HttpResponse<String> signAndSend(String URL, HTTPMethod method, byte[] data, PrivateKey signingKey,
            SignatureType signatureType,final Map<String,String> headers,boolean disableSSLValidation, boolean verbose)
            throws IOException, GeneralSecurityException, InterruptedException;

}