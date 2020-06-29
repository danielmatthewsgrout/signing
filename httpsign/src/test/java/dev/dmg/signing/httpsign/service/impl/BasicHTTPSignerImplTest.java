package dev.dmg.signing.httpsign.service.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockserver.integration.ClientAndServer.startClientAndServer;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.net.ssl.HttpsURLConnection;

import org.bouncycastle.operator.OperatorCreationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.logging.MockServerLogger;
import org.mockserver.mock.action.ExpectationResponseCallback;
import org.mockserver.model.Header;
import org.mockserver.model.HttpRequest;
import org.mockserver.socket.tls.KeyStoreFactory;

import dev.dmg.signing.httpsign.service.HTTPSigner;
import dev.dmg.signing.httpsign.service.HTTPSigner.HTTPMethod;
import dev.dmg.signing.httpsign.service.HTTPSigner.SignatureType;

public class BasicHTTPSignerImplTest {
    private MockServerClient cas;
    private   KeyPair kp ;
    @Before
    public void setup() throws IOException, KeyManagementException, NoSuchAlgorithmException, CertificateException,
            KeyStoreException, UnrecoverableKeyException, OperatorCreationException {

                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(1024);
              kp= kpg.generateKeyPair();
       HttpsURLConnection.setDefaultSSLSocketFactory(
                new KeyStoreFactory(new MockServerLogger()).sslContext().getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, sslSession) -> true);
        cas = startClientAndServer(8443);

        cas.when(request().withPath("/test")).respond(new ExpectationResponseCallback() {

            @Override
            public org.mockserver.model.HttpResponse handle(HttpRequest r) throws Exception {
                System.out.println("got request");

                for (Header h : r.getHeaderList()) {
                    System.out.println(h.toString());
                }

                System.out.println(r.getBodyAsString());

                if (verify(r.getHeader("Signature").get(0),r.getBodyAsRawBytes()))
                    return response().withBody(r.getBodyAsString()).withStatusCode(200);
                else
                    return response().withBody("bad signature").withStatusCode(403);

            }
        });

    }

    @After
    public void tearDown() {
        cas.stop();
    }

    private static final String testString = "this is a test";

    @Test
    public void testSignAndSend()
            throws IOException, GeneralSecurityException, InterruptedException, OperatorCreationException {
        System.out.println("testing sign and send");

        final Properties props = System.getProperties();
        props.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.TRUE.toString());
        final HTTPSigner httpSigner = BasicHTTPSignerImpl.getHttpSigner(BasicSignDataImpl.INSTANCE);
        byte[] data = testString.getBytes();

        Map<String, String> headersMap = new HashMap<>();
        headersMap.put("testKey1", "testValue1");
        headersMap.put("testKey2", "testValue2");

        HttpResponse<String> resp = httpSigner.signAndSend("https://localhost:8443/test", HTTPMethod.POST, data,
                kp.getPrivate(), SignatureType.SHA256, headersMap, true,true);

        System.out.println("Got response code: " + resp.statusCode());
        System.out.println("Got body: " + resp.body());
        assertEquals(200, resp.statusCode());
        assertTrue("Got: " + resp.body() + " wanted: " + testString, resp.body().equals(testString));
    }

  

    public boolean verify(String sign, byte[] data) throws KeyStoreException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, UnrecoverableEntryException {

        Signature signer = Signature.getInstance( SignatureType.SHA256.getAlgo());
        signer.initVerify(kp.getPublic());
        signer.update(data);
        System.out.println("verifying signature: " + sign );
        return signer.verify(Base64.getUrlDecoder().decode(sign));
    }

}