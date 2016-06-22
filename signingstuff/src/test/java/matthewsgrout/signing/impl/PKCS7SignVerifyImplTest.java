package matthewsgrout.signing.impl;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import com.google.common.io.ByteStreams;

import matthewsgrout.signing.SignAlgorithm;
import matthewsgrout.signing.SignVerify;
import matthewsgrout.signing.util.CertificateAndKey;
import matthewsgrout.signing.util.CertificateTools;

public class PKCS7SignVerifyImplTest {


	@Test
	public void testSignDetached() throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, OperatorCreationException, CMSException, IOException, CertificateException, PKCSException {
		byte[] testData = ByteStreams.toByteArray(this.getClass().getClassLoader().getResourceAsStream("test.txt"));
		byte[] pem = ByteStreams.toByteArray(this.getClass().getClassLoader().getResourceAsStream("test.pem"));
		byte[] certBytes = ByteStreams.toByteArray(this.getClass().getClassLoader().getResourceAsStream("test.cert"));

		CertificateAndKey ck = CertificateTools.loadCombined(pem);
		for (SignAlgorithm a: SignAlgorithm.values()) {
			SignVerify sv = new PKCS7SignVerifyImpl(a,false);
			byte[] signed = sv.signDetached(ck.getCertificate(), testData, ck.getKey());
	
			assertTrue(sv.verifyDetached(signed, testData));
			String b64=new String(Base64.encode(signed));
			String url = URLEncoder.encode(b64, StandardCharsets.UTF_8.name());
	
			byte[] decode = Base64.decode(b64.getBytes());
			byte[] decodeURL = Base64.decode(URLDecoder.decode(url, StandardCharsets.UTF_8.name()).getBytes());
			assertTrue(sv.verifyDetached(decode, testData));
			assertTrue(sv.verifyDetached(signed, testData));
			assertTrue(sv.verifyDetached(decodeURL, testData));
			assertTrue(sv.verifyDetached(decode, testData,ck.getCertificate()));
			assertTrue(sv.verifyDetached(signed, testData,ck.getCertificate()));
			assertTrue(sv.verifyDetached(decodeURL, testData,ck.getCertificate()));
			
			Certificate cert = CertificateTools.loadX509Certificate(certBytes);
			
			assertTrue(sv.verifyDetached(decode, testData,cert));
			assertTrue(sv.verifyDetached(signed, testData,cert));
			assertTrue(sv.verifyDetached(decodeURL, testData,cert));
		}
	}

	@Test
	public void testSignEncapulsated() throws OperatorCreationException, CMSException, IOException, CertificateException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, PKCSException {
		byte[] pem = ByteStreams.toByteArray(this.getClass().getClassLoader().getResourceAsStream("test.pem"));
		byte[] testData = ByteStreams.toByteArray(this.getClass().getClassLoader().getResourceAsStream("test.txt"));
		byte[] certBytes = ByteStreams.toByteArray(this.getClass().getClassLoader().getResourceAsStream("test.cert"));

		CertificateAndKey ck = CertificateTools.loadCombined(pem);
		
		for (SignAlgorithm a: SignAlgorithm.values()) {
			SignVerify sv = new PKCS7SignVerifyImpl(a,false);
		
			byte[] signed = sv.signEncapulsated(ck.getCertificate(), testData, ck.getKey());
			String b64=new String(Base64.encode(signed));
			String url = URLEncoder.encode(b64, StandardCharsets.UTF_8.name());
	
			byte[] decode = Base64.decode(b64.getBytes());
			byte[] decodeURL = Base64.decode(URLDecoder.decode(url, StandardCharsets.UTF_8.name()).getBytes());
	
			assertTrue(sv.verifyEncapsulated(decode));
			assertTrue(sv.verifyEncapsulated(signed));
			assertTrue(sv.verifyEncapsulated(decodeURL));
			assertTrue(sv.verifyEncapsulated(decode,ck.getCertificate()));
			assertTrue(sv.verifyEncapsulated(signed,ck.getCertificate()));
			assertTrue(sv.verifyEncapsulated(decodeURL,ck.getCertificate()));
			Certificate cert = CertificateTools.loadX509Certificate(certBytes);
			
			assertTrue(sv.verifyEncapsulated(decode,cert));
			assertTrue(sv.verifyEncapsulated(signed,cert));
			assertTrue(sv.verifyEncapsulated(decodeURL,cert));
		}
	}
}
