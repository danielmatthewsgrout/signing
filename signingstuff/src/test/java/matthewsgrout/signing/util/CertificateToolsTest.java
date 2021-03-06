package matthewsgrout.signing.util;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import com.google.common.io.ByteStreams;

import matthewsgrout.signing.SignAlgorithm;
import matthewsgrout.signing.SignVerify;
import matthewsgrout.signing.impl.PKCS7SignVerifyImpl;

public class CertificateToolsTest {
	private static final  String TEST_TEXT="The quick brown fox jumps over the lazy dog";
	private final SignVerify sv = new PKCS7SignVerifyImpl(SignAlgorithm.SHA1,true);

	//http://fm4dd.com/openssl/certexamples.htm
	
	@Test
	public void testLoadRSAPrivateKeyAndLoadX509Certificate() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, OperatorCreationException, CMSException {
		byte[] certBytes= ByteStreams.toByteArray(this.getClass().getClassLoader().getResourceAsStream("test.cert"));
		byte[] keyBytes = ByteStreams.toByteArray(this.getClass().getClassLoader().getResourceAsStream("test.key"));
		Certificate publicCertificate = CertificateTools.loadX509Certificate(certBytes);
		AsymmetricKeyParameter privateKey = CertificateTools.loadRSAPrivateKey(keyBytes);
		
		byte[] signed = sv.signEncapulsated(publicCertificate, TEST_TEXT.getBytes(), privateKey);
		
		assertTrue(sv.verifyEncapsulated(signed));
	}
	
	@Test 
	public void testLoadCombined() throws IOException, OperatorCreationException, CertificateException, CMSException, PKCSException {
		byte[] pem = ByteStreams.toByteArray(this.getClass().getClassLoader().getResourceAsStream("test.pem"));

		CertificateAndKey cak = CertificateTools.loadCombined(pem);
		
		byte[] signed = sv.signEncapulsated(cak.getCertificate(), TEST_TEXT.getBytes(), cak.getKey());
		String b64 = new String( Base64.encode(signed));
		assertTrue(sv.verifyEncapsulated(Base64.decode(b64.getBytes())));
		
		byte[] signed2 = sv.signDetached(cak.getCertificate(), TEST_TEXT.getBytes(), cak.getKey());
		String b642 = new String( Base64.encode(signed2));
		assertTrue(sv.verifyDetached(Base64.decode(b642.getBytes()),TEST_TEXT.getBytes()));
	}
		
}
