package matthewsgrout.signing.impl;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import matthewsgrout.signing.SignVerify;
import matthewsgrout.signing.util.CertificateAndKey;
import matthewsgrout.signing.util.CertificateTools;

public class PKCS7SignVerifyImplTest {

	private static final  String TEST_TEXT="The quick brown fox jumps over the lazy dog";
	private static final String SIGN_ALGO="SHA1withRSA";
	private static final String KEY_ALGO="RSA";

	@Test
	public void testSignDetached() throws InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, OperatorCreationException, CMSException, IOException, CertificateException {
	
		CertificateAndKey ck = CertificateTools.generateCertAndKey(SIGN_ALGO,KEY_ALGO);
		
		SignVerify sv = new PKCS7SignVerifyImpl(SIGN_ALGO);
		
		byte[] signed = sv.signDetached(ck.getCertificate(), TEST_TEXT.getBytes(), ck.getKey());

		assertTrue(sv.verifyDetached(signed, TEST_TEXT.getBytes()));
		String b64=new String(Base64.encode(signed),StandardCharsets.UTF_8);
		System.out.println(b64);
		byte[] decode = Base64.decode(b64.getBytes(StandardCharsets.UTF_8));
		assertTrue(sv.verifyDetached(decode, TEST_TEXT.getBytes()));
		assertTrue(sv.verifyDetached(signed, TEST_TEXT.getBytes()));
	}

	@Test
	public void testSignEncapulsated() throws OperatorCreationException, CMSException, IOException, CertificateException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException {
	CertificateAndKey ck = CertificateTools.generateCertAndKey(SIGN_ALGO,KEY_ALGO);
		
		SignVerify sv = new PKCS7SignVerifyImpl(SIGN_ALGO);
		
		byte[] signed = sv.signEncapulsated(ck.getCertificate(), TEST_TEXT.getBytes(), ck.getKey());
		String b64=new String(Base64.encode(signed),StandardCharsets.UTF_8);
		System.out.println(b64);
		byte[] decode = Base64.decode(b64.getBytes(StandardCharsets.UTF_8));
		assertTrue(sv.verifyEncapsulated(decode));
		assertTrue(sv.verifyEncapsulated(signed));
	}

}
