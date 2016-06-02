package matthewsgrout.signing.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * @author Daniel Matthews-Grout
 * 
 * Utilities for working with certificates and keys
 *
 */
@SuppressWarnings("deprecation")
public class CertificateTools {

	private static final Random ran = new SecureRandom();
	/**
	 * Generates a certificate and private key
	 * 
	 * 
	 * @param signatureAlgorithm
	 * @param keyAlgorithm
	 * @return an instance CertificateAndKey with the right bits
	 * @throws CertificateEncodingException
	 * @throws InvalidKeyException
	 * @throws IllegalStateException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 */
	public static CertificateAndKey generateCertAndKey(String signatureAlgorithm, String keyAlgorithm) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException {
	
		// load the provider on instantiation of the class
		Security.addProvider(new BouncyCastleProvider());
		
		Calendar cal = Calendar.getInstance();
		Date startDate = cal.getTime();                // time from which certificate is valid
		cal.add(Calendar.YEAR, 10);
		Date expiryDate = cal.getTime();               // time after which certificate is not valid
		long l = ran.nextLong();
		BigInteger serialNumber = BigInteger.valueOf(l<0?l*-1:l);       // serial number for certificate
		KeyPair keyPair = KeyPairGenerator.EC.getInstance(keyAlgorithm).generateKeyPair();        // EC public/private key pair
		
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();		
		X500Principal              dnName = new X500Principal("CN=Test CA Certificate");
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(dnName);
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(dnName);                       // note: same as issuer
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm(signatureAlgorithm);
	
		
		X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");
		 
		return new CertificateAndKey(cert, keyPair.getPrivate());
		
	}
	
	/**
	 * Loads a certificate from a file
	 * 
	 * @param file path to the certificate to load
	 * @return an instance of Certificate loaded from the file
	 * @throws IOException
	 * @throws CertificateException
	 */
	public static Certificate loadX509Certificate(Path file) throws IOException, CertificateException {
		
		byte[] data = Files.readAllBytes(file);
		
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		
		return certFactory.generateCertificate(new ByteArrayInputStream(data));
	}
	
	
	/**
	 * Loads a private key from a file
	 * 
	 * @param file path to a file containing the private key in PKCS8
	 * @return an instance of PrivateKey based on the file passed
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static PrivateKey loadRSAPrivateKey(Path file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		byte[] keyBytes = Files.readAllBytes(file);
		
		 PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
		
	}
}
