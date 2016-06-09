package matthewsgrout.signing.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
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
		KeyPair keyPair = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();        // EC public/private key pair
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();		
		X500Principal dnName = new X500Principal("CN=Test CA Certificate");
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
	public static Certificate loadX509Certificate(byte[] certBytes) throws IOException, CertificateException {
		
		 try ( PEMParser pemParser =  new PEMParser(new InputStreamReader(new ByteArrayInputStream(certBytes)))) {
			 Object o = pemParser.readObject();
		        JcaX509CertificateConverter certconv = new JcaX509CertificateConverter().setProvider("BC");

		        if (o instanceof X509CertificateHolder) {
	                try {   
	                 return certconv.getCertificate((X509CertificateHolder) o);  
	                } catch (Exception e) {
	                    throw new RuntimeException("Failed to read X509 certificate", e);
	                }
			  } else {
	                throw new RuntimeException("no pair found");
			  }
		 }
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
	public static PrivateKey loadRSAPrivateKey(byte[] keyBytes) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {		
		
		 try ( PEMParser pemParser =  new PEMParser(new InputStreamReader(new ByteArrayInputStream(keyBytes)))) {
			 Object o = pemParser.readObject();
		        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

			  if (o instanceof PEMKeyPair) {
		            try {
		                KeyPair kp =  converter.getKeyPair((PEMKeyPair) o);
		               return kp.getPrivate();
		            } catch (PEMException e) {
		                throw new RuntimeException("Failed to construct public/private key pair", e);
		            }
			  } else {
	                throw new RuntimeException("no pair found");
			  }
		 }
	}
	
	/**
	 * Loads certificate and key from a pem file
	 * 
	 * @param pemBytes bytes of the file containing pem data
	 * @return instance of CertificateAndKey containing both
	 * @throws PKCSException
	 * @throws OperatorCreationException
	 * @throws IOException
	 */
	public static CertificateAndKey loadCombined(byte[] pemBytes) throws PKCSException, OperatorCreationException, IOException {
	
		PrivateKey pk=null;
		Certificate cert=null;
		 try ( PEMParser pemParser =  new PEMParser(new InputStreamReader(new ByteArrayInputStream(pemBytes)))) {
			        
	        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
	        JcaX509CertificateConverter certconv = new JcaX509CertificateConverter().setProvider("BC");
	        
	        for (Object o = pemParser.readObject(); o !=null; o=pemParser.readObject() ) {
	        	
	       // System.out.println("type: " + o.getClass().getName());
	        	  
	    
	        if (o instanceof PEMKeyPair) {
	            try {
	                KeyPair kp =  converter.getKeyPair((PEMKeyPair) o);
	                pk=kp.getPrivate();
	            } catch (PEMException e) {
	                throw new RuntimeException("Failed to construct public/private key pair", e);
	            }
	        } else if(o instanceof RSAPrivateCrtKey){
	                 pk = (PrivateKey) o;
	           } else if (o instanceof X509CertificateHolder) {
	                try {   
	                  cert= certconv.getCertificate((X509CertificateHolder) o);  
	                } catch (Exception e) {
	                    throw new RuntimeException("Failed to read X509 certificate", e);
	                }
	           }
	        }
			        
			return new CertificateAndKey(cert, pk);
		}
	}
}
