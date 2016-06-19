package matthewsgrout.signing.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

/**
 * @author Daniel Matthews-Grout
 * 
 * Utilities for working with certificates and keys
 *
 */
public class CertificateTools {
	static {
		// load the provider on instantiation of the class
				Security.addProvider(new BouncyCastleProvider());
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
	public static AsymmetricKeyParameter loadRSAPrivateKey(byte[] keyBytes) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {		
		 try ( PEMParser pemParser =  new PEMParser(new InputStreamReader(new ByteArrayInputStream(keyBytes)))) {
			 Object o = pemParser.readObject();
			  if (o instanceof PEMKeyPair) {
		            try {
		                PEMKeyPair kp = (PEMKeyPair)o;
		               return PrivateKeyFactory.createKey(kp.getPrivateKeyInfo());
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
	
		AsymmetricKeyParameter pk=null;
		Certificate cert=null;
		 try ( PEMParser pemParser =  new PEMParser(new InputStreamReader(new ByteArrayInputStream(pemBytes)))) {
			        
	     //   JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
	        JcaX509CertificateConverter certconv = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
	        
	        for (Object o = pemParser.readObject(); o !=null; o=pemParser.readObject() ) {
	        	
	       // System.out.println("type: " + o.getClass().getName());
	        	  
	    
	        if (o instanceof PEMKeyPair) {
	            try {
	            	PEMKeyPair kp = (PEMKeyPair)o;
	                pk=PrivateKeyFactory.createKey(kp.getPrivateKeyInfo());
	            } catch (PEMException e) {
	                throw new RuntimeException("Failed to construct public/private key pair", e);
	            }
	       // } else if(o instanceof RSAPrivateCrtKey){
	          //       pk = (PrivateKey) o;
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
