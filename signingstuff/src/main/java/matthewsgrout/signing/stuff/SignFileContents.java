package matthewsgrout.signing.stuff;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;

import matthewsgrout.signing.SignVerify;
import matthewsgrout.signing.impl.PKCS7SignVerifyImpl;
import matthewsgrout.signing.util.CertificateAndKey;
import matthewsgrout.signing.util.CertificateTools;

public class SignFileContents {
	private static final String SIGN_ALGO="SHA1withRSA";

	public static void main(String[] args) {
		
		System.out.println("Sign File Contents");
		System.out.println("------------------");
		
		//param 0 = path to certificate
		//param 1 = path to private key file base64 enc
		//param 2 = path to file to sign
		//param 3 = encapsulate
		//output = base64 encoded signature
		
		if (args.length<2) {
			showHelp();
		} else {
			try {
				
			boolean encap = Boolean.parseBoolean(args[4]);
			
			if (encap) System.out.println("using encapsulated signature");
			
			String pathToFile = args[3];
			byte[] data = Files.readAllBytes(new File(pathToFile).toPath());

				
				Certificate cert;
				PrivateKey privateKey;
				if (args[0].equalsIgnoreCase("separate")) {
					if (args.length !=5) {
						showHelp();
						return;
					}
					
					String pathToCert = args[1];
					String pathToPK = args[2];
					System.out.println("loading cert and key from files: " + pathToCert + " and " + pathToPK);
					byte[] certBytes = Files.readAllBytes(new File(pathToCert).toPath());
					byte[] keyBytes = Files.readAllBytes(new File(pathToPK).toPath());
					
					cert  = CertificateTools.loadX509Certificate(certBytes);
					privateKey = CertificateTools.loadRSAPrivateKey(keyBytes);
				} else if (args[0].equalsIgnoreCase("combined")) {
								
					if (args.length !=3) {
							showHelp();
							return;
					}
					String pem =args[1];
					
					System.out.println("loading cert and key from pem: " + pem);
					
					byte[] bytes = Files.readAllBytes(new File(pem).toPath());

					CertificateAndKey cak = CertificateTools.loadCombined(bytes);
					
					cert=cak.getCertificate();
					privateKey=cak.getKey();
				} else {
					showHelp();
					return;
				}
				SignVerify sv = new PKCS7SignVerifyImpl(SIGN_ALGO);
				System.out.println("signing file: " + pathToFile);
				byte[] signed = encap? sv.signEncapulsated(cert, data, privateKey):sv.signDetached(cert, data, privateKey);
				
				String base64 = Base64.encodeBase64String(signed);
				System.out.println("Result");
				System.out.println("------");
				System.out.println("");
				System.out.println(base64);
			} catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | OperatorCreationException | CMSException | PKCSException e) {
				e.printStackTrace();
			}	
		}
	}
	
	private static void showHelp()  {
		System.out.println("* Certificate and key files must be in pem format");
		System.out.println("* Pem files must not use passsword in this version");
		System.out.println("* Signatures will be PKCS#7 using " + SIGN_ALGO + " encoded in Base64");
		System.out.println("---");
		System.out.println("Usage: SignFileContents separate <path to certificate> <path to private key> <path to data to sign> <encapsulate true or false>");
//		System.out.println("or:    SignFileContents pkcs12 <path to PKCS12> <cert alias> <key alias> <path to data to sign> <encapsulate true or false>");
		System.out.println("or:    SignFileContents combined <path to pem> <path to data to sign> <encapsulate true or false>");

	}

}
