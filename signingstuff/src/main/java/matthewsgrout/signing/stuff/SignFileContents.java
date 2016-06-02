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

import matthewsgrout.signing.SignVerify;
import matthewsgrout.signing.impl.PKCS7SignVerifyImpl;
import matthewsgrout.signing.util.CertificateTools;

public class SignFileContents {
	private static final String SIGN_ALGO="SHA1withRSA";

	public static void main(String[] args) {
		
		System.out.println("Sign File Contents");
		System.out.println("------------------");
		System.out.println("");
		
		//param 0 = path to certificate
		//param 1 = path to private key file base64 enc
		//param 2 = path to file to sign
		//param 3 = encapsulate
		//output = base64 encoded signature
		
		if (args.length!=4) {
			showHelp();
		} else {
			
			String pathToCert = args[0];
			String pathToPK = args[1];
			String pathToFile = args[2];
			boolean encap = Boolean.parseBoolean(args[3]);
			
			if (encap) System.out.println("using encapsulated signature");
			
			try {
				byte[] data = Files.readAllBytes(new File(pathToFile).toPath());
				Certificate cert  = CertificateTools.loadX509Certificate(new File(pathToCert).toPath());
				PrivateKey privateKey = CertificateTools.loadRSAPrivateKey(new File(pathToPK).toPath());
				
				SignVerify sv = new PKCS7SignVerifyImpl(SIGN_ALGO);
				
				byte[] signed = encap? sv.signEncapulsated(cert, data, privateKey):sv.signDetached(cert, data, privateKey);
				
				String base64 = Base64.encodeBase64String(signed);
				
				System.out.println(base64);
				
			} catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | OperatorCreationException | CMSException e) {
				e.printStackTrace();
			}
		}
	}
	
	private static void showHelp()  {
		System.out.println("Usage: SignFileContents <path to certificate> <path to private key> <path to data to sign> <encapsulate true or false>");
	}

}
