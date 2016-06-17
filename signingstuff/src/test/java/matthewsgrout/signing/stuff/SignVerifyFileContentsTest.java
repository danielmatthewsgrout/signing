package matthewsgrout.signing.stuff;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.Test;

public class SignVerifyFileContentsTest {

	@Test
	public void testMain() throws OperatorCreationException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException, CMSException, IOException, PKCSException {
		
		
		String[] args= new String[]{"-mode" ,"sign","-keyType","combined", "-hash","SHA1", 
				"-certAndKeyFile","src/test/resources/test.pem", "-in","src/test/resources/test.txt","-det"
		};
		
		//sign the test data
		SignVerifyFileContents.main(args);
		
		
		String[] args2= new String[]{"-mode" ,"verify","-keyType","combined", "-hash","SHA1", 
				"-certAndKeyFile","src/test/resources/test.pem", "-in","src/test/resources/test.txt","-det",
				"-sig","src/test/resources/test.sign"
		};
	
		//verify the test signature
		SignVerifyFileContents.main(args2);
		
	}

}
