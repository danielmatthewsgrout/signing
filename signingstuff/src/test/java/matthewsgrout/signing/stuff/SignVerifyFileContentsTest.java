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
		
		String[] args2= new String[]{"-mode" ,"verify","-keyType","combined", "-hash","SHA1", 
				"-certAndKeyFile","src/test/resources/test.pem", "-in","src/test/resources/test.txt","-det",
				"-sig","src/test/resources/test.sign"
		};
	
		String[] args3= new String[]{"-mode" ,"sign","-keyType","combined", "-hash","SHA1", 
				"-certAndKeyFile","src/test/resources/test.pem", "-in","src/test/resources/test.txt",
				"-det","-url"
		};
	
		String[] args4= new String[]{"-mode" ,"sign","-keyType","combined", "-hash","SHA1", 
				"-certAndKeyFile","src/test/resources/test.pem", "-in","src/test/resources/test.txt",
				"-det","-url","-v"
		};
		
		String[] args5= new String[]{"-mode" ,"verify", "-hash","SHA1", "-in","src/test/resources/test.txt","-det",
				"-sig","src/test/resources/test.sign"};

		
		String[] args6= new String[]{"-mode" ,"verify","-keyType","separate", "-hash","SHA1", 
				"-certFile","src/test/resources/test.cert", "-in","src/test/resources/test.txt","-det",
				"-sig","src/test/resources/test.sign"};
		
		SignVerifyFileContents.main(args);
		SignVerifyFileContents.main(args2);
		SignVerifyFileContents.main(args3);
		SignVerifyFileContents.main(args4);
		SignVerifyFileContents.main(args5);
		SignVerifyFileContents.main(args6);
	}

}
