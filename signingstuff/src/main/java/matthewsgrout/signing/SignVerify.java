package matthewsgrout.signing;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

public interface SignVerify {

	public byte[] signDetached(Certificate publicCertificate, byte[] data, PrivateKey privateKey)
			throws OperatorCreationException, CertificateEncodingException, CMSException, IOException;

	public byte[] signEncapulsated(Certificate publicCertificate, byte[] data, PrivateKey privateKey)
			throws OperatorCreationException, CertificateEncodingException, CMSException, IOException;

	public boolean verifyDetached(byte[] signature, byte[] body) throws OperatorCreationException, CertificateException, CMSException ;

	public boolean verifyEncapsulated(byte[] signature) throws OperatorCreationException, CertificateException, CMSException ;

}
