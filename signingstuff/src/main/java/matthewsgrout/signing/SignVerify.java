package matthewsgrout.signing;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.OperatorCreationException;

/**
 * @author Daniel Matthew-Grout
 *
 */
public interface SignVerify {

	/**
	 * Creates a signature based on input data and certificate and key.  Data is not encapsulated in the signature.
	 * 
	 * @param publicCertificate certificate for verifying signature
	 * @param data data to be signed
	 * @param privateKey private key of the certificate
	 * @return byte array of the signature data
	 * @throws OperatorCreationException
	 * @throws CertificateEncodingException
	 * @throws CMSException
	 * @throws IOException
	 */
	public byte[] signDetached(Certificate publicCertificate, byte[] data, AsymmetricKeyParameter privateKey)
			throws OperatorCreationException, CertificateEncodingException, CMSException, IOException;

	/**
	 * Creates a signature based on input data and certificate and key.  Data is encapsulated in the signature.
	 * @param publicCertificate certificate for verifying signature
	 * @param data the data to be signed and encapsulated
	 * @param privateKey private key for certificate
	 * @return byte array containing signature
	 * @throws OperatorCreationException
	 * @throws CertificateEncodingException
	 * @throws CMSException
	 * @throws IOException
	 */
	public byte[] signEncapulsated(Certificate publicCertificate, byte[] data, AsymmetricKeyParameter privateKey)
			throws OperatorCreationException, CertificateEncodingException, CMSException, IOException;

	/**
	 * Verifies a signature against original data
	 * 
	 * @param signature byte array of signature
	 * @param body byte array of original body
	 * @return true/false was signature verified
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws CMSException
	 */
	public boolean verifyDetached(byte[] signature, byte[] body) throws OperatorCreationException, CertificateException, CMSException ;

	/**
	 * Verifies a signature against the encapsulated data
	 * 
	 * @param signature byte array of signature
	 * @return true/false was signature verified
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws CMSException
	 */
	public boolean verifyEncapsulated(byte[] signature) throws OperatorCreationException, CertificateException, CMSException ;

}
