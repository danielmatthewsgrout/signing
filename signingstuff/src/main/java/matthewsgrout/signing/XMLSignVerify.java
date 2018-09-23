package matthewsgrout.signing;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.xml.sax.SAXException;

public interface XMLSignVerify {
	public byte[] doSignXML(SignAlgorithm algo,boolean withComments,final PrivateKey key, X509Certificate certificate, final byte[] xmlKeyInfo,
			final byte[] xmlData)
			throws IOException, ParserConfigurationException, SAXException, XMLSecurityException, TransformerException, GeneralSecurityException;
	
	public boolean doVerifyXML(SignAlgorithm algo,final byte[] xmlData, X509Certificate certificate)
			throws IOException, ParserConfigurationException, SAXException, XMLSecurityException,
			GeneralSecurityException, XMLSignatureException;
}
