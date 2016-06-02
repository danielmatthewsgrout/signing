package matthewsgrout.signing.util;

import java.security.PrivateKey;
import java.security.cert.Certificate;

public class CertificateAndKey {

	private Certificate certificate;
	private PrivateKey key;
	
	public CertificateAndKey(Certificate certificate, PrivateKey key) {
		this.certificate = certificate;
		this.key = key;
	}
	public Certificate getCertificate() {
		return certificate;
	}
	public PrivateKey getKey() {
		return key;
	}
	
}
