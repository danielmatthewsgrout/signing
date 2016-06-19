package matthewsgrout.signing.util;

import java.security.cert.Certificate;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class CertificateAndKey {

	private Certificate certificate;
	private AsymmetricKeyParameter key;
	
	public CertificateAndKey(Certificate certificate, AsymmetricKeyParameter key) {
		this.certificate = certificate;
		this.key = key;
	}
	public Certificate getCertificate() {
		return certificate;
	}
	public AsymmetricKeyParameter getKey() {
		return key;
	}
	
}
