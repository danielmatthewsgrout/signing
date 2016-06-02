package matthewsgrout.signing.impl;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import matthewsgrout.signing.SignVerify;

public class PKCS7SignVerifyImpl implements SignVerify {
	private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
	private static final String PROVIDER = "BC";

	public PKCS7SignVerifyImpl() {
		// load the provider on instantiation of the class
		Security.addProvider(new BouncyCastleProvider());
	}

	public byte[] signDetached(Certificate cert, byte[] data, PrivateKey key)
			throws OperatorCreationException, CertificateEncodingException, CMSException, IOException {
		return this.sign(false, data, cert, key);
	}

	public byte[] signEncapulsated(Certificate cert, byte[] data, PrivateKey key)
			throws OperatorCreationException, CertificateEncodingException, CMSException, IOException {
		return this.sign(true, data, cert, key);
	}

	public boolean verifyDetached(byte[] signature, byte[] body) throws OperatorCreationException, CertificateException, CMSException  {
	       return this.verifiy(signature, body);   
	}

	public boolean verifyEncapsulated(byte[] signature) throws OperatorCreationException, CertificateException, CMSException {
		return this.verifiy(signature, null);   
	}

	private byte[] sign(boolean encapulate, byte[] data, Certificate cert, PrivateKey key)
			throws OperatorCreationException, CertificateEncodingException, CMSException, IOException {

		KeyPair kp = new KeyPair(cert.getPublicKey(), key);

		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		// get our signer!
		ContentSigner sha1Signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER)
				.build(kp.getPrivate());
		// add the signing info to the signature
		JcaSignerInfoGeneratorBuilder sigBuilder = new JcaSignerInfoGeneratorBuilder(
				new JcaDigestCalculatorProviderBuilder().setProvider(PROVIDER).build());

		SignerInfoGenerator sig = sigBuilder.build(sha1Signer, (X509Certificate) cert);
		gen.addSignerInfoGenerator(sig);
		// add the certificates to the signature information
		gen.addCertificates(new JcaCertStore(Arrays.asList(new Certificate[] { cert })));
		// do the actual signing
		CMSSignedData sigData = gen.generate(new CMSProcessableByteArray(data), encapulate);
		// return Base64 encoded string
		return sigData.getEncoded();
	}

	@SuppressWarnings("unchecked")
	private boolean verifiy(byte[] signedData, byte[] originalData) throws OperatorCreationException, CertificateException, CMSException{
		// only include the data if it's passed - this is a private method so it
		// being null is indicitave of it being encapulsated in the signature
		CMSSignedData cms = originalData == null ? new CMSSignedData(signedData)
				: new CMSSignedData(new CMSProcessableByteArray(originalData), signedData);

		for (SignerInformation signer : (Collection<SignerInformation>) cms.getSignerInfos().getSigners())
			for (X509CertificateHolder certHolder : (Collection<X509CertificateHolder>) cms.getCertificates()
					.getMatches(signer.getSID()))
				if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(PROVIDER)
						.build(new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(certHolder))))
					return true;
		return false;
	}

}
