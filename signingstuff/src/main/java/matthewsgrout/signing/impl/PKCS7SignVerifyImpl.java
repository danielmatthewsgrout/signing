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
import java.util.Calendar;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import matthewsgrout.signing.SignVerify;

/**
 * @author Daniel Matthews-Grout
 * 
 * 
 * PKCS7 implementation of the SignVerify interface
 *
 */
public class PKCS7SignVerifyImpl implements SignVerify {
	private final String signatureAlgorithm;
	private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

	public PKCS7SignVerifyImpl(String signatureAlgorithm) {
		this.signatureAlgorithm=signatureAlgorithm;
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


		   /* Construct signed attributes */
	    ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
	    signedAttributes.add(new Attribute(CMSAttributes.contentType, new DERSet(new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId()))));
	    signedAttributes.add(new Attribute(CMSAttributes.signingTime, new DERSet(new DERUTCTime(Calendar.getInstance().getTime()))));

	    
	    
	    AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
	    signedAttributesTable.toASN1EncodableVector();
	    DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributesTable);

	    SignerInfoGeneratorBuilder signerInfoBuilder = new SignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
	    signerInfoBuilder.setSignedAttributeGenerator(signedAttributeGenerator);
	    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
	    JcaContentSignerBuilder contentSigner = new JcaContentSignerBuilder(signatureAlgorithm);
	    contentSigner.setProvider(PROVIDER);

	    generator.addSignerInfoGenerator(signerInfoBuilder.build(contentSigner.build(key), new X509CertificateHolder(cert.getEncoded())));

		// add the certificates to the signature information
	    generator.addCertificates(new JcaCertStore(Arrays.asList(new Certificate[] { cert })));
		// do the actual signing
		CMSSignedData sigData = generator.generate(new CMSProcessableByteArray(data), encapulate);
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
