package matthewsgrout.signing.impl;

import java.io.IOException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAlgorithmProtection;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.bc.BcRSASignerInfoVerifierBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import matthewsgrout.signing.SignVerify;

/**
 * @author Daniel Matthews-Grout
 * 
 * 
 * PKCS7 implementation of the SignVerify interface
 *
 */
public class PKCS7SignVerifyImpl implements SignVerify {
	
	private static final Logger logger = Logger.getLogger(PKCS7SignVerifyImpl.class);
	private final String signatureAlgorithm;
	private final boolean verbose;
	public PKCS7SignVerifyImpl(String signatureAlgorithm,boolean verbose) {
		this.signatureAlgorithm=signatureAlgorithm;
		this.verbose=verbose;
		// load the provider on instantiation of the class
		Security.addProvider(new BouncyCastleProvider());
	}

	public byte[] signDetached(Certificate cert, byte[] data, AsymmetricKeyParameter key)
			throws OperatorCreationException, CertificateEncodingException, CMSException, IOException {
		return this.sign(false, data, cert, key);
	}

	public byte[] signEncapulsated(Certificate cert, byte[] data, AsymmetricKeyParameter key)
			throws OperatorCreationException, CertificateEncodingException, CMSException, IOException {
		return this.sign(true, data, cert, key);
	}

	public boolean verifyDetached(byte[] signature, byte[] body) throws OperatorCreationException, CertificateException, CMSException  {
	       return this.verifiy(signature, body);   
	}

	public boolean verifyEncapsulated(byte[] signature) throws OperatorCreationException, CertificateException, CMSException {
		return this.verifiy(signature, null);   
	}

	private byte[] sign(boolean encapulate, byte[] data, Certificate cert, AsymmetricKeyParameter key)
			throws OperatorCreationException, CertificateEncodingException, CMSException, IOException {
	    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
	    
	    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm);
	    AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

	    X509CertificateHolder ch=new X509CertificateHolder(cert.getEncoded());
	  
	    generator.addSignerInfoGenerator(new SignerInfoGeneratorBuilder(
	    		new BcDigestCalculatorProvider())
	    		.build( new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
	    		.build(key),ch));
	    
	    if (verbose) this.outputCertificateInformation(ch);
	
		generator.addCertificate(ch);

		CMSSignedData cms =generator.generate(new CMSProcessableByteArray(data), encapulate);
		
		if (verbose) outputCMSData(cms);

		// do the actual signing
		return cms.getEncoded();
	}

	@SuppressWarnings("unchecked")
	private boolean verifiy(byte[] signedData, byte[] originalData) throws OperatorCreationException, CertificateException, CMSException{
		// only include the data if it's passed - this is a private method so it
		// being null is indicative of it being encapsulated in the signature
		CMSSignedData cms = originalData == null ? new CMSSignedData(signedData) : new CMSSignedData(new CMSProcessableByteArray(originalData), signedData);
		
		if (verbose) outputCMSData(cms);
		
		for (SignerInformation signer : (Collection<SignerInformation>) cms.getSignerInfos().getSigners())
			for (X509CertificateHolder certHolder : (Collection<X509CertificateHolder>) cms.getCertificates().getMatches(signer.getSID())) {
				 BcRSASignerInfoVerifierBuilder bcr = new BcRSASignerInfoVerifierBuilder(new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(),
		                    new DefaultDigestAlgorithmIdentifierFinder(), new BcDigestCalculatorProvider());
				 
				 if (verbose) this.outputCertificateInformation(certHolder);
				 
				 if (signer.verify(bcr.build(certHolder))) return true;				
			}
		
		//no relevant information found
		return false;
	}

	private void outputCMSData(CMSSignedData csd) {
		AlgorithmNameFinder anf = new DefaultAlgorithmNameFinder();
		StringBuilder b=new StringBuilder();
		b.append("Version Number: ");
		b.append(csd.getVersion());
		b.append("\n");

		for (AlgorithmIdentifier aid: csd.getDigestAlgorithmIDs()) {
			b.append("Algorithm: ");
			b.append(aid.getAlgorithm());
			b.append("\n");
		}
		for (SignerInformation si : csd.getSignerInfos().getSigners()) {
			b.append("Digest Algo: ");
			b.append(si.getDigestAlgorithmID().getAlgorithm().getId());
			b.append("\n");
			b.append("Encryption Algo: ");
			b.append(si.getEncryptionAlgOID());
			b.append("\n");
			b.append("Content Type: ");
			b.append(si.getContentType());
			b.append("\n");
			if (si.getSignedAttributes()!=null)
			for (Attribute a : si.getSignedAttributes().toASN1Structure().getAttributes()) {
				b.append("Signed Attribute: ");
				b.append(a.getAttrType().getId());
				b.append("\n");
				for(ASN1Encodable e: a.getAttributeValues()) {
					
					if (e instanceof CMSAlgorithmProtection) {
						b.append("Algorithm: ");
						CMSAlgorithmProtection cap = (CMSAlgorithmProtection)e;
						b.append(anf.getAlgorithmName(cap.getDigestAlgorithm()));
						b.append("with");
						b.append(anf.getAlgorithmName(cap.getSignatureAlgorithm()));
					} else if (e instanceof Time) {
						b.append("Time: ");
						Time t = (Time)e;
						b.append(t.getDate());
					} else {
						b.append("Value: ");
						b.append(e.toASN1Primitive());
					}
					b.append("\n");
				}
			}
			if(si.getUnsignedAttributes()!=null)
			for (Attribute a : si.getUnsignedAttributes().toASN1Structure().getAttributes()) {
				b.append("Unsigned Attribute: ");
				b.append(a.getAttrType().getId());
				b.append("\n");
				for(ASN1Encodable e: a.getAttributeValues()) {
					b.append("Value: ");
					b.append(e);
					b.append("\n");
				}
			}		
		}
		
		logger.info("Signature information: \n" + b);
		
	}
	
	private void outputCertificateInformation(X509CertificateHolder cert) {
		StringBuilder b=new StringBuilder();
		b.append("Version Number: ");
		b.append(cert.getVersionNumber());
		b.append("\n");
		
		b.append("Issuer: ");
		b.append(cert.getIssuer());
		b.append("\n");
		
		b.append("Not After: ");
		b.append(cert.getNotAfter());
		b.append("\n");
		
		b.append("Not Before: ");
		b.append(cert.getNotBefore());
		b.append("\n");
		
		b.append("Serial Number: ");
		b.append(cert.getSerialNumber());
		b.append("\n");
		
		b.append("Signature: ");
		b.append(new String(Base64.encode(cert.getSignature())));
		b.append("\n");
		
		b.append("Subject: ");
		b.append(cert.getSubject());
		b.append("\n");
		
		b.append("Subject Public Key Info: ");
		b.append(cert.getSubjectPublicKeyInfo().getPublicKeyData());
		b.append("\n");
		
		
		logger.info("Certificate information: \n" + b);
	}

}
