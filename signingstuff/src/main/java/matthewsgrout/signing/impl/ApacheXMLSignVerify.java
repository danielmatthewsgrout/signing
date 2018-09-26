package matthewsgrout.signing.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.operator.OperatorCreationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import matthewsgrout.signing.SignAlgorithm;
import matthewsgrout.signing.SignVerify;
import matthewsgrout.signing.XMLSignVerify;
import matthewsgrout.signing.util.XMLUtils;


public class ApacheXMLSignVerify implements XMLSignVerify {

	
	private final DocumentBuilderFactory documentBuilderFactory;

	private final TransformerFactory transformerFactory;

	private static final String W3C_DIGEST_ALGORITHM_URL = DigestMethod.SHA256;
	private static final String SIGNATURE_CONTAINER_NAMESPACE = "urn:iso:std:iso:20022:tech:xsd:head.001.001.01";
	private static final String[] SIGNATURE_CONTAINER_ELEMENT_PATH = new String[] { "AppHdr", "head:Sgntr" };

	public ApacheXMLSignVerify()
			throws IOException, TransformerConfigurationException, TransformerFactoryConfigurationError {

		Init.init();

		this.transformerFactory = TransformerFactory.newInstance();

		documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setIgnoringComments(false);
		documentBuilderFactory.setNamespaceAware(true);
	
		}

	public byte[] doSignXML(SignAlgorithm algo, boolean withComments, final AsymmetricKeyParameter key,final X509Certificate certificate,
			final byte[] xmlKeyInfo, final byte[] xmlData) throws IOException, ParserConfigurationException,
			SAXException, XMLSecurityException, TransformerException, GeneralSecurityException,CMSException,OperatorCreationException {
		
		final SignVerify sv = new PKCS7SignVerifyImpl(algo, false);

		final Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(xmlData));

		ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "");

		// Generate the digest for the XML document
		final XMLSignature xmlSignature = new XMLSignature(document, "", algo.internal,
				withComments ? Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS : Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);

		final SignedInfo signedInfo = generateDocumentDigest(document, xmlSignature, certificate, xmlKeyInfo);

		// Insert signature
		XMLUtils.extractElement(xmlSignature.getElement(), "SignatureValue")
			.setTextContent(Base64.encode(sv.signDetached(certificate,signedInfo.getCanonicalizedOctetStream(), key), 0));


		final StringWriter buffer = new StringWriter();

		//Perform transform
		final Transformer transformer = this.transformerFactory.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
		transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
		transformer.setOutputProperty(OutputKeys.INDENT, "no");
		transformer.setOutputProperty(OutputKeys.METHOD, "xml");
		transformer.transform(new DOMSource(document), new StreamResult(buffer));
		
		return buffer.toString().getBytes("UTF-8");
	}

	private SignedInfo generateDocumentDigest(final Document document, final XMLSignature signature,
			final X509Certificate certificate, final byte[] xmlKeyInfo) throws XMLSecurityException {

		//Attach signature to document
		final Element signatureParentElement = XMLUtils.buildElementPath(document, SIGNATURE_CONTAINER_ELEMENT_PATH,
				SIGNATURE_CONTAINER_NAMESPACE);
		signatureParentElement.appendChild(signature.getElement());

		// Create the transforms for the document
		final Transforms transforms = new Transforms(document);
		transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
		transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);

		signature.addDocument("", transforms, W3C_DIGEST_ALGORITHM_URL);

		//Add the certificate info
		if (xmlKeyInfo != null) {
			//Strip xml tags
			final String certificateDN = new String(xmlKeyInfo)
					.replaceAll(".*<X509SubjectName[^>]*>(.*)</X509SubjectName>.*", "$1");

			// Build the certificate identifier elements
			final Element x509SubjectNameElement = document.createElementNS(Constants.SignatureSpecNS,"X509SubjectName");
			x509SubjectNameElement.setTextContent(certificateDN);

			final Element x509DataElement = document.createElementNS(Constants.SignatureSpecNS, "X509Data");
			x509DataElement.appendChild(x509SubjectNameElement);

			if (certificate != null && certificate.getIssuerDN() != null && certificate.getSerialNumber() != null) {
				// Build the certificate issuer elements
				final Element x509IssuerNameElement = document.createElementNS(Constants.SignatureSpecNS, "X509IssuerName");
				x509IssuerNameElement.setTextContent(certificate.getIssuerDN().getName());

				final Element x509SerialNumberElement = document.createElementNS(Constants.SignatureSpecNS,"X509SerialNumber");
				x509SerialNumberElement.setTextContent(certificate.getSerialNumber().toString());

				final Element x509IssuerSerialElement = document.createElementNS(Constants.SignatureSpecNS, "X509IssuerSerial");
				x509IssuerSerialElement.appendChild(x509IssuerNameElement);
				x509IssuerSerialElement.appendChild(x509SerialNumberElement);

				x509DataElement.appendChild(x509IssuerSerialElement);
			}

			//Build the certificate data
			signature.getKeyInfo().add( new X509Data(x509DataElement, ""));
		}
		//Generate the signed info XML fragment
		final SignedInfo signedInfo = signature.getSignedInfo();
		signedInfo.generateDigestValues();

		return signedInfo;
	}

	public boolean doVerifyXML(SignAlgorithm algo, final byte[] xmlData, X509Certificate certificate)
			throws IOException, ParserConfigurationException, SAXException, XMLSecurityException,
			GeneralSecurityException, XMLSignatureException,CMSException,OperatorCreationException {

		documentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
		documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
		documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
		documentBuilderFactory.setXIncludeAware(false);
		documentBuilderFactory.setExpandEntityReferences(false);

		// Instantiate the document to be verified
		final Document document = documentBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(xmlData));

		// Find the enveloped signature element
		final Element signatureElement = XMLUtils.extractElementNS(document, Constants.SignatureSpecNS, "Signature");

		if (signatureElement == null) {
			throw new XMLSignatureException("No Signature element found in XML.");
		}

		// Create an XML signature object from the document
		ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "");

		final XMLSignature signature = new XMLSignature(signatureElement, "");

		// Fetch and add the certificate
		final KeyInfo keyInfo = signature.getKeyInfo();

		if (keyInfo == null) {
			throw new XMLSecurityException("No KeyInfo section found in XML signature.");
		}

		final X509Data x509Data = keyInfo.containsX509Data() ? keyInfo.itemX509Data(0) : null;

		if (x509Data == null) {
			throw new XMLSecurityException("No X509Data section found in XML signature.");
		}

		final String certificateDN = x509Data.containsSubjectName() ? x509Data.itemSubjectName(0).getSubjectName() : "";

		if (certificateDN == null || certificateDN.isEmpty()) {
			throw new XMLSecurityException("No certificate DN found in XML signature.");
		}

		final SignedInfo signedInfo = signature.getSignedInfo();

		if (signedInfo != null && signedInfo.verify()) {
			// Content matches the digest in the signed info, so now check the validity of the signed info itself
			final SignVerify sv = new PKCS7SignVerifyImpl(algo, false);
			return sv.verifyDetached(signature.getSignatureValue(), signedInfo.getCanonicalizedOctetStream(), certificate);
		} else {
			return false;
		}
	}
}
