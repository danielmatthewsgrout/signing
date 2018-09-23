// Copyright (c) 2013 VocaLink Ltd
package matthewsgrout.signing.util;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Provides common XML handling functionality.
 */
public final class XMLUtils {
    /**
     * The character set encoding used for XML to byte-stream conversions (and back again).
     */
    public static final String XML_CHARSET = "UTF-8";

    /**
     * The digest method used as part of the XML signing process.
     */
    public static final String XML_DIGEST_NAME = "SHA-256";

    /**
     * The W3C URI for the digest method used as part of the XML signing process.
     */
    public static final String W3C_XML_DIGEST_NAME = DigestMethod.SHA256;

    /**
     * The canonicalisation method used when signing or verifying XML.
     */
    public static final String XML_CANONICALISATION_NAME = Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;

    /**
     * The W3C URI for the canonicalisation method used when signing or verifying XML.
     */
    public static final String W3C_XML_CANONICALISATION_NAME = CanonicalizationMethod.INCLUSIVE;

    private static final String ANY_NAMESPACE = "*";

    private static final String XML_NAMESPACE = "http://www.w3.org/2000/xmlns/";

    private static final ThreadLocal<Map<String, Canonicalizer>> CANONICALISER_CACHE = new ThreadLocal<Map<String, Canonicalizer>>();

    private XMLUtils() {
    }

    /**
     * Normalises a block of XML according to the W3C canonicalisation rules.
     * @param rawXML The XMl to normalise.
     * @return The normalised XML.
     * @see XMLUtils#XML_CANONICALISATION_NAME The default canonicalisation algorithm.
     * @throws IOException If there is a problem normalising the XML.
     */
    public static byte[] normaliseXML(final byte[] rawXML) throws IOException {
        return normaliseXML(rawXML, XML_CANONICALISATION_NAME);
    }

    /**
     * Normalises a block of XML according to the W3C canonicalisation rules.
     * @param rawXML The XMl to normalise.
     * @param algorithm The name of the canonicalisation algorithm to use.
     * @return The normalised XML.
     * @throws IOException If there is a problem normalising the XML.
     */
    public static byte[] normaliseXML(final byte[] rawXML, final String algorithm) throws IOException {
        try {
            final Canonicalizer canonicalizer = getCanonicalizer(algorithm);
            return canonicalizer.canonicalize(rawXML);
        } catch (SAXException exception) {
            throw new IOException("XML could not be parsed - " + exception);
        } catch (CanonicalizationException exception) {
            throw new IOException("XML could not be canonicalised - " + exception);
        } catch (ParserConfigurationException exception) {
            throw new IOException("Unable to set up the XML parser.", exception);
        } catch (InvalidCanonicalizerException exception) {
            throw new IOException("Unable to set up the XML canonicalisation using " + algorithm + " algorithm.", exception);
        }
    }

    private static Canonicalizer getCanonicalizer(final String canonicalisationName) throws InvalidCanonicalizerException {
        // Fetch the set of configured canonicalisers for this thread
        Map<String, Canonicalizer> canonicaliserMap = CANONICALISER_CACHE.get();
        if (canonicaliserMap == null) {
            canonicaliserMap = new HashMap<String, Canonicalizer>();
            CANONICALISER_CACHE.set(canonicaliserMap);
        }

        Canonicalizer canonicaliser = canonicaliserMap.get(canonicalisationName);
        if (canonicaliser == null) {
            synchronized (Init.class) {
                // Set up the XML normaliser components
                if (!Init.isInitialized()) {
                    Init.init();
                }
            }
            canonicaliser = Canonicalizer.getInstance(canonicalisationName);
            canonicaliserMap.put(canonicalisationName, canonicaliser);
        }
        return canonicaliser;
    }

    /**
     * Normalises a block of XML and calculates the digest, using the default algorithms.
     * @param xmlData The XML.
     * @return The digest.
     * @see XMLUtils#XML_CANONICALISATION_NAME The default canonicalisation algorithm.
     * @see XMLUtils#XML_DIGEST_NAME The default digest algorithm.
     * @see XMLUtils#normaliseXML(byte[])
     * @throws IOException If there is a problem reading or digesting the XML.
     */
    public static byte[] normaliseAndDigest(final byte[] xmlData) throws IOException {
        return normaliseAndDigest(xmlData, XML_CANONICALISATION_NAME, XML_DIGEST_NAME);
    }

    /**
     * Normalises a block of XML and calculates the digest.
     * @param xmlData The XML.
     * @param canonicalisationAlgorithm The name of the canonicalisation algorithm to use.
     * @param digestAlgorithm The name of the digest algorithm to use.
     * @return The digest.
     * @see XMLUtils#normaliseXML(byte[])
     * @throws IOException If there is a problem reading or digesting the XML.
     */
    public static byte[] normaliseAndDigest(final byte[] xmlData, final String canonicalisationAlgorithm, final String digestAlgorithm) throws IOException {
        try {
            final MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
            digest.update(XMLUtils.normaliseXML(xmlData, canonicalisationAlgorithm));
            return digest.digest();
        } catch (NoSuchAlgorithmException exception) {
            throw new IOException("Unable to digest the XML using " + digestAlgorithm + " algorithm.", exception);
        }
    }

    /**
     * Extracts the text from an element within an XML document.
     * @param document The parsed XML document.
     * @param elementPath The path to the element (intermediate elements may be omitted).
     * @return The element text, or null if the element denoted by the path was not found.
     */
    public static String extractElementText(final Document document, final String... elementPath) {
        return extractElementTextNS(document, null, elementPath);
    }

    /**
     * Extracts the text from an element within an XML document.
     * @param document The parsed XML document.
     * @param namespace The XML namespace to search within, or null to find elements in any namespace.
     * @param elementPath The path to the element (intermediate elements may be omitted).
     * @return The element text, or null if the element denoted by the path was not found.
     */
    public static String extractElementTextNS(final Document document, final String namespace, final String... elementPath) {
        final Element element = extractElementNS(document, namespace, elementPath);
        if (element != null) {
            return element.getTextContent();
        } else {
            return null;
        }
    }

    /**
     * Extracts an element within an XML document.
     * @param document The parsed XML document.
     * @param elementPath The path to the element (intermediate elements may be omitted).
     * @return The element, or null if the element denoted by the path was not found.
     */
    public static Element extractElement(final Document document, final String... elementPath) {
        return extractElementNS(document, null, elementPath);
    }

    /**
     * Extracts an element within an XML document.
     * @param document The parsed XML document.
     * @param namespace The XML namespace to search within, or null to find elements in any namespace.
     * @param elementPath The path to the element (intermediate elements may be omitted).
     * @return The element, or null if the element denoted by the path was not found.
     */
    public static Element extractElementNS(final Document document, final String namespace, final String... elementPath) {
        return extractElementNS(document.getDocumentElement(), namespace, elementPath);
    }

    /**
     * Extracts an element within an XML document.
     * @param document The parsed XML document.
     * @param namespace The XML namespace for the final element, or null to find elements in any namespace.
     * @param elementPath The path to the element (intermediate elements may be omitted).
     * @return The element, or null if the element denoted by the path was not found.
     */
    public static Element extractElementWithFinalNS(final Document document, final String namespace, final String... elementPath) {
        if (elementPath != null && elementPath.length > 1) {
            final String[] elementSearchPath = Arrays.copyOfRange(elementPath, 0, elementPath.length - 1);
            final Element elementSearchRoot = extractElementNS(document, null, elementSearchPath);
            return extractElementNS(elementSearchRoot, namespace, elementPath[elementPath.length - 1]);
        } else {
            return extractElementNS(document.getDocumentElement(), namespace, elementPath);
        }
    }

    /**
     * Extracts an element within another XML element.
     * @param rootElement The root XML element.
     * @param elementPath The path to the element (intermediate elements may be omitted).
     * @return The element, or null if the element denoted by the path was not found.
     */
    public static Element extractElement(final Element rootElement, final String... elementPath) {
        return extractElementNS(rootElement, null, elementPath);
    }

    /**
     * Extracts an element within another XML element.
     * @param rootElement The root XML element.
     * @param namespace The XML namespace to search within, or null to find elements in any namespace.
     * @param elementPath The path to the element (intermediate elements may be omitted).
     * @return The element, or null if the element denoted by the path was not found.
     */
    public static Element extractElementNS(final Element rootElement, final String namespace, final String... elementPath) {
        return extractElementNS(rootElement, namespace, false, elementPath);
    }

    /**
     * Extracts an element within another XML element.
     * @param rootElement The root XML element.
     * @param namespace The XML namespace to search within, or null to find elements in any namespace.
     * @param elementPath The path to the element (intermediate elements may be omitted).
     * @param reverseSearch True to search backwards through the document, false otherwise.
     * @return The element, or null if the element denoted by the path was not found.
     */
    public static Element extractElementNS(final Element rootElement, final String namespace, final boolean reverseSearch, final String... elementPath) {
        final String sanitisedNamespace = (namespace != null) ? namespace : ANY_NAMESPACE;

        Element currentElement = rootElement;
        if (elementPath != null) {
            for (int pathIndex = 0; pathIndex < elementPath.length; pathIndex++) {
                final String elementName = elementPath[pathIndex];
                final NodeList matchedElements = currentElement.getElementsByTagNameNS(sanitisedNamespace, elementName);

                if (matchedElements.getLength() > 0) {
                    final int nodeIndex = reverseSearch ? matchedElements.getLength() - 1 : 0;
                    currentElement = (Element) matchedElements.item(nodeIndex);
                    if (pathIndex == elementPath.length - 1) {
                        return currentElement;
                    }
                } else {
                    return null;
                }
            }
            // We should never reach here, as the final element path check should always result in success or failure
        }
        return null;
    }

    /**
     * Ensures that the specified element is present in the document at the (partial) path.
     * If it is not present then it will be added, along with any missing path elements.
     * The preceding path will always be built using the current namespace, while the final element can be given a new namespace if required.
     * @param document The XML document that should contain the element.
     * @param elementPath The path to the element, with the final item being the name of the element itself.
     * @param lastElementNamespace The namespace for the final element, or null to use the current namespace at that location in the DOM.
     * @return The element, either found in the XML document, or after it has been added to the XML document.
     */
    public static Element buildElementPath(final Document document, final String[] elementPath, final String lastElementNamespace) {
        Element currentElement = document.getDocumentElement();
        if (currentElement != null && elementPath != null) {
            for (int index = 0; index < elementPath.length; index++) {
                // Use the signature container namespace for the final element in the path, otherwise use any namespace
                final String namespace = (index == elementPath.length - 1) ? lastElementNamespace : null;

                final String nextElementQualifiedName = elementPath[index];
                final String nextElementName;
                final String nextElementPrefix;
                if (nextElementQualifiedName != null && nextElementQualifiedName.contains(":")) {
                    final String[] nextElementQualifiedNameParts = nextElementQualifiedName.split(":", 2);
                    nextElementPrefix = nextElementQualifiedNameParts[0];
                    nextElementName = nextElementQualifiedNameParts[1];
                } else {
                    nextElementPrefix = null;
                    nextElementName = nextElementQualifiedName;
                }

                final Element nextElement;
                if (index == 0 && currentElement.getLocalName().equals(nextElementName) && (lastElementNamespace == null || lastElementNamespace.equals(currentElement.getNamespaceURI()))) {
                    // Special case where the first element in the list is the document root element, i.e.: the very first currentElement value
                    nextElement = currentElement;
                } else {
                    nextElement = XMLUtils.extractElementNS(currentElement, namespace, nextElementName);
                }

                if (nextElement != null) {
                    currentElement = nextElement;
                } else {
                    // Add the final element with the designated container namespace, otherwise use the parent element namespace
                    currentElement = createElementWithNamespace(document, currentElement, namespace, nextElementPrefix, nextElementName);
                }
            }
        }
        return currentElement;
    }

    /**
     * Creates an element with a particular namespace, and attempts to pick a suitable prefix for the namespace (to comply with BCSIS requirements).
     * NOTE: Try and avoid using the forcedPrefix parameter -- it has the potential to force invalid XML to be generated!
     *  Example 1: If a prefix is forced that does not exist in the current XML context, and no namespace is specified.  This will lead to a prefix with no associated namespace!
     *  Example 2: If a prefix is forced with a namespace that conflicts with a prefix defined elsewhere with the same name.
     * @param document The XML document containing the parent element.
     * @param parentElement The parent element, within which the new element will be added as a child.
     * @param namespace The namespace for the new element, or null to namespace of the parent element (if it has one).
     * @param forcedPrefix If specified then the generated element will have this prefix, or null to select a matching prefix (or no prefix) from the chain of parent nodes.
     * @param localName The unqualified name of the new element.
     * @return The generated element, already added to the DOM as a child of the specified parent element.
     */
    private static Element createElementWithNamespace(final Document document, final Element parentElement, final String namespace, final String forcedPrefix, final String localName) {
        final String newNamespace = (namespace != null) ? namespace : parentElement.getNamespaceURI();

        // Try and find an existing prefix for the target namespace
        final String existingPrefix = (newNamespace != null) ? findAncestorPrefixForNamespace(parentElement, newNamespace) : null;
        final String newElementPrefix = (forcedPrefix != null) ? forcedPrefix : existingPrefix;

        final String qualifiedNewElementName = (newElementPrefix != null && !newElementPrefix.isEmpty()) ? newElementPrefix + ":" + localName : localName;
        final Element newElement = document.createElementNS(newNamespace, qualifiedNewElementName);

        if (newNamespace != null && (existingPrefix == null || !existingPrefix.equals(newElementPrefix))) {
            // The new element has a namespace that is not used by any parent elements, so explicitly set its XMLNS attribute.
            final String newElementQualifiedPrefix = (newElementPrefix != null) ? "xmlns:" + newElementPrefix : "xmlns";
            newElement.setAttributeNS(XML_NAMESPACE, newElementQualifiedPrefix, newNamespace);
        }

        parentElement.appendChild(newElement);
        return newElement;
    }

    /**
     * Find the prefix currently assigned to the XML namespace in the ancestor path of the specified node.
     * @param node The starting point for the search.
     * @param namespace The XML namespace to look for.
     * @return The assigned prefix (which will be an empty string for the default namespace), or null if no such namespace has yet been defined.
     */
    private static String findAncestorPrefixForNamespace(final Node node, final String namespace) {
        Node candidateNode = node;
        while (candidateNode instanceof Element) {
            final Element ancestorElement = (Element) candidateNode;
            final NamedNodeMap attributes = ancestorElement.getAttributes();
            for (int index = 0; index < attributes.getLength(); index++) {
                // Find matching namespace attribute and extract the prefix...
                final Attr attribute = (Attr) attributes.item(index);
                if (attribute.getNamespaceURI() != null && attribute.getNamespaceURI().equals(XML_NAMESPACE) && attribute.getValue().equals(namespace)) {
                    return attribute.getLocalName().equals("xmlns") ? "" : attribute.getLocalName();
                }
            }

            candidateNode = ancestorElement.getParentNode();
        }
        return null;
    }
}
