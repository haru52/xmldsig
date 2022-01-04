// ref. https://docs.oracle.com/javase/6/docs/technotes/guides/security/xmldsig/Validate.java

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.*;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class Validate {
  public static void main(String[] args) {
    if (args.length != 1) {
      System.err.println("Usage: java Validate [input XML path]");
      System.exit(1);
    }

    try {
      validate(args[0]);
    } catch (Exception e) {
      System.err.println(e);
      System.exit(1);
    }
  }

  public static boolean validate(String inXmlPath) throws Exception {
    // Instantiate the document to be validated
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(inXmlPath));

    // Find Signature element
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (nl.getLength() == 0)
      throw new Exception("Cannot find Signature element");

    // Create a DOM XMLSignatureFactory that will be used to unmarshal the
    // document containing the XMLSignature
    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

    // Create a DOMValidateContext and specify a KeyValue KeySelector
    // and document context
    DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl.item(0));

    // unmarshal the XMLSignature
    XMLSignature signature = fac.unmarshalXMLSignature(valContext);

    // Validate the XMLSignature (generated above)
    boolean coreValidity = signature.validate(valContext);

    // Check core validation status
    if (!coreValidity) {
      System.err.println("Signature failed core validation");
      boolean sv = signature.getSignatureValue().validate(valContext);
      System.out.println("signature validation status: " + sv);
      // check the validation status of each Reference
      Iterator i = signature.getSignedInfo().getReferences().iterator();
      for (int j = 0; i.hasNext(); j++) {
        boolean refValid = ((Reference) i.next()).validate(valContext);
        System.out.println("ref[" + j + "] validity status: " + refValid);
      }
    } else
      System.out.println("Signature passed core validation");
    return coreValidity;
  }

  /**
   * KeySelector which retrieves the public key out of the
   * KeyValue element and returns it.
   * NOTE: If the key algorithm doesn't match signature algorithm,
   * then the public key will be ignored.
   */
  private static class KeyValueKeySelector extends KeySelector {
    public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
      if (keyInfo == null)
        throw new KeySelectorException("Null KeyInfo object!");
      SignatureMethod sm = (SignatureMethod) method;

      for (Object keyInfoContent : keyInfo.getContent()) {
        if (keyInfoContent instanceof X509Data) {
          for (Object x509Content : ((X509Data) keyInfoContent).getContent()) {
            X509Certificate cert = (X509Certificate) x509Content;
            PublicKey pk = cert.getPublicKey();
            // make sure algorithm is compatible with method
            if (algEquals(sm.getAlgorithm(), pk.getAlgorithm()))
              return new SimpleKeySelectorResult(pk);
          }
        }
      }
      throw new KeySelectorException("No KeyValue element found!");
    }

    static boolean algEquals(String algURI, String algName) {
      if (algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA256))
        return true;
      else if (algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1))
        return true;
      else if (algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1))
        return true;
      else
        return false;
    }
  }

  private static class SimpleKeySelectorResult implements KeySelectorResult {
    private PublicKey pk;

    SimpleKeySelectorResult(PublicKey pk) {
      this.pk = pk;
    }

    public Key getKey() {
      return pk;
    }
  }
}
