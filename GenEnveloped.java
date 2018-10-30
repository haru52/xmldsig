import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.List;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

public class GenEnveloped {
  public static void main(String[] args) {
    if (args.length != 4) {
      System.err.println("Usage: java GenEnveloped [input XML path] [output XML path] [private key path (pk8)] [certificate path]");
      System.exit(1);
    }

    try {
      genEnveloped(args[0], args[1], args[2], args[3]);
    } catch (Exception e) {
      System.err.println(e);
      System.exit(1);
    }
  }

  public static void genEnveloped(String inXmlPath, String outXmlPath, String privateKeyPath, String certPath) throws Exception {
    // Create a DOM XMLSignatureFactory that will be used to generate the
    // enveloped signature
    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

    // Create a Reference to the enveloped document (in this case we are
    // signing the whole document, so a URI of "" signifies that) and
    // also specify the SHA256 digest algorithm and the ENVELOPED Transform.
    DigestMethod dm = fac.newDigestMethod(DigestMethod.SHA256, null);
    List<Transform> transforms = Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
    Reference ref = fac.newReference("", dm, transforms, null, null);

    // Create the SignedInfo
    CanonicalizationMethod cm = fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null);
    SignatureMethod sm = fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null);
    List<Reference> references = Collections.singletonList(ref);
    SignedInfo si = fac.newSignedInfo(cm, sm, references);

    // Read a RSA private key
    FileInputStream fis = new FileInputStream(privateKeyPath);
    byte[] privateKeyByte = new byte[fis.available()];
    fis.read(privateKeyByte);
    fis.close();
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    RSAPrivateKey privateKey = (RSAPrivateKey) kf.generatePrivate(keySpec);

    // Read a X.509 certificate
    KeyInfoFactory kif = fac.getKeyInfoFactory();
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(certPath));
    X509Data x509Data = kif.newX509Data(Collections.singletonList(cert));

    // Create a KeyInfo and add the X509Data to it
    KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509Data));

    // Instantiate the document to be signed
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(inXmlPath));

    // Create a DOMSignContext and specify the RSA PrivateKey and
    // location of the resulting XMLSignature's parent element
    DOMSignContext dsc = new DOMSignContext(privateKey, doc.getDocumentElement());

    // Create the XMLSignature (but don't sign it yet)
    XMLSignature signature = fac.newXMLSignature(si, ki);

    // Marshal, generate (and sign) the enveloped signature
    signature.sign(dsc);

    // output the resulting document
    OutputStream os = new FileOutputStream(outXmlPath);
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer trans = tf.newTransformer();
    trans.transform(new DOMSource(doc), new StreamResult(os));
  }
}
