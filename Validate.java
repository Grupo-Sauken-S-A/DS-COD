import java.io.FileInputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.File;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.nio.file.*;
import java.nio.charset.Charset;
import java.util.Arrays;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Element;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;

/**
 * This is a simple example of validating an XML Signature using the JSR 105
 * API. It assumes the key needed to validate the signature is contained in a
 * KeyValue KeyInfo.
 */
public class Validate {

    //
    // Synopsis: java validate [document]
    //
    // where "document" is the name of a file containing the XML document
    // to be validated.
    //
    static boolean ERROR = false;
    static String outputMsg;

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
          System.out.println("Usage: java -jar validar.jar [documento] [output-msg] [output-error]");
          System.out.println("                             [--help]");
          System.out.println("");
          System.out.println("        --help  -h                               Muestra ésta ayuda");
          System.out.println("");
          System.out.println("        documento                                Documento a validar");
          System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
          System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
          System.exit(0);
        }
        // Command line input options
        switch (args[0])
        {
          case "-h":
            System.out.println("Usage: java -jar validar.jar [documento] [output-msg] [output-error]");
            System.out.println("                             [--help]");
            System.out.println("");
            System.out.println("        --help  -h                               Muestra ésta ayuda");
            System.out.println("");
            System.out.println("        documento                                Documento a validar");
            System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
            System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
            System.exit(0);
            break;
            
          case "--help":
            System.out.println("Usage: java -jar validar.jar [documento] [output-msg] [output-error]");
            System.out.println("                             [--help]");
            System.out.println("");
            System.out.println("        --help  -h                               Muestra ésta ayuda");
            System.out.println("");
            System.out.println("        documento                                Documento a validar");
            System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
            System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
            System.exit(0);
            break;
        }
        int codID = 0;
        int codehID = 1;
        
        // Set output-error
        if (args.length > 2)
        {
          PrintStream err = new PrintStream(new FileOutputStream(args[2]));
          System.setErr(err);
          System.out.println("Errores en " + args[2]);
        }

        // Set output-msg
        if (args.length > 1)
        {
          outputMsg = args[1];
          List<String> lines = Arrays.asList("");
          Path file = Paths.get(outputMsg);
          Files.write(file, lines, Charset.forName("UTF-8"));
          System.out.println("Salida en " + args[1]);
        }

        boolean verifiedCOD = verifySignature(args[0], codID);
        if (verifiedCOD) {
            boolean verifiedCODEH = verifySignature(args[0], codehID);
        }
    }
    
    public static boolean verifySignature(String fileName, int id) throws Exception {
        // Instantiate the document to be validated
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(
                new FileInputStream(fileName));

        // Find Signature element
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS,
                "Signature");
        if (nl.getLength() == 0) {
            if (outputMsg != null)
            {
                List<String> lines = Arrays.asList("No se puede encontrar la firma");
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println("No se puede encontrar la firma");
            }
            return false;
        }
        if (id == 1) {
            if (nl.getLength() < 2) {
                if (outputMsg != null)
                {
                    List<String> lines = Arrays.asList("CODEH no firmado");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println("CODEH no firmado");
                }
                return false;
            }
        }
        
        // Get the reference URI
        Element nodeElement = (Element) nl.item(id);
        NodeList sigInfo = nodeElement.getElementsByTagName("SignedInfo");
        Element sigElement = (Element) sigInfo.item(0);
        NodeList referenceURI = sigElement.getElementsByTagName("Reference");
                
        Element referenceElement = (Element) referenceURI.item(0);
        String URI = referenceElement.getAttributes().getNamedItem("URI").getNodeValue();
        
        
        // Create a DOM XMLSignatureFactory that will be used to unmarshal the
        // document containing the XMLSignature
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
         
        if (URI != null && URI.equals("#COD")) {
            XPathExpression exprCOD = xpath.compile(String.format("//*[@id='%s']", "COD"));
            NodeList nodesCOD = (NodeList) exprCOD.evaluate(doc, XPathConstants.NODESET);
            Node nodeCOD = nodesCOD.item(0);
            ((Element) nodeCOD).setIdAttribute("id", true);
        } else if (URI != null && URI.equals("#CODEH")) {
            XPathExpression exprCODEH = xpath.compile(String.format("//*[@id='%s']", "CODEH"));
            NodeList nodesCODEH = (NodeList) exprCODEH.evaluate(doc, XPathConstants.NODESET);     
            Node nodeCODEH = nodesCODEH.item(0);
            ((Element) nodeCODEH).setIdAttribute("id", true);  
        }
        
        // Create a DOMValidateContext and specify a KeyValue KeySelector
        // and document context
        DOMValidateContext valContext = new DOMValidateContext(
                new KeyValueKeySelector(), nl.item(id));

        // unmarshal the XMLSignature
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        
        // Validate the XMLSignature (generated above)
        boolean coreValidity = signature.validate(valContext);

        // Check core validation status
        if (coreValidity == false) {
            if (id == 0) {
                if (outputMsg != null)
                {
                    List<String> lines = Arrays.asList("La firma en COD ha fallado la verificación base");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println("La firma en COD ha fallado la verificación base");
                }
                boolean sv = signature.getSignatureValue().validate(valContext);
                if (outputMsg != null)
                {
                    List<String> lines = Arrays.asList("Estado de validez del COD: "+ sv);
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println("Estado de validez : "+ sv);
                }

                // check the validation status of each Reference
                Iterator<?> i = signature.getSignedInfo().getReferences().iterator();
                for (int j = 0; i.hasNext(); j++) {
                    boolean refValid = ((Reference) i.next()).validate(valContext);
                    if (outputMsg != null)
                    {
                        List<String> lines = Arrays.asList("Estado de validez del COD: "+ refValid);
                        Path file = Paths.get(outputMsg);
                        Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    } else {
                        System.out.println("Estado de validez del COD: "+ refValid);
                    }
                }
            } else if (id == 1) {
                if (outputMsg != null)
                {
                    List<String> lines = Arrays.asList("La firma en CODEH ha fallado la verificación base");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println("La firma en CODEH ha fallado la verificación base");
                }
                boolean sv = signature.getSignatureValue().validate(valContext);
                if (outputMsg != null)
                {
                    List<String> lines = Arrays.asList("Estado de validez del CODEH: "+ sv);
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println("Estado de validez : "+ sv);
                }

                // check the validation status of each Reference
                Iterator<?> i = signature.getSignedInfo().getReferences().iterator();
                for (int j = 0; i.hasNext(); j++) {
                    boolean refValid = ((Reference) i.next()).validate(valContext);
                    if (outputMsg != null)
                    {
                        List<String> lines = Arrays.asList("Estado de validez del CODEH: "+ refValid);
                        Path file = Paths.get(outputMsg);
                        Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    } else {
                        System.out.println("Estado de validez del CODEH: "+ refValid);
                    }
                }
            } 
            return false;
        } else {
            if (id == 0) {
                if (outputMsg != null)
                {
                    List<String> lines = Arrays.asList("La firma en COD ha pasado la verificación base");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println("La firma en COD ha pasado la verificación base");
                }
            } else if (id == 1) {
                if (outputMsg != null)
                {
                    List<String> lines = Arrays.asList("La firma en CODEH ha pasado la verificación base");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println("La firma en CODEH ha pasado la verificación base");
                }
            }
            return true;
        }
    }

    /**
     * KeySelector which retrieves the public key out of the KeyValue element
     * and returns it. NOTE: If the key algorithm doesn't match signature
     * algorithm, then the public key will be ignored.
     */
    private static class KeyValueKeySelector extends KeySelector {
        public KeySelectorResult select(KeyInfo keyInfo,
                KeySelector.Purpose purpose, AlgorithmMethod method,
                XMLCryptoContext context) throws KeySelectorException {
            
            if (keyInfo == null) {
                throw new KeySelectorException("El objeto KeyInfo no existe!");
            }
            SignatureMethod sm = (SignatureMethod) method;
            List<?> list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof X509Data) {
                    PublicKey pk = null;
                    List<?> l = ((X509Data) xmlStructure).getContent();
                    if (l.size() > 0) {
                        X509Certificate cert = (X509Certificate) l.get(0);
                        pk = cert.getPublicKey();
                        if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                            return new SimpleKeySelectorResult(pk);
                        }
                    }
                }
                if (xmlStructure instanceof KeyValue) {
                    PublicKey pk = null;
                    try {
                        pk = ((KeyValue) xmlStructure).getPublicKey();
                    } catch (KeyException ke) {
                    }
                    // make sure algorithm is compatible with method
                    if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                        return new SimpleKeySelectorResult(pk);
                    }
                }
            }
            throw new KeySelectorException("KeyValue no encontrado!");
        }

        // @@@FIXME: this should also work for key types other than DSA/RSA
        boolean algEquals(String algURI, String algName) {
            if (algName.equalsIgnoreCase("DSA")
                    && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
                return true;
            } else if (algName.equalsIgnoreCase("RSA")
                    && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
                return true;
            } else {
                return false;
            }
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