import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.TokenManager;
import iaik.security.provider.IAIK;
import iaik.xml.crypto.XSecProvider;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;
import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.XMLCryptoContext;
import java.security.PublicKey;
import java.util.Iterator;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import java.security.KeyException;
import java.nio.file.*;
import java.nio.charset.Charset;
import java.util.Arrays;

public class DsCOD
{
  private IAIKPkcs11 pkcs11Provider_;
  private PrivateKey signatureKey_;
  public X509Certificate signingCertificate_;
  private Document doc_;
  Document doc;
  static boolean cod;
  static boolean codeh;
  final int codID = 0;
  final int codehID = 1;
  String URICOD = null;
  String URICODEH = null;
  static boolean ERROR = false;
  static String outputMsg;
  boolean cntCODEH = false;
  /**
   * Main constructor, loads the necessary providers
   * 
   * @param data Location of the module or the cert
   */
  public DsCOD(String data, int token)
  {
    if (token == 1)
    {
      Security.addProvider(new IAIK());
      
      Properties pkcs11config = new Properties();
      pkcs11config.put("PKCS11_NATIVE_MODULE", data);
      this.pkcs11Provider_ = new IAIKPkcs11(pkcs11config);
      Security.addProvider(this.pkcs11Provider_);
      
      XSecProvider xsecProvider = new XSecProvider();
      
      XSecProvider.setDelegationProvider("Signature.SHA1withRSA", this.pkcs11Provider_.getName());
      Security.addProvider(xsecProvider);
    }
    else if (token == 0)
    {
      try{
        getSignatureFromFile(data);
      } catch(Exception e) {
          e.printStackTrace();
      }
    }
  }
  
  /**
   * Select key from stick
   * 
   * @param pin Stick password
   */
  public void selectSignatureKey(String pin)
    throws GeneralSecurityException
  {
    KeyStore tokenKeyStore = this.pkcs11Provider_.getTokenManager().getKeyStore();
    try
    {
      tokenKeyStore.load(null, pin.toCharArray());
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    Enumeration aliases = tokenKeyStore.aliases();
    while (aliases.hasMoreElements())
    {
      String keyAlias = aliases.nextElement().toString();
      Key key = tokenKeyStore.getKey(keyAlias, null);
      if ((key instanceof RSAPrivateKey))
      {
        Certificate[] certificateChain = tokenKeyStore.getCertificateChain(keyAlias);
        X509Certificate signerCertificate = (X509Certificate)certificateChain[0];
        boolean[] keyUsage = signerCertificate.getKeyUsage();
        if ((keyUsage == null) || (keyUsage[0]) || (keyUsage[1]))
        {
          this.signatureKey_ = ((PrivateKey)key);
          this.signingCertificate_ = signerCertificate;
          break;
        }
      }
    }
    if (this.signatureKey_ == null) {
      throw new GeneralSecurityException("Llave de firma no encontrada. Asegurese que un token valido esta insertado.");
    }
  }
  
   /**
   * Get key from file
   * 
   * @param fileName Input file
   */
  public void getSignatureFromFile(String fileName)
    throws IOException, GeneralSecurityException
  {
    this.signingCertificate_ = loadPublicX509(fileName);
    try
    {
      this.signatureKey_ = loadPrivateKey(fileName);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
  }
  
  /**
   * Create xml signature
   * 
   * @param dataURL If signing COD or CODEH
   * @param fileInput Xml to sign
   * @param xsd Schema
   */
  public void createXmlSignature(String dataURL, String fileInput)
    throws GeneralSecurityException, ParserConfigurationException, XMLSignatureException, MarshalException, Exception
  { 
    try
    {
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      dbf.setNamespaceAware(true);
      this.doc = dbf.newDocumentBuilder().parse(new FileInputStream(fileInput));
    }
    catch (Exception e)
    {
      e.printStackTrace();
    } 
    
    try {
        getURI(doc);
    } catch (Exception e) {}
    if (cod) {
        if (URICOD != null && URICOD.equals("#CODEH")) {
			if (outputMsg != null)
      	    {
         	  List<String> lines = Arrays.asList("Tag CODEH ya firmado, no es posible firmar tag COD, verifique el xml");
         	  Path file = Paths.get(outputMsg);
        	  Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
      	    } else {
         	  System.out.println("Tag CODEH ya firmado, no es posible firmar tag COD, verifique el xml");
      	    }
            ERROR = true;
            return;
        } else if (URICOD != null && URICOD.equals("#COD")) {
            boolean verifiedCOD = verifySignature(fileInput, codID);
            if (verifiedCOD) {
				if (outputMsg != null)
      	   	 	{
         		  List<String> lines = Arrays.asList("Tag COD ya firmado de manera válida");
         		  Path file = Paths.get(outputMsg);
        		  Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
      	   		 } else {
         		  System.out.println("Tag COD ya firmado de manera válida");
      	   	 	}
                ERROR = true;
                return;
            } else {
				if (outputMsg != null)
      	   	 	{
         		  List<String> lines = Arrays.asList("Tag COD ya firmado de manera inválida, verifique el xml");
         		  Path file = Paths.get(outputMsg);
        		  Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
      	   		 } else {
         		  System.out.println("Tag COD ya firmado de manera inválida, verifique el xml");
      	   	 	}
                ERROR = true;
                return;
            }
        }
        if (URICODEH != null && URICODEH.equals("#CODEH")) {
            boolean verifiedCODEH = verifySignature(fileInput, codehID);
            if (verifiedCODEH) {
				if (outputMsg != null)
      	   	 	{
         		  List<String> lines = Arrays.asList("Tag CODEH ya firmado de manera válida, no es posible firmar tag COD");
         		  Path file = Paths.get(outputMsg);
        		  Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
      	   		 } else {
         		  System.out.println("Tag CODEH ya firmado de manera válida, no es posible firmar tag COD");
      	   	 	}
                ERROR = true;
                return;
            }
        }
    } else if (codeh) {
        if (URICOD != null && URICOD.equals("#COD")) {
            boolean verifiedCOD = verifySignature(fileInput, codID);
            if (verifiedCOD) {
				if (outputMsg != null)
      	   	 	{
         		  List<String> lines = Arrays.asList("Tag COD firmado de manera válida");
         		  Path file = Paths.get(outputMsg);
        		  Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
      	   		 } else {
         		  System.out.println("Tag COD firmado de manera validá");
      	   	 	}
				cntCODEH = true;
            } else {
				if (outputMsg != null)
      	   	 	{
         		  List<String> lines = Arrays.asList("Tag COD firmado de manera inválida, verifique el xml");
         		  Path file = Paths.get(outputMsg);
        		  Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
      	   		 } else {
         		  System.out.println("Tag COD firmado de manera inválida, verifique el xml");
      	   	 	}
                ERROR = true;
                return;
            }
        } else {
			if (outputMsg != null)
      	   	{
         	  List<String> lines = Arrays.asList("Tag COD no firmado, verifique el xml");
         	  Path file = Paths.get(outputMsg);
        	  Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
      	   	} else {
         	  System.out.println("Tag COD no firmado, verifique el xml");
      	   	}
            ERROR = true;
            return;
        }
        if (URICODEH != null && URICODEH.equals("#CODEH")) {
            boolean verifiedCODEH = verifySignature(fileInput, codehID);
            if (verifiedCODEH) {
				if (outputMsg != null)
      	   		{
         		  List<String> lines = Arrays.asList("Tag CODEH ya firmado de manera válida, no es posible volver a realizar la firma");
         		  Path file = Paths.get(outputMsg);
        		  Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
      	   		} else {
         		  System.out.println("Tag CODEH ya firmado de manera válida, no es posible volver a realizar la firma");
      	   		}
                ERROR = true;
                return;
            } else {
				if (outputMsg != null)
      	   		{
         		  List<String> lines = Arrays.asList("Tag CODEH ya firmado de manera inválida, verifique el xml");
         		  Path file = Paths.get(outputMsg);
        		  Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
      	   		} else {
         		  System.out.println("Tag CODEH ya firmado de manera inválida, verifique el xml");
      	   		}
                ERROR = true;
                return;
            }
        }
    }
    
    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
    
    try {
        XPathFactory factory = XPathFactory.newInstance();
        XPath xpath = factory.newXPath();
         
        XPathExpression expr = xpath.compile(String.format("//*[@id='%s']", dataURL));
        NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
        if (nodes.getLength() == 0) {
			if (outputMsg != null)
      	   	{
         	  List<String> lines = Arrays.asList("No es posible encontrar el nodo: " + dataURL);
         	  Path file = Paths.get(outputMsg);
			  if (cntCODEH) {
        	  	Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
        	  } else {
			  	Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
        	  }
      	   	} else {
         	  System.out.println("No es posible encontrar el nodo: " + dataURL);
      	   	}
            ERROR = true;
            return;
        }
 
        Node nodeToSign = nodes.item(0);
        ((Element) nodeToSign).setIdAttribute("id", true);  
        Node sigParent = nodeToSign.getParentNode();
        String referenceURI = "#" + dataURL;
                  
        // Create an Array of Transform, add it one Transform which specify the Signature ENVELOPED method.         
        List<Transform> transformList = new ArrayList<Transform>(1);
        //transformList.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));  
    
        Reference ref = fac.newReference(referenceURI, fac.newDigestMethod("http://www.w3.org/2000/09/xmldsig#sha1", null), transformList, null, null);
        List<Reference> referenceList = Collections.singletonList(ref);
        
        CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", (C14NMethodParameterSpec)null);
        SignatureMethod signatureMethod = fac.newSignatureMethod("http://www.w3.org/2000/09/xmldsig#rsa-sha1", null);
        SignedInfo si = fac.newSignedInfo(canonicalizationMethod, signatureMethod, referenceList);
        
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data x509data = kif.newX509Data(Collections.nCopies(1, this.signingCertificate_));
        
        KeyInfo ki = kif.newKeyInfo(Collections.nCopies(1, x509data));
        
        XMLSignature signature = fac.newXMLSignature(si, ki);
        
        // Create the DOMSignContext by specifying the signing informations: Private Key, Node to be signed
        DOMSignContext signContext = new DOMSignContext(this.signatureKey_, sigParent);
        
        signature.sign(signContext);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
  }
  
  /**
   * Get  reference URI of the signature
   * 
   * @param doc Xml document
   * @return the reference URI of the signature
   */
  public void getURI(Document doc) {
      // Try to find Signature element
      NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS,
                "Signature");
      if (nl.getLength() != 0) {
          // Get the COD reference URI
          Element nodeElementCOD = (Element) nl.item(codID);
          NodeList sigInfoCOD = nodeElementCOD.getElementsByTagName("SignedInfo");
          Element sigElementCOD = (Element) sigInfoCOD.item(0);
          NodeList referenceURICOD = sigElementCOD.getElementsByTagName("Reference");
          Element referenceElementCOD = (Element) referenceURICOD.item(0);
          URICOD = referenceElementCOD.getAttributes().getNamedItem("URI").getNodeValue();
          
          if (URICOD.equals("#CODEH")) {
              URICODEH = URICOD;
              return;
          }
          // Get the CODEH reference URI
          Element nodeElementCODEH = (Element) nl.item(codehID);
          NodeList sigInfoCODEH = nodeElementCODEH.getElementsByTagName("SignedInfo");
          Element sigElementCODEH = (Element) sigInfoCODEH.item(0);
          NodeList referenceURICODEH = sigElementCODEH.getElementsByTagName("Reference");
          Element referenceElementCODEH = (Element) referenceURICODEH.item(0);
          URICODEH = referenceElementCODEH.getAttributes().getNamedItem("URI").getNodeValue();
      }
  }
  
  /**
   * Load certificate
   * 
   * @param fileName Location/Name of the cert
   * @return the loaded certificate
   * @throws IOException
   * @throws GeneralSecurityException
   */
  public static X509Certificate loadPublicX509(String fileName)
    throws IOException, GeneralSecurityException
  {
    FileInputStream is = null;
    X509Certificate crt = null;
    try
    {
      is = new FileInputStream(fileName);
      BufferedReader br = new BufferedReader(new InputStreamReader(is));
      StringBuilder builder = new StringBuilder();
      boolean inKey = false;
      for (String line = br.readLine(); line != null; line = br.readLine()) {
        if (!inKey)
        {
          if ((line.startsWith("-----BEGIN")) && 
            (line.endsWith(" CERTIFICATE-----"))) {
            inKey = true;
          }
        }
        else
        {
          if ((line.startsWith("-----END")) && 
            (line.endsWith(" CERTIFICATE-----")))
          {
            inKey = false;
            break;
          }
          builder.append(line);
        }
      }
      byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      InputStream in = new ByteArrayInputStream(encoded);
      crt = (X509Certificate)certFactory.generateCertificate(in);
    }
    finally
    {
      closeSilent(is);
    }
    return crt;
  }
  
  /**
   * Load private key from cert
   * 
   * @param fileName Location/Name of the cert
   * @return the loaded private key
   * @throws IOException
   * @throws GeneralSecurityException
   */
  public PrivateKey loadPrivateKey(String fileName)
    throws IOException, GeneralSecurityException
  {
    PrivateKey key = null;
    FileInputStream is = null;
    try
    {
      is = new FileInputStream(fileName);
      BufferedReader br = new BufferedReader(new InputStreamReader(is));
      StringBuilder builder = new StringBuilder();
      boolean inKey = false;
      for (String line = br.readLine(); line != null; line = br.readLine()) {
        if (!inKey)
        {
          if ((line.startsWith("-----BEGIN ")) && 
            (line.endsWith(" PRIVATE KEY-----"))) {
            inKey = true;
          }
        }
        else
        {
          if ((line.startsWith("-----END ")) && 
            (line.endsWith(" PRIVATE KEY-----")))
          {
            inKey = false;
            break;
          }
          builder.append(line);
        }
      }
      byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      key = kf.generatePrivate(keySpec);
    }
    finally
    {
      closeSilent(is);
    }
    return key;
  }
  
  /**
   * Close input stream
   * 
   * @param is Input stream
   */
  public static void closeSilent(InputStream is)
  {
    if (is == null) {
      return;
    }
    try
    {
      is.close();
    }
    catch (Exception localException) {}
  }
  
  /**
   * Write results to a file
   * 
   * @param args Input arguments to read the output
   */
  public void writeResult(String[] args)
    throws TransformerException, IOException
  {
    OutputStream os = System.out;
    if (isToken == 1)
    {
      if (args.length > 5) {
        os = new FileOutputStream(args[5]);
      } else {
        os = System.out;
      }
    }
    else if (isToken == 0) {
      if (args.length > 4) {
        os = new FileOutputStream(args[4]);
      } else {
        os = System.out;
      }
    }
    
    // Format xml
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer trans = tf.newTransformer();
    trans.transform(new DOMSource(this.doc), new StreamResult(os));
    
    if (cod) {
		if (outputMsg != null)
      	{
          List<String> lines = Arrays.asList("COD firmado correctamente");
          Path file = Paths.get(outputMsg);
		  if (cntCODEH) {
          	Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
          } else {
		  	Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
          }
      	} else {
          System.out.println("COD firmado correctamente");
      	}
    } else if (codeh) {
        if (outputMsg != null)
      	{
          List<String> lines = Arrays.asList("CODEH firmado correctamente");
          Path file = Paths.get(outputMsg);
		  if (cntCODEH) {
          	Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
          } else {
		  	Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
          }
      	} else {
          System.out.println("CODEH firmado correctamente");
      	}
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
  
  static int isToken = -1;
  
  /**
   * Main method, input read and execution
   * 
   * @param args Input arguments
   */
  public static void main(String[] args)
    throws Exception
  {
    if (args.length == 0 || args.length < 3) {
      System.out.println("Usage: java -jar firmar.jar [--soft/--token/--help]");
      System.out.println("                            [--soft]     [path-al-cert]          [COD/CODEH]     [documento] [output] [output-msg] [output-error]");
      System.out.println("                            [--token]    [config-con-dll]  [pin] [COD/CODEH]     [documento] [output] [output-msg] [output error]");
      System.out.println("");
      System.out.println("        --help  -h                               Muestra ésta ayuda");
      System.out.println("        --soft  -s    path-al-cert               Direccion del PEM");
      System.out.println("        --token -t    conf-con-dll               Direccion del conf.txt con el DLL");
      System.out.println("");
      System.out.println("        COD/CODEH                                Elegir como firmar");
      System.out.println("        pin                                      Contraseña del token");
      System.out.println("        documento                                Elegir documento a firmar");
      System.out.println("        output                                   Documento de salida");
	  System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
      System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
      System.exit(0);
    }
    // Command line input options
    switch (args[0])
    {
    case "-s": 
      isToken = 0;
      break;
    case "--soft": 
      isToken = 0;
      break;
    case "-t": 
      isToken = 1;
      break;
    case "--token": 
      isToken = 1;
      break;
    case "-h": 
      System.out.println("Usage: java -jar firmar.jar [--soft/--token/--help]");
      System.out.println("                            [--soft]     [path-al-cert]          [COD/CODEH]     [documento] [output] [output-msg] [output-error]");
      System.out.println("                            [--token]    [config-con-dll]  [pin] [COD/CODEH]     [documento] [output] [output-msg] [output error]");
      System.out.println("");
      System.out.println("        --help  -h                               Muestra ésta ayuda");
      System.out.println("        --soft  -s    path-al-cert               Direccion del PEM");
      System.out.println("        --token -t    conf-con-dll               Direccion del conf.txt con el DLL");
      System.out.println("");
      System.out.println("        COD/CODEH                                Elegir como firmar");
      System.out.println("        pin                                      Contraseña del token");
      System.out.println("        documento                                Elegir documento a firmar");
      System.out.println("        output                                   Documento de salida");
	  System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
      System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
      System.exit(0);
      break;
    case "--help": 
      System.out.println("Usage: java -jar firmar.jar [--soft/--token/--help]");
      System.out.println("                            [--soft]     [path-al-cert]          [COD/CODEH]     [documento] [output] [output-error]");
      System.out.println("                            [--token]    [config-con-dll]  [pin] [COD/CODEH]     [documento] [output] [output error]");
      System.out.println("");
      System.out.println("        --help  -h                               Muestra ésta ayuda");
      System.out.println("        --soft  -s    path-al-cert               Direccion del PEM");
      System.out.println("        --token -t    conf-con-dll               Direccion del conf.txt con el DLL");
      System.out.println("");
      System.out.println("        COD/CODEH                                Elegir como firmar");
      System.out.println("        pin                                      Contraseña del token");
      System.out.println("        documento                                Elegir documento a firmar");
      System.out.println("        output                                   Documento de salida");
	  System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
      System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
      System.exit(0);
      break;
    }
    
    // If token is selected with an output file for errors
    if (isToken == 1)
    {
      if (args.length < 4) {
        System.out.println("Usage: java -jar firmar.jar [--soft/--token/--help]");
        System.out.println("                            [--soft]     [path-al-cert]          [COD/CODEH]     [documento] [output] [output-msg] [output-error]");
        System.out.println("                            [--token]    [config-con-dll]  [pin] [COD/CODEH]     [documento] [output] [output-msg] [output error]");
        System.out.println("");
        System.out.println("        --help  -h                               Muestra ésta ayuda");
        System.out.println("        --soft  -s    path-al-cert               Direccion del PEM");
        System.out.println("        --token -t    conf-con-dll               Direccion del conf.txt con el DLL");
        System.out.println("");
        System.out.println("        COD/CODEH                                Elegir como firmar");
        System.out.println("        pin                                      Contraseña del token");
        System.out.println("        documento                                Elegir documento a firmar");
        System.out.println("        output                                   Documento de salida");
  	    System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
        System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
        System.exit(0);
      }  
      
	  // Set output-error
      if (args.length > 7)
      {
        PrintStream err = new PrintStream(new FileOutputStream(args[7]));
        System.setErr(err);
        System.out.println("Errores en " + args[7]);
      }

	  // Set output-msg
	  if (args.length > 6)
      {
        outputMsg = args[6];
        List<String> lines = Arrays.asList("");
        Path file = Paths.get(outputMsg);
        Files.write(file, lines, Charset.forName("UTF-8"));
		System.out.println("Salida en " + args[6]);
      }
    }
    
    // If soft is selected with an output file for errors
    else if (isToken == 0)
	{
	  // Set output-error
	  if (args.length > 6) 
      {
        PrintStream err = new PrintStream(new FileOutputStream(args[6]));
        System.setErr(err);
        System.out.println("Errores en " + args[6]);
      }

	  // Set output-msg
	  if (args.length > 5)
      {
        outputMsg = args[5];
        List<String> lines = Arrays.asList("");
        Path file = Paths.get(outputMsg);
        Files.write(file, lines, Charset.forName("UTF-8"));
		System.out.println("Salida en " + args[5]);
      }
    }
    
    // If token selected
    if (isToken == 1)
    {
      cod = args[3].equals("COD");
      codeh = args[3].equals("CODEH");
      if (!((!cod && codeh) || (cod && !codeh))) {
		if (outputMsg != null)
      	{
         	List<String> lines = Arrays.asList("No es posible firmar el nodo: " + args[3], "Por favor, use COD o CODEH solamente");
         	Path file = Paths.get(outputMsg);
        	Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
			return;
      	} else {
         	System.out.println("No es posible firmar el nodo: " + args[3]);
			System.out.println("Por favor, use COD o CODEH solamente");
        	return;
      	}
      }
      String dll = new Scanner(new File(args[1])).useDelimiter("\\Z").next();
      
      DsCOD genEnvel = new DsCOD(dll, isToken);
      genEnvel.selectSignatureKey(args[2]);
      genEnvel.createXmlSignature(args[3], args[4]);
      if (!ERROR) {
          genEnvel.writeResult(args);
      } else {
		  if (outputMsg != null)
      	  {
         	List<String> lines = Arrays.asList("Se ha producido un error al crear la firma");
         	Path file = Paths.get(outputMsg);
        	Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
      	  } else {
         	System.out.println("Se ha producido un error al crear la firma");
      	  }
      }
    }
    
    // If soft selected
    else if ((isToken == 0))
    {
      cod = args[2].equals("COD");
      codeh = args[2].equals("CODEH");
      if (!((!cod && codeh) || (cod && !codeh))) {
        if (outputMsg != null)
      	{
         	List<String> lines = Arrays.asList("No es posible firmar el nodo: " + args[2], "Por favor, use COD o CODEH solamente");
         	Path file = Paths.get(outputMsg);
        	Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
			return;
      	} else {
         	System.out.println("No es posible firmar el nodo: " + args[2]);
			System.out.println("Por favor, use COD o CODEH solamente");
        	return;
      	}
      }
      
      String fileName = args[1];
      
      DsCOD genEnvel = new DsCOD(fileName, isToken);
      genEnvel.createXmlSignature(args[2], args[3]);
      if (!ERROR) {
          genEnvel.writeResult(args);
      } else {
          if (outputMsg != null)
      	  {
         	List<String> lines = Arrays.asList("Se ha producido un error al crear la firma");
         	Path file = Paths.get(outputMsg);
        	Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
      	  } else {
         	System.out.println("Se ha producido un error al crear la firma");
      	  }
      }
    }
  }
}