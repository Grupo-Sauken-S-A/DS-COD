/*
  Derechos Reservados © 2024 Grupo Sauken S.A.
  Este es un Software Libre; como tal redistribuirlo y/o modificarlo está
  permitido, siempre y cuando se haga bajo los términos y condiciones de la
  Licencia Pública General GNU publicada por la Free Software Foundation,
  ya sea en su versión 2 ó cualquier otra de las posteriores a la misma.
  Este “Programa” se distribuye con la intención de que sea útil, sin
  embargo carece de garantía, ni siquiera tiene la garantía implícita de
  tipo comercial o inherente al propósito del mismo “Programa”. Ver la
  Licencia Pública General GNU para más detalles.
  Se debe haber recibido una copia de la Licencia Pública General GNU con
  este “Programa”, si este no fue el caso, favor de escribir a la Free
  Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
  MA 02110-1301 USA.
  Correo electrónico: mailto:soporte@sauken.com.ar
  Empresa: Grupo Sauken S.A.
  WebSite: https://www.sauken.com.ar/
  <>
  Copyright © Grupo Sauken S.A.
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  You should have received a copy of the GNU General Public License along
  with this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
  E-mail: mailto:soporte@sauken.com.ar
  Company: Grupo Sauken S.A.
  WebSite: https://www.sauken.com.ar/
 */

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.security.provider.IAIK;
import iaik.xml.crypto.XSecProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class DsCOD
{
    static X509Certificate signingCertificate_;
    private static IAIKPkcs11 pkcs11Provider_;
    private static PrivateKey signatureKey_;
    private static String URICOD = null;
    private static String URICODEH = null;
    private final int codID = 0;
    private final int codehID = 1;

    /**
     * Main constructor, loads the necessary providers
     *
     * @param data Location of the module or the cert
     */
    public DsCOD(String data, int token, String outputMsg) throws CustomException, IOException {
        if (token == 1) {
            Security.addProvider(new IAIK());

            Properties pkcs11config = new Properties();
            pkcs11config.put("PKCS11_NATIVE_MODULE", data);

            // Set slot 2
            Module module;
            try {
                module = IAIKPkcs11.getModule(pkcs11config);
            } catch (Exception ignored) {
                throw new CustomException("#### \n" + "No se puede encontrar el módulo especificado, verifique el archivo de configuración");
            }

            Slot[] slots = new Slot[0];
            try {
                slots = module.getSlotList(true);
            } catch (TokenException e) {
                e.printStackTrace();
            }
            if (slots.length == 0) {
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList("Token no disponible");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println("Token no disponible");
                }
                return;
            }
            Slot selectedSlot = slots[0]; // select one slot
            pkcs11config.put("SLOT_ID", Long.toString(selectedSlot.getSlotID()));

            pkcs11Provider_ = new IAIKPkcs11(pkcs11config);
            Security.addProvider(pkcs11Provider_);
            XSecProvider xsecProvider = new XSecProvider();

            XSecProvider.setDelegationProvider("Signature.SHA1withRSA", pkcs11Provider_.getName());
            Security.addProvider(xsecProvider);
        } else if (token == 0) {
            try {
                getSignatureFromFile(data);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static void showHelp() {
        System.out.println("Uso:    java -jar firmar.jar [--soft/--token/--help/--licencia]");
        System.out.println("                            [--soft]    [path-al-cert]         [COD/CODEH] [documento] [output] [output-msg] [output-error]");
        System.out.println("                            [--token]   [config-con-dll] [pin] [COD/CODEH] [documento] [output] [output-msg] [output-error]");
        System.out.println();
        System.out.println("        --help     -h                        Muestra ésta ayuda");
        System.out.println("        --licencia -l                        Muestra la licencia del programa");
        System.out.println("        --soft     -s    path-al-cert        Ubicación del certificado x509 en formato PEM");
        System.out.println("        --token    -t    conf-con-dll        Ubicación del programa PKCS#11 (.dll) del Token utilizado");
        System.out.println();
        System.out.println("        COD/CODEH                            Elegir como firmar");
        System.out.println("        pin                                  Contraseña del token");
        System.out.println("        documento                            Documento a firmar");
        System.out.println("        output                               Documento de salida");
        System.out.println();
        System.out.println("        output-msg    OPCIONAL               Documento de salida de mensajes, si no se especifica, se mostrará en pantalla");
        System.out.println("        output-error  OPCIONAL*              Documento de salida de errores, si no se especifica, se mostrará en pantalla");
        System.out.println("                                             *Opcional sólo si output-msg está establecido");
    }

    /**
     * Main method, input read and execution
     *
     * @param args Input arguments
     */
    public static void main(String[] args)
            throws Exception, CustomException {
        int isToken = -1;
        boolean cod;
        boolean codeh;
        String outputMsg = null;
        boolean ERROR;

        // Startup of the jar file
        String startup = "DS-COD versión 1.2.3\n" +
                "Derechos Reservados © 2024 Grupo Sauken S.A.\n" +
                "Copyright © Grupo Sauken S.A.\n\n" +
                "DS-COD carece totalmente de garantía. Este es Software Libre y\n" +
                "está permitido redistribuirlo bajo ciertas condiciones.\n" +
                "Agregue \"--licencia\" al comando para más detalles.\n";
        System.out.println(startup);

        String version = System.getProperty("java.version");
        if (version.startsWith("1.")) {
            version = version.substring(2, 3);
        } else {
            int dot = version.indexOf(".");
            if (dot != -1) {
                version = version.substring(0, dot);
            }
        }
        if (Integer.parseInt(version) != 8) {
            System.out.println("Error: Por favor ejecute con java 8");
        }

        String licencia = " Derechos Reservados © 2024 Grupo Sauken S.A.\n" +
                "\n" +
                " Este es un Software Libre; como tal redistribuirlo y/o modificarlo está\n" +
                " permitido, siempre y cuando se haga bajo los términos y condiciones de la\n" +
                " Licencia Pública General GNU publicada por la Free Software Foundation,\n" +
                " ya sea en su versión 2 ó cualquier otra de las posteriores a la misma.\n" +
                "\n" +
                " Este \"Programa\" se distribuye con la intención de que sea útil, sin\n" +
                " embargo carece de garantía, ni siquiera tiene la garantía implícita de\n" +
                " tipo comercial o inherente al propósito del mismo \"Programa\". Ver la\n" +
                " Licencia Pública General GNU para más detalles.\n" +
                "\n" +
                " Se debe haber recibido una copia de la Licencia Pública General GNU con\n" +
                " este \"Programa\", si este no fue el caso, favor de escribir a la Free\n" +
                " Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,\n" +
                " MA 02110-1301 USA.\n" +
                "\n" +
                " Correo electrónico: mailto:soporte@sauken.com.ar\n" +
                " Empresa: Grupo Sauken S.A.\n" +
                " WebSite: https://www.sauken.com.ar/\n" +
                "\n" +
                "                                  --------------------------------------------------------------\n" +
                "\n" +
                " Copyright © Grupo Sauken S.A.\n" +
                "\n" +
                " This program is free software; you can redistribute it and/or modify\n" +
                " it under the terms of the GNU General Public License as published by\n" +
                " the Free Software Foundation; either version 2 of the License, or\n" +
                " (at your option) any later version.\n" +
                "\n" +
                " This program is distributed in the hope that it will be useful,\n" +
                " but WITHOUT ANY WARRANTY; without even the implied warranty of\n" +
                " MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n" +
                " GNU General Public License for more details.\n" +
                "\n" +
                " You should have received a copy of the GNU General Public License along\n" +
                " with this program; if not, write to the Free Software Foundation, Inc.,\n" +
                " 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.\n" +
                "\n" +
                " E-mail: mailto:soporte@sauken.com.ar\n" +
                " Company: Grupo Sauken S.A.\n" +
                " WebSite: https://www.sauken.com.ar/" +
                "\n";

        if (args.length == 0) {
            showHelp();
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

            case "--licencia":
                System.out.println(licencia);
                System.exit(0);
                break;

            case "-l":
                System.out.println(licencia);
                System.exit(0);
                break;

            case "-h":
                showHelp();
                System.exit(0);
                break;

            case "--help":
                showHelp();
                System.exit(0);
                break;

            default:
                showHelp();
                System.exit(0);
                break;
        }

        // If token is selected with an output file for errors
        if (isToken == 1)
        {
            if (args.length < 4) {
                showHelp();
                System.exit(0);
            }

            // Set output-error
            if (args.length > 7)
            {
                Path file = Paths.get(args[7]);
                Files.deleteIfExists(file);
                Files.createFile(file);
                List<String> linesTmp = Collections.singletonList("####");
                Files.write(file, linesTmp, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                PrintStream err = new PrintStream(new FileOutputStream(args[7]));
                System.setErr(err);
                System.out.println("Errores en " + args[7]);
            }

            // Set output-msg
            if (args.length > 6)
            {
                outputMsg = args[6];
                Path file = Paths.get(outputMsg);
                Files.deleteIfExists(file);
                Files.createFile(file);
                List<String> linesTmp = Collections.singletonList("####");
                Files.write(file, linesTmp, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                System.out.println("Salida en " + args[6]);
            }

            cod = args[3].equals("COD");
            codeh = args[3].equals("CODEH");
            if (!((!cod && codeh) || (cod && !codeh))) {
                if (outputMsg != null) {
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

            File out = new File(args[5]);

            String dll = new Scanner(new File(args[1])).useDelimiter("\\Z").next();
            if (!args[1].contains(".txt")) {
                throw new CustomException("#### \n" + dll + " no es un archivo de configuración valido");
            }

            createDir(out);

            File f = new File(args[4]);
            String docName = f.getName();

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(args[4]));

            DsCOD genEnvel = new DsCOD(dll, isToken, outputMsg);
            genEnvel.selectSignatureKey(args[2]);
            ERROR = genEnvel.createXmlSignature(args[3], doc, cod, codeh, docName, outputMsg);
            if (!ERROR) {
                genEnvel.writeResult(args, isToken, cod, codeh, doc, docName, outputMsg);
            } else {
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList(docName + ": Se ha producido un error al crear la firma");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": Se ha producido un error al crear la firma");
                }
            }

        } else if (isToken == 0) {  // If soft is selected with an output file for errors
            if (args.length < 3) {
                showHelp();
                System.exit(0);
            }

            // Set output-error
            if (args.length > 6)
            {
                Path file = Paths.get(args[6]);
                Files.deleteIfExists(file);
                Files.createFile(file);
                List<String> linesTmp = Collections.singletonList("####");
                Files.write(file, linesTmp, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                PrintStream err = new PrintStream(new FileOutputStream(args[6]));
                System.setErr(err);
                System.out.println("Errores en " + args[6]);
            }

            // Set output-msg
            if (args.length > 5)
            {
                outputMsg = args[5];
                Path file = Paths.get(outputMsg);
                Files.deleteIfExists(file);
                Files.createFile(file);
                List<String> linesTmp = Collections.singletonList("####");
                Files.write(file, linesTmp, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                System.out.println("Salida en " + args[5]);
            }

            cod = args[2].equals("COD");
            codeh = args[2].equals("CODEH");
            if (!((!cod && codeh) || (cod && !codeh))) {
                if (outputMsg != null) {
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
            File out = new File(args[4]);

            if (!fileName.contains(".pem")) {
                throw new CustomException("#### \n" + fileName + " no es un certificado valido");
            }

            DsCOD genEnvel = new DsCOD(fileName, isToken, outputMsg);

            createDir(out);

            File f = new File(args[3]);
            String docName = f.getName();

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(args[3]));

            ERROR = genEnvel.createXmlSignature(args[2], doc, cod, codeh, docName, outputMsg);
            if (!ERROR) {
                genEnvel.writeResult(args, isToken, cod, codeh, doc, docName, outputMsg);
            } else {
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList(docName + ": Se ha producido un error al crear la firma");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": Se ha producido un error al crear la firma");
                }
            }
        }
    }

    /**
     * Load certificate
     *
     * @param fileName Location/Name of the cert
     * @return the loaded certificate
     */
    private static X509Certificate loadPublicX509(String fileName)
            throws IOException, GeneralSecurityException {
        FileInputStream is = null;
        X509Certificate crt;
        try {
            is = new FileInputStream(fileName);
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if ((line.startsWith("-----BEGIN")) &&
                            (line.endsWith(" CERTIFICATE-----"))) {
                        inKey = true;
                    }
                } else {
                    if ((line.startsWith("-----END")) &&
                            (line.endsWith(" CERTIFICATE-----"))) {
                        break;
                    }
                    builder.append(line);
                }
            }
            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(encoded);
            crt = (X509Certificate) certFactory.generateCertificate(in);
        } finally {
            closeSilent(is);
        }
        return crt;
    }

    /**
     * Close input stream
     *
     * @param is Input stream
     */
    private static void closeSilent(InputStream is) {
        if (is == null) {
            return;
        }
        try {
            is.close();
        } catch (Exception ignored) {
        }
    }

    /**
     * Helper method to create a directory if it doesn't exist
     *
     * @param file Name of the file
     * @throws CustomException error
     */
    private static void createDir(File file) throws CustomException {
        if (!file.exists() && !file.getName().contains(".xml")) {
            boolean result = file.mkdirs();

            if (!result) {
                throw new CustomException("No se pudo crear el directorio: " + file.getName());
            }
        }
    }

    /**
     * Method to verify the validity of the signature
     *
     * @param docName Name of the document
     * @param id      id
     * @return if it's verified or not
     * @throws Exception Exception
     */
    private static boolean verifySignature(Document doc, String docName, int id, String outputMsg) throws Exception {
        // Find Signature element
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS,
                "Signature");
        if (nl.getLength() == 0) {
            if (outputMsg != null) {
                List<String> lines = Collections.singletonList(docName + ": No se puede encontrar la firma" + "URICOD: " + URICOD + ", URICODEH: " + URICODEH);
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println(docName + ": No se puede encontrar la firma");
            }
            return false;
        }
        if (id == 1) {
            if (nl.getLength() < 2) {
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList(docName + ": CODEH no firmado");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": CODEH no firmado");
                }
                return false;
            }
        }

        // Get the reference URI
        Element nodeElement = (Element) nl.item(id);
        NodeList sigInfo = nodeElement.getElementsByTagNameNS(XMLSignature.XMLNS, "SignedInfo");
        Element sigElement = (Element) sigInfo.item(0);
        NodeList referenceURI = sigElement.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");

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

        // Unmarshal the XMLSignature
        XMLSignature signature = fac.unmarshalXMLSignature(valContext);

        // Validate the XMLSignature (generated above)
        boolean coreValidity = signature.validate(valContext);

        // Check core validation status
        if (!coreValidity) {
            if (id == 0) {
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList(docName + ": La firma en COD ha fallado la verificación base");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": La firma en COD ha fallado la verificación base");
                }
                boolean sv = signature.getSignatureValue().validate(valContext);
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList(docName + ": Estado de validez del COD: " + sv);
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": Estado de validez : " + sv);
                }

                // check the validation status of each Reference
                for (Object o : signature.getSignedInfo().getReferences()) {
                    boolean refValid = ((Reference) o).validate(valContext);
                    if (outputMsg != null) {
                        List<String> lines;
                        lines = Collections.singletonList(docName + ": Estado de validez del COD: " + refValid);
                        Path file = Paths.get(outputMsg);
                        Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    } else {
                        System.out.println(docName + ": Estado de validez del COD: " + refValid);
                    }
                }
            } else if (id == 1) {
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList(docName + ": La firma en CODEH ha fallado la verificación base");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": La firma en CODEH ha fallado la verificación base");
                }
                boolean sv = signature.getSignatureValue().validate(valContext);
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList(docName + ": Estado de validez del CODEH: " + sv);
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": Estado de validez : " + sv);
                }

                // check the validation status of each Reference
                for (Object o : signature.getSignedInfo().getReferences()) {
                    boolean refValid = ((Reference) o).validate(valContext);
                    if (outputMsg != null) {
                        List<String> lines = Collections.singletonList(docName + ": Estado de validez del CODEH: " + refValid);
                        Path file = Paths.get(outputMsg);
                        Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    } else {
                        System.out.println(docName + ": Estado de validez del CODEH: " + refValid);
                    }
                }
            }
            return false;
        } else {
            if (id == 0) {
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList(docName + ": La firma en COD ha pasado la verificación base");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": La firma en COD ha pasado la verificación base");
                }
            } else if (id == 1) {
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList(docName + ": La firma en CODEH ha pasado la verificación base");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": La firma en CODEH ha pasado la verificación base");
                }
            }
            return true;
        }
    }

    /**
     * Select key from stick
     *
     * @param pin Stick password
     */
    void selectSignatureKey(String pin)
            throws Exception, CustomException {
        KeyStore tokenKeyStore;
        if (pkcs11Provider_.getTokenManager().getKeyStore() != null) {
            tokenKeyStore = pkcs11Provider_.getTokenManager().getKeyStore();
        } else {
            throw new CustomException("#### \n" + "No es posible acceder al token, verifique el archivo de configuracion");
        }
        try
        {
            tokenKeyStore.load(null, pin.toCharArray());
        }
        catch (Exception ignored)
        {
            throw new CustomException("#### \n" + "Contraseña invalida");
        }
        Enumeration<String> aliases = tokenKeyStore.aliases();
        while (aliases.hasMoreElements())
        {
            String keyAlias = aliases.nextElement();
            Key key = tokenKeyStore.getKey(keyAlias, null);
            if ((key instanceof RSAPrivateKey))
            {
                Certificate[] certificateChain = tokenKeyStore.getCertificateChain(keyAlias);
                X509Certificate signerCertificate = (X509Certificate)certificateChain[0];
                boolean[] keyUsage = signerCertificate.getKeyUsage();
                if ((keyUsage == null) || (keyUsage[0]) || (keyUsage[1])) {
                    signatureKey_ = ((PrivateKey) key);
                    signingCertificate_ = signerCertificate;
                    break;
                }
            }
        }
        if (signatureKey_ == null) {
            throw new GeneralSecurityException("#### \n" + "Llave de firma no encontrada. Asegurese que un token valido esta insertado.");
        }
    }

    /**
     * Get key from file
     *
     * @param fileName Input file
     */
    private void getSignatureFromFile(String fileName)
            throws IOException, GeneralSecurityException {
        signingCertificate_ = loadPublicX509(fileName);
        try {
            signatureKey_ = loadPrivateKey(fileName);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    /**
     * Create xml signature
     *
     * @param dataURL Tags
     * @param doc Document to sign
     * @param cod If is cod
     * @param codeh If is codeh
     * @param docName Name of the document
     * @param outputMsg output-msg
     * @return if signed correctly
     * @throws Exception Exception
     */
    private boolean createXmlSignature(String dataURL, Document doc, boolean cod, boolean codeh, String docName, String outputMsg)
            throws Exception
    {
        getURI(doc);

        if (cod) {
            if (URICOD != null && URICOD.equals("#CODEH")) {
                if (outputMsg != null)
                {
                    List<String> lines = Collections.singletonList(docName + ": Tag CODEH ya firmado, no es posible firmar tag COD, verifique el xml");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": Tag CODEH ya firmado, no es posible firmar tag COD, verifique el xml");
                }
                return true;
            } else if (URICOD != null && URICOD.equals("#COD")) {
                boolean verifiedCOD = verifySignature(doc, docName, codID, outputMsg);
                if (verifiedCOD) {
                    if (outputMsg != null)
                    {
                        List<String> lines = Collections.singletonList(docName + ": Tag COD ya firmado de manera válida");
                        Path file = Paths.get(outputMsg);
                        Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    } else {
                        System.out.println(docName + ": Tag COD ya firmado de manera válida");
                    }
                    return true;
                } else {
                    if (outputMsg != null)
                    {
                        List<String> lines = Collections.singletonList(docName + ": Tag COD ya firmado de manera inválida, verifique el xml");
                        Path file = Paths.get(outputMsg);
                        Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    } else {
                        System.out.println(docName + ": Tag COD ya firmado de manera inválida, verifique el xml");
                    }
                    return true;
                }
            }
            if (URICODEH != null && URICODEH.equals("#CODEH")) {
                boolean verifiedCODEH = verifySignature(doc, docName, codehID, outputMsg);
                if (verifiedCODEH) {
                    if (outputMsg != null)
                    {
                        List<String> lines = Collections.singletonList(docName + ": Tag CODEH ya firmado de manera válida, no es posible firmar tag COD");
                        Path file = Paths.get(outputMsg);
                        Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    } else {
                        System.out.println(docName + ": Tag CODEH ya firmado de manera válida, no es posible firmar tag COD");
                    }
                    return true;
                }
            }
        } else if (codeh) {
            if (URICOD != null && URICOD.equals("#COD")) {
                boolean verifiedCOD = verifySignature(doc, docName, codID, outputMsg);
                if (verifiedCOD) {
                    if (outputMsg != null)
                    {
                        List<String> lines = Collections.singletonList(docName + ": Tag COD firmado de manera válida");
                        Path file = Paths.get(outputMsg);
                        Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    } else {
                        System.out.println(docName + ": Tag COD firmado de manera validá");
                    }
                } else {
                    if (outputMsg != null)
                    {
                        List<String> lines = Collections.singletonList(docName + ": Tag COD firmado de manera inválida, verifique el xml");
                        Path file = Paths.get(outputMsg);
                        Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    } else {
                        System.out.println(docName + ": Tag COD firmado de manera inválida, verifique el xml");
                    }
                    return true;
                }
            } else {
                if (outputMsg != null)
                {
                    List<String> lines = Collections.singletonList(docName + ": Tag COD no firmado, verifique el xml");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": Tag COD no firmado, verifique el xml");
                }
                return true;
            }
            if (URICODEH != null && URICODEH.equals("#CODEH")) {
                boolean verifiedCODEH = verifySignature(doc, docName, codehID, outputMsg);
                if (verifiedCODEH) {
                    if (outputMsg != null)
                    {
                        List<String> lines = Collections.singletonList(docName + ": Tag CODEH ya firmado de manera válida, no es posible volver a realizar la firma");
                        Path file = Paths.get(outputMsg);
                        Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    } else {
                        System.out.println(docName + ": Tag CODEH ya firmado de manera válida, no es posible volver a realizar la firma");
                    }
                    return true;
                } else {
                    if (outputMsg != null)
                    {
                        List<String> lines = Collections.singletonList(docName + ": Tag CODEH ya firmado de manera inválida, verifique el xml");
                        Path file = Paths.get(outputMsg);
                        Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    } else {
                        System.out.println(docName + ": Tag CODEH ya firmado de manera inválida, verifique el xml");
                    }
                    return true;
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
                    List<String> lines = Collections.singletonList(docName + ": No es posible encontrar el nodo: " + dataURL);
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": No es posible encontrar el nodo: " + dataURL);
                }
                return true;
            }

            Node nodeToSign = nodes.item(0);
            ((Element) nodeToSign).setIdAttribute("id", true);
            Node sigParent = nodeToSign.getParentNode();
            String referenceURI = "#" + dataURL;

            // Create an Array of Transform, add it one Transform which specify the Signature ENVELOPED method.
            List<Transform> transformList = new ArrayList<>(1);
            transformList.add(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
            transformList.add(fac.newTransform("http://www.w3.org/2001/10/xml-exc-c14n#", (TransformParameterSpec) null));

            Reference ref = fac.newReference(referenceURI, fac.newDigestMethod("http://www.w3.org/2000/09/xmldsig#sha1", null), transformList, null, null);
            List<Reference> referenceList;
            referenceList = Collections.singletonList(ref);

            CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod
                    (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                            (XMLStructure) null);
            SignatureMethod signatureMethod = fac.newSignatureMethod(SignatureMethod.RSA_SHA1,null);
            SignedInfo si = fac.newSignedInfo(canonicalizationMethod, signatureMethod, referenceList);

            KeyInfoFactory kif = fac.getKeyInfoFactory();

            // Get the subject name and the certificate to display
            List<Object> x509Content = new ArrayList<>();
            x509Content.add(signingCertificate_.getSubjectX500Principal().getName());
            x509Content.add(signingCertificate_);
            X509Data x509data = kif.newX509Data(x509Content);

            // Get and put the KeyValue in a list with the data
            List<XMLStructure> list = new ArrayList<>();
            KeyValue kv = kif.newKeyValue(signingCertificate_.getPublicKey());
            list.add(kv);
            list.add(x509data);

            KeyInfo ki = kif.newKeyInfo(list);

            XMLSignature signature = fac.newXMLSignature(si, ki);

            // Create the DOMSignContext by specifying the signing informations: Private Key, Node to be signed
            DOMSignContext signContext = new DOMSignContext(signatureKey_, sigParent);
            signContext.setDefaultNamespacePrefix("ds");

            try {
                signature.sign(signContext);
                return false;
            } catch (Exception e) {
                e.printStackTrace();
                return true;
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return true;
        }
    }

    /**
     * Get  reference URI of the signature
     *
     */
    private void getURI(Document doc) {
        try {
            // Try to find Signature element
            NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS,
                    "Signature");
            if (nl.getLength() != 0) {
                // Get the COD reference URI
                Element nodeElementCOD = (Element) nl.item(codID);
                NodeList sigInfoCOD = nodeElementCOD.getElementsByTagNameNS(XMLSignature.XMLNS, "SignedInfo");
                Element sigElementCOD = (Element) sigInfoCOD.item(0);
                NodeList referenceURICOD = sigElementCOD.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
                Element referenceElementCOD = (Element) referenceURICOD.item(0);
                URICOD = referenceElementCOD.getAttributes().getNamedItem("URI").getNodeValue();

                if (URICOD.equals("#CODEH")) {
                    URICODEH = URICOD;
                    return;
                }
                // Get the CODEH reference URI
                Element nodeElementCODEH = (Element) nl.item(codehID);
                NodeList sigInfoCODEH = nodeElementCODEH.getElementsByTagNameNS(XMLSignature.XMLNS, "SignedInfo");
                Element sigElementCODEH = (Element) sigInfoCODEH.item(0);
                NodeList referenceURICODEH = sigElementCODEH.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
                Element referenceElementCODEH = (Element) referenceURICODEH.item(0);
                URICODEH = referenceElementCODEH.getAttributes().getNamedItem("URI").getNodeValue();
            }
        } catch (Exception ignored) {}
    }

    /**
     * Load private key from cert
     *
     * @param fileName Location/Name of the cert
     * @return the loaded private key
     */
    private PrivateKey loadPrivateKey(String fileName)
            throws IOException, GeneralSecurityException
    {
        PrivateKey key;
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
     * Write results to a file
     *
     * @param args Input arguments to read the output
     */
    private void writeResult(String[] args, int isToken, boolean cod, boolean codeh, Document doc, String docName, String outputMsg)
            throws Exception {
        OutputStream os = System.out;
        if (isToken == 1) {
            File file = new File(args[5]);
            if (file.isDirectory()) {
                if (args.length > 5) {
                    os = new FileOutputStream(file.getAbsolutePath() + File.separator + docName);
                } else {
                    os = System.out;
                }
            } else {
                if (args.length > 5) {
                    os = new FileOutputStream(args[5]);
                } else {
                    os = System.out;
                }
            }
        }
        else if (isToken == 0) {
            File file = new File(args[4]);
            if (file.isDirectory()) {
                if (args.length > 4) {
                    os = new FileOutputStream(file.getAbsolutePath() + File.separator + docName);
                } else {
                    os = System.out;
                }
            } else {
                if (args.length > 4) {
                    os = new FileOutputStream(args[4]);
                } else {
                    os = System.out;
                }
            }
        }

        // Format xml
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));

        if (cod) {
            if (outputMsg != null)
            {
                List<String> lines = Collections.singletonList(docName + ": COD firmado correctamente");
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println(docName + ": COD firmado correctamente");
            }
        } else if (codeh) {
            if (outputMsg != null)
            {
                List<String> lines = Collections.singletonList(docName + ": CODEH firmado correctamente");
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println(docName + ": CODEH firmado correctamente");
            }
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
                throw new KeySelectorException("#### \n" + "El objeto KeyInfo no existe!");
            }
            SignatureMethod sm = (SignatureMethod) method;
            List<?> list = keyInfo.getContent();

            for (Object aList : list) {
                XMLStructure xmlStructure = (XMLStructure) aList;
                if (xmlStructure instanceof X509Data) {
                    PublicKey pk;
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
                    } catch (KeyException ignored) {
                    }
                    // make sure algorithm is compatible with method
                    assert pk != null;
                    if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                        return new SimpleKeySelectorResult(pk);
                    }
                }
            }
            throw new KeySelectorException("#### \n" + "KeyValue no encontrado!");
        }
        boolean algEquals(String algURI, String algName) {
            return algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)
                    || algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1);
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

    public static class CustomException extends Throwable {
        CustomException(String message) {
            super(message, null, true, false);
        }

        @Override
        public String toString() {
            String s = getClass().getName();
            String message = getLocalizedMessage();
            return (message != null) ? message : s;
        }
    }
}