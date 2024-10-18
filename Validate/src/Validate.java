/*
  Derechos Reservados © 2017 Martín Iván Ríos, Grupo Sauken S.A.

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

  Autor: Martín Iván Ríos
  Correo electrónico: mailto:irios@sauken.com,rios.martinivan@gmail.com
  Empresa: Grupo Sauken S.A.
  WebSite: http://www.sauken.com/

  <>

  Copyright © Martín Iván Ríos, Grupo Sauken S.A.

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

  Author: Martín Iván Ríos
  E-mail: mailto:irios@sauken.com,rios.martinivan@gmail.com
  Company: Grupo Sauken S.A.
  WebSite: http://www.sauken.com/

 */

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.crypto.*;
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
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

public class Validate {

    private static void showHelp() {
        System.out.println("Uso:    java -jar validar.jar [--list/--xml] [lista/documento] [output-msg] [output-error]");
        System.out.println("                              [--help/--licencia]");
        System.out.println();
        System.out.println("        --help      -h                       Muestra ésta ayuda");
        System.out.println("        --licencia  -l                       Muestra la licencia del programa");
        System.out.println("        --list      -l    lista              Lista con los documentos a validar, uno debajo de otro");
        System.out.println("        --xml       -x    documento          Documento a validar");
        System.out.println();
        System.out.println("        output-msg    OPCIONAL               Documento de salida de mensajes, si no se especifica, se mostrará en pantalla");
        System.out.println("        output-error  OPCIONAL*              Documento de salida de errores, si no se especifica, se mostrará en pantalla");
        System.out.println("                                             *Opcional sólo si output-msg está establecido");
    }

    public static void main(String[] args) throws CustomException, Exception {

        String outputMsg = null;

        // Startup of the jar file
        String startup = "DS-COD versión 1.2.2\n" +
                "Derechos Reservados © 2017 Martín Iván Ríos, Grupo Sauken S.A.\n" +
                "Copyright © 2017 Martín Iván Ríos, Grupo Sauken S.A.\n\n" +
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

        String licencia = " Derechos Reservados © 2017 Martín Iván Ríos, Grupo Sauken S.A.\n" +
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
                " Autor: Martín Iván Ríos\n" +
                " Correo electrónico: mailto:irios@sauken.com,rios.martinivan@gmail.com\n" +
                " Empresa: Grupo Sauken S.A.\n" +
                " WebSite: http://www.sauken.com/\n" +
                "\n" +
                "                                  --------------------------------------------------------------\n" +
                "\n" +
                " Copyright © Martín Iván Ríos, Grupo Sauken S.A.\n" +
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
                " Author: Martín Iván Ríos\n" +
                " E-mail: mailto:irios@sauken.com,rios.martinivan@gmail.com\n" +
                " Company: Grupo Sauken S.A.\n" +
                " WebSite: http://www.sauken.com/" +
                "\n";

        if (args.length == 0) {
            showHelp();
            System.exit(0);
        }
        // Command line input options
        switch (args[0])
        {
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
        }
        int codID = 0;
        int codehID = 1;

        // Set output-error
        if (args.length > 3)
        {
            Path file = Paths.get(args[3]);
            Files.deleteIfExists(file);
            Files.createFile(file);
            PrintStream err = new PrintStream(new FileOutputStream(args[3]));
            System.setErr(err);
            List<String> linesTmp = Collections.singletonList("####");
            Files.write(file, linesTmp, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            System.out.println("Errores en " + args[3]);
        }

        // Set output-msg
        if (args.length > 2)
        {
            outputMsg = args[2];
            Path file = Paths.get(outputMsg);
            Files.deleteIfExists(file);
            Files.createFile(file);
            List<String> lines = Collections.singletonList("####");
            Files.write(file, lines, Charset.forName("UTF-8"));
            System.out.println("Salida en " + args[2]);
        }

        // Check if is a single document or not
        switch (args[0]) {
            case "--list":
                if (!args[1].contains(".txt")) {
                    throw new CustomException("#### \n" + args[1] + " no es una lista valida");
                }

                // Put each doc listed in an array
                Scanner sc = new Scanner(new File(args[1]));
                List<String> docLines = new ArrayList<>();
                while (sc.hasNextLine()) {
                    docLines.add(sc.nextLine());
                }
                String[] arr = docLines.toArray(new String[0]);

                for (String docPath : arr) {
                    File f = new File(docPath);
                    String docName = f.getName();

                    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                    dbf.setNamespaceAware(true);
                    Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(docPath));

                    boolean verifiedCOD = verifySignature(doc, docName, codID, outputMsg);
                    if (verifiedCOD) {
                        verifySignature(doc, docName, codehID, outputMsg);
                    }
                }
                break;
            case "-l":
                if (!args[1].contains(".txt")) {
                    throw new CustomException("#### \n" + args[1] + " no es una lista valida");
                }

                // Put each doc listed in an array
                Scanner sc2 = new Scanner(new File(args[1]));
                List<String> docLines2 = new ArrayList<>();
                while (sc2.hasNextLine()) {
                    docLines2.add(sc2.nextLine());
                }
                String[] arr2 = docLines2.toArray(new String[0]);

                for (String docPath : arr2) {
                    File f = new File(docPath);
                    String docName = f.getName();

                    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                    dbf.setNamespaceAware(true);
                    Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(docPath));

                    boolean verifiedCOD = verifySignature(doc, docName, codID, outputMsg);
                    if (verifiedCOD) {
                        verifySignature(doc, docName, codehID, outputMsg);
                    }
                }
                break;
            case "--xml":
                if (!args[1].contains(".xml")) {
                    throw new CustomException("#### \n" + args[1] + " no es un xml valido");
                }

                File f = new File(args[1]);
                String docName = f.getName();

                DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                dbf.setNamespaceAware(true);
                Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(args[1]));

                boolean verifiedCOD = verifySignature(doc, docName, codID, outputMsg);
                if (verifiedCOD) {
                    verifySignature(doc, docName, codehID, outputMsg);
                }
                break;
            case "-x":
                if (!args[1].contains(".xml")) {
                    throw new CustomException("#### \n" + args[1] + " no es un xml valido");
                }

                File f2 = new File(args[1]);
                String docName2 = f2.getName();

                DocumentBuilderFactory dbf2 = DocumentBuilderFactory.newInstance();
                dbf2.setNamespaceAware(true);
                Document doc2 = dbf2.newDocumentBuilder().parse(new FileInputStream(args[1]));

                boolean verifiedCOD2 = verifySignature(doc2, docName2, codID, outputMsg);
                if (verifiedCOD2) {
                    verifySignature(doc2, docName2, codehID, outputMsg);
                }
                break;
            default:
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList("Por favor, use las opciones \"--list\" o \"--xml\" solamente");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println("Por favor, use las opciones \"--list\" o \"--xml\" solamente");
                }
                break;
        }
    }

    private static String getExecutionPath(Class c) {
        URL rootPath = c.getProtectionDomain().getCodeSource().getLocation();
        String URI = rootPath.toString().substring(6);
        String[] currentPath = URI.split("validar.jar");
        currentPath[0] = currentPath[0].replaceAll("%20", " ");
        return currentPath[0];
    }

    /**
     * Method to verify the validity of the signature
     *
     * @param doc Document to validate
     * @param docName Name of the document
     * @param id id
     * @return if it's verified or not
     * @throws Exception Exception
     */
    private static boolean verifySignature(Document doc, String docName, int id, String outputMsg) throws Exception {

        // Find Signature element
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS,
                "Signature");
        if (nl.getLength() == 0) {
            if (outputMsg != null)
            {
                List<String> lines = Collections.singletonList(docName + ": No se puede encontrar la firma");
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println(docName + ": No se puede encontrar la firma");
            }
            return false;
        }
        if (id == 1) {
            if (nl.getLength() < 2) {
                if (outputMsg != null)
                {
                    List<String> lines = Collections.singletonList(docName + ": CODEH no firmado");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": CODEH no firmado");
                }
                return false;
            }
        }

        Element nodeElement = (Element) nl.item(id);

        // Get the reference URI
        NodeList sigInfo = nodeElement.getElementsByTagName("ds:SignedInfo");
        Element sigElement = (Element) sigInfo.item(0);
        NodeList referenceURI = sigElement.getElementsByTagName("ds:Reference");

        Element referenceElement = (Element) referenceURI.item(0);
        String URI = referenceElement.getAttributes().getNamedItem("URI").getNodeValue();

        // Make a temporary pem
        NodeList keyInfo = nodeElement.getElementsByTagName("ds:KeyInfo");
        Element keyElement = (Element) keyInfo.item(0);
        NodeList keyData = keyElement.getElementsByTagName("ds:X509Data");
        Element keyDataElement = (Element) keyData.item(0);
        NodeList certificate = keyDataElement.getElementsByTagName("ds:X509Certificate");

        Element certificateElement = (Element) certificate.item(0);
        String certElm = certificateElement.getTextContent();

        String pemCert = "-----BEGIN CERTIFICATE-----\n" + certElm + "\n-----END CERTIFICATE-----";
        String i = (id == 0) ? "cod" : "codeh";
        String pem = getExecutionPath(Validate.class) + "temp-xml-" + i + ".pem";
        Path pemPath = Paths.get(pem);
        Files.deleteIfExists(pemPath);
        Files.createFile(pemPath);
        List<String> pemLines = Collections.singletonList(pemCert);
        Files.write(pemPath, pemLines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);


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
        if (!coreValidity) {
            if (id == 0) {
                if (outputMsg != null)
                {
                    List<String> lines = Collections.singletonList(docName + ": La firma en COD ha fallado la verificación base");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": La firma en COD ha fallado la verificación base");
                }
                boolean sv = signature.getSignatureValue().validate(valContext);
                if (outputMsg != null)
                {
                    List<String> lines = Collections.singletonList(docName + ": Estado de validez del COD: " + sv);
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": Estado de validez : "+ sv);
                }

                // check the validation status of each Reference
                for (Object o : signature.getSignedInfo().getReferences()) {
                    boolean refValid = ((Reference) o).validate(valContext);
                    if (outputMsg != null) {
                        List<String> lines = Collections.singletonList(docName + ": Estado de validez del COD: " + refValid);
                        Path file = Paths.get(outputMsg);
                        Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    } else {
                        System.out.println(docName + ": Estado de validez del COD: " + refValid);
                    }
                }
            } else if (id == 1) {
                if (outputMsg != null)
                {
                    List<String> lines = Collections.singletonList(docName + ": La firma en CODEH ha fallado la verificación base");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": La firma en CODEH ha fallado la verificación base");
                }
                boolean sv = signature.getSignatureValue().validate(valContext);
                if (outputMsg != null)
                {
                    List<String> lines = Collections.singletonList(docName + ": Estado de validez del CODEH: " + sv);
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": Estado de validez : "+ sv);
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
                if (outputMsg != null)
                {
                    List<String> lines = Collections.singletonList(docName + ": La firma en COD ha pasado la verificación base");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": La firma en COD ha pasado la verificación base");
                }
                // Check the validity of the certificates
                checkCertValidity(outputMsg, pem, docName, id);
            } else if (id == 1) {
                if (outputMsg != null)
                {
                    List<String> lines = Collections.singletonList(docName + ": La firma en CODEH ha pasado la verificación base");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": La firma en CODEH ha pasado la verificación base");
                }
                // Check the validity of the certificates
                checkCertValidity(outputMsg, pem, docName, id);
            }
            return true;
        }
    }

    private static void checkCertValidity(String outputMsg, String pem, String docName, int id)
            throws CertificateException, IOException, CRLException {
        String i;
        if (id == 0) {
            i = "COD";
        } else {
            i = "CODEH";
        }

        // Check the validity of the certificate
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(pem);
        X509Certificate cert = (X509Certificate) fact.generateCertificate(is);

        String cn = cert.getIssuerX500Principal().toString().split("CN=")[1].split(",")[0];
        try {
            cert.checkValidity();

            if (outputMsg != null) {
                List<String> lines = Collections.singletonList(docName + ": El certificado de la firma en " + i + " es válido actualmente");
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println(docName + ": El certificado de la firma en " + i + " es válido actualmente");
            }
        } catch (CertificateExpiredException e) {
            if (outputMsg != null) {
                List<String> lines = Collections.singletonList(docName + ": El certificado de la firma en " + i + " ha expirado");
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println(docName + ": El certificado de la firma en " + i + " ha expirado");
            }
        } catch (CertificateNotYetValidException e) {
            if (outputMsg != null) {
                List<String> lines = Collections.singletonList(docName + ": El certificado de la firma en " + i + " todabía no es válido");
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println(docName + ": El certificado de la firma en " + i + " todabía no es válido");
            }
        }
        String certString = cert.toString();
        if (certString.contains("CRLDistributionPoints")) {
            String[] tmp = certString.split("CRLDistributionPoints \\[");
            String[] parts = tmp[1].split("]]");
            String[] distPoints = parts[0].substring(4, parts[0].length() - 1).split(",");

            boolean noInternetError = false;
            boolean revoked = false;
            List<String> urlList = new ArrayList<>();
            for (String tempDist : distPoints) {
                String[] tmpUrl = tempDist.split("\\[URIName: ");
                String url;
                try {
                    url = tmpUrl[1].substring(0, tmpUrl[1].length() - 1).replaceAll("]", "");
                } catch (Exception ignored) {
                    url = tmpUrl[0].replaceAll("]", "");
                }
                if (!url.substring(url.length() - 3).equals("crl")) {
                    url = tmpUrl[1].replaceAll("]", "");
                }
                url = url.replace("URIName: ", "");
                url = url.replace("URIName:", "");

                X509CRLEntry revokedCertificate;
                X509CRL crl;

                // Create a new trust manager that trust all certificates
                TrustManager[] trustAllCerts = new TrustManager[]{
                        new X509TrustManager() {
                            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                                return null;
                            }

                            public void checkClientTrusted(
                                    java.security.cert.X509Certificate[] certs, String authType) {
                            }

                            public void checkServerTrusted(
                                    java.security.cert.X509Certificate[] certs, String authType) {
                            }
                        }
                };

                // Activate the new trust manager
                try {
                    SSLContext sc = SSLContext.getInstance("SSL");
                    sc.init(null, trustAllCerts, new java.security.SecureRandom());
                    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
                } catch (Exception ignored) {
                }

                URL crlUrl = new URL(url);
                HttpURLConnection connection = (HttpURLConnection) (crlUrl.openConnection());
                connection.connect();
                try {
                    if (connection.getResponseCode() == 301) {
                        connection = (HttpURLConnection) (new URL(connection.getHeaderField("Location")).openConnection());
                    }
                    StringBuilder inputLine = new StringBuilder();
                    String tmp2;
                    DataInputStream inStream = new DataInputStream(connection.getInputStream());
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inStream));
                    int i2 = 0;
                    while ((tmp2 = bufferedReader.readLine()) != null) {
                        if (i2 > 20) {
                            i2 = 0;
                            break;
                        }
                        inputLine.append(tmp2);
                        i2++;
                    }
                    bufferedReader.close();
                    inStream.close();
                    if (i2 > 0 && inputLine.toString().contains(".assign(\"")) {
                        String[] a = inputLine.toString().split(Pattern.quote(".assign(\""));
                        String finalStr = a[1].split(Pattern.quote("\");"))[0];

                        connection = (HttpURLConnection) (new URL(finalStr).openConnection());
                    } else {
                        connection.disconnect();
                        connection = (HttpURLConnection) (crlUrl.openConnection());
                        if (connection.getResponseCode() == 301) {
                            connection = (HttpURLConnection) (new URL(connection.getHeaderField("Location")).openConnection());
                        }
                    }
                    inStream = new DataInputStream(connection.getInputStream());
                    crl = (X509CRL) fact.generateCRL(inStream);
                } catch (UnknownHostException e) {
                    noInternetError = true;
                    break;
                }

                revokedCertificate = crl.getRevokedCertificate(cert.getSerialNumber());
                if (revokedCertificate != null) {
                    // Revoked
                    revoked = true;
                }
                urlList.add(url);
            }
            String parsedUrlList = "";
            for (String url : urlList) {
                if (parsedUrlList.equals("")) {
                    parsedUrlList = url;
                } else {
                    parsedUrlList = parsedUrlList + ", " + url;
                }
            }
            if (noInternetError) {
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList(docName + ": No es posible validar contra AC del certificado de la firma en " + i + ", no hay conneción a internet");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": No es posible validar contra AC del certificado de la firma en " + i + ", no hay conneción a internet");
                }
                return;
            }
            if (revoked) {
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList(docName + ": El certificado de la firma en " + i + " está actualmente revocado, contra la AC: " + cn);
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": El certificado de la firma en " + i + " está actualmente revocado, contra la AC: " + cn);
                }
            } else {
                if (outputMsg != null) {
                    List<String> lines = Collections.singletonList(docName + ": El certificado de la firma en " + i + " es actualmente válido, contra la AC: " + cn);
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": El certificado de la firma en " + i + " es actualmente válido, contra la AC: " + cn);
                }
            }
            if (outputMsg != null) {
                List<String> lines = Collections.singletonList(docName + ": Revoked list urls: " + parsedUrlList);
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println(docName + ": URLs de las listas de revocados: " + parsedUrlList);
            }
        } else {
            if (outputMsg != null) {
                List<String> lines = Collections.singletonList(docName + ": No pudo validarse si la firma esta revocada");
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println(docName + ": No pudo validarse si la firma esta revocada");
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

    public static class CustomException extends Throwable
    {
        @Override
        public String toString() {
            String s = getClass().getName();
            String message = getLocalizedMessage();
            return (message != null) ? message : s;
        }

        CustomException(String message)
        {
            super(message, null, true, false);
        }
    }
}