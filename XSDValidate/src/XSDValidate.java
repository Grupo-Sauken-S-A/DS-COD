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
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.*;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;

public class XSDValidate {

    private static void showHelp() {
        System.out.println("Uso:    java -jar validar-xsd.jar [xsd] [--list/--xml] [documento/lista] [output-msg] [output-warning] [output-error]");
        System.out.println("                                 [--help/--licencia]");
        System.out.println();
        System.out.println("        --help      -h                         Muestra ésta ayuda");
        System.out.println("        --licencia  -l                         Muestra la licencia del programa");
        System.out.println("        --list      -l    lista                Lista con los documentos a validar, uno debajo de otro");
        System.out.println("        --xml       -x    documento            Documento a validar");
        System.out.println();
        System.out.println("        xsd                                    Esquema a utilizar, \"DEFAULT\" hará que se utilice el del documento");
        System.out.println("        output-msg      OPCIONAL               Documento de salida de mensajes, si no se especifica, se mostrará en pantalla");
        System.out.println("        output-warning  OPCIONAL*              Documento de salida de alertas, si no se especifica, se mostrará en pantalla");
        System.out.println("                                               *Opcional sólo si output-msg está establecido");
        System.out.println("        output-error    OPCIONAL*              Documento de salida de errores, si no se especifica, se mostrará en pantalla");
        System.out.println("                                               *Opcional sólo si output-warning está establecido");
    }

    public static void main(String[] args) throws Exception, CustomException {

        String outputMsg = null;
        String outputWarn = null;

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

        // Set output-error
        if (args.length > 5)
        {
            Path file = Paths.get(args[5]);
            Files.deleteIfExists(file);
            Files.createFile(file);
            PrintStream err = new PrintStream(new FileOutputStream(args[5]));
            System.setErr(err);
            List<String> linesTmp = Collections.singletonList("####");
            Files.write(file, linesTmp, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            System.out.println("Errores en " + args[5]);
        }

        // Set output-msg
        if (args.length > 3)
        {
            outputMsg = args[3];
            Path file = Paths.get(outputMsg);
            Files.deleteIfExists(file);
            Files.createFile(file);
            List<String> linesTmp = Collections.singletonList("####");
            Files.write(file, linesTmp, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            System.out.println("Salida en " + args[3]);
        }

        // Set output-warning
        if (args.length > 4)
        {
            outputWarn = args[4];
            Path file = Paths.get(outputWarn);
            Files.deleteIfExists(file);
            Files.createFile(file);
            System.out.println("Alertas en " + args[4]);
        }

        String xmlPath = args[2];
        String xsd = args[0];

        // Check if is a single document or not
        switch (args[1]) {
            case "--list":
                if (!xmlPath.contains(".txt")) {
                    throw new CustomException("#### \n" + xmlPath + " no es una lista valida");
                }

                // Put each doc listed in an array
                Scanner sc = new Scanner(new File(xmlPath));
                List<String> docLines = new ArrayList<>();
                while (sc.hasNextLine()) {
                    docLines.add(sc.nextLine());
                }
                String[] arr = docLines.toArray(new String[0]);

                for (String doc : arr) {
                    File f = new File(doc);
                    String docName = f.getName();

                    validate(xsd, doc, docName, outputMsg, outputWarn);
                }
                break;
            case "--xml":
                if (!xmlPath.contains(".xml")) {
                    throw new CustomException("#### \n" + xmlPath + " no es un xml valido");
                }

                File f = new File(xmlPath);
                String docName = f.getName();

                validate(xsd, xmlPath, docName, outputMsg, outputWarn);
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

    private static void validate(String xsd, String xmlPath, String docName, String outputMsg, String outputWarn) throws Exception, CustomException {

        String xsdPath;

        boolean isDefault = false;
        if (xsd.equals("DEFAULT")) {
            isDefault = true;
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(xmlPath));
            NodeList nl = doc.getElementsByTagName("ns1:Envelope");
            Element xsdElement = (Element) nl.item(0);
            if (nl.getLength() != 0 || xsdElement != null ) {
                String schemaLocation = xsdElement.getAttributes().getNamedItem("xsi:schemaLocation").getNodeValue();
                String[] xsdSplited = schemaLocation.split("\\s+");
                xsdPath = xsdSplited[1];
            } else {
                if (outputMsg != null)
                {
                    List<String> lines = Collections.singletonList(docName + ": Esquema no encontrado");
                    Path file = Paths.get(outputMsg);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                    return;
                } else {
                    System.out.println(docName + ": Esquema no encontrado");
                    return;
                }
            }
        } else {
            xsdPath = xsd;
        }

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(xmlPath));
        NodeList nl = doc.getElementsByTagName("CODVer");
        Element codVer = (Element) nl.item(0);
        if (nl.getLength() != 0 || codVer != null ) {
            String codVerStr = codVer.getFirstChild().getNodeValue();
            if (xsdPath != null && !xsdPath.contains(codVerStr)) {
                if (outputWarn != null)
                {
                    List<String> lines = Collections.singletonList(docName + ": El esquema dado y el especificado por el documento no concuerdan");
                    Path file = Paths.get(outputWarn);
                    Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                } else {
                    System.out.println(docName + ": El esquema dado y el especificado por el documento no concuerdan");
                }
            }
        } else {
            throw new CustomException("#### \n" + docName + ": Tag \"CODVer\" no encontrado");
        }

        if (validateXMLSchema(xsdPath, xmlPath, docName, isDefault, outputMsg)) {
            if (outputMsg != null)
            {
                List<String> lines;
                if (isDefault) {
                    lines = Arrays.asList(docName + ": Esquema del documento: " + xsdPath, docName + ": El XML ha pasado la verificación de esquema");
                } else {
                    lines = Arrays.asList(docName + ": Esquema local: " + xsdPath, docName + ": El XML ha pasado la verificación de esquema");
                }

                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                if (isDefault) {
                    System.out.println(docName + ": Esquema del documento: " + xsdPath);
                    System.out.println(docName + ": El XML ha pasado la verificación de esquema");
                } else {
                    System.out.println(docName + ": Esquema local: " + xsdPath);
                    System.out.println(docName + ": El XML ha pasado la verificación de esquema");
                }
            }
        } else if (!validateXMLSchema(xsdPath, xmlPath, docName, isDefault, outputMsg)) {
            if (outputMsg != null)
            {
                List<String> lines;
                if (isDefault) {
                    lines = Arrays.asList(docName + ": Esquema del documento: " + xsdPath, docName + ": El XML ha fallando la verificación de esquema");
                } else {
                    lines = Arrays.asList(docName + ": Esquema local: " + xsdPath, docName + ": El XML ha fallando la verificación de esquema");
                }
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                if (isDefault) {
                    System.out.println(docName + ": Esquema del documento: " + xsdPath);
                    System.out.println(docName + ": El XML ha fallando la verificación de esquema");
                } else {
                    System.out.println(docName + ": Esquema local: " + xsdPath);
                    System.out.println(docName + ": El XML ha fallando la verificación de esquema");
                }
            }
        }
    }

    private static boolean validateXMLSchema(String xsdPath, String xmlPath, String docName, boolean isDefault, String outputMsg)
            throws Exception {

        try {
            SchemaFactory factory =
                    SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema;
            if (isDefault) {
                schema = factory.newSchema(new URL(xsdPath));
            } else {
                schema = factory.newSchema(new File(xsdPath));
            }
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new File(xmlPath)));
            return true;
        } catch (SAXException e) {
            if (outputMsg != null)
            {
                List<String> lines = Collections.singletonList(docName + ": " + e.getMessage());
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println(e.getMessage());
            }
            return false;
        } catch (IOException ignored) {
            return false;
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