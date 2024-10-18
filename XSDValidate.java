import java.io.File;
import java.io.IOException;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.PrintStream;
import java.io.FileOutputStream;
import java.util.List;
import java.util.Arrays;
import java.nio.file.*;
import java.nio.charset.Charset;

import org.xml.sax.SAXException;

public class XSDValidate {
    
    static String outputMsg;

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args.length < 1) {
          System.out.println("Usage: java -jar validar-xsd.jar [xsd]    [documento] [output-msg] [output-error]");
          System.out.println("                                 [--help]");
          System.out.println("");
          System.out.println("        --help  -h                               Muestra ésta ayuda");
          System.out.println("");
          System.out.println("        xsd                                      Esquema a utilizar");
          System.out.println("        documento                                Documento a validar");
          System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
          System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
          System.exit(0);
        }
        
        // Command line input options
        switch (args[0])
        {
          case "-h":
            System.out.println("Usage: java -jar validar-xsd.jar [xsd]    [documento] [output-msg] [output-error]");
            System.out.println("                                 [--help]");
            System.out.println("");
            System.out.println("        --help  -h                               Muestra ésta ayuda");
            System.out.println("");
            System.out.println("        xsd                                      Esquema a utilizar");
            System.out.println("        documento                                Documento a validar");
            System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
            System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
            System.exit(0);
            break;
            
          case "--help":
            System.out.println("Usage: java -jar validar-xsd.jar [xsd]    [documento] [output-msg] [output-error]");
            System.out.println("                                 [--help]");
            System.out.println("");
            System.out.println("        --help  -h                               Muestra ésta ayuda");
            System.out.println("");
            System.out.println("        xsd                                      Esquema a utilizar");
            System.out.println("        documento                                Documento a validar");
            System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
            System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
            System.exit(0);
            break;
        }
        
        // Set output-error
        if (args.length > 3)
        {
          PrintStream err = new PrintStream(new FileOutputStream(args[3]));
          System.setErr(err);
          System.out.println("Errores en " + args[3]);
        }

        // Set output-msg
        if (args.length > 2)
        {
          outputMsg = args[2];
          System.out.println("Salida en " + args[2]);
        }
      
        String xsdPath = args[0];
        String xmlPath = args[1];
        
        if (validateXMLSchema(xsdPath, xmlPath)) {
            if (outputMsg != null)
            {
                List<String> lines = Arrays.asList("El XML ha pasado la verificación de esquema");
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"));
            } else {
                System.out.println("El XML ha pasado la verificación de esquema");
            }
        } else if (!validateXMLSchema(xsdPath, xmlPath)) {
            if (outputMsg != null)
            {
                List<String> lines = Arrays.asList("El XML ha fallando la verificación de esquema");
                Path file = Paths.get(outputMsg);
                Files.write(file, lines, Charset.forName("UTF-8"));
            } else {
                System.out.println("El XML ha fallando la verificación de esquema");
            }
        }
      }
    
    public static boolean validateXMLSchema(String xsdPath, String xmlPath)
        throws Exception, SAXException{
        
        try {
            SchemaFactory factory = 
                    SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema = factory.newSchema(new File(xsdPath));
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new File(xmlPath)));
        } catch (IOException | SAXException e) {
            throw new Exception("Exception: "+e.getMessage());
        }
        return true;
    }
}