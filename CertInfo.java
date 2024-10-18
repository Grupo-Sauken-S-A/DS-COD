import java.io.OutputStream;
import java.io.PrintStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Scanner;
import java.security.cert.X509Certificate;
import java.nio.file.*;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Arrays;

/**
 * Write a description of class CertInfo here.
 * 
 * @author (your name) 
 * @version (a version number or a date)
 */
public class CertInfo
{
    
  static int isToken = -1;
  
     /**
   * Main method, input read and execution
   * 
   * @param args Input arguments
   */
  public static void main(String[] args)
    throws Exception
  {
    if (args.length == 0 || args.length < 1) {
      System.out.println("Usage: java -jar ds-cod.jar [--soft/--token/--help]");
      System.out.println("                            [--soft]     [path-al-cert]          [output-msg] [output-error]");
      System.out.println("                            [--token]    [config-con-dll]  [pin] [output-msg] [output error]");
      System.out.println("");
      System.out.println("        --help  -h                               Muestra ésta ayuda");
      System.out.println("        --soft  -s    path-al-cert               Direccion del PEM");
      System.out.println("        --token -t    conf-con-dll               Direccion del conf.txt con el DLL");
      System.out.println("");
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
          System.out.println("Usage: java -jar certificado.jar [--soft/--token/--help]");
          System.out.println("                            [--soft]     [path-al-cert]          [output-msg] [output-error]");
          System.out.println("                            [--token]    [config-con-dll]  [pin] [output-msg] [output error]");
          System.out.println("");
          System.out.println("        --help  -h                               Muestra ésta ayuda");
          System.out.println("        --soft  -s    path-al-cert               Direccion del PEM");
          System.out.println("        --token -t    conf-con-dll               Direccion del conf.txt con el DLL");
          System.out.println("");
          System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
          System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
          System.exit(0);
          break;
        case "--help": 
          System.out.println("Usage: java -jar certificado.jar [--soft/--token/--help]");
          System.out.println("                            [--soft]     [path-al-cert]          [output-msg] [output-error]");
          System.out.println("                            [--token]    [config-con-dll]  [pin] [output-msg] [output error]");
          System.out.println("");
          System.out.println("        --help  -h                               Muestra ésta ayuda");
          System.out.println("        --soft  -s    path-al-cert               Direccion del PEM");
          System.out.println("        --token -t    conf-con-dll               Direccion del conf.txt con el DLL");
          System.out.println("");
          System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
          System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
          System.exit(0);
          break;
    }
    
    // If token is selected with an output file for errors
    if (isToken == 1)
    {
      if (args.length < 2) {
        System.out.println("Usage: java -jar certificado.jar [--soft/--token/--help]");
        System.out.println("                            [--soft]     [path-al-cert]          [output-msg] [output-error]");
        System.out.println("                            [--token]    [config-con-dll]  [pin] [output-msg] [output error]");
        System.out.println("");
        System.out.println("        --help  -h                               Muestra ésta ayuda");
        System.out.println("        --soft  -s    path-al-cert               Direccion del PEM");
        System.out.println("        --token -t    conf-con-dll               Direccion del conf.txt con el DLL");
        System.out.println("");
        System.out.println("        output-msg    OPCIONAL                   Documento de salida de mensajes, si no se especifica, se mostrara en pantalla");
        System.out.println("        output-error  OPCIONAL                   Documento de salida de errores, si no se especifica, se mostrara en pantalla");
        System.exit(0);
      }
        
      if (args.length > 4)
      {
        PrintStream err = new PrintStream(new FileOutputStream(args[4]));
        System.setErr(err);
        System.out.println("Errores en " + args[4]);
      }
    }
    
    // If soft is selected with an output file for errors
    else if ((isToken == 0) && 
      (args.length > 3))
    {
      PrintStream err = new PrintStream(new FileOutputStream(args[3]));
      System.setErr(err);
      System.out.println("Errores en " + args[3]);
    }
    
    // If token selected
    if (isToken == 1)
    {
      String dll = new Scanner(new File(args[1])).useDelimiter("\\Z").next();
      
      DsCOD genEnvel = new DsCOD(dll, isToken);
      genEnvel.selectSignatureKey(args[2]);
      X509Certificate signingCertificate_ = genEnvel.signingCertificate_;
      if (args.length > 3)
      {
          System.out.println("Salida en " + args[3]);
          List<String> lines = Arrays.asList(signingCertificate_.toString());
          Path file = Paths.get(args[3]);
          Files.write(file, lines, Charset.forName("UTF-8"));
      } else {
          System.out.println(signingCertificate_);
      }
    }
    
    // If soft selected
    else if ((isToken == 0))
    {
      String fileName = args[1];
      
      DsCOD genEnvel = new DsCOD(fileName, isToken);
      X509Certificate signingCertificate_ = genEnvel.signingCertificate_;
      if (args.length > 2)
      {
          System.out.println("Salida en " + args[2]);
          List<String> lines = Arrays.asList(signingCertificate_.toString());
          Path file = Paths.get(args[2]);
          Files.write(file, lines, Charset.forName("UTF-8"));
      } else {
          System.out.println(signingCertificate_);
      }
    }
  }
}
