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

import org.apache.commons.codec.binary.Base64;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;

public class CertInfo
{

    private static void showHelp() {
        System.out.println("Uso:    java -jar certificado.jar [--soft/--token/--help/--licencia]");
        System.out.println("                                 [--soft]   [path-al-cert]         [output-msg] [output-error]");
        System.out.println("                                 [--token]  [config-con-dll] [pin] [output-msg] [output-error]");
        System.out.println();
        System.out.println("        --help      -h                       Muestra ésta ayuda");
        System.out.println("        --licencia  -l                       Muestra la licencia del programa");
        System.out.println("        --soft      -s    path-al-cert       Ubicación del certificado x509 en formato PEM");
        System.out.println("        --token     -t    conf-con-dll       Ubicación del programa PKCS#11 (.dll) del Token utilizado");
        System.out.println();
        System.out.println("        output-msg    OPCIONAL               Documento de salida de mensajes, si no se especifica, se mostrará en pantalla");
        System.out.println("        output-error  OPCIONAL*              Documento de salida de errores, si no se especifica, se mostrará en pantalla");
        System.out.println("                                             *Opcional sólo si output-msg está establecido");
    }

    private static X509Certificate getCert(String info, int isToken, String outputMsg)
            throws IOException, DsCOD.CustomException {
        if (isToken == 0) {
            DsCOD genEnvel = new DsCOD(info, isToken, outputMsg);
            return DsCOD.signingCertificate_;
        } else {
            return null;
        }
    }

    private static X509Certificate getCert(String info, int isToken, String pin, String outputMsg)
            throws Exception, DsCOD.CustomException {
        if (isToken == 1) {
            DsCOD genEnvel = new DsCOD(info, isToken, outputMsg);
            genEnvel.selectSignatureKey(pin);
            return DsCOD.signingCertificate_;
        } else {
            return null;
        }
    }


    private static String getExecutionPath(Class c) {
        URL rootPath = c.getProtectionDomain().getCodeSource().getLocation();
        String URI = rootPath.toString().substring(6);
        String[] currentPath = URI.split("certificado.jar");
        currentPath[0] = currentPath[0].replaceAll("%20", " ");
        return currentPath[0];
    }

    /**
     * Main method, input read and execution
     *
     * @param args Input arguments
     */
    public static void main(String[] args)
            throws Exception, DsCOD.CustomException {
        int isToken = -1;
        String outputMsg = null;
        String cert_begin = "-----BEGIN CERTIFICATE-----\n";
        String end_cert = "-----END CERTIFICATE-----";

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
            if (args.length < 2) {
                showHelp();
                System.exit(0);
            }

            // Set output-msg
            if (args.length > 3)
            {
                outputMsg = args[3];
                Path file = Paths.get(outputMsg);
                Files.deleteIfExists(file);
                Files.createFile(file);
                System.out.println("Salida en " + args[3]);
            }

            // Set output-err
            if (args.length > 4)
            {
                Path file = Paths.get(args[4]);
                Files.deleteIfExists(file);
                Files.createFile(file);
                PrintStream err = new PrintStream(new FileOutputStream(args[4]));
                System.setErr(err);
                List<String> linesTmp = Collections.singletonList("####");
                Files.write(file, linesTmp, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                System.out.println("Errores en " + args[4]);
            }

            String dll = new Scanner(new File(args[1])).useDelimiter("\\Z").next();

            if (!args[1].contains(".txt")) {
                throw new DsCOD.CustomException("#### \n" + dll + " no es un archivo de configuración valido");
            }

            X509Certificate signingCertificate_ = getCert(dll, isToken, args[2], outputMsg);
            if (outputMsg != null) {
                System.out.println("Salida en " + outputMsg);
                Path file = Paths.get(outputMsg);
                Files.deleteIfExists(file);
                Files.createFile(file);
                List<String> lines = Collections.singletonList(signingCertificate_.toString());
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                byte[] derCert = signingCertificate_.getEncoded();
                String pemCertPre = Base64.encodeBase64String(derCert);
                String pemCert = cert_begin + pemCertPre + end_cert;
                String pem = getExecutionPath(CertInfo.class) + "pem.pem";
                Path pemPath = Paths.get(pem);
                Files.deleteIfExists(pemPath);
                Files.createFile(pemPath);
                List<String> pemLines = Collections.singletonList(pemCert);
                Files.write(pemPath, pemLines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println(signingCertificate_);
            }
        } else if ((isToken == 0)) {
            if (args.length > 3) {
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
                System.out.println("Salida en " + args[2]);
            }

            String fileName = args[1];

            if (!fileName.contains(".pem")) {
                throw new DsCOD.CustomException("#### \n" + fileName + " no es un certificado valido");
            }

            X509Certificate signingCertificate_ = getCert(fileName, isToken, outputMsg);
            if (outputMsg != null)
            {
                System.out.println("Salida en " + outputMsg);
                Path file = Paths.get(outputMsg);
                Files.deleteIfExists(file);
                Files.createFile(file);
                List<String> lines = Collections.singletonList(signingCertificate_.toString());
                Files.write(file, lines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
                byte[] derCert = signingCertificate_.getEncoded();
                String pemCertPre = Base64.encodeBase64String(derCert);
                String pemCert = cert_begin + pemCertPre + end_cert;
                String pem = getExecutionPath(CertInfo.class) + "pem.pem";
                Path pemPath = Paths.get(pem);
                Files.deleteIfExists(pemPath);
                Files.createFile(pemPath);
                List<String> pemLines = Collections.singletonList(pemCert);
                Files.write(pemPath, pemLines, Charset.forName("UTF-8"), StandardOpenOption.APPEND);
            } else {
                System.out.println(signingCertificate_);
            }
        }
    }
}