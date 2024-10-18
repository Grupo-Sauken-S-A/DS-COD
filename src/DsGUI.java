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

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.xml.bind.DatatypeConverter;
import java.awt.*;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

public class DsGUI {

    private static Double height;
    private static JFrame frame = new JFrame("DS-COD 1.2.2 - Certificado de Origen Digital de ALADI - Grupo Sauken S.A.");
    private JButton selectPEMButton;
    private JTextField selectedPEM;
    private JCheckBox CODCheckBox;
    private JCheckBox CODEHCheckBox;
    private JButton selectDocButton;
    private JTextField selectedDoc;
    private JTextField selectedOut;
    private JButton selectOutButton;
    private JButton signButton;
    private JPanel panelMain;
    private JPasswordField passwordField;
    private JTextField selectedConf;
    private JButton selectConfButton;
    private JCheckBox CODCheckBoxH;
    private JCheckBox CODEHCheckBoxH;
    private JTextField selectedDocH;
    private JButton selectDocButtonH;
    private JTextField selectedOutH;
    private JButton selectOutButtonH;
    private JButton signButtonH;
    private JTextField selectedDocVal;
    private JButton selectDocValButton;
    private JTextField selectedXSD;
    private JButton selectXSDButton;
    private JTextField selectedDocXSD;
    private JButton selectDocXSDButton;
    private JButton validateButton;
    private JButton validateXSDButton;
    private JTextArea certSwTextArea;
    private JTextField selectedPEMCert;
    private JButton selectPEMCertButton;
    private JButton certSwButton;
    private JTextArea certHwTextArea;
    private JButton certHwButton;
    private JTextField selectedConfCert;
    private JButton selectConfCertButton;
    private JPasswordField passwordCertField;
    private JButton openXMLH;
    private JButton openXML;
    private JTabbedPane tabbedPane;
    private JTabbedPane tabbedPaneFirmar;
    private JTextPane textPane2;
    private JEditorPane editorPane1;
    private JButton openLog;
    private JButton openLogH;
    private JCheckBox listDocCheckBoxH;
    private JCheckBox listDocCheckBox;
    private JCheckBox listValCheckBox;
    private JCheckBox listXSDCheckBox;
    private JButton openLogVal;
    private JButton openLogXSD;
    private JTextField issuerS;
    private JTextField sinceS;
    private JTextField untilS;
    private JTextField keyS;
    private JTextField algorithmS;
    private JTextField issuerH;
    private JTextField sinceH;
    private JTextField untilH;
    private JTextField algorithmH;
    private JButton moreInfoH;
    private JButton moreInfoS;
    private JTextField serialH;
    private JTextField serialS;
    private JEditorPane editorPane2 = new JEditorPane();
    private JScrollPane jScrollPane2 = new JScrollPane(editorPane2);
    private JEditorPane editorPaneCert = new JEditorPane();
    private JScrollPane jScrollPaneCert = new JScrollPane(editorPaneCert);
    private JLabel jlabel1;
    private JTabbedPane jTabbedPaneLog = new JTabbedPane(JTabbedPane.TOP);
    // Used variables
    private File pemFile;
    private File docFile;
    private File docFileH;
    private File outFile;
    private File outFileH;
    private File confFile;
    private File docVal;
    private File docValXSD;
    private File xsd;
    private File pemCertFile;
    private File confCertFile;
    private JFileChooser fc = new JFileChooser();
    private JFileChooser fcOut = new JFileChooser();
    private String outputMsg = getExecutionPath() + File.separator + "output-msg.txt";
    private String outputWarn = getExecutionPath() + File.separator + "output-warn.txt";
    private String outputErr = getExecutionPath() + File.separator + "output-err.txt";
    private String pemPath = getExecutionPath() + "pem.pem";

    private DsGUI() {

        String version = Runtime.class.getPackage().getImplementationVersion();
        if (!version.split("\\.")[1].equals("8")) {
            JOptionPane.showMessageDialog(frame,
                "Versión de Java incorrecta. \n" +
                    "Versión detectada: " + version + "\n" +
                    "Versión necesaria: 1.8.x",
                "Versión de Java incorrecta",
                JOptionPane.ERROR_MESSAGE);

            System.exit(1);
        }

        List<Path> paths = new ArrayList<>();
        paths.add(Paths.get(getExecutionPath() + File.separator + "xmlsec-1.5.5.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "validar-xsd.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "validar.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "org.apache.commons.io.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "jaxb-api-2.4.0-b180830.0359.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "javax.activation-api-1.2.0.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "iaikPkcs11Wrapper.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "iaikPkcs11Provider.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "iaik_xsect.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "iaik_jce.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "firmar-gui.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "firmar.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "commons-logging-1.2.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "commons-codec-1.11.jar"));
        paths.add(Paths.get(getExecutionPath() + File.separator + "certificado.jar"));

        for (Path p : paths) {
            if (!p.toFile().exists()) {
                JOptionPane.showMessageDialog(frame,
                    "Dependencias no encontradas. \n" +
                        "Por favor no mueva el archivo de su carpeta de origen",
                    "Dependencias no encontradas",
                    JOptionPane.ERROR_MESSAGE);

                System.exit(1);
            }
        }

        // Initialize
        selectedPEM.setText("Nada seleccionado");
        selectedDoc.setText("Nada seleccionado");
        selectedDocVal.setText("Nada seleccionado");
        selectedDocXSD.setText("Nada seleccionado");
        selectedXSD.setText("Elija un archivo XSD o se utilizará el del documento");
        selectedConf.setText("Nada seleccionado");
        selectedDocH.setText("Nada seleccionado");
        selectedPEMCert.setText("Nada seleccionado");
        selectedConfCert.setText("Nada seleccionado");
        CODCheckBox.setSelected(true);
        CODCheckBoxH.setSelected(true);
        signButtonH.setPreferredSize(openXMLH.getPreferredSize());
        signButton.setPreferredSize(openXML.getPreferredSize());
        openLog.setPreferredSize(openXML.getPreferredSize());
        openLogH.setPreferredSize(openXMLH.getPreferredSize());
        openLogVal.setPreferredSize(validateButton.getPreferredSize());
        openLogXSD.setPreferredSize(validateXSDButton.getPreferredSize());
        validateButton.setPreferredSize(selectDocValButton.getPreferredSize());
        validateXSDButton.setPreferredSize(selectDocXSDButton.getPreferredSize());
        certSwButton.setPreferredSize(selectPEMCertButton.getPreferredSize());
        certHwButton.setPreferredSize(selectConfCertButton.getPreferredSize());

        editorPane1.setEditorKit(JEditorPane.createEditorKitForContentType("text/html"));
        editorPane1.setText("<html>&nbsp; <br>" +
                "<b><center>" + frame.getTitle() + "</center></b>" +
                "&nbsp; <br>" +
                "&nbsp; ATENCIÓN: Esta versión del DS-COD (versión 1) no tiene más soporte <br>" +
                "&nbsp; <br>" +
                "&nbsp; Esta aplicación tiene por objetivo proveer un mecanismo sencillo de integración para aquellos sistemas <br>" +
                "&nbsp; pre existentes en instalaciones de exportadores y/o despachantes de aduana. Está orientado su uso al área <br>" +
                "&nbsp; de sistemas de dichas entidades. <br>" +
                "&nbsp; <br>" + "" +
                "&nbsp; Esta aplicación es de distrubición gratuita con código fuente bajo la licencia de uso <a href=\"GPLv2\">GPLv2</a>" +
                "&nbsp; <br>" +
                "&nbsp; <br>" +
                "&nbsp; <br>" +
                "&nbsp; <b>Referencias: </b><br>" +
                "&nbsp; <br>" +
                "&nbsp; COD AFIP: <a href=\"http://www.afip.gob.ar/cod\">http://www.afip.gob.ar/cod</a> <br>" +
                "&nbsp; Visualizador COD: <a href=\"http://www.afip.gob.ar/aladi/cod_visualizer.html\">http://www.afip.gob.ar/aladi/cod_visualizer.html</a> <br>" +
                "&nbsp; COD ALADI: <a href=\"https://www.codaladi.org/\">https://www.codaladi.org/</a> <br>" +
                "&nbsp; Versiones del COD: <a href=\"http://foros.aladi.org/gtah/inicio_versiones.asp\">http://foros.aladi.org/gtah/inicio_versiones.asp</a> <br>" +
                "&nbsp; Directorio del COD: <a href=\"http://www.codaladi.org/directorio\">http://www.codaladi.org/directorio</a> <br>" +
                "&nbsp; Página pública del COD de ALADI: <a href=\"http://www.aladi.org/sitioAladi/facilitacionComercioCOD.html\">http://www.aladi.org/sitioAladi/facilitacionComercioCOD.html</a> <br>" +
                "&nbsp; Página del foro técnico de ALADI: <a href=\"http://foros.aladi.org/gtah/inicio.asp\">http://foros.aladi.org/gtah/inicio.asp</a> <br>" +
                "&nbsp; <br>" +
                "&nbsp; <br>" +
                "&nbsp; <br>" +
                "&nbsp; <br>" +
                "&nbsp; <br>" +
                "&nbsp; <br>" +
                "&nbsp; &nbsp; Fuente - GitHub: <a href=\"https://github.com/riosmartinivan/ds-cod\">https://github.com/riosmartinivan/ds-cod</a> </p></div>" +
                "&nbsp; <br> </html>"
        );

        editorPane2.setEditorKit(JEditorPane.createEditorKitForContentType("text/html"));
        editorPane2.setEditable(false);
        editorPane2.setOpaque(false);
        editorPane2.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        editorPane2.setText("<html> Derechos Reservados © 2017 Martín Iván Ríos, Grupo Sauken S.A. <br>" +
                "<br>" +
                " Este es un Software Libre; como tal redistribuirlo y/o modificarlo está <br>" +
                " permitido, siempre y cuando se haga bajo los términos y condiciones de la <br>" +
                " Licencia Pública General GNU publicada por la Free Software Foundation, <br>" +
                " ya sea en su versión 2 ó cualquier otra de las posteriores a la misma. <br>" +
                "<br>" +
                " Este \"Programa\" se distribuye con la intención de que sea útil, sin <br>" +
                " embargo carece de garantía, ni siquiera tiene la garantía implícita de <br>" +
                " tipo comercial o inherente al propósito del mismo \"Programa\". Ver la <br>" +
                " Licencia Pública General GNU para más detalles. <br>" +
                "<br>" +
                " Se debe haber recibido una copia de la Licencia Pública General GNU con <br>" +
                " este \"Programa\", si este no fue el caso, favor de escribir a la Free <br>" +
                " Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, <br>" +
                " MA 02110-1301 USA. <br>" +
                "<br>" +
                " Autor: Martín Iván Ríos <br>" +
                " Correo electrónico: mailto:irios@sauken.com,rios.martinivan@gmail.com <br>" +
                " Empresa: Grupo Sauken S.A. <br>" +
                " WebSite: <a href=\"http://www.sauken.com/\">http://www.sauken.com/</a> <br>" +
                "<br>" +
                "                                  -------------------------------------------------------------- <br>" +
                "<br>" +
                " Copyright © Martín Iván Ríos, Grupo Sauken S.A. <br>" +
                "<br>" +
                " This program is free software; you can redistribute it and/or modify <br>" +
                " it under the terms of the GNU General Public License as published by <br>" +
                " the Free Software Foundation; either version 2 of the License, or <br>" +
                " (at your option) any later version. <br>" +
                "<br>" +
                " This program is distributed in the hope that it will be useful,<br>" +
                " but WITHOUT ANY WARRANTY; without even the implied warranty of <br>" +
                " MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the <br>" +
                " GNU General Public License for more details. <br>" +
                "<br>" +
                " You should have received a copy of the GNU General Public License along <br>" +
                " with this program; if not, write to the Free Software Foundation, Inc., <br>" +
                " 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA. <br>" +
                "<br>" +
                " Author: Martín Iván Ríos <br>" +
                " E-mail: mailto:irios@sauken.com,rios.martinivan@gmail.com <br>" +
                " Company: Grupo Sauken S.A. <br>" +
                " WebSite: <a href=\"http://www.sauken.com/\">http://www.sauken.com/</a> <br>" +
                "&nbsp;</html>");

        editorPaneCert.setEditorKit(JEditorPane.createEditorKitForContentType("text/html"));
        editorPaneCert.setEditable(false);
        editorPaneCert.setOpaque(false);
        editorPaneCert.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        editorPane1.addHyperlinkListener(e -> {
            if(e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                if (e.getDescription().equals("GPLv2")) {
                    JDialog jDialog = new JDialog();
                    jDialog.setTitle("GNU General Public License, version 2");
                    jDialog.setContentPane(jScrollPane2);
                    jDialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
                    jDialog.setPreferredSize(new Dimension(
                            jDialog.getPreferredSize().width,
                            height.intValue()));
                    jDialog.pack();
                    jDialog.setLocationRelativeTo(null);
                    jDialog.setVisible(true);
                } else if(Desktop.isDesktopSupported()) {
                    try {
                        Desktop.getDesktop().browse(e.getURL().toURI());
                    } catch (IOException | URISyntaxException e1) {
                        e1.printStackTrace();
                    }
                }
            }
        });
        editorPane2.addHyperlinkListener(e -> {
            if(e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                if(Desktop.isDesktopSupported()) {
                    try {
                        Desktop.getDesktop().browse(e.getURL().toURI());
                    } catch (IOException | URISyntaxException e1) {
                        e1.printStackTrace();
                    }
                }
            }
        });
        

        JTextArea jTextAreaMsg = new JTextArea();
        JTextArea jTextAreaWarn = new JTextArea();
        JTextArea jTextAreaErr = new JTextArea();
        JScrollPane jScrollPaneMsg = new JScrollPane(jTextAreaMsg);
        JScrollPane jScrollPaneWarn = new JScrollPane(jTextAreaWarn);
        JScrollPane jScrollPaneErr = new JScrollPane(jTextAreaErr);
        jTextAreaMsg.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        jTextAreaWarn.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        jTextAreaErr.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        jTextAreaMsg.setEditable(false);
        jTextAreaWarn.setEditable(false);
        jTextAreaErr.setEditable(false);
        JPanel mJPanelMsg = new JPanel(new BorderLayout());
        JPanel mJPanelWarn = new JPanel(new BorderLayout());
        JPanel mJPanelErr = new JPanel(new BorderLayout());
        mJPanelMsg.add(jScrollPaneMsg, BorderLayout.CENTER);
        mJPanelWarn.add(jScrollPaneWarn, BorderLayout.CENTER);
        mJPanelErr.add(jScrollPaneErr, BorderLayout.CENTER);
        mJPanelMsg.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        mJPanelWarn.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        mJPanelErr.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        jTabbedPaneLog.addTab("Mensajes", mJPanelMsg);
        jTabbedPaneLog.addTab("Advertencias", mJPanelWarn);
        jTabbedPaneLog.addTab("Errores", mJPanelErr);

        selectPEMButton.addActionListener(e -> {
            //Handle open button action.
            FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos PEM (*.pem)", "pem");
            fc.setDialogTitle("Seleccionar PEM");
            fc.resetChoosableFileFilters();
            fc.setFileFilter(xmlFilter);
            fc.setMultiSelectionEnabled(false);
            fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int returnVal = fc.showOpenDialog(frame);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                pemFile = fc.getSelectedFile();
                selectedPEM.setText(pemFile.getAbsolutePath());
            }
        });
        selectConfButton.addActionListener(e -> {
            //Handle open button action.
            FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos TXT (*.txt)", "txt");
            fc.setDialogTitle("Seleccionar conf");
            fc.resetChoosableFileFilters();
            fc.setFileFilter(xmlFilter);
            fc.setMultiSelectionEnabled(false);
            fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int returnVal = fc.showOpenDialog(frame);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                confFile = fc.getSelectedFile();
                selectedConf.setText(confFile.getAbsolutePath());
            }
        });
        selectDocButton.addActionListener(e -> {
            if (listDocCheckBox.isSelected()) {
                FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos TXT (*.txt)", "txt");
                String title = "Seleccionar lista a firmar";
                docFile = openDocFCList(fc, xmlFilter, selectedDoc, title);
                if (docFile == null) {
                    selectedDoc.setText("");
                }
            } else {
                FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos XML (*.xml)", "xml");
                String title = "Seleccionar xml a firmar";
                docFile = openDocFC(fc, xmlFilter, listDocCheckBox, selectedDoc, title);
                if (docFile == null) {
                    selectedDoc.setText("");
                }
            }
        });
        selectDocButtonH.addActionListener(e -> {
            if (listDocCheckBoxH.isSelected()) {
                FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos TXT (*.txt)", "txt");
                String title = "Seleccionar lista a firmar";
                docFileH = openDocFCList(fc, xmlFilter, selectedDocH, title);
                if (docFileH == null) {
                    selectedDocH.setText("");
                }
            } else {
                FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos XML (*.xml)", "xml");
                String title = "Seleccionar xml a firmar";
                docFileH = openDocFC(fc, xmlFilter, listDocCheckBoxH, selectedDocH, title);
                if (docFileH == null) {
                    selectedDocH.setText("");
                }
            }
        });
        selectOutButton.addActionListener(e -> {
            //Handle open button action.
            FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos XML (*.xml)", "xml");
            fcOut.resetChoosableFileFilters();
            fcOut.setFileFilter(xmlFilter);
            fcOut.setMultiSelectionEnabled(false);
            fcOut.setDialogTitle("Xml o carpeta de salida");
            fcOut.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            if (docFile != null && !docFile.getName().contains(".xml")) {
                fcOut.setDialogTitle("Carpeta de salida");
                fcOut.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            }
            int returnVal = fcOut.showOpenDialog(frame);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                outFile = fcOut.getSelectedFile();
                selectedOut.setText(outFile.getAbsolutePath());
            }
        });
        selectOutButtonH.addActionListener(e -> {
            //Handle open button action.
            FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos XML (*.xml)", "xml");
            fcOut.resetChoosableFileFilters();
            fcOut.setFileFilter(xmlFilter);
            fcOut.setMultiSelectionEnabled(false);
            fcOut.setDialogTitle("Xml o carpeta de salida");
            fcOut.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            if (docFileH != null && !docFileH.getName().contains(".xml")) {
                fcOut.setDialogTitle("Carpeta de salida");
                fcOut.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            }
            int returnVal = fcOut.showOpenDialog(frame);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                outFileH = fcOut.getSelectedFile();
                selectedOutH.setText(outFileH.getAbsolutePath());
            }
        });
        selectDocValButton.addActionListener(e -> {
            if (listValCheckBox.isSelected()) {
                FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos TXT (*.txt)", "txt");
                String title = "Seleccionar lista a validar";
                docVal = openDocFCList(fc, xmlFilter, selectedDocH, title);
                if (docVal != null) {
                    selectedDocH.setText("");
                }
            } else {
                FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos XML (*.xml)", "xml");
                String title = "Seleccionar xml a validar";
                docVal = openDocFC(fc, xmlFilter, listValCheckBox, selectedDocVal, title);
                if (docVal != null) {
                    selectedDocH.setText("");
                }
            }
        });
        selectXSDButton.addActionListener(e -> {
            //Handle open button action.
            FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos XSD (*.xsd)", "xsd");
            fc.setDialogTitle("Seleccionar esqema XSD");
            fc.setFileFilter(xmlFilter);
            fc.setMultiSelectionEnabled(false);
            fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int returnVal = fc.showOpenDialog(frame);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                xsd = fc.getSelectedFile();
                selectedXSD.setText(xsd.getAbsolutePath());
            }
        });
        selectDocXSDButton.addActionListener(e -> {
            if (listXSDCheckBox.isSelected()) {
                FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos TXT (*.txt)", "txt");
                String title = "Seleccionar lista a validar por esquema";
                docValXSD = openDocFCList(fc, xmlFilter, selectedDocH, title);
                if (docValXSD != null) {
                    selectedDocXSD.setText(docValXSD.getAbsolutePath());
                }
            } else {
                FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos XML (*.xml)", "xml");
                String title = "Seleccionar xml a validar por esquema";
                docValXSD = openDocFC(fc, xmlFilter, listXSDCheckBox, selectedDocXSD, title);
                if (docValXSD != null) {
                    selectedDocXSD.setText(docValXSD.getAbsolutePath());
                }
            }
        });
        selectPEMCertButton.addActionListener(e -> {
            //Handle open button action.
            FileNameExtensionFilter xmlFilter = new FileNameExtensionFilter("Archivos PEM (*.pem)", "pem");
            fc.setDialogTitle("Seleccionar PEM");
            fc.resetChoosableFileFilters();
            fc.setFileFilter(xmlFilter);
            fc.setMultiSelectionEnabled(false);
            fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int returnVal = fc.showOpenDialog(frame);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                pemCertFile = fc.getSelectedFile();
                selectedPEMCert.setText(pemCertFile.getAbsolutePath());

                // Remove last cert info fields and make more info inactive until you touch the extract button
                issuerS.setText("");
                sinceS.setText("");
                untilS.setText("");
                algorithmS.setText("");
                serialS.setText("");
                moreInfoS.setEnabled(false);
            }
        });
        selectConfCertButton.addActionListener(e -> {
            //Handle open button action.
            fc.setDialogTitle("Seleccionar conf");
            fc.resetChoosableFileFilters();
            fc.setMultiSelectionEnabled(false);
            fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
            int returnVal = fc.showOpenDialog(frame);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                confCertFile = fc.getSelectedFile();
                selectedConfCert.setText(confCertFile.getAbsolutePath());
            }
        });
        CODCheckBox.addActionListener(e -> {
            if (CODCheckBox.isSelected()) {
                CODEHCheckBox.setSelected(false);
            } else {
                CODEHCheckBox.setSelected(true);
            }
        });
        CODCheckBoxH.addActionListener(e -> {
            if (CODCheckBoxH.isSelected()) {
                CODEHCheckBoxH.setSelected(false);
            } else {
                CODEHCheckBoxH.setSelected(true);
            }
        });
        CODEHCheckBox.addActionListener(e -> {
            if (CODEHCheckBox.isSelected()) {
                CODCheckBox.setSelected(false);
            } else {
                CODCheckBox.setSelected(true);
            }
        });
        CODEHCheckBoxH.addActionListener(e -> {
            if (CODEHCheckBoxH.isSelected()) {
                CODCheckBoxH.setSelected(false);
            } else {
                CODCheckBoxH.setSelected(true);
            }
        });

        // Sign action
        signButton.addActionListener(e -> {
            String CODSelection;
            if (CODCheckBox.isSelected()) {
                CODSelection = "COD";
            } else {
                CODSelection = "CODEH";
            }
            ProcessBuilder pb = null;
            List<ProcessBuilder> pbL = null;
            if (pemFile == null || !pemFile.toPath().toFile().exists()) {
                JOptionPane.showMessageDialog(frame,
                        "Por favor, seleccione un certificado válido",
                        "Certificado no seleccionado",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            if (docFile == null || !docFile.toPath().toFile().exists()) {
                JOptionPane.showMessageDialog(frame,
                        "Por favor, seleccione un documento válido",
                        "Documento no seleccionado",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            boolean canCreate;
            if (outFile == null) {
                JOptionPane.showMessageDialog(frame,
                        "Por favor, seleccione una salida válida",
                        "Salida no seleccionada",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            if (listDocCheckBox.isSelected()) {
                Scanner sc = null;
                try {
                    sc = new Scanner(new File(docFile.getAbsolutePath()));
                } catch (FileNotFoundException ignored) {
                }
                pbL = new ArrayList<>();
                while (sc.hasNextLine()) {
                    pbL.add(new ProcessBuilder("java", "-jar",
                            getExecutionPath() + File.separator + "firmar.jar",
                            "-s", pemFile.getAbsolutePath(), CODSelection,
                            sc.nextLine(), outFile.getAbsolutePath(),
                            outputMsg,
                            outputErr));
                }
            } else {
                pb = new ProcessBuilder("java", "-jar",
                        getExecutionPath() + File.separator + "firmar.jar",
                        "-s", pemFile.getAbsolutePath(), CODSelection,
                        docFile.getAbsolutePath(), outFile.getAbsolutePath(),
                        outputMsg,
                        outputErr);
            }
            try {
                int result = 0;
                if (pb != null) {
                    pb.directory(new File(getExecutionPath()));
                    Process p = pb.start();
                    result = p.waitFor();
                } else if (pbL != null) {
                    for (ProcessBuilder processBuilder : pbL) {
                        Process process = processBuilder.start();
                        process.waitFor();
                    }
                }

                if (result == 0) {

                    // Enable the display button
                    openXML.setEnabled(true);
                    // Enable the logs
                    openLog.setEnabled(true);

                    // Not display results if recursive
                    if (!listDocCheckBox.isSelected()) {
                        // Display dialog with the results
                        displayResults();
                        // Display dialog with the errors
                        displayErrors();
                    }
                } else {
                    // Enable the logs
                    openLog.setEnabled(true);

                    // Not display results if recursive
                    if (!listDocCheckBox.isSelected()) {
                        // Display dialog with the errors
                        displayErrors();
                    }
                }
            } catch (Exception e1) {
                e1.printStackTrace();
            }

            nullDocFile();
        });
        signButtonH.addActionListener(e -> {
            String CODSelection;
            Process p;
            String passText = new String(passwordField.getPassword());
            if (CODCheckBoxH.isSelected()) {
                CODSelection = "COD";
            } else {
                CODSelection = "CODEH";
            }
            ProcessBuilder pb = null;
            List<ProcessBuilder> pbL = null;
            if (confFile == null || !confFile.toPath().toFile().exists()) {
                JOptionPane.showMessageDialog(frame,
                        "Por favor, seleccione un archivo de configuración válido",
                        "Archivo de configuración no seleccionado",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            if (passText.equals("")) {
                JOptionPane.showMessageDialog(frame,
                        "Por favor, escriba una contraseña",
                        "Contraseña no encontrada",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            if (docFileH == null  || !docFileH.toPath().toFile().exists()) {
                JOptionPane.showMessageDialog(frame,
                        "Por favor, seleccione un documento válido",
                        "Documento no seleccionado",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            if (outFileH == null) {
                JOptionPane.showMessageDialog(frame,
                        "Por favor, seleccione una salida válida",
                        "Salida no seleccionada",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            if (listDocCheckBoxH.isSelected()) {
                Scanner sc = null;
                try {
                    sc = new Scanner(new File(docFileH.getAbsolutePath()));
                } catch (FileNotFoundException ignored) {
                }
                pbL = new ArrayList<>();
                while (sc.hasNextLine()) {
                    pbL.add(new ProcessBuilder("java", "-jar",
                            getExecutionPath() + File.separator + "firmar.jar",
                            "-t", confFile.getAbsolutePath(), passText, CODSelection,
                            sc.nextLine(), outFileH.getAbsolutePath(),
                            outputMsg,
                            outputErr));
                }
            } else {
                pb = new ProcessBuilder("java", "-jar",
                        getExecutionPath() + File.separator + "firmar.jar",
                        "-t", confFile.getAbsolutePath(), passText, CODSelection,
                        docFileH.getAbsolutePath(), outFileH.getAbsolutePath(),
                        outputMsg,
                        outputErr);
            }

            try {
                int result = 0;
                if (pb != null) {
                    pb.directory(new File(getExecutionPath()));
                    p = pb.start();
                    result = p.waitFor();
                } else if (pbL != null) {
                    for (ProcessBuilder processBuilder : pbL) {
                        Process process = processBuilder.start();
                        process.waitFor();
                    }
                }

                // Waits for the process to finish
                if (result == 0) {
                    // Enable the display button
                    openXMLH.setEnabled(true);
                        // Enable the logs
                    openLogH.setEnabled(true);

                    // Not display results if recursive
                    if (!listDocCheckBoxH.isSelected()) {
                        // Display dialog with the results
                        displayResults();
                        // Display dialog with the errors
                        displayErrors();
                    }
                } else {
                    // Enable the logs
                    openLogH.setEnabled(true);
                    // Not display results if recursive
                    if (!listDocCheckBoxH.isSelected()) {
                        // Display dialog with the errors
                        displayErrors();
                    }
                }
            } catch (Exception e1) {
                e1.printStackTrace();
            }

            nullDocFileH();
        });

        // Validate and Cert buttons
        validateButton.addActionListener(e -> {
            Process p;
            ProcessBuilder pb;
            if (docVal == null || !docVal.toPath().toFile().exists()) {
                JOptionPane.showMessageDialog(frame,
                        "Por favor, seleccione un documento válido",
                        "Documento no seleccionado",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            if (listValCheckBox.isSelected()) {
                pb = new ProcessBuilder("java", "-jar",
                        getExecutionPath() + File.separator + "validar.jar", "--list",
                        docVal.getAbsolutePath(),
                        outputMsg,
                        outputErr);
            } else {
                pb = new ProcessBuilder("java", "-jar",
                        getExecutionPath() + File.separator + "validar.jar", "--xml",
                        docVal.getAbsolutePath(),
                        outputMsg,
                        outputErr);
            }
            pb.directory(new File(getExecutionPath()));
            try {
                p = pb.start();

                // Waits for the process to finish
                int result = p.waitFor();
                if (result == 0) {
                    // Enable the logs
                    openLogVal.setEnabled(true);

                    // Not display results if recursive
                    if (!listValCheckBox.isSelected()) {
                        // Display dialog with the results
                        displayResults();
                        // Display dialog with the errors
                        displayErrors();
                    }
                } else {
                    // Enable the logs
                    openLogVal.setEnabled(true);

                    // Not display results if recursive
                    if (!listValCheckBox.isSelected()) {
                        // Display dialog with the errors
                        displayErrors();
                    }
                }
            } catch (Exception e1) {
                e1.printStackTrace();
            }

            nullDocVal();
        });
        validateXSDButton.addActionListener(e -> {
            Process p;
            ProcessBuilder pb;
            if (docValXSD == null  || !docValXSD.toPath().toFile().exists()) {
                JOptionPane.showMessageDialog(frame,
                        "Por favor, seleccione un documento válido",
                        "Documento no seleccionado",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            if (listXSDCheckBox.isSelected()) {
                if (xsd == null) {
                    pb = new ProcessBuilder("java", "-jar",
                            getExecutionPath() + File.separator + "validar-xsd.jar",
                            "DEFAULT", "--list", docValXSD.getAbsolutePath(),
                            outputMsg,
                            outputWarn,
                            outputErr);
                } else {
                    pb = new ProcessBuilder("java", "-jar",
                            getExecutionPath() + File.separator + "validar-xsd.jar",
                            xsd.getAbsolutePath(), "--list", docValXSD.getAbsolutePath(),
                            outputMsg,
                            outputWarn,
                            outputErr);
                }
            } else {
                if (xsd == null) {
                    pb = new ProcessBuilder("java", "-jar",
                            getExecutionPath() + File.separator + "validar-xsd.jar",
                            "DEFAULT", "--xml", docValXSD.getAbsolutePath(),
                            outputMsg,
                            outputWarn,
                            outputErr);
                } else {
                    pb = new ProcessBuilder("java", "-jar",
                            getExecutionPath() + File.separator + "validar-xsd.jar",
                            xsd.getAbsolutePath(), "--xml", docValXSD.getAbsolutePath(),
                            outputMsg,
                            outputWarn,
                            outputErr);
                }
            }
            pb.directory(new File(getExecutionPath()));
            try {
                p = pb.start();

                // Waits for the process to finish
                int result = p.waitFor();
                if (result == 0) {
                    // Enable the logs
                    openLogXSD.setEnabled(true);

                    // Not display results if recursive
                    if (!listXSDCheckBox.isSelected()) {
                        // Display dialog with the results
                        displayResults();
                        // Display dialog with the warnings
                        displayWarnings();
                        // Display dialog with the errors
                        displayErrors();
                    }
                } else {
                    // Enable the logs
                    openLogXSD.setEnabled(true);

                    // Not display results if recursive
                    if (!listXSDCheckBox.isSelected()) {
                        // Display dialog with the warnings
                        displayWarnings();
                        // Display dialog with the errors
                        displayErrors();
                    }
                }
            } catch (Exception e1) {
                e1.printStackTrace();
            }

            nullDocValXSD();
        });
        certSwButton.addActionListener(e -> {
            Process p;
            if (pemCertFile == null  || !pemCertFile.toPath().toFile().exists()) {
                JOptionPane.showMessageDialog(frame,
                        "Por favor, seleccione un certificado válido",
                        "Certificado no seleccionado",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            ProcessBuilder pb = new ProcessBuilder("java", "-jar",
                    getExecutionPath() + File.separator + "certificado.jar",
                    "-s", pemCertFile.getAbsolutePath(),
                    outputMsg,
                    outputErr);
            pb.directory(new File(getExecutionPath()));
            try {
                p = pb.start();

                // Waits for the process to finish
                int result = p.waitFor();
                if (result == 0) {
                    // Display the cert in the text area
                    displayCert(0);
                } else {
                    displayErrors();
                }
            } catch (Exception e1) {
                e1.printStackTrace();
            }
        });
        certHwButton.addActionListener(e -> {
            Process p;
            String passText = new String(passwordCertField.getPassword());
            if (confCertFile == null || !confCertFile.toPath().toFile().exists()) {
                JOptionPane.showMessageDialog(frame,
                        "Por favor, seleccione un archivo de configuración válido",
                        "Archivo de configuración no seleccionado",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            if (passText.equals("")) {
                JOptionPane.showMessageDialog(frame,
                        "Por favor, escriba una contraseña",
                        "Contraseña no encontrada",
                        JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            ProcessBuilder pb = new ProcessBuilder("java", "-jar",
                    getExecutionPath() + File.separator + "certificado.jar",
                    "-t", confCertFile.getAbsolutePath(), passText,
                    outputMsg,
                    outputErr);
            pb.directory(new File(getExecutionPath()));
            try {
                p = pb.start();

                // Waits for the process to finish
                int result = p.waitFor();
                if (result == 0) {
                    // Display the cert in the text area
                    displayCert(1);
                } else {
                    displayErrors();
                }
            } catch (Exception e1) {
                e1.printStackTrace();
            }
        });
        moreInfoS.addActionListener(e -> {
            JDialog jDialog = new JDialog();
            jDialog.setTitle("Certificado Completo");
            jDialog.setContentPane(jScrollPaneCert);
            jDialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
            jDialog.setPreferredSize(new Dimension(
                    jDialog.getPreferredSize().width,
                    height.intValue()));
            jDialog.pack();
            jDialog.setLocationRelativeTo(null);
            jDialog.setVisible(true);
        });
        moreInfoH.addActionListener(e -> {
            JDialog jDialog = new JDialog();
            jDialog.setTitle("Certificado Completo");
            jDialog.setContentPane(jScrollPaneCert);
            jDialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
            jDialog.setPreferredSize(new Dimension(
                    jDialog.getPreferredSize().width,
                    height.intValue()));
            jDialog.pack();
            jDialog.setLocationRelativeTo(null);
            jDialog.setVisible(true);
        });

        // Open document buttons
        openXML.addActionListener(e -> {
            Desktop dt = Desktop.getDesktop();
            try {
                dt.open(outFile);
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        });
        openXMLH.addActionListener(e -> {
            Desktop dt = Desktop.getDesktop();
            try {
                dt.open(outFileH);
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        });

        ActionListener actionListenerLogs = e -> {
            try {
                Path file = Paths.get(outputMsg);
                if (file.toFile().exists()) {
                    List<String> mOutputMsg = Files.readAllLines(Paths.get(
                            outputMsg),
                            StandardCharsets.UTF_8);
                    if (!mOutputMsg.isEmpty()) {
                        StringBuilder resultMsg = new StringBuilder();
                        boolean next = false;
                        for (String lines : mOutputMsg) {
                            if (next) {
                                resultMsg.append(lines).append("\n");
                            }
                            if (lines.contains("####")) {
                                next = true;
                            }
                        }
                        if (resultMsg.length() > 0) {
                            System.out.println(resultMsg.toString());
                            jTextAreaMsg.setText(resultMsg.toString());
                        }
                    }
                }
            } catch (IOException e2) {
                e2.printStackTrace();
            }

            try {
                Path file = Paths.get(outputWarn);
                if (file.toFile().exists()) {
                    FileReader fr = new FileReader(outputWarn);
                    BufferedReader reader = new BufferedReader(fr);
                    jTextAreaWarn.read(reader,"Advertencias");
                }
            } catch (IOException e2) {
                e2.printStackTrace();
            }

            try {
                Path file = Paths.get(outputErr);
                if (file.toFile().exists()) {
                    List<String> mOutputErr = Files.readAllLines(Paths.get(
                            outputErr),
                            StandardCharsets.ISO_8859_1);
                    if (!mOutputErr.isEmpty()) {
                        StringBuilder resultErr = new StringBuilder();
                        boolean next = false;
                        for (String lines : mOutputErr) {
                            if (next) {
                                resultErr.append(lines).append("\n");
                            }
                            if (lines.contains("####")) {
                                next = true;
                            }
                        }
                        if (resultErr.length() > 0) {
                            jTextAreaErr.setText(resultErr.toString());
                        }
                    }
                }
            } catch (IOException e2) {
                e2.printStackTrace();
            }

            JDialog jDialog = new JDialog();
            jDialog.setTitle("Logs");
            jDialog.setContentPane(jTabbedPaneLog);
            jDialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
            jDialog.setPreferredSize(new Dimension(
                    800,
                    height.intValue()));
            jDialog.pack();
            jDialog.setLocationRelativeTo(null);
            jDialog.setVisible(true);
        };

        openLog.addActionListener(actionListenerLogs);
        openLogH.addActionListener(actionListenerLogs);
        openLogVal.addActionListener(actionListenerLogs);
        openLogXSD.addActionListener(actionListenerLogs);
    }

    public static void main(String[] args) {
        DsGUI dsGUI = new DsGUI();
        frame.setContentPane(dsGUI.panelMain);
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        Double width = frame.getPreferredSize().width * 1.7;
        height = frame.getPreferredSize().height * 1.4;
        frame.setPreferredSize(new Dimension(
                width.intValue(),
                height.intValue()));
        // Set icon
        frame.setIconImage(Toolkit.getDefaultToolkit().getImage("icon.png"));

        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    /**
     * Helper method to find and add all the xml's in a directory
     *
     * @param directory Main directory
     * @param files Array to add the files
     * @return the array with the files
     */
    private ArrayList<String> listf(File directory, ArrayList<String> files) {

        // get all the files from a directory
        File[] fList = directory.listFiles();
        if (fList != null) {
            for (File file : fList) {
                if (file.isFile()) {
                    if (file.getName().contains(".xml")) {
                        files.add(file.getAbsolutePath());
                    }
                } else if (file.isDirectory()) {
                    listf(file, files);
                }
            }
            return files;
        } else {
            return null;
        }
    }

    /**
     * Helper method to open a file chooser
     *
     * @param mFc File chooser
     * @param xmlFilter Filter
     * @param mDocText Field to change
     * @return selected file
     */
    private File openDocFC(JFileChooser mFc, FileNameExtensionFilter xmlFilter, JCheckBox listCheckBox, JTextField mDocText, String title) {
        //Handle open button action.
        File mDocFile = null;
        Path lastSign = Paths.get(getExecutionPath() + File.separator + "ultima-firma.txt");
        try {
            Files.deleteIfExists(lastSign);
        } catch (IOException e) {
            e.printStackTrace();
        }

        mFc.setDialogTitle(title);
        mFc.resetChoosableFileFilters();
        mFc.setFileFilter(xmlFilter);
        mFc.setMultiSelectionEnabled(true);
        mFc.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        int returnVal = mFc.showOpenDialog(frame);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File[] files = mFc.getSelectedFiles();
            if(files.length > 1) {
                try {
                    Files.deleteIfExists(lastSign);
                    Files.createFile(lastSign);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                List<String> fileList = new ArrayList<>();
                for (File file : files) {
                    if (file.isDirectory()) {
                        ArrayList<String> fileTemp = new ArrayList<>();
                        List<String> fileListTmp = listf(file, fileTemp);
                        if (fileListTmp != null) {
                            fileList.addAll(fileListTmp);
                        }
                    } else {
                        fileList.add(file.getAbsolutePath());
                    }
                }
                try {
                    Files.write(lastSign, fileList, Charset.forName("UTF-8"), StandardOpenOption.TRUNCATE_EXISTING);
                    mDocFile = new File(String.valueOf(lastSign));
                    listCheckBox.setSelected(true);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            } else {
                if (files[0].isDirectory()) {
                    try {
                        Files.deleteIfExists(lastSign);
                        Files.createFile(lastSign);
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }
                    ArrayList<String> fileTemp = new ArrayList<>();
                    List<String> fileList = listf(files[0], fileTemp);
                    if (fileList != null) {
                        try {
                            Files.write(lastSign, fileList, Charset.forName("UTF-8"), StandardOpenOption.TRUNCATE_EXISTING);
                            mDocFile = new File(String.valueOf(lastSign));
                            listCheckBox.setSelected(true);
                        } catch (IOException e1) {
                            e1.printStackTrace();
                        }
                    }
                } else {
                    mDocFile = files[0];
                }
            }
            if (mDocFile != null) {
                mDocText.setText(mDocFile.getAbsolutePath());
            }
        }

        return mDocFile;
    }

    /**
     * Helper method to open a file chooser
     *
     * @param mFc File chooser
     * @param xmlFilter Filter
     * @param mDocText Field to change
     * @return selected file
     */
    private File openDocFCList(JFileChooser mFc, FileNameExtensionFilter xmlFilter, JTextField mDocText, String title) {
        //Handle open button action.
        File mDocFile = null;

        mFc.setDialogTitle(title);
        mFc.resetChoosableFileFilters();
        mFc.setFileFilter(xmlFilter);
        mFc.setMultiSelectionEnabled(false);
        mFc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int returnVal = mFc.showOpenDialog(frame);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            mDocFile = mFc.getSelectedFile();
            mDocText.setText(mDocFile.getAbsolutePath());
        }

        return mDocFile;
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
     * Helper method to display the result of the jar processes
     *
     * @throws Exception Exception
     */
    private void displayResults() throws Exception {
        File f = new File(outputMsg);
        if (f.exists()) {
            java.util.List<String> outputMsg = Files.readAllLines(Paths.get(
                    this.outputMsg),
                    StandardCharsets.UTF_8);
            if (!outputMsg.isEmpty()) {
                StringBuilder resultMsg = new StringBuilder();
                boolean next = false;
                for (String lines : outputMsg) {
                    if (next) {
                        resultMsg.append(lines).append("\n");
                    }
                    if (lines.contains("####")) {
                        next = true;
                    }
                }
                if (resultMsg.length() > 0) {
                    JOptionPane.showMessageDialog(frame,
                            resultMsg.toString(),
                            "Resultados",
                            JOptionPane.INFORMATION_MESSAGE);
                }
            }
        }
    }

    /**
     * Helper method to display the errors of the jar processes
     *
     * @throws Exception Exception
     */
    private void displayErrors() throws Exception {
        File f = new File(outputErr);
        if (f.exists()) {
            java.util.List<String> outputErr = Files.readAllLines(Paths.get(
                    this.outputErr),
                    StandardCharsets.ISO_8859_1);
            if (!outputErr.isEmpty()) {
                StringBuilder resultErr = new StringBuilder();
                boolean next = false;
                for (String lines : outputErr) {
                    if (next) {
                        resultErr.append(lines).append("\n");
                    }
                    if (lines.contains("####")) {
                        next = true;
                    }
                }
                if (resultErr.length() > 0) {
                    JOptionPane.showMessageDialog(frame,
                            resultErr.toString(),
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }

    /**
     * Helper method to display the warnings of the jar processes
     *
     * @throws Exception Exception
     */
    private void displayWarnings() throws Exception {
        File f = new File(outputWarn);
        if (f.exists()) {
            java.util.List<String> outputWarn = Files.readAllLines(Paths.get(
                    this.outputWarn),
                    StandardCharsets.UTF_8);
            if (!outputWarn.isEmpty()) {
                StringBuilder resultErr = new StringBuilder();
                for (String lines : outputWarn) {
                    resultErr.append(lines).append("\n");
                }
                if (resultErr.length() > 0) {
                    JOptionPane.showMessageDialog(frame,
                            resultErr.toString(),
                            "Advertencia",
                            JOptionPane.WARNING_MESSAGE);
                }
            }
        }
    }

    private String getExecutionPath(){
        URL rootPath = getClass().getProtectionDomain().getCodeSource().getLocation();
        String URI = rootPath.toString().substring(6);
        String[] currentPath = URI.split("firmar-gui.jar");
        currentPath[0] = currentPath[0].replaceAll("%20"," ");
        return currentPath[0];
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

    private static void checkCertValidity(String pem)
            throws CertificateException, IOException, CRLException {
        // Check the validity of the certificate
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(pem);
        X509Certificate cert = (X509Certificate) fact.generateCertificate(is);
        is.close();

        String cn = cert.getIssuerX500Principal().toString().split("CN=")[1].split(",")[0];
        try {
            cert.checkValidity();

            JOptionPane.showMessageDialog(frame,
                    "El certificado que se está utilizando es válido actualmente",
                    "Certificado válido",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (CertificateExpiredException e) {
            JOptionPane.showMessageDialog(frame,
                    "El certificado que se está utilizando ha expirado",
                    "Certificado expirado",
                    JOptionPane.WARNING_MESSAGE);
        } catch (CertificateNotYetValidException e) {
            JOptionPane.showMessageDialog(frame,
                    "El certificado que se está utilizando todabía no es válido",
                    "Certificado invalido",
                    JOptionPane.WARNING_MESSAGE);
        }
        String certString = cert.toString();
        if (certString.contains("CRLDistributionPoints")) {
            String[] tmp = certString.split("CRLDistributionPoints \\[");
            String[] parts = tmp[1].split("]]");
            String[] distPoints = parts[0].substring(4, parts[0].length() - 1).split(",");

            boolean noInternetError = false;
            boolean revoked = false;
            for (String tempDist : distPoints) {
                String[] tmpUrl = tempDist.split("\\[URIName: ");
                String url = tmpUrl[1].substring(0, tmpUrl[1].length() - 1).replaceAll("]", "");

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
            }
            if (noInternetError) {
                JOptionPane.showMessageDialog(frame,
                        "No es posible validar contra AC del certificado actual, no hay conneción a internet",
                        "No hay conección",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (revoked) {
                JOptionPane.showMessageDialog(frame,
                        "El certificado que se está utilizando esta actualmente revocado, contra la AC: " + cn,
                        "Certificado revocado",
                        JOptionPane.WARNING_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(frame,
                        "El certificado que se está utilizando es actualmente válido, contra la AC: " + cn,
                        "Certificado válido",
                        JOptionPane.INFORMATION_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(frame,
                    "No pudo validarse si la firma esta revocada",
                    "No pudo validarse revocados",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    /**
     * Helper method to display the certificate of the jar processes in a text area
     *
     * @throws Exception Exception
     */
    private void displayCert(int isToken) throws Exception {
        java.util.List<String> outputMsg = Files.readAllLines(Paths.get(
                this.outputMsg),
                StandardCharsets.UTF_8);
        if (!outputMsg.isEmpty()) {
            StringBuilder resultMsg = new StringBuilder();
            resultMsg.append("<html>");
            for (String lines : outputMsg) {
                resultMsg.append(lines).append("<br>");
            }
            resultMsg.append("</html>");
            if (resultMsg.length() > 0) {
                X509Certificate cert = loadPublicX509(pemPath);
                if (isToken == 1) {
                    // Set the Issuer
                    LdapName ln = new LdapName(cert.getIssuerX500Principal().toString());
                    for (Rdn rdn : ln.getRdns()) {
                        if (rdn.getType().equalsIgnoreCase("CN")) {
                            issuerH.setText(rdn.getValue().toString());
                            break;
                        }
                    }
                    sinceH.setText(cert.getNotBefore().toString());
                    untilH.setText(cert.getNotAfter().toString());
                    algorithmH.setText(cert.getSigAlgName());
                    serialH.setText(cert.getSerialNumber().toString(16));

                    editorPaneCert.setText(resultMsg.toString());
                    moreInfoH.setEnabled(true);

                    checkCertValidity(pemPath);
                    Files.deleteIfExists(Paths.get(pemPath));
                } else if (isToken == 0) {
                    // Set the Issuer
                    LdapName ln = new LdapName(cert.getIssuerX500Principal().toString());
                    for (Rdn rdn : ln.getRdns()) {
                        if (rdn.getType().equalsIgnoreCase("CN")) {
                            issuerS.setText(rdn.getValue().toString());
                            break;
                        }
                    }

                    sinceS.setText(cert.getNotBefore().toString());
                    untilS.setText(cert.getNotAfter().toString());
                    algorithmS.setText(cert.getSigAlgName());
                    serialS.setText(cert.getSerialNumber().toString(16));

                    editorPaneCert.setText(resultMsg.toString());
                    moreInfoS.setEnabled(true);

                    checkCertValidity(pemPath);
                    Files.deleteIfExists(Paths.get(pemPath));
                }
            }
        }
    }

    private void nullDocFile() {
        docFile = null;
        selectedDoc.setText("");
    }

    private void nullDocFileH() {
        docFileH = null;
        selectedDocH.setText("");
    }

    private void nullDocVal() {
        docVal = null;
        selectedDocVal.setText("");
    }

    private void nullDocValXSD() {
        docValXSD = null;
        selectedDocXSD.setText("");
    }
}