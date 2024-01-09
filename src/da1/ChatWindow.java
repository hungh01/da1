/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package da1;

import java.awt.Color;
import java.awt.EventQueue;
import java.awt.FileDialog;

import javax.swing.JFrame;
import javax.swing.JTextArea;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.JLabel;
import javax.swing.ScrollPaneConstants;

import java.awt.Font;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.WindowEvent;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

// TODO: add idle-echo message
class ClientSender {

    private int port;
    private DatagramSocket socket;
    private String hostname = "localhost";

    ClientSender(DatagramSocket s, int p) throws Exception {
        socket = s;
        port = p;
    }

    public void sendMessage(String s) throws Exception {
        InetAddress address = InetAddress.getByName(hostname);

        SecretKey secretkey = generateSecretKeyFromString(address.getHostAddress());

        String sms = encrypt(s, secretkey);
        byte buf[] = sms.getBytes();
        DatagramPacket packet = new DatagramPacket(buf, buf.length, address, port);
        socket.send(packet);

        // TODO: add verify class
        //ChatVerify verify = ChatVerify.getInstance();
        //System.out.println(verify.addVerify(s));
    }

    public static SecretKey generateSecretKeyFromString(String keyString) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        // Use a secure hash function to generate a key of the desired length
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha.digest(keyString.getBytes("UTF-8"));

        // Use only the first 16, 24, or 32 bytes for AES
        keyBytes = Arrays.copyOf(keyBytes, 32); // 32 bytes for AES-256

        // Create a SecretKey from the key bytes
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static String encrypt(String plaintext, SecretKey secretKey) throws Exception {

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String ciphertext, SecretKey secretKey) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace(); // Print the stack trace for debugging
            throw e; // Re-throw the exception after printing the stack trace
        }
    }

//    void sendFile(String filePath) throws UnknownHostException, IOException, UnsupportedEncodingException, NoSuchAlgorithmException {
//        InetAddress address = InetAddress.getByName(hostname);
//        SecretKey secretkey = generateSecretKeyFromString(address.getHostAddress());
//        byte[] incomingData = new byte[1024];
//        FileEvent event = getFileEvent(filePath);
//        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//        ObjectOutputStream os = new ObjectOutputStream(outputStream);
//        System.out.println("os"+os);
//
//        os.writeObject(event);
//        String s;
//        try {
//            System.out.println("------------------>" + outputStream);
//            s = encrypt(outputStream.toString(), secretkey);
//            //System.out.println("------------------>" + s);
//            byte[] data = s.getBytes();
//            System.out.println("file encrypt sent: "+ s);
//            //System.out.println("------------------>" + data);
//
//            DatagramPacket sendPacket = new DatagramPacket(data, data.length, address, port);
//            socket.send(sendPacket);
//        } catch (Exception ex) {
//            Logger.getLogger(ClientSender.class.getName()).log(Level.SEVERE, null, ex);
//        }
//
//    }
    void sendFile(String filePath) throws UnknownHostException, IOException, UnsupportedEncodingException, NoSuchAlgorithmException {
        InetAddress address = InetAddress.getByName(hostname);
        SecretKey secretkey = generateSecretKeyFromString(address.getHostAddress());
        FileEvent f = getFileEvent(filePath);
        String[] pathElements = f.getFilename().split("/");
        String filename = pathElements[pathElements.length-1]+" ";
        
        // Create an array for storing file data in chunks
        byte[] buffer = new byte[1024];

        // Create FileInputStream and ObjectOutputStream inside try-with-resources
        try (FileInputStream fileInputStream = new FileInputStream(filePath);
                ObjectOutputStream os = new ObjectOutputStream(new ByteArrayOutputStream())) {

            int bytesRead;
            while ((bytesRead = fileInputStream.read(buffer)) != -1) {
                // Encrypt the current chunk of data
                String encryptedChunk = encrypt(filename+new String(buffer, 0, bytesRead, StandardCharsets.UTF_8), secretkey);

                // Send the encrypted chunk
                byte[] data = encryptedChunk.getBytes(StandardCharsets.UTF_8);
                DatagramPacket sendPacket = new DatagramPacket(data, data.length, address, port);
                socket.send(sendPacket);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Logger.getLogger(ClientSender.class.getName()).log(Level.SEVERE, null, ex);
        }

//        // Send an additional packet indicating the end of file
//        String endOfFileMarker;
//        try {
//            endOfFileMarker = encrypt(f.getSourceDirectory(), secretkey);
//            byte[] eofData = endOfFileMarker.getBytes(StandardCharsets.UTF_8);
//            DatagramPacket eofPacket = new DatagramPacket(eofData, eofData.length, address, port);
//            socket.send(eofPacket);
//        } catch (Exception ex) {
//            Logger.getLogger(ClientSender.class.getName()).log(Level.SEVERE, null, ex);
//        }
        
    }

    public FileEvent getFileEvent(String sourceFilePath) {
        FileEvent fileEvent = new FileEvent();
        String fileName = sourceFilePath.substring(sourceFilePath.lastIndexOf("\\") + 1, sourceFilePath.length());
        String path = sourceFilePath.substring(0, sourceFilePath.lastIndexOf("\\") + 1);
        fileEvent.setFilename(fileName);
        //System.out.println("file name: " + fileName);
        fileEvent.setSourceDirectory(sourceFilePath);
        File file = new File(sourceFilePath);
        if (file.isFile()) {
            try {
                DataInputStream diStream = new DataInputStream(new FileInputStream(file));
                long len = (int) file.length();
                byte[] fileBytes = new byte[(int) len];
                int read = 0;
                int numRead = 0;
                while (read < fileBytes.length && (numRead = diStream.read(fileBytes, read,
                        fileBytes.length - read)) >= 0) {
                    read = read + numRead;
                }
                fileEvent.setFileSize(len);
                fileEvent.setFileData(fileBytes);
                fileEvent.setStatus("Success");
            } catch (IOException e) {
                e.printStackTrace();
                fileEvent.setStatus("Error");
            }
        } else {
            System.out.println("duong dan ko chi den 1 file");
            fileEvent.setStatus("co loi");
        }
        return fileEvent;
    }

}

public class ChatWindow extends JPanel implements ActionListener {

    JFrame frame;
    private String name;

    // TODO: add host/port select
    public final static int PORT = 7332;

    JTextArea msgArea;
    JButton sendButton;
    JTextPane msgPane;
    InetAddress ipAddress;

    /**
     * Launch the application.
     *
     * @throws SocketException
     */
//    public static void main(String[] args) {
//        EventQueue.invokeLater(new Runnable() {
//            public void run() {
//                try {
//                    ChatWindow window = new ChatWindow();
//                    window.frame.setVisible(true);
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }
//            }
//        });
//    }
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == sendButton) {
            System.out.println("Send was pressed");
        }
    }

    public ChatWindow(String name) throws Exception {
        frame = new FrameReceiver(PORT, name);
        frame.setBounds(100, 100, 584, 578);
        frame.getContentPane().setBackground(Color.decode("#006699"));

        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().setLayout(null);
        this.name = name;
    }
}

class FrameReceiver extends JFrame implements Runnable {

    Thread t;
    final JTextArea msgArea;
    final JTextArea usersArea;
    final JTextPane msgPane;

    DatagramSocket socket;
    ClientSender sender;
    int port;
    byte buf[];

    FrameReceiver(int p, String name) throws Exception {
        // TODO: format messages?
        msgArea = new JTextArea();
        msgArea.setWrapStyleWord(true);
        msgArea.setEditable(false);
        msgArea.setBounds(10, 54, 372, 368);
        this.getContentPane().add(msgArea);

        JScrollPane scrollPane = new JScrollPane(msgArea);
        scrollPane.setBounds(10, 54, 372, 368);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        this.getContentPane().add(scrollPane);

        usersArea = new JTextArea();
        usersArea.setEditable(false);
        usersArea.setBounds(392, 54, 163, 368);
        this.getContentPane().add(usersArea);

        JScrollPane scrollPane2 = new JScrollPane(usersArea);
        scrollPane2.setBounds(392, 54, 163, 368);
        scrollPane2.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        this.getContentPane().add(scrollPane2);

        msgPane = new JTextPane();
        msgPane.setBounds(20, 499, 318, 36);
        this.getContentPane().add(msgPane);

        JLabel lblTreWiadomoci = new JLabel("Message:");
        lblTreWiadomoci.setFont(new Font("Tahoma", Font.PLAIN, 14));
        lblTreWiadomoci.setBounds(10, 474, 187, 14);
        this.getContentPane().add(lblTreWiadomoci);
        lblTreWiadomoci.setForeground(Color.WHITE);

        JLabel lblWiadomoci = new JLabel("Chat:");
        lblWiadomoci.setFont(new Font("Tahoma", Font.PLAIN, 14));
        lblWiadomoci.setBounds(10, 29, 231, 14);
        this.getContentPane().add(lblWiadomoci);
        lblWiadomoci.setForeground(Color.WHITE);

        JLabel lblOnline = new JLabel("Online:");
        lblOnline.setFont(new Font("Tahoma", Font.PLAIN, 14));
        lblOnline.setBounds(392, 29, 46, 14);
        this.getContentPane().add(lblOnline);
        lblOnline.setForeground(Color.WHITE);

        socket = new DatagramSocket();
        sender = new ClientSender(socket, p);

        JButton fileButton = new JButton("Send File");
        fileButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (e.getSource() == fileButton) {
                    // Handle file selection and sending
                    FileDialog fd = new FileDialog(new JFrame(), "Select File...", FileDialog.LOAD);
                    fd.show();
                    String filePath = fd.getDirectory() + fd.getFile();
                    try {
                        try {
                            //sourceFilePath = filePath;
                            sender.sendFile(filePath);
                        } catch (UnknownHostException ex) {
                            Logger.getLogger(FrameReceiver.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (UnsupportedEncodingException ex) {
                            Logger.getLogger(FrameReceiver.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (NoSuchAlgorithmException ex) {
                            Logger.getLogger(FrameReceiver.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    } catch (IOException ex) {
                        Logger.getLogger(FrameReceiver.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    //System.out.println(filePath);
                }
            }
        });
        fileButton.setBounds(480, 499, 90, 36);
        this.add(fileButton);

        JButton sendButton = new JButton("Send");
        sendButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                try {
                    //send message
                    sender.sendMessage(msgPane.getText());
                    msgPane.setText("");

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        sendButton.setBounds(354, 499, 113, 36);
        this.getContentPane().add(sendButton);
        sender.sendMessage("");

        buf = new byte[1024];
        t = new Thread(this);
        t.start();
        sender.sendMessage(name);
    }

    public void processWindowEvent(WindowEvent we) {
        if (we.getID() == WindowEvent.WINDOW_CLOSING) {
            try {
                // TODO: add special commands
                sender.sendMessage("EXIT");
            } catch (Exception e) {
                e.printStackTrace();
            }
            dispose();
        }
    }

    public void run() {
        while (true) {
            try {

                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);

                String received = ChatDgram.toString(packet);
                //System.out.println("Dữ liệu nhận: " + received);
                String address = InetAddress.getByName("localhost").getHostAddress();
                SecretKey secretkey = generateSecretKeyFromString(address);

                received = decrypt(received, secretkey);
                //System.out.println("Dữ liệu nhận giải mã: " + received);
                checkMessage(received);
                //msgArea.append(received + "\n");

            } catch (Exception e) {
                System.err.println("lỗi: " + e);
            }
        }
    }
    private FileEvent fileEvent = new FileEvent();

    // TODO: new class to parse message (protocol class)
    private void checkMessage(String msg) throws IOException, ClassNotFoundException {
        //System.out.println("msg :" + msg);
        
        String regexPattern = ".+\\.txt.+";

        if (Pattern.matches(regexPattern, msg)) {
            // client gửi file
            System.out.println("File gui den :" + msg);
            String[] parts = msg.split("\\s+");
            String username = parts[0].substring(2);
            fileEvent.setFilename(parts[1]);
            byte[] filedata = msg.substring(parts[0].length()+parts[1].length()+2).getBytes();
            fileEvent.setFileData(filedata);
            System.out.println(username+"->"+parts[1]+"->"+msg.substring(parts[0].length()+parts[1].length()+2));
            msgArea.append(username+" " + fileEvent.getFilename()+ "\n");
            int st = JOptionPane.showConfirmDialog(null, "Client gửi 1 file. Bạn có muốn nhân?");
            System.out.println("File :" + fileEvent.getFilename());
            if (st == 0) {
                // chọn thư mục lưu file 012345
                JOptionPane.showMessageDialog(null, "Chọn nơi lưu file");
                JFileChooser chooser = new JFileChooser();
                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                chooser.showOpenDialog(null);
                File f = chooser.getSelectedFile();
                String filePath = f.getPath();
                String destinationPath = filePath;
                // ghi file nhan duoc tu client
                createAndWriteFile(destinationPath);
                //msgArea.append("File :" + fileEvent.getFilename());
                JOptionPane.showMessageDialog(null, "Đã nhận file: " + fileEvent.getFilename());
            } 
        } else {
            Pattern inputPattern = Pattern.compile("^([\\d]+)#(.*)$", Pattern.UNICODE_CHARACTER_CLASS);
            Matcher results = inputPattern.matcher(msg);
            if (!results.matches()) {
                return;
            }

            int code = Integer.parseInt(results.group(1));
            String content = results.group(2);

            /*
		 * 0 - normal
		 * 1 - from server
		 * 2 - online list
             */
            switch (code) {
                case 0:
                    msgArea.append(content + "\n");
                    break;

                case 1:
                    msgArea.append("\n" + content + "\n");
                    break;

                case 2:
                    content = content.replace("<|>", "\n");
                    usersArea.setText(content);

                default:
                    return;
            }
        }
    }

    public static SecretKey generateSecretKeyFromString(String keyString) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        // Use a secure hash function to generate a key of the desired length
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha.digest(keyString.getBytes("UTF-8"));

        // Use only the first 16, 24, or 32 bytes for AES
        keyBytes = Arrays.copyOf(keyBytes, 32); // 32 bytes for AES-256

        // Create a SecretKey from the key bytes
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static String encrypt(String plaintext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String ciphertext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
        System.out.println("decrypt: " + decryptedBytes);
        System.out.println("decrypt to string : ");
        return new String(decryptedBytes).trim();
    }

    public void createAndWriteFile(String destinationPath) {
        fileEvent.setDestinationDirectory(destinationPath);
        String outputFile = fileEvent.getDestinationDirectory() + "/" + fileEvent.getFilename();
        if (!new File(fileEvent.getDestinationDirectory()).exists()) {
            new File(fileEvent.getDestinationDirectory()).mkdirs();
        }
        File dstFile = new File(outputFile);
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream(dstFile);
            fileOutputStream.write(fileEvent.getFileData());
            fileOutputStream.flush();
            fileOutputStream.close();
            System.out.println("Output file : " + outputFile + " is successfully saved ");
//            JOptionPane.showMessageDialog(null, "Đã nhận file thành công");

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
