package da1;

import static da1.ClientSender.generateSecretKeyFromString;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

public class ChatServer extends Thread {

    private enum CODE {
        STANDARD, SERVER, LIST;
    }

    // TODO: select port/class from CLI
    public final static int PORT = 7332;
    private byte[] buf = new byte[1024];
    private String IP = getIpClient();

    private DatagramSocket socket;
    private DatagramPacket packet;

    // TODO: one structure
    private ArrayList<InetAddress> cIPs;
    private ArrayList<Integer> cPorts;
    private HashSet<String> cIDs;
    private Map<String, String> cNicks;

    public ChatServer() throws IOException {
        socket = new DatagramSocket(PORT);
        packet = new DatagramPacket(buf, buf.length);
        cIPs = new ArrayList<InetAddress>();
        cPorts = new ArrayList<Integer>();
        cIDs = new HashSet<String>();
        cNicks = new HashMap<String, String>();
    }

    public void run() {
        // TODO: new class to parse message (protocol class)
        String start = "IP: " + IP + " Port: " + PORT;
        System.out.println(start);
        
        JOptionPane.showMessageDialog(null, start, "Server được khởi động tại: ", JOptionPane.INFORMATION_MESSAGE);

        while (true) {
            try {
                // Reply reset
                String replyMSG = "";

                socket.receive(packet);

                String content = ChatDgram.toString(packet);

                System.out.println("----content received-->>> " + content);

                InetAddress clientAddress = packet.getAddress();
                SecretKey secretkey;
                try {
                    secretkey = generateSecretKeyFromString(clientAddress.getHostAddress());
                    content = decrypt(content, secretkey);
                    //System.out.println("----content received-->>> " + content);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(ChatServer.class.getName()).log(Level.SEVERE, null, ex);
                }

                int clientPort = packet.getPort();

                String id = clientAddress.toString() + ":" + clientPort;
                System.out.println(id + ": " + content);

                // Add new client
                if (!cIDs.contains(id)) {
                    cIDs.add(id);
                    cPorts.add(clientPort);
                    cIPs.add(clientAddress);
                    cNicks.put(id, "");

                    // Nick request
                    //replyMSG = "1#Enter your username";
                    DatagramPacket reply = ChatDgram.toDatagram(replyMSG, clientAddress, clientPort);
                    socket.send(reply);
                    System.out.println("Server to " + id + ": " + replyMSG);

                    continue;
                }
                // Already used?
                if (cIDs.contains(id) && (cNicks.get(id).equals(""))) {
                    if (cNicks.containsValue(content)) {
                        replyMSG = "1#This username is used";
                        DatagramPacket reply = ChatDgram.toDatagram(replyMSG, clientAddress, clientPort);
                        socket.send(reply);

                        continue;
                    } else {
                        cNicks.put(id, content);
                        replyMSG = "1#Welcome, you can send messages";

                        DatagramPacket reply = ChatDgram.toDatagram(replyMSG, clientAddress, clientPort);
                        socket.send(reply);
                    }

                    sendToAll(content + " joins to chat", CODE.SERVER, null);
                    sendOnlineList();
                    continue;
                }
                // Remove client
                if (content.equals("EXIT")) {
                    int index = cIPs.indexOf(clientAddress);
                    String nick = cNicks.get(id);

                    cIPs.remove(index);
                    cPorts.remove(index);

                    cNicks.remove(id);
                    cIDs.remove(id);

                    sendToAll(nick + " leaves the chat", CODE.SERVER, null);
                    sendOnlineList();
                    continue;
                }
                sendToAll(content, CODE.STANDARD, id);
            } catch (Exception e) {
                System.err.println(e);
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

    private void sendToAll(String message, CODE code, String id) throws IOException, UnsupportedEncodingException {
        String msg;

        switch (code) {
            case STANDARD:
                msg = "0#" + cNicks.get(id) + ": " + message;
                break;

            case SERVER:
                msg = "1#Server: " + message;
                break;

            case LIST:
                msg = "2#" + message;
                break;

            default:
                return;
        }

        for (int i = 0; i < cIPs.size(); i++) {
            try {
                SecretKey secretkey;
                secretkey = generateSecretKeyFromString(cIPs.get(i).getHostAddress());
                //System.out.println(cIPs.get(i).getHostAddress()+"----Secrect Key-->>> "+ secretkey);
                try {
                    String sms = encrypt(msg, secretkey);
                    //System.out.println("------sms--->"+ sms);
                    DatagramPacket reply = ChatDgram.toDatagram(sms, cIPs.get(i), cPorts.get(i));
                    socket.send(reply);
                } catch (Exception ex) {
                    Logger.getLogger(ChatServer.class.getName()).log(Level.SEVERE, null, ex);
                }
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(ChatServer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private void sendOnlineList() throws IOException {
        String list = "";

        for (Entry<String, String> entry : cNicks.entrySet()) {
            list += entry.getValue() + "<|>";
        }
        sendToAll(list, CODE.LIST, null);
    }

    public static void main(String args[]) throws Exception {
        new ChatServer().start();
    }

    public static String getIpClient() {
        String ip = "";
        try {
            Enumeration interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = (NetworkInterface) interfaces.nextElement();
                // filters out 127.0.0.1 and inactive interfaces
                if (iface.isLoopback() || !iface.isUp()) {
                    continue;
                }

                Enumeration addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = (InetAddress) addresses.nextElement();

                    if (addr instanceof Inet6Address) {
                        continue;
                    }

                    ip = addr.getHostAddress();
                }
            }
        } catch (SocketException e) {
            throw new RuntimeException(e);
        }
        return ip;
    }
}
