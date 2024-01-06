/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package da1;

import java.awt.Color;
import java.awt.EventQueue;

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
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
        byte buf[] = s.getBytes();
        InetAddress address = InetAddress.getByName(hostname);
        DatagramPacket packet = new DatagramPacket(buf, buf.length, address, port);
        socket.send(packet);

        // TODO: add verify class
        //ChatVerify verify = ChatVerify.getInstance();
        //System.out.println(verify.addVerify(s));
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
        frame = new FrameReceiver(PORT,name);
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

    FrameReceiver(int p,String name) throws Exception {
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
    public static SecretKey generateSecretKeyFromString(String keyString) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        // Chuyển đổi chuỗi thành mảng byte sử dụng Base64
        byte[] keyBytes = Base64.getDecoder().decode(keyString);

        // Tạo đối tượng SecretKey từ mảng byte
        return new SecretKeySpec(keyBytes, "AES");
    }

    public void run() {
        while (true) {
            try {

                DatagramPacket packet = new DatagramPacket(buf, buf.length);
                socket.receive(packet);

                String received = ChatDgram.toString(packet);
                System.out.println(received);
                checkMessage(received);
                //msgArea.append(received + "\n");

            } catch (Exception e) {
                System.err.println(e);
            }
        }
    }

    // TODO: new class to parse message (protocol class)
    private void checkMessage(String msg) {
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
