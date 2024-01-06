package da1;

import java.io.*;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.Map.Entry;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ChatServer extends Thread 
{
	private enum CODE {
	    STANDARD, SERVER, LIST;
	}
	
	// TODO: select port/class from CLI
    public final static int PORT = 7332;
    private byte[] buf = new byte[1024]; 
    
    private DatagramSocket socket;
    private DatagramPacket packet;
    
    // TODO: one structure
    private ArrayList<InetAddress> cIPs;
    private ArrayList<Integer> cPorts;
    private HashSet<String> cIDs;
    private Map <String, String> cNicks;

    
    public ChatServer() throws IOException 
    {
        socket = new DatagramSocket(PORT);
        packet = new DatagramPacket(buf, buf.length);
        cIPs = new ArrayList<InetAddress>();
        cPorts = new ArrayList<Integer>();
        cIDs = new HashSet<String>();
        cNicks = new HashMap<String, String>();
    }
    
    
    public void run() 
    {
    	// TODO: new class to parse message (protocol class)
        while (true) 
        {
            try 
            {
                // Reply reset
                String replyMSG = "";
                
                socket.receive(packet);
                
                String content = ChatDgram.toString(packet);
                

                
                InetAddress clientAddress = packet.getAddress();
                int clientPort = packet.getPort();
                String id = clientAddress.toString() + ":" + clientPort;
                System.out.println(id + ": " + content);

                // Add new client
                if (!cIDs.contains(id)) 
                {
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
                if (cIDs.contains(id) && (cNicks.get(id).equals("")))
                {
                	if (cNicks.containsValue(content))
                	{
                		replyMSG = "1#This username is used";
                        DatagramPacket reply = ChatDgram.toDatagram(replyMSG, clientAddress, clientPort);
                        socket.send(reply);
                        
                        continue;
                	}
                	else
                	{
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
                if (content.equals("EXIT"))
                {
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
            } 
            catch(Exception e) 
            {
                System.err.println(e);
            }
        }
    }
    public static SecretKey generateSecretKeyFromString(String keyString) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        // Chuyển đổi chuỗi thành mảng byte sử dụng Base64
        byte[] keyBytes = Base64.getDecoder().decode(keyString);

        // Tạo đối tượng SecretKey từ mảng byte
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
        return new String(decryptedBytes);
    }
    
    private void sendToAll(String message, CODE code, String id) throws IOException
    {
    	String msg;
    	
    	switch (code)
    	{
    	case STANDARD:
    		msg = "0#" + cNicks.get(id) + ": " +  message;
    		break;
    		
    	case SERVER:
    		msg = "1#Server: " +  message;
    		break;
    		
    	case LIST:
    		msg = "2#" + message;
    		break;
    		
    		default:
    			return;
    	}

        for (int i=0; i < cIPs.size(); i++) 
        {
			DatagramPacket reply = ChatDgram.toDatagram(msg, cIPs.get(i), cPorts.get(i));
            socket.send(reply);
        }	
    }
    
    
    private void sendOnlineList() throws IOException
    {
    	String list = "";
    	
    	for(Entry <String, String> entry : cNicks.entrySet()) {
    	    list += entry.getValue() + "<|>";
    	}
    	
    	sendToAll(list, CODE.LIST, null);	
    }
    
    
    public static void main(String args[]) throws Exception 
    {
        new ChatServer().start();
    }
}