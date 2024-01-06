/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package da1;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

public class ChatDgram {

    // Convert DatagramPacket to String
    public static String toString(DatagramPacket packet) {
        byte[] data = packet.getData();
        int length = packet.getLength();
        return new String(data, 0, length).trim();
    }

    // Convert String to DatagramPacket
    public static DatagramPacket toDatagram(String message, InetAddress address, int port) {
        byte[] data = message.getBytes();
        return new DatagramPacket(data, data.length, address, port);
    }
}
