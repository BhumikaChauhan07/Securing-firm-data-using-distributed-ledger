package register_login_code;
/*import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.List;

public class UserRegistration {
    private static final List<String> registeredPeers = new ArrayList<>();

    public static void main(String[] args) {
        final int REGISTRY_PORT = 5000;
        final int PEER_PORT = 6000;

        try {
            ServerSocket serverSocket = new ServerSocket(REGISTRY_PORT);
            System.out.println("Central Registry started...");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("New peer connected: " + clientSocket);

                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

                String mutualCode = in.readLine();

                if (isFirstTimeRegistration(mutualCode, clientSocket.getInetAddress().getHostAddress())) {
                    registerNewPeer(clientSocket);
                    out.println("Registered");
                    sendListOfRegisteredPeers(out);
                } else if (validateMutualNumericalCode(mutualCode)) {
                    out.println("LoginSuccessful");
                    sendListOfRegisteredPeers(out); // Send list after successful login
                } else {
                    out.println("InvalidMutualCode");
                }
            }
        } catch (IOException e) {
            e.printStackTrace();        
        }
    }

    private static boolean isFirstTimeRegistration(String providedCode, String peerAddress) {
        return validateMutualNumericalCode(providedCode) && !registeredPeers.contains(peerAddress);
    }

    private static void registerNewPeer(Socket clientSocket) {
        String peerAddress = clientSocket.getInetAddress().getHostAddress();
        registeredPeers.add(peerAddress);
    }

    private static void sendListOfRegisteredPeers(PrintWriter out) {
        out.println("List of registered peer IP addresses:");
        for (String peer : registeredPeers) {
            out.println(peer);
        }
    }

    private static boolean validateMutualNumericalCode(String providedCode) {
        return providedCode.equals("YourSecretCode123"); // Replace with your agreed-upon code
    }
}*/


import java.io.*;
import java.net.*;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class UserRegistration {
    private static final Map<String, Socket> connectedPeers = new HashMap<>();
    private static String YOUR_IP_ADDRESS= "192.168.248.171" ; // Replace with your IP address

    public static void main(String[] args) {
        final int REGISTRY_PORT = 5000;
        //YOUR_IP_ADDRESS = getIPAddress();
        try {
            ServerSocket serverSocket = new ServerSocket(REGISTRY_PORT);
            System.out.println("Central Registry started...");
            System.out.println(connectedPeers );

            while (true) {
                Socket clientSocket = serverSocket.accept();
                String clientAddress = clientSocket.getInetAddress().getHostAddress();

                System.out.println("Discovered peers who tried to connect: " + clientAddress);

                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

                String mutualCode = in.readLine();

                /*if (clientAddress.equals(YOUR_IP_ADDRESS)) {
                    out.println("Registered");
                    connectedPeers.put(clientAddress, clientSocket);
                } else if (isFirstTimeRegistration(mutualCode, clientAddress)) {
                    if (connectedPeers.containsKey(clientAddress)) {
                        out.println("Already connected");
                        clientSocket.close();
                    } else {
                        connectedPeers.put(clientAddress, clientSocket);
                        out.println("Registered");
                        sendListOfRegisteredPeers(out);
                    }
                } else {
                    out.println("Access Denied");
                    clientSocket.close();
                }
                System.out.println(connectedPeers );*/
                if (clientAddress.equals(YOUR_IP_ADDRESS)) {
                    out.println("Registered");
                    connectedPeers.put(clientAddress, clientSocket);
                } else if (isFirstTimeRegistration(mutualCode, clientAddress)) {
                   /* if (connectedPeers.containsKey(clientAddress)) {
                        out.println("Connected");
                        clientSocket.close();
                    } else {*/
                        connectedPeers.put(clientAddress, clientSocket);
                        out.println("Registered");
                        sendListOfRegisteredPeers(out);
                   // }
                }else if (connectedPeers.containsKey(clientAddress)) {
                    out.println("Connected");
                    clientSocket.close();} 
                else {
                    out.println("Access Denied");
                    clientSocket.close();
                }
                System.out.println(connectedPeers);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static boolean isFirstTimeRegistration(String providedCode, String peerAddress) {
        return providedCode.equals("YourSecretCode123") && !connectedPeers.containsKey(peerAddress);
    }
    
    private static String getIPAddress() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) {
                    continue;
                }

                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof Inet4Address) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void sendListOfRegisteredPeers(PrintWriter out) {
        out.println("List of registered peer IP addresses:");
        for (String peer : connectedPeers.keySet()) {
            out.println(peer);
        }
    }
}






