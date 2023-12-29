package register_login_code;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.Base64;

//RevisedRegistration, login and Key Exchange:


public class Peer {
  private static final int REGISTRY_PORT = 5000;
  private static final int PEER_PORT = 6000;
  private static final List<String> peerAddresses = new ArrayList<>();
  private static final String REGISTRATION_FILE = "registration_status.txt";

  private static boolean isRegistered ;

  public static void main(String[] args) {
      try {
    	  loadRegistrationStatus();
          Scanner scanner = new Scanner(System.in);

          if (!isRegistered) {
              performInitialRegistration(scanner);
          } else {
              performLogin(scanner);
              connectToOtherPeers(); // For subsequent logins, connect to other peers
          }

          scanner.close();
          saveRegistrationStatus();
      } catch (IOException | NoSuchAlgorithmException e) {
          e.printStackTrace();
      }
  }

  private static void performInitialRegistration(Scanner scanner) throws IOException, NoSuchAlgorithmException {
      System.out.print("Enter the mutual numerical code: ");
      String providedCode = scanner.nextLine();

      if (providedCode.equals("YourSecretCode123")) {
          Socket registrySocket = new Socket("localhost", REGISTRY_PORT);
          PrintWriter out = new PrintWriter(registrySocket.getOutputStream(), true);
          BufferedReader in = new BufferedReader(new InputStreamReader(registrySocket.getInputStream()));
          
          out.println(providedCode); // Send mutual code to registry
          String registrationResponse = in.readLine();

          if (registrationResponse.equals("Registered")) {
              System.out.println("Registration Successful");
              receiveListOfRegisteredPeers(in);
              //System.out.println("List of Registered Peers:");
              
              /*for (String peerAddress : peerAddresses) {
                  System.out.println(peerAddress);
              }*/

              KeyPair keyPair = generateRSAKeyPair();
              PublicKey publicKey = keyPair.getPublic();
              String publicKeyAsString = Base64.getEncoder().encodeToString(publicKey.getEncoded());

              System.out.println("Public Key: " + publicKeyAsString);

              startListeningForConnections();
              connectToOtherPeers(); // Connect to other peers after initial registration

              isRegistered = true;
              System.out.println("Registration Status: " + isRegistered); // Print the registration status
          }else if (registrationResponse.equals("Connected")) {
        	  System.out.println("Connected");
          }
          else {
              System.out.println("Registration Denied");
          }

          registrySocket.close();
      } else {
          System.out.println("Invalid Mutual Numerical Code. Registration denied.");
      }
  }

  private static void performLogin(Scanner scanner) throws IOException {
      if (!isRegistered) {
          System.out.println("You are not registered. Please perform the initial registration first.");
          return;
      }

      System.out.print("Enter the mutual numerical code: ");
      String providedCode = scanner.nextLine();

      if (providedCode.equals("YourSecretCode123")) {
          System.out.println("Login Successful");
          Socket registrySocket = new Socket("localhost", REGISTRY_PORT);
          PrintWriter out = new PrintWriter(registrySocket.getOutputStream(), true);
          BufferedReader in = new BufferedReader(new InputStreamReader(registrySocket.getInputStream()));

          out.println("GetListOfPeers"); // Requesting the list of peers after login
          receiveListOfRegisteredPeers(in);
          /*System.out.println("List of Registered Peers:");
          for (String peerAddress : peerAddresses) {
              System.out.println(peerAddress);
          }*/

          // Connect to other peers after login
          connectToOtherPeers();
      } else {
          System.out.println("Invalid Mutual Numerical Code. Peer login denied.");
      }
  }

  private static void receiveListOfRegisteredPeers(BufferedReader in) throws IOException {
      /*String line;
      while ((line = in.readLine()) != null && !line.isEmpty()) {
          if (line.equals("List of registered peer IP addresses:")) {
              continue; // Skip the header
          }
          peerAddresses.add(line);*/
	  String header = in.readLine(); // Read the header line
	    if (header.equals("List of registered peer IP addresses:")) {
	        System.out.println("List of Registered Peers:");
	        String peer;
	        boolean listStarted = false;
	        while ((peer = in.readLine()) != null) {
	            if (listStarted || !peer.equals("List of registered peer IP addresses:")) {
	                // If the list has started or if it's not the control signal
	                if (peer.isEmpty()) {
	                    System.out.println("No peers are currently registered.");
	                } else {
	                    System.out.println(peer);
	                }
	                peerAddresses.add(peer);
	                listStarted = true;
	            } else {
	                break; // Exit loop if the control signal is received again
	            }
	            
	        }
	    } else {
	        System.out.println("Unexpected format or issue with peer list.");
	    }
          
      }
    

  private static void connectToOtherPeers() {
      try {
          for (String address : peerAddresses) {
              connectToPeer(address, getPublicKey());
          }
      } catch (Exception e) {
          e.printStackTrace();
      }
  }

  private static void connectToPeer(String address, String publicKey) throws IOException {
      Socket peerSocket = new Socket(address, PEER_PORT);
      PrintWriter peerOut = new PrintWriter(peerSocket.getOutputStream(), true);
      BufferedReader peerIn = new BufferedReader(new InputStreamReader(peerSocket.getInputStream()));

      peerOut.println("Public Key: " + publicKey);

      // Further interactions with the peer can be implemented here

      peerSocket.close();
      
  }

  private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      return keyPairGenerator.generateKeyPair();
  }

  private static String getPublicKey() throws NoSuchAlgorithmException {
      KeyPair keyPair = generateRSAKeyPair();
      PublicKey publicKey = keyPair.getPublic();
      return Base64.getEncoder().encodeToString(publicKey.getEncoded());
  }

  private static boolean validateMutualNumericalCode(String providedCode) {
      return providedCode.equals("YourSecretCode123"); // Replace with your agreed-upon code
  }

  private static void startListeningForConnections() {
      new Thread(() -> {
          try {
              ServerSocket serverSocket = new ServerSocket(PEER_PORT);
              System.out.println("Listening for incoming connections...");

              while (true) {
                  Socket clientSocket = serverSocket.accept();
                  // Handle incoming connections (optional: perform desired operations upon connection)
              }
          } catch (IOException e) {
              e.printStackTrace();
          }
      }).start();
  }
  
  private static void loadRegistrationStatus() {
      try (BufferedReader br = new BufferedReader(new FileReader(REGISTRATION_FILE))) {
          String status = br.readLine();
          isRegistered = Boolean.parseBoolean(status);
      } catch (IOException e) {
          // If the file doesn't exist or encounters an issue, default to not registered
          isRegistered = false;
      }
  }
  
  private static void saveRegistrationStatus() {
      try (BufferedWriter bw = new BufferedWriter(new FileWriter(REGISTRATION_FILE))) {
          bw.write(String.valueOf(isRegistered));
      } catch (IOException e) {
          e.printStackTrace();
      }
  }
}

/*

To ensure that firewall settings are appropriately configured for your application to communicate between peers, consider the following steps:

### Firewall Configuration:

1. **Allow Inbound and Outbound Connections:** Ensure that the firewall settings on all involved peers allow both inbound and outbound connections on the specified port. This often involves configuring the firewall to permit traffic on the specific port that your application uses for communication.

2. **Allow Application Exceptions:** Add exceptions for your application or specific ports used for communication in the firewall settings. This ensures that the firewall doesn't block traffic for the application.

3. **Network Configuration:** If peers are behind a network with its own firewall or router, configure the network firewall or router to permit traffic on the specified port.

### Additional Recommendations:

- **Use Secure Protocols:** If applicable, use secure protocols like SSL or TLS to encrypt communication between peers, ensuring secure data transfer.

- **Testing and Error Handling:** Implement robust error handling mechanisms to deal with connection failures due to firewall restrictions. Log connection errors to identify issues.

- **Network Admin Assistance:** In enterprise or complex network setups, consult network administrators or IT support for help with firewall configurations.

It's important to note that firewall and network configurations can significantly vary based on the environment and systems involved. Always follow security best practices and consider potential security implications when configuring firewalls.

*/

