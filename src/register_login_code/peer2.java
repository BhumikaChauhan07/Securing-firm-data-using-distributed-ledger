package register_login_code;

import java.io.BufferedReader;
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
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class peer2 {
	private static final int REGISTRY_PORT = 5000;
	  private static final int PEER_PORT = 7000;
	  private static final List<String> peerAddresses = new ArrayList<>();
	  private static boolean isRegistered = true;

	  public static void main(String[] args) {
	      try {
	          Scanner scanner = new Scanner(System.in);

	          if (!isRegistered) {
	              performInitialRegistration(scanner);
	          } else {
	              performLogin(scanner);
	              connectToOtherPeers(); // For subsequent logins, connect to other peers
	          }

	          scanner.close();
	      } catch (IOException | NoSuchAlgorithmException e) {
	          e.printStackTrace();
	      }
	  }

	  private static void performInitialRegistration(Scanner scanner) throws IOException, NoSuchAlgorithmException {
	      System.out.print("Enter the mutual numerical code: ");
	      String providedCode = scanner.nextLine();

	      if (validateMutualNumericalCode(providedCode)) {
	          Socket registrySocket = new Socket("localhost", REGISTRY_PORT);
	          PrintWriter out = new PrintWriter(registrySocket.getOutputStream(), true);
	          BufferedReader in = new BufferedReader(new InputStreamReader(registrySocket.getInputStream()));

	          out.println(providedCode); // Send mutual code to registry
	          String registrationResponse = in.readLine();

	          if (registrationResponse.equals("Registered")) {
	              System.out.println("Registration Successful");
	              receiveListOfRegisteredPeers(in);

	              KeyPair keyPair = generateRSAKeyPair();
	              PublicKey publicKey = keyPair.getPublic();
	              String publicKeyAsString = Base64.getEncoder().encodeToString(publicKey.getEncoded());

	              System.out.println("Public Key: " + publicKeyAsString);

	              startListeningForConnections();
	              connectToOtherPeers(); // Connect to other peers after initial registration

	              isRegistered = true;
	              System.out.println("Registration Status: " + isRegistered); // Print the registration status
	          } else {
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

	      if (validateMutualNumericalCode(providedCode)) {
	          System.out.println("Login Successful");
	          Socket registrySocket = new Socket("localhost", REGISTRY_PORT);
	          PrintWriter out = new PrintWriter(registrySocket.getOutputStream(), true);
	          BufferedReader in = new BufferedReader(new InputStreamReader(registrySocket.getInputStream()));

	          out.println("GetListOfPeers"); // Requesting the list of peers after login
	          receiveListOfRegisteredPeers(in);

	          // Connect to other peers after login
	          connectToOtherPeers();
	      } else {
	          System.out.println("Invalid Mutual Numerical Code. Peer login denied.");
	      }
	  }

	  private static void receiveListOfRegisteredPeers(BufferedReader in) throws IOException {
	      String line;
	      while ((line = in.readLine()) != null) {
	          if (line.equals("List of registered peer IP addresses:")) {
	              continue; // Skip the header
	          }
	          peerAddresses.add(line);
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

}
