package register_login_code;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class PeerClient {
    private static final String REGISTRY_ADDRESS = "localhost";
    private static final int REGISTRY_PORT = 5000;

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Select an option:");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();

            Socket socket = new Socket(REGISTRY_ADDRESS, REGISTRY_PORT);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            if (choice == 1) {
                System.out.print("Enter the mutual numerical code to register: ");
                String mutualCode = scanner.next();
                out.println(mutualCode);
                String response = in.readLine();
                if (response.equals("Registered")) {
                    System.out.println("Registration Successful");
                    // Additional logic after successful registration can be added here
                } else {
                    System.out.println("Registration Denied");
                }
            } else if (choice == 2) {
                System.out.print("Enter the mutual numerical code to log in: ");
                String mutualCode = scanner.next();
                out.println(mutualCode);
                String response = in.readLine();
                if (response.equals("LoginSuccessful")) {
                    System.out.println("Login Successful");
                    // Additional logic after successful login can be added here
                } else {
                    System.out.println("Login Failed");
                }
            } else {
                System.out.println("Invalid choice.");
            }

            socket.close();
            scanner.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

