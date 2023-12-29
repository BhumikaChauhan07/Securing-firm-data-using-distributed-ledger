package ledger_structure;

import java.io.*;
import java.nio.file.*;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import java.io.FileReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.net.NetworkInterface;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Scanner;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// STRAT OF LEDGER CLASS

public class Ledger {
	// an array list to store each block of the blockchain
    private static List<Block> blockchain = new ArrayList<>();
    
    //list to store only the hashes of the blocks
    private static List<String> blockchainHashes = new ArrayList<>();

    private static String lastHashFromFile;
    private static String lastHashInLedger;
    // at the time of registration these values will be checked from database and then entered
    private static int userId ;
    private static String publicKey_entry;
    
    private static byte[]original_key;
    private static byte[]serialized_ciphertxt;
 // The file to store block hashes
    private static final String HASHES_FILE = "D:\\saved_ledger\\block_hashes.txt";

    // scanner object
    private static final Scanner scanner = new Scanner(System.in);
    private static String viewfilename;
    
//**************************************************************************************************************************************************************************************************************************************************************    
  
    //main method
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, ClassNotFoundException {
    	
    	// creating a general folder 
    	 String folderPath = "C:\\SFDUDL";
    	 createFolder(folderPath);
    	
    	
    	// temporarily generating public and private key here
       keypairgen();
       publicKey_entry=readPublicKeyFromFile("C:\\SFDUDL\\publicKey.txt");
    	
    	// method to read from existing ledger. This is done so that we can check the validity of ledger and know if it has been tampered with
    	readBlockchainFromJson();
    	
    	// function to read hashes from a read only file
    	readBlockHashes();
    	
    	// if the blockchain arraylist is empty it means the ledger is empty so the default genesis block is created
    	if (blockchain.isEmpty()) {
    	        // If it's empty, create the genesis block
    	        Block genesisBlock = new Block(0, "0", System.currentTimeMillis(), "Genesis Block");    // uses the current 
    	        blockchain.add(genesisBlock);
    	        saveBlockHash(genesisBlock.getHash());
    	    }        
    	
    	// printing the menu
        String choice;
        while (true) {
            System.out.println("\nMenu:");
           /* System.out.println("1. Login");*/
            System.out.println("1. Upload Document");
            System.out.println("2. View Document");
            System.out.println("3. Exit");
            System.out.println("Enter Your choice:");
            /* choice = scanner.nextLine();*/
            
            
           // keep on asking for choices 
           if (scanner.hasNextLine()) {
        	   choice = scanner.nextLine();
            /*if (choice.equals("1")) {
                if (login()) {
                    System.out.println("Login successful.");
                } else {
                    System.out.println("Login failed.");
                }
            } else*/
            if (choice.equals("1")) {
                saveBlockchainToJson(); // Save the blockchain to JSON after uploading the document
                uploadDocument();
                printBlockchain(); // Print the blockchain after uploading the document
            } else if (choice.equals("2")) {
                
                saveBlockchainToJson(); // Save the blockchain to JSON after viewing the document
                viewDocument();
                printBlockchain(); // Print the blockchain after viewing the document
            } else if (choice.equals("3")) {
                break;
            } else {
                System.out.println("Invalid choice. Please select a valid option.");
            }          
          } 
           else {
            System.out.println("No input found.");
            break;
          }
           
        }
        
        scanner.close(); // Close the scanner when done.
        
        
        
        
        
        
        
    }

//**********************************************************************************************************************************************************************
    
    private static void createFolder(String folderPath) {
        // Convert the folder path string to a Path object
        Path folder = Paths.get(folderPath);

        try {
            // Check if the folder already exists
            if (!Files.exists(folder)) {
                // Create the folder if it doesn't exist
                Files.createDirectories(folder);
                System.out.println("Folder created successfully: " + folderPath);
            } else {
                System.out.println("Folder already exists: " + folderPath);
            }
        } catch (Exception e) {
            // Handle any exceptions that may occur during folder creation
            System.err.println("Error creating folder: " + e.getMessage());
        }
    }
   
    
//**************************************************************************************************************************************************************************************************************************************    
    
    
    
public static void keypairgen() throws NoSuchAlgorithmException {
	
	 // Specify the directory where you want to store the files
    String directoryPath = "C:\\SFDUDL";
	
	// Specify the file names for public and private keys
    String publicKeyFileName = "publicKey.txt";
    String privateKeyFileName = "privateKey.txt";

    // Check if the key files already exist
    if (keyFilesExist(directoryPath, publicKeyFileName, privateKeyFileName)) {
        System.out.println("Key files already exist. Skipping key pair generation.");
        return;
    }

	
	  // Generate a unique seed value based on the system's MAC address
    String systemSpecificInfo = getMacAddress(); // Implement this method
    String seedValue = "YourUniqueSeedPrefix" + systemSpecificInfo;

    // Generate an RSA key pair for the user with the unique seed value
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048, new SecureRandom(seedValue.getBytes()));
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    // Store the user's public key securely in the server's user database
    PublicKey publicKey = keyPair.getPublic();
    String publicKeyAsString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
   // publicKey_entry = publicKeyAsString;

    
 // Store the public key in the user's account information
    saveKeyToFile(directoryPath, "publicKey.txt", publicKeyAsString);
    publicKey_entry=readPublicKeyFromFile("C:\\SFDUDL\\publicKey.txt");
    publicKey_entry = publicKey_entry.replace("\r", "").replace("\n", "");
    System.out.println("public key:line 208"+publicKey_entry);
    userListTable1Entry(publicKey_entry);
    System.out.println("Public Key: " + publicKeyAsString);

    // Access the private key
    PrivateKey privateKey = keyPair.getPrivate();

    // Convert the private key to a byte array for display (for testing purposes
    // only)
    byte[] privateKeyBytes = privateKey.getEncoded();
    
    // Store the private key in a file
    saveKeyToFile(directoryPath, "privateKey.txt", Base64.getEncoder().encodeToString(privateKeyBytes));

    // Print the private key (for testing purposes only)
    System.out.println("Private Key stored in default s/w folder " );

}


private static void saveKeyToFile(String directoryPath, String fileName, String key) {
    try {
        // Create the directory if it doesn't exist
        Files.createDirectories(Paths.get(directoryPath));
        
        // Create the file path
        String filePath = Paths.get(directoryPath, fileName).toString();
        
        // Write the key to the file
        try (PrintWriter writer = new PrintWriter(filePath)) {
            writer.println(key);
            System.out.println("Key saved to file: " + filePath);
        }
    } catch (IOException e) {
        e.printStackTrace();
        System.err.println("Error saving key to file: " + e.getMessage());
    }
}


private static boolean keyFilesExist(String directoryPath, String publicKeyFileName, String privateKeyFileName) {
    Path publicKeyPath = Paths.get(directoryPath, publicKeyFileName);
    Path privateKeyPath = Paths.get(directoryPath, privateKeyFileName);
    return Files.exists(publicKeyPath) && Files.exists(privateKeyPath);
}
 

public static String getMacAddress() {
    try {
        Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
        while (networkInterfaces.hasMoreElements()) {
            NetworkInterface networkInterface = networkInterfaces.nextElement();
            byte[] mac = networkInterface.getHardwareAddress();
            if (mac != null) {
                StringBuilder macAddress = new StringBuilder();
                for (int i = 0; i < mac.length; i++) {
                    macAddress.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                }
                return macAddress.toString();
            }
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
    return "UnknownMacAddress" ;}

 
//************************************************************************************************************************************************************************************************************************************************************** 
    
    public static boolean login() {
        // Implement user authentication logic here
        // Return true if login is successful, otherwise false
        boolean loggedIn = true; // Simplified, always returns true
        return loggedIn;
    }
 //************************************************************************************************************************************************************************************************************************************************************** 
 
    public static void uploadDocument() throws IOException {
        if (login()) {
        	
        	addBlock("Uploaded Document" );
        	
            //Scanner scanner = new Scanner(System.in);
        	System.out.print("Enter document name: ");
            String docName = scanner.nextLine();

            System.out.print("Upload the document(file path): ");
            String document = scanner.nextLine();

            //scanner.close(); // Remember to close the scanner

            if (isDocumentVerified()) {
                // a folder where all the files 
                String folderPath = "C:\\SFDUDL\\Encrypted_files";
                createFolder( folderPath);
            	
                
                String filePath = folderPath + File.separator + docName;
                
                // Encrypt the document (simplified, no actual encryption)
            	
                String documentEncrypted = Cryptography.Working.Encrypted_data(document);
                // gets the original key in byte format
                byte[] original_key = AES_Encryption.Plain_text_cipher.returnOriginalKey();
                byte[][] Cipher_Text = AES_Encryption.Plain_text_cipher.returnCipherText();
                String fileHash = AES_Encryption.Plain_text_cipher.FileHash();
               // System.out.println(documentEncrypted);
                
                
                
          
                
                // displaying the list of the lookuptable1 and store permissions in table 2 where insertion is performed
                showUserList( Cipher_Text, original_key, fileHash , docName);
                
                
                
                
                
                
                
                
                
                try {
                    // Create the file object
                    File file = new File(filePath);

                    // Create the parent directory if it doesn't exist
                    file.getParentFile().mkdirs();

                    // Create a FileWriter to write to the file
                    try (FileWriter writer = new FileWriter(file)) {
                        // Write the content to the file
                        writer.write(documentEncrypted);
                    }

                    // Set the file to read-only
                    file.setReadOnly();

                    System.out.println("File created and written successfully.");
                } catch (IOException e) {
                    // Handle IO exceptions, e.g., if there's an issue writing to the file
                    e.printStackTrace();
                }
                               
                System.out.println("Please get the encrypted document from the location: " + filePath + " \n copy the link to browser to upload the file - https://drive.google.com/drive/folders/1vdauGG-uybxtKMsdIrks3pM9TFxitO25?usp=drive_link " );
                
                System.out.println("enter Y once uploaded the file: " );
                String ans = scanner.nextLine();
                if(ans.equals("y")||ans.equals("Y")) {
                	System.out.println("File uploaded" );
                }
                
            } else {
                System.out.println("Error: Document not verified.");
            }
        } else {
            System.out.println("Error: Login failed.");
        }
    }
//************************************************************************************************************************************************************************************************************************************************************** 
   
    public static void viewDocument() throws ClassNotFoundException, IOException {
        if (login()) {
            if (isDocumentVerified()) {
            	if(checkpermission()) {
         
            	addBlock("Viewed Document");
            	
                String folderPath = "C:\\SFDUDL\\Downloaded_Encrypted_files";
                createFolder( folderPath); 
                
                
                // implement print the list of documents from the database
                
                /*System.out.println("Enter the name of the file you want to view: ");
                String docName = scanner.nextLine();*/
                 
                // implement the query to search whether this use has permission or not
                // for now let it be as it is otherwise it would come in if else part
                System.out.println("\nDownload the documnet from the link - https://drive.google.com/drive/folders/1vdauGG-uybxtKMsdIrks3pM9TFxitO25?usp=drive_link " + "\nSave the downloaded encrypted document  to the location: C:\\SFDUDL\\Downloaded_Encrypted_files\n");
                // aad yes option to wait till user downloads
               
                System.out.print("enter Y once uploaded the file: " );
                // Now read the input
                String ans = scanner.nextLine();
                
                if(ans.equals("y")||ans.equals("Y")) {
                	System.out.println("\nFILE UPLOADED" );
                }
                String filePath = folderPath + File.separator + viewfilename;
                StringBuilder content = new StringBuilder();

                // read the encrypted data
                try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        content.append(line).append("\n");
                    }
                } catch (IOException e) {
                    System.err.println("An error occurred: " + e.getMessage());
                }
                
            	// convert the string to cipher text matrix and implement key expansion saved in other file during encryption and then perform decryption
                

            	System.out.println("document content: "+ Cryptography.Working.Decryption(original_key, content, serialized_ciphertxt));
            	// after decrypting you have to verify hash just in case he gives and downloads other file although the decryption will result in undesired content then but viewer wont know
            	
            	
                // Decrypt the document (simplified, no actual decryption)
                String documentDecrypted = getCurrentBlock().getData();
                //System.out.println("Document: " + documentDecrypted);
            }
                
            } else {
                System.out.println("Error: Document not verified.");
            }
        } else {
            System.out.println("Error: Login failed.");
        }
    }
//************************************************************************************************************************************************************************************************************************************************************** 
    
    public static void addBlock(String data) {
    	
    	readBlockHashes();
        lastHashFromFile = blockchainHashes.isEmpty() ? null : blockchainHashes.get(blockchainHashes.size() - 1);
       
        lastHashInLedger = getCurrentBlock().getHash();


        if (!compareHashes(lastHashFromFile, lastHashInLedger)) {
            System.out.println("Error: Blockchain integrity check failed.");
            // Additional actions if integrity check fails (e.g., exit the program)
        } else {
            int index = getCurrentBlock().getIndex() + 1;
            String previousHash = getCurrentBlock().getHash();
            long timestamp = System.currentTimeMillis();
            Block newBlock = new Block(index, previousHash, timestamp, data);
            blockchain.add(newBlock);
            saveBlockchainToJson();
            saveBlockHash(newBlock.getHash());

            System.out.println("Block added successfully.");
        }
    }
    
    
    private static boolean compareHashes(String hashFromFile, String hashInLedger) {
        // Implement the logic to compare the hashes
        return hashFromFile != null && hashFromFile.equals(hashInLedger);
    }
    
    
//************************************************************************************************************************************************************************************************************************************************************** 

    public static boolean isDocumentVerified() {
        // Implement document verification logic here
        return true; // Simplified, always returns true
    }
    
    
//************************************************************************************************************************************************************************************************************************************************************** 

    public static Block getCurrentBlock() {
        return blockchain.get(blockchain.size() - 1);
    }

//**************************************************************************************************************************************************************************************************************************************************************     
    
    public static void printBlockchain() {
        // Print the blockchain
        for (Block block : blockchain) {
            System.out.println(blockToJson(block));
        }
    }
  //************************************************************************************************************************************************************************************************************************************************************** 
    
    public static String blockToJson(Block block) {
        return "{\n" +
                "  \"index\": " + block.getIndex() + ",\n" +
                "  \"previous_hash\": \"" + block.getPreviousHash() + "\",\n" +
                "  \"timestamp\": " +"\"" +block.getTimestamp() +"\""+ ",\n" +
                "  \"operation\": \"" + block.getData()+ "\",\n" +
                "  \"hash\": \"" + block.getHash() + "\"\n" +
                "}";
    }
    
//**************************************************************************************************************************************************************************************************************************************************************    
    
    // function to save a block to the json ledger file
    public static void saveBlockchainToJson() {
        try (// creates a file writer object to write to the ledger
        	FileWriter fileWriter = new FileWriter("D:\\saved_ledger\\ledger.json")) 
        {
        	// creates a file object to represent a file at given location
        	File file = new File("D:\\saved_ledger\\ledger.json");
        	
        	// checks if the file exist if it does'nt, the file is created
        	if (!file.exists()) {
                file.createNewFile();
                System.out.println("Ledger file created!");
            }
        	
        	// writes the content according to the format of json( basically it will be seen as an array of blocks in the ledger json)
        	fileWriter.write("[\n");
             
        	// loop for writing the elements(blocks) of the blockchain array list into the json file
        	 for (int i = 0; i < blockchain.size(); i++) {
                 fileWriter.write(blockToJson(blockchain.get(i)));
                 if (i < blockchain.size() - 1) {
                     fileWriter.write(",\n");
                 }
             }
        	 
        	 // closes the array in json
            fileWriter.write("]\n");
            //System.out.println("block added to Blockchain and saved to ledger");
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Error: Unable to save blockchain to JSON file.");
        }
    }
//**************************************************************************************************************************************************************************************************************************************************************    
    
    private static void readBlockHashes() {       
        try (Scanner fileScanner = new Scanner(new File(HASHES_FILE))) {
            while (fileScanner.hasNextLine()) {
                String hash = fileScanner.nextLine();
                blockchainHashes.add(hash);
            }
        } catch (FileNotFoundException e) {
            System.out.println("Block hashes file not found. Creating a new one.");
        }

        // Set lastHashFromFile to the last hash in the list (if the list is not empty)
        if (!blockchainHashes.isEmpty()) {
            lastHashFromFile = blockchainHashes.get(blockchainHashes.size() - 1);
        } else {
            lastHashFromFile = null;
        }
    }

    private static void saveBlockHash(String hash) {
        /*try {*/
            /*Path path = Paths.get(HASHES_FILE);

            // Temporarily remove the read-only attribute
            Files.setAttribute(path, "dos:readonly", false);*/

            try (FileWriter fileWriter = new FileWriter(HASHES_FILE, true)) {
                fileWriter.write(hash + "\n");
            } catch (IOException e) {
                e.printStackTrace();
                System.out.println("Error: Unable to save block hash to file.");
            } /*finally {
                // Restore the read-only attribute
                Files.setAttribute(path, "dos:readonly", true);
            }
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Error: Unable to modify file attributes.");
        }*/
    }
    
    public static void readBlockchainFromJson() {
        try (Scanner fileScanner = new Scanner(new File("D:\\saved_ledger\\ledger.json"))) {
            StringBuilder jsonStringBuilder = new StringBuilder();
            while (fileScanner.hasNextLine()) {
                jsonStringBuilder.append(fileScanner.nextLine());
            }

            // Parse the JSON array and populate the blockchain
            JSONArray jsonArray = new JSONArray(jsonStringBuilder.toString());
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject jsonObject = jsonArray.getJSONObject(i);
                int index = jsonObject.getInt("index");
                String previousHash = jsonObject.getString("previous_hash");
                long timestamp = parseTimestamp(jsonObject.getString("timestamp"));
                String data = jsonObject.getString("operation");
                String hash = jsonObject.getString("hash");

                Block block = new Block(index, previousHash, timestamp, data);
                block.setHash(hash);
                blockchain.add(block);
            }
        } catch (FileNotFoundException e) {
            System.out.println("Ledger file not found. Creating a new one.");
        } catch (JSONException e) {
            System.out.println("Error parsing JSON. Ledger file may be corrupted.");
        }
    }
    
//**************************************************************************************************************************************************************************************************************************************************************    
    
    public static long parseTimestamp(String formattedTimestamp) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(formattedTimestamp, formatter);
        return zonedDateTime.toInstant().toEpochMilli();
    }
    
//**************************************************************************************************************************************************************************************************************************************************************    

//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------    
    // nested class for creating a block of the blockchain
    static class Block {
    	
        // what all does a block consist of
        private int index;
        private String previousHash;
        private long timestamp;
        private String data;
        private String hash;
      //**************************************************************************************************************************************************************************************************************************************************************    

        // parameterized constructor
        public Block(int index, String previousHash, long timestamp, String data) {
            this.index = index;
            this.previousHash = previousHash;
            this.timestamp = timestamp;
            this.data = data;
            this.hash = calculateHash();
        }

      //**************************************************************************************************************************************************************************************************************************************************************    

        // method to calculate hash for current block using SHA 256
        public String calculateHash() {
            String value = index + previousHash + timestamp + data;
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] encodedHash = digest.digest(value.getBytes());
                StringBuilder hexString = new StringBuilder(2 * encodedHash.length);
                for (byte b : encodedHash) {
                    String hex = Integer.toHexString(0xff & b);
                    if (hex.length() == 1) {
                        hexString.append('0');
                    }
                    hexString.append(hex);
                }
                return hexString.toString();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                return null;
            }
        }
      //**************************************************************************************************************************************************************************************************************************************************************    

        
        /*private String calculateGenesisHash() {
            // Calculate the hash for the fixed values of the genesis block
            String value = "0" + "0" + System.currentTimeMillis() + "Genesis Block";
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] encodedHash = digest.digest(value.getBytes());
                StringBuilder hexString = new StringBuilder(2 * encodedHash.length);
                for (byte b : encodedHash) {
                    String hex = Integer.toHexString(0xff & b);
                    if (hex.length() == 1) {
                        hexString.append('0');
                    }
                    hexString.append(hex);
                }
                return hexString.toString();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                return null;
            }
        }*/

      //**************************************************************************************************************************************************************************************************************************************************************    

        
        public void setHash(String hash) {
            this.hash = hash;
        }
        
        
      //**************************************************************************************************************************************************************************************************************************************************************    

        public boolean isValidBlock() {
            /*if (index == 0) {
                // Genesis block has a fixed hash
                return hash.equals(calculateGenesisHash());
            }*/

            String calculatedHash = calculateHash();
            return calculatedHash.equals(hash) && isTimestampValid();
        }
      //**************************************************************************************************************************************************************************************************************************************************************    

        public int getIndex() {
            return this.index;                 // i think this should be used here
        }

        
      //**************************************************************************************************************************************************************************************************************************************************************    

        public String getPreviousHash() {
            return previousHash;
        }
      //**************************************************************************************************************************************************************************************************************************************************************    

        
        // this function is converting the long format of the date to a human understandable format and returning it so that it can be entered that way in the block
        public String getTimestamp() {
            //return timestamp;
        	// Convert the timestamp to ZonedDateTime with a specific timezone
            Instant instant = Instant.ofEpochMilli(timestamp);
            ZoneId zoneId = ZoneId.of("UTC"); // Change this to your desired timezone
            ZonedDateTime zonedDateTime = ZonedDateTime.ofInstant(instant, zoneId);

            // Format the timestamp using a specific pattern
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");
            return zonedDateTime.format(formatter);
        }
      //**************************************************************************************************************************************************************************************************************************************************************    

        
        private boolean isTimestampValid() {
            // Get the formatted timestamp of the previous block
            String previousBlockTimestamp = getPreviousBlockTimestamp();

            // Convert the formatted timestamp to ZonedDateTime
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");
            ZonedDateTime previousTimestamp = ZonedDateTime.parse(previousBlockTimestamp, formatter);

            // Convert the current block's timestamp to ZonedDateTime
            ZonedDateTime currentTimestamp = ZonedDateTime.parse(getTimestamp(), formatter);

            // Check if the current block's timestamp is after the previous block's timestamp
            return currentTimestamp.isAfter(previousTimestamp);
        }

      //**************************************************************************************************************************************************************************************************************************************************************    

        private String getPreviousBlockTimestamp() {
            // Get the previous block from the blockchain
            Block previousBlock = blockchain.get(blockchain.size() - 2); // Note: This assumes there's at least one block in the blockchain

            // Return the formatted timestamp of the previous block
            return previousBlock.getTimestamp();
        }
        
      //**************************************************************************************************************************************************************************************************************************************************************    

        public String getData() {
            return this.data;                   // i think this.data should be used here 
        }
      //**************************************************************************************************************************************************************************************************************************************************************    

        public String getHash() {
            return this.hash;
        }
//**************************************************************************************************************************************************************************************************************************************************************    

    }
    
    
 // end of nested class
//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

public static void userListTable1Entry(String publicKeyAsString) {
    // Store the public key in the user's account information basically  will be done during registration process
    // JDBC connection parameters
	
	
    String jdbcUrl = "jdbc:mysql://localhost:3306/Lookup_tables";
    String username = "root";
    String password = "root";
    userId = 1;
    try (Connection connection = DriverManager.getConnection(jdbcUrl, username, password)) {
        // SQL query with a prepared statement using INSERT IGNORE
        String insertQuery = "INSERT IGNORE INTO lookup_table1_userlist (user_id, public_key) VALUES (?, ?)";

        try (PreparedStatement preparedStatement = connection.prepareStatement(insertQuery)) {
            // Set values for the parameters
            preparedStatement.setInt(1, userId);
            preparedStatement.setString(2, publicKeyAsString);

            // Execute the query
            int rowsAffected = preparedStatement.executeUpdate();

            if (rowsAffected > 0) {
                System.out.println("Data inserted successfully.");
            } else {
                System.out.println("Data already exists; no insertion performed.");
            }
        }
    } catch (SQLException e) {
        e.printStackTrace();
    }
}
//-------------------------------------------------------------------------------------------------------------
public static void showUserList(byte[][] CipherText,byte[] Originalkey, String filehash, String filename) throws IOException {
    String jdbcUrl = "jdbc:mysql://localhost:3306/Lookup_tables";
    String username = "root";
    String password = "root";
    try {
        // Load the JDBC driver
        Class.forName("com.mysql.cj.jdbc.Driver");

        // Establish a connection
        try (Connection connection = DriverManager.getConnection(jdbcUrl, username, password)) {
            // Fetch data from the lookup_table1
            ArrayList<String> publicKeys = getPublicKeys(connection);

            // Display the fetched data
            displayPublicKeys(publicKeys);
           String publickeyuploader = publicKey_entry;

            // Let the user select public keys until "done" is entered
            ArrayList<String> selectedPublicKeys = selectPublicKeys(publicKeys);
            if (!selectedPublicKeys.isEmpty()) {
                
                // Insert entries into lookup_table2_permissionsTable
                for (String publicKey : selectedPublicKeys) {
             
					insertPermissionEntry(connection, filename, filehash,publickeyuploader, publicKey , Originalkey, CipherText);
                }
            
        }
    }
    }
      catch(ClassNotFoundException | SQLException e) {
            e.printStackTrace();
        }  
       	
}


private static ArrayList<String> getPublicKeys(Connection connection) throws SQLException {
    ArrayList<String> publicKeys = new ArrayList<>();

    String query = "SELECT public_key FROM lookup_table1_userlist";
    try (PreparedStatement preparedStatement = connection.prepareStatement(query);
         ResultSet resultSet = preparedStatement.executeQuery()) {

        while (resultSet.next()) {
            String publicKey = resultSet.getString("public_key");
            publicKeys.add(publicKey);
        }
    }

    return publicKeys;
}

private static void displayPublicKeys(ArrayList<String> publicKeys) {
    System.out.println("List of public keys:");
    for (String publicKey : publicKeys) {
        System.out.println(publicKey);
    }
    System.out.println();
}

private static ArrayList<String> selectPublicKeys(ArrayList<String> publicKeys) {
    
    ArrayList<String> selectedPublicKeys = new ArrayList<>();

    System.out.println("Select public keys , copy the public key to the prompt (type 'done' when finished):");
    String userInput;
    do {
        userInput = scanner.nextLine();
        if (!userInput.equalsIgnoreCase("done") && publicKeys.contains(userInput)) {
            selectedPublicKeys.add(userInput);
            System.out.println("Public key '" + userInput + "' selected.");
        } else if (!userInput.equalsIgnoreCase("done")) {
            System.out.println("Invalid public key. Please select from the list.");
        }
    } while (!userInput.equalsIgnoreCase("done"));

    // Print the selected public keys
    System.out.println("Selected public keys:");
    for (String selectedKey : selectedPublicKeys) {
        System.out.println(selectedKey);
    }
    return selectedPublicKeys;
}

private static void insertPermissionEntry(Connection connection, String documentName, String documentHash, String publicKeyUploader, String publicKeyViewer, byte[] encryptedKey, byte[][] ciphertxt) throws SQLException, IOException {
    String selectQuery = "SELECT COUNT(*) FROM lookup_table2_permissionsTable " +
            "WHERE document_name = ? AND document_hash = ? AND public_key_uploader = ? AND public_key_viewer = ?";
    // serialized
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (ObjectOutputStream out = new ObjectOutputStream(bos)) {
        out.writeObject(ciphertxt);
    }
    
    byte[] serializedBytes = bos.toByteArray();
   

    try (PreparedStatement countStatement = connection.prepareStatement(selectQuery)) {
        // Set values for the prepared statement
        countStatement.setString(1, documentName);
        countStatement.setString(2, documentHash);
        countStatement.setString(3, publicKeyUploader);
        countStatement.setString(4, publicKeyViewer);

        try (ResultSet resultSet = countStatement.executeQuery()) {
            if (resultSet.next() && resultSet.getInt(1) == 0) {
                // Entry doesn't exist, proceed with the insertion
                String insertQuery = "INSERT INTO lookup_table2_permissionsTable " +
                        "(permission_id, document_name, document_hash, public_key_uploader, public_key_viewer, encrypted_key, cipher_text) " +
                        "VALUES (?, ?, ?, ?, ?, ?, ?)";

                try (PreparedStatement insertStatement = connection.prepareStatement(insertQuery)) {
                    // Set values for the prepared statement
                    insertStatement.setInt(1, generatePermissionId(connection));
                    insertStatement.setString(2, documentName);
                    insertStatement.setString(3, documentHash);
                    insertStatement.setString(4, publicKeyUploader);
                    insertStatement.setString(5, publicKeyViewer);
                    insertStatement.setBytes(6, encryptedKey);
                    insertStatement.setBytes(7, serializedBytes);
                    // Execute the insert statement
                    insertStatement.executeUpdate();
                }
            } else {
                System.out.println("Entry already exists for document: " + documentName +
                        ", uploader key: " + publicKey_entry + ", viewer key: " + publicKeyViewer);
            }
        }
    } catch (SQLException e) {
        e.printStackTrace();
    }
}


private static int generatePermissionId(Connection connection) throws SQLException {
    // Generate a unique permission_id, e.g., by getting the maximum existing ID and incrementing it
    String query = "SELECT MAX(permission_id) FROM lookup_table2_permissionsTable";
    try (PreparedStatement preparedStatement = connection.prepareStatement(query);
         ResultSet resultSet = preparedStatement.executeQuery()) {

        if (resultSet.next()) {
            return resultSet.getInt(1) + 1;
        } else {
            return 1; // If the table is empty
        }
    }catch (SQLException e) {
        e.printStackTrace();
        return -1; // Error case
    }
}
//---------------------------------------------------------------------------------------------------------------------------------------------------------------
// method to check whether user has permission to view the file 
public static boolean checkpermission() {
	boolean flag = false;
	
	 try {
         // Load the JDBC driver
		 Class.forName("com.mysql.cj.jdbc.Driver");
         String jdbcUrl = "jdbc:mysql://localhost:3306/Lookup_tables";
         String username = "root";
         String password = "root";
         try {
         Connection connection = DriverManager.getConnection(jdbcUrl, username, password);

         // Get unique document names
         String query = "SELECT DISTINCT document_name FROM lookup_table2_permissionsTable";
         PreparedStatement statement = connection.prepareStatement(query);
         ResultSet resultSet = statement.executeQuery();

         // Display unique document names
         System.out.println("\nAvailable Documents:");
         while (resultSet.next()) {
             System.out.println(resultSet.getString("document_name"));
         }

         // Ask user to input document name
         Scanner scanner = new Scanner(System.in);
         System.out.println("\nEnter the name of the document you want to select:");
         String selectedDocument = scanner.nextLine();
         viewfilename =selectedDocument;

         // Ask user to input public key file path

         String publicKeyFilePath = "C:\\SFDUDL\\publicKey.txt";

         // Read public key from the specified path
         String publicKey = readPublicKeyFromFile(publicKeyFilePath);

         // Replace \r and \n in the public key
         publicKey = publicKey.replace("\r", "").replace("\n", "");
         
         
         
         // 


         // Check if the document and public key combination exists in the database
         query = "SELECT * FROM lookup_table2_permissionsTable WHERE document_name = ? AND public_key_viewer = ?";
         statement = connection.prepareStatement(query);
         statement.setString(1, selectedDocument);
         statement.setString(2, publicKey);
         resultSet = statement.executeQuery();

         /* Retrieve the public key viewer from the ResultSet
         String publicKeyViewer = resultSet.getString("public_key_viewer");
         System.out.println("line 987 Public Key Viewer: " + publicKeyViewer);*/
         
         
         if (resultSet.next()) {
             // Proceed with further code
             System.out.println("\nAccess granted.");
             flag = true;
             // Retrieve the encrypted key (VARBINARY) from the ResultSet
             original_key = resultSet.getBytes("encrypted_key");
             serialized_ciphertxt = resultSet.getBytes("cipher_text");
             
         } else {
             // Display permission denied message
             System.out.println("You are not permitted to view the file.");
         }

         // Close resources
         resultSet.close();
         statement.close();
         connection.close();
         

     }catch(SQLException e) {
         e.printStackTrace();
     }}catch(ClassNotFoundException e) {
         e.printStackTrace();
     } 
	return flag;
}

private static String readPublicKeyFromFile(String filePath) {
    try {
        // Read all lines from the file
        Path path = Paths.get(filePath);
        byte[] bytes = Files.readAllBytes(path);
        
        // Convert the byte array to a String
        return new String(bytes);

    } catch (IOException e) {
        e.printStackTrace();
        return null; // Handle the error as needed in your application
    }
}


}
//end of ledger class
//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


//C:\Users\91730\OneDrive\Desktop\input data\sensitive_doc.txt