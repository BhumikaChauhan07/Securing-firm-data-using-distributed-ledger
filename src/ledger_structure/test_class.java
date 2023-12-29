package ledger_structure;



import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import ledger_structure.Ledger.Block;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class test_class {

    private static List<Block> blockchain = new ArrayList<>();

    public static void main(String[] args) {
        // Create an instance of LedgerTest to test the readBlockchainFromJson method
        test_class ledgerTest = new test_class();

        // Call the readBlockchainFromJson method
        ledgerTest.readBlockchainFromJson();

        // Print the content of the blockchain for testing purposes
        ledgerTest.printBlockchain();
    }

    public void readBlockchainFromJson() {
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

    public void printBlockchain() {
        // Print the content of the blockchain
        for (Block block : blockchain) {
            System.out.println(blockToJson(block));
        }
    }

    public static long parseTimestamp(String formattedTimestamp) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");
        ZonedDateTime zonedDateTime = ZonedDateTime.parse(formattedTimestamp, formatter);
        return zonedDateTime.toInstant().toEpochMilli();
    }

    public static String blockToJson(Block block) {
        return "{\n" +
                "  \"index\": " + block.getIndex() + ",\n" +
                "  \"previous_hash\": \"" + block.getPreviousHash() + "\",\n" +
                "  \"timestamp\": " +"\"" +block.getTimestamp() +"\""+ ",\n" +
                "  \"operation\": \"" + block.getData()+ "\",\n" +
                "  \"hash\": \"" + block.getHash() + "\"\n" +
                "}";
    }

    static class Block {
        private int index;
        private String previousHash;
        private long timestamp;
        private String data;
        private String hash;

        public Block(int index, String previousHash, long timestamp, String data) {
            this.index = index;
            this.previousHash = previousHash;
            this.timestamp = timestamp;
            this.data = data;
            this.hash = calculateHash();
        }

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
        
        
        private String calculateGenesisHash() {
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
        }

        
        
        public void setHash(String hash) {
            this.hash = hash;
        }
        
        public boolean isValidBlock() {
            if (index == 0) {
                // Genesis block has a fixed hash
                return hash.equals(calculateGenesisHash());
            }

            String calculatedHash = calculateHash();
            return calculatedHash.equals(hash) && isTimestampValid();
        }

        public int getIndex() {
            return index;
        }

        public String getPreviousHash() {
            return previousHash;
        }

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


        private String getPreviousBlockTimestamp() {
            // Get the previous block from the blockchain
            Block previousBlock = blockchain.get(blockchain.size() - 2); // Note: This assumes there's at least one block in the blockchain

            // Return the formatted timestamp of the previous block
            return previousBlock.getTimestamp();
        }
        
        
        public String getData() {
            return data;
        }

        public String getHash() {
            return hash;
        }
    }
}