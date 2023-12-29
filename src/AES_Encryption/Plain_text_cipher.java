
package AES_Encryption;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import Key_Expansion_Algorithm.*;
public class  Plain_text_cipher{
	
	 private final static byte[][] sBoxTable = {
	     	    {(byte)0x63, (byte)0x7C, (byte)0x77, (byte)0x7B, (byte)0xF2, (byte)0x6B, (byte)0x6F, (byte)0xC5, (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2B, (byte)0xFE, (byte)0xD7, (byte)0xAB, (byte)0x76},
	     	    {(byte)0xCA, (byte)0x82, (byte)0xC9, (byte)0x7D, (byte)0xFA, (byte)0x59, (byte)0x47, (byte)0xF0, (byte)0xAD, (byte)0xD4, (byte)0xA2, (byte)0xAF, (byte)0x9C, (byte)0xA4, (byte)0x72, (byte)0xC0},
	     	    {(byte)0xB7, (byte)0xFD, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3F, (byte)0xF7, (byte)0xCC, (byte)0x34, (byte)0xA5, (byte)0xE5, (byte)0xF1, (byte)0x71, (byte)0xD8, (byte)0x31, (byte)0x15},
	     	    {(byte)0x04, (byte)0xC7, (byte)0x23, (byte)0xC3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9A, (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xE2, (byte)0xEB, (byte)0x27, (byte)0xB2, (byte)0x75},
	     	    {(byte)0x09, (byte)0x83, (byte)0x2C, (byte)0x1A, (byte)0x1B, (byte)0x6E, (byte)0x5A, (byte)0xA0, (byte)0x52, (byte)0x3B, (byte)0xD6, (byte)0xB3, (byte)0x29, (byte)0xE3, (byte)0x2F, (byte)0x84},
	     	    {(byte)0x53, (byte)0xD1, (byte)0x00, (byte)0xED, (byte)0x20, (byte)0xFC, (byte)0xB1, (byte)0x5B, (byte)0x6A, (byte)0xCB, (byte)0xBE, (byte)0x39, (byte)0x4A, (byte)0x4C, (byte)0x58, (byte)0xCF},
	     	    {(byte)0xD0, (byte)0xEF, (byte)0xAA, (byte)0xFB, (byte)0x43, (byte)0x4D, (byte)0x33, (byte)0x85, (byte)0x45, (byte)0xF9, (byte)0x02, (byte)0x7F, (byte)0x50, (byte)0x3C, (byte)0x9F, (byte)0xA8},
	     	    {(byte)0x51, (byte)0xA3, (byte)0x40, (byte)0x8F, (byte)0x92, (byte)0x9D, (byte)0x38, (byte)0xF5, (byte)0xBC, (byte)0xB6, (byte)0xDA, (byte)0x21, (byte)0x10, (byte)0xFF, (byte)0xF3, (byte)0xD2},
	     	    {(byte)0xCD, (byte)0x0C, (byte)0x13, (byte)0xEC, (byte)0x5F, (byte)0x97, (byte)0x44, (byte)0x17, (byte)0xC4, (byte)0xA7, (byte)0x7E, (byte)0x3D, (byte)0x64, (byte)0x5D, (byte)0x19, (byte)0x73},
	     	    {(byte)0x60, (byte)0x81, (byte)0x4F, (byte)0xDC, (byte)0x22, (byte)0x2A, (byte)0x90, (byte)0x88, (byte)0x46, (byte)0xEE, (byte)0xB8, (byte)0x14, (byte)0xDE, (byte)0x5E, (byte)0x0B, (byte)0xDB},
	     	    {(byte)0xE0, (byte)0x32, (byte)0x3A, (byte)0x0A, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5C, (byte)0xC2, (byte)0xD3, (byte)0xAC, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xE4, (byte)0x79},
	     	    {(byte)0xE7, (byte)0xC8, (byte)0x37, (byte)0x6D, (byte)0x8D, (byte)0xD5, (byte)0x4E, (byte)0xA9, (byte)0x6C, (byte)0x56, (byte)0xF4, (byte)0xEA, (byte)0x65, (byte)0x7A, (byte)0xAE, (byte)0x08},
	     	    {(byte)0xBA, (byte)0x78, (byte)0x25, (byte)0x2E, (byte)0x1C, (byte)0xA6, (byte)0xB4, (byte)0xC6, (byte)0xE8, (byte)0xDD, (byte)0x74, (byte)0x1F, (byte)0x4B, (byte)0xBD, (byte)0x8B, (byte)0x8A},
	     	    {(byte)0x70, (byte)0x3E, (byte)0xB5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xF6, (byte)0x0E, (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xB9, (byte)0x86, (byte)0xC1, (byte)0x1D, (byte)0x9E},
	     	    {(byte)0xE1, (byte)0xF8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xD9, (byte)0x8E, (byte)0x94, (byte)0x9B, (byte)0x1E, (byte)0x87, (byte)0xE9, (byte)0xCE, (byte)0x55, (byte)0x28, (byte)0xDF},
	     	    {(byte)0x8C, (byte)0xA1, (byte)0x89, (byte)0x0D, (byte)0xBF, (byte)0xE6, (byte)0x42, (byte)0x68, (byte)0x41, (byte)0x99, (byte)0x2D, (byte)0x0F, (byte)0xB0, (byte)0x54, (byte)0xBB, (byte)0x16}
	     	    };
	 private final static int[][] MixColumnTable = {
			 {2, 3, 1, 1},
			 {1, 2, 3, 1},
			 {1, 1, 2, 3},
			 {3, 1, 1, 2}
	 };
	 
	 
	public static int[][] Saved_Word = new int[11][4];
	public static byte[][] Cipher_Text;
	static byte[] originalKey;
	static String fileHash;
	
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
	
	public static void writeArrayToFile(int[][] array) {
		String filePath = "C:\\Users\\91730\\OneDrive\\Desktop\\Saved_Words_Folder\\array_data.txt";

	    try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
	        for (int[] row : array) {
	            for (int value : row) {
	                writer.write(value + " ");
	            }
	            writer.newLine();
	        }
	    } catch (IOException e) {e.printStackTrace();} // Handle the exception properly in your code
	}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   

    public static byte[][] GenerateCipher(String file_address) throws Exception {
    	
    	String filePath = file_address; // Replace with the actual file path
        StringBuilder content = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(new FileReader(new File(filePath))))
        {
        	int charsRead = 0;
            int targetChars = 16; // Number of characters to read

            int data;
            while (charsRead < targetChars && (data = reader.read()) != -1) {
                content.append((char) data);
                charsRead++;
            }
        }catch(IOException e) {
            e.printStackTrace(); // Handle any potential exceptions
        }

        String inputString = content.toString();
        
       // calculate hash
        try {
            fileHash = calculateSHA256(inputString);

        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA-256 algorithm not available.");
            e.printStackTrace();
        }
        
        
        
    	
    	int index=0;
        byte[] bytes = inputString.getBytes(); //Convert each Character into byte.
        originalKey = KeyExpansion.GenerateKey(); // Generating a Randomly secured 128 Bits Key!!
        
        // printing the  original key in string format 
        //System.out.println("\nline 101: plaintext code:  "+Base64.getEncoder().encodeToString(originalKey));

        // Store the encrypted key (replace this with your storage logic)
        storeEncryptedKey(originalKey);
        
        
        
        
        int words[] = KeyExpansion.key_word_initial(originalKey); //Calling the Key Expansion algorithm for generation of the initial Word Set
        SavedWord(index, words); //Storing Initial Word
        index++;
        
        //Round 0- Plain Text XOR with Initial Key. Initial Transformation
        for (int i = 0; i < bytes.length; i++) {
        	bytes[i] = (byte) (bytes[i] ^ originalKey[i]);
        	// System.out.println(bytes[i]);      	
		}
        
        //Creating a Plain Text Byte Grid of 4x4.
        byte matrix[][] = new byte[4][4];
        int k = 0;
        for (int i=0; i<4; i++) {
        	for (int j=0; j<4; j++) {
        		matrix[j][i] = bytes[k];
        		k++;
        	}
        }
        
        // Round 1 - 10 transformation of the Encryption Algorithm.
        int counter = 0;
        while (counter < 10) {
        	words = KeyExpansion.round_words(words, counter);
        	// matrix = MixColumns(ShiftRows(SubstitutionBytes(matrix)));
        	if(counter < 9) {
        		matrix = AddRoundKey(MixColumns(ShiftRows(SubstitutionBytes(matrix))), words);
        	}
        	else {
        		matrix = AddRoundKey(ShiftRows(SubstitutionBytes(matrix)), words);
        	}
        	SavedWord(index, words); // Storing the round Words.
        	index++;
        	counter++;
        }
        
        //Saving the Cipher text in a variable.
        Cipher_Text = matrix;
        
        
        /*System.out.println(" the cipher text from plaintext class line 161:");
        for (int i = 0; i < matrix.length; i++) {
            // Iterate through columns
            for (int j = 0; j < matrix[i].length; j++) {
                // Print each element
                System.out.print(matrix[i][j] + " ");
            }}*/
        
        writeArrayToFile(Saved_Word);
		return Cipher_Text; 
    }
 //-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
    
    private static int[][] SavedWord(int index, int[] words){
    	for(int i=0; i<4; i++) {
       	 Saved_Word[index][i] = words[i];
       }
    return Saved_Word;
    	
    }
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
    
    private static byte[][] SubstitutionBytes( byte[][] bytes) {
    	for (int i = 0; i<4; i++) {
    		for (int j=0; j<4; j++) {
    			int rowIndex = (bytes[i][j] >> 4) & 0x0F; // The first 4 bits determine the row 
    		    int colIndex = bytes[i][j] & 0x0F; // The last 4 bits determine the column
    		    bytes[i][j] = sBoxTable[rowIndex][colIndex];
    		}
    	}
		return bytes;
    }
    // End of the Method
    
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
    private static byte[][] ShiftRows(byte[][] bytes) {
    	int a = 0; 
		int [] temp = new int[4];
		for(int i=1; i<4; i++) {
			while(a<i) {
				temp[a] = bytes[i][a];
				a++;
			}
			for(int j=0; j<4; j++) {
				if(j+i<4) {
					bytes[i][j] = bytes[i][j+i];
				}
				else {
					bytes[i][j] = (byte) temp[(i+j)%4];
				}
			}
			a = 0;
		}
		return bytes;
	}
    //End of Method 
    
 //-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
    private static byte[][] MixColumns(byte[][] bytes) {
        for (int col = 0; col < 4; col++) {
            byte[] originalColumn = new byte[4];
            for (int row = 0; row < 4; row++) {
                originalColumn[row] = bytes[row][col];
            }
            byte[] newColumn = mixColumn(originalColumn);
            for (int row = 0; row < 4; row++) {
                bytes[row][col] = newColumn[row];
            }
        }
        return bytes;
    }

    private static byte[] mixColumn(byte[] column) {
        byte[] result = new byte[4];
        for (int row = 0; row < 4; row++) {
            int value = 0;
            for (int i = 0; i < 4; i++) {
                int factor = MixColumnTable[row][i];
                int byteValue = column[i] & 0xFF; // Convert to an unsigned byte
                int product = galoisMultiply(factor, byteValue);
                value ^= product;
            }
            result[row] = (byte)value;
        }
        return result;
    }

    private static int galoisMultiply(int a, int b) {
        int result = 0;
        while (b != 0) {
            if ((b & 1) != 0) {
                result ^= a;
            }
            boolean carry = (a & 0x80) != 0;
            a <<= 1;
            if (carry) {
                a ^= 0x1B; // This is the irreducible polynomial x^8 + x^4 + x^3 + x + 1
            }
            b >>= 1;
        }
        return result;
    }
//-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    // End of Method
    
    // AddRoundKey 
    private static byte[][] AddRoundKey(byte[][] bytes, int[] words){ // words -> original
    	// byte[][] Round_Word_Byte = new byte[4][4];
    	for (int i = 0; i<4; i++) {
			for(int j=0; j<4; j++) {
				int byteValue = (words[i] >> (8 * (3 - j)) & 0xFF); // WE created a byte matrix of each Word!
				// Round_Word_Byte[j][i] = (byte) byteValue;
				bytes[j][i] = (byte) (bytes[j][i] ^ (byte)byteValue);
			}
		}
    	return bytes;
    }
    //End of Method
//---------------------------------------------------------------------------------------------------------------------------------------------
// only added line 99to 100 as extra and now functions regarding this

    private static void storeEncryptedKey(byte[] OriginalKey) {
        // Replace this with your storage logic (e.g., storing in a database)
    	String encryptedKeyStrigFormat = Base64.getEncoder().encodeToString(OriginalKey);
        //System.out.println("\n Encrypted AES Key:line 300: plaintext code:  " + Base64.getEncoder().encodeToString(OriginalKey));
     
        		try (BufferedWriter writer = new BufferedWriter(new FileWriter("C:\\Users\\91730\\OneDrive\\Desktop\\encrypted key\\encryptedKey.txt"))) {
                    // Write the encrypted key to the file
                    writer.write(encryptedKeyStrigFormat);
                } catch (Exception e) {
                    e.printStackTrace();
    }

    }
    
    public static byte[] returnOriginalKey (){ 
    	return originalKey;
    }
    
    public static byte[][] returnCipherText (){ 
    	return Cipher_Text;
    }
    
    
    private static String calculateSHA256(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(input.getBytes());

        // Convert byte array to hexadecimal string
        StringBuilder hexStringBuilder = new StringBuilder();
        for (byte hashByte : hashBytes) {
            String hex = Integer.toHexString(0xff & hashByte);
            if (hex.length() == 1) {
                hexStringBuilder.append('0');
            }
            hexStringBuilder.append(hex);
        }

        return hexStringBuilder.toString();
    }
    
    public static String FileHash(){ 
    	return fileHash;
    }

}