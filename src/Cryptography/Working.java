




package Cryptography;



import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;

import AES_Decryption.Cipher_text_plain;
import AES_Encryption.*;


public class Working {
	private static String finalString = new String();
	private static byte[][] Cipher_Text ;
	//public static void main(String[] args) throws Exception 
	public static String Encrypted_data(String inputString)
	{
		
		try {
		Cipher_Text = Encryption(inputString);
		
		/*System.out.println("Input String: "+inputString);
		System.out.println();*/
		StringBuilder result = new StringBuilder();
	
        for (int i = 0; i < 4; i++) {
			for (int j = 0; j < 4; j++) {
				char character = (char) Cipher_Text[j][i];
				result.append(character);
			}
			System.out.println();
		}
        finalString = result.toString();
		//System.out.println("Cipher Text: "+finalString);
		//System.out.println();
		//System.out.println("Decrypted Text: "+Decryption(Cipher_Text));
        //return finalString;
		} catch (Exception e) {System.out.print("Entered Text Should be of 16 byte");}
		
		//System.out.println("line 42 working: "+finalString);
		return finalString;
	}
	
	public static String Decryption(byte[] retrievedOriginalKey, StringBuilder content, byte[] serialized_cipher ) throws ClassNotFoundException, IOException {
		/*StringBuilder stringBuilder = content;
		// read the encrypted content from file and convert it to the byte array
		String contentstr = stringBuilder.toString();
        byte[] byteArray = contentstr.getBytes();*/
		
        //Creating a Text Byte Grid of 4x4.
        byte matrix[][] = new byte[4][4];
        //int totalElements = content.length();

        // Create a byte array to store the result
        byte[] byteArray = content.toString().getBytes();;
      
       int k = 0;
        for (int i=0; i<4; i++) {
        	for (int j=0; j<4; j++) {
        		matrix[j][i] = byteArray[k];
        		k++;
        	}
        }
        
        byte[][] deserialized_cipher;
        ByteArrayInputStream bis = new ByteArrayInputStream(serialized_cipher);
        ObjectInputStream in = new ObjectInputStream(bis);
        	deserialized_cipher =(byte[][]) in.readObject();
        
        
		
		String Plain_Text = (String) Cipher_text_plain.Dcrypt(deserialized_cipher,retrievedOriginalKey);
		return Plain_Text;		
	}

	public static byte[][] Encryption(String inputString) throws Exception {
		byte[][] Cipher_Text = Plain_text_cipher.GenerateCipher(inputString);
		return Cipher_Text;
	}
}