import javax.crypto.*;
import java.util.Base64;
import java.security.*;
import java.io.*;
import java.security.SecureRandom;

public class ciph { 

	private static void printArray(byte[] byteArr) {
		for (byte b : byteArr) {
			System.out.print(b + ",");
		}
		System.out.println();
	}

	public static void main (String args[]) throws Exception  
	{ 
		Cipher ciph = Cipher.getInstance("AES");

		Cipher ciph2 = Cipher.getInstance("AES");

		KeyGenerator kgen = KeyGenerator.getInstance("AES");

		kgen.init(128);


		SecretKey aesKey = kgen.generateKey();

		// int num_bytes;
		// SecureRandom rand = new SecureRandom();

		// for (num_bytes = 16; num_bytes < 1025 ; num_bytes*=2){
		// 	byte [] b = new byte[num_bytes];
		// 	rand.nextBytes(b);
		// 	printArray(b);	
		// }

		ciph.init(Cipher.ENCRYPT_MODE, aesKey); // for example
		int numbytes;

		String b = "xddssdadadssdaddsadssdasdaldsaldsldasldlsadsalsdalsdaldslasdlasdldlads";
		byte[] enc = ciph.doFinal(b.getBytes());
		System.out.println("toy: encrypted : | " + new String(enc) + "|");


		ciph2.init(Cipher.DECRYPT_MODE, aesKey); // for example

		byte[] plain = ciph2.doFinal(enc);
		System.out.println("toy: decrypted : | " + new String(plain) + "|");
	} 
} 


// encrypt pollaplasia tou 16 1M tou input text tou string
// aplo encrypt 
// random bytes to string kathe fora 
// 10 fores
// 
