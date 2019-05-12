import javax.crypto.*;
import java.util.Base64;
import java.security.*;
import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;

public class ciph { 

	private static void printArray(byte[] byteArr) {
		System.out.println("About to print bytearray");
		for (byte b : byteArr) {
			System.out.print(b);
		}
		System.out.println();
	}


	public static void main (String args[]) throws Exception  
	{ 
		
		int num_bytes;
		SecureRandom rand = new SecureRandom();
		

		num_bytes = Integer.parseInt(args[0]);

		Cipher ciph = Cipher.getInstance("AES");

		Cipher ciph2 = Cipher.getInstance("AES");


		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128);
		SecretKey aesKey = kgen.generateKey();


		byte [] b = new byte[num_bytes];
		// rand.nextBytes(b);
		Arrays.fill(b, (byte)1);

		// System.out.println("test: plaintext len: " + num_bytes);
		// System.out.println("test: plaintext: | " + Arrays.toString(b) + "|");

		long enc_start = System.nanoTime();

		ciph.init(Cipher.ENCRYPT_MODE, aesKey); // for example
		byte[] enc = ciph.doFinal(b);

		long enc_time = System.nanoTime() - enc_start;

		// System.out.println("test: encrypted: | " + Arrays.toString(enc) + "|");
		
		long dec_start = System.nanoTime();

		ciph2.init(Cipher.DECRYPT_MODE, aesKey); // for example
		byte[] plain = ciph2.doFinal(enc);


		long dec_time = System.nanoTime() - dec_start;


		// System.out.println("test: decrypted : | " + Arrays.toString(plain) + "|");
		// System.out.println("Plaintext  size : " + num_bytes + " (B)");
		// System.out.println("KeyGen     time : " + keygen_time + " (ns)");
		// System.out.println("Encryption time : " + enc_time + " (ns)");
		// System.out.println("Decryption time : " + dec_time + " (ns)");

		File file = new File("AES_"+num_bytes+".txt");
		FileWriter fr = new FileWriter(file, true);
		BufferedWriter br = new BufferedWriter(fr);
		br.write(num_bytes+","+enc_time+","+dec_time+"\n");
		br.close();
		fr.close();
		System.out.println(num_bytes+","+enc_time+","+dec_time);

		if(!Arrays.equals(b,plain)){
			System.out.println("something went wrong to test");
		}
		
		
	}
} 


// encrypt pollaplasia tou 16 1M tou input text tou string
// aplo encrypt 
// random bytes to string kathe fora 
// 10 fores
// 
