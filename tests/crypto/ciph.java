import javax.crypto.*;
import java.util.Base64;
import java.security.*;
import java.io.*;

public class ciph { 

	public static void main (String args[]) throws Exception  
	{ 
		Cipher ciph = Cipher.getInstance("AES");
		Cipher ciph2 = Cipher.getInstance("AES");

		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128);
		SecretKey aesKey = kgen.generateKey();
		ciph.init(Cipher.ENCRYPT_MODE, aesKey); // for example
		ciph2.init(Cipher.DECRYPT_MODE, aesKey); // for example
		String b = "xsde1";
		byte[] enc = ciph.doFinal(b.getBytes());
		byte[] plain = ciph2.doFinal(enc);
		System.out.println("| " + new String(plain) + "|");
	} 
} 
