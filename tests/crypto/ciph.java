import javax.crypto.*;
import java.util.Base64;
import java.security.*;
import java.io.*;

public class ciph { 
  
    public static void main (String args[]) throws Exception  
    { 
        Cipher ciph = Cipher.getInstance("AES");
       	
       	KeyGenerator kgen = KeyGenerator.getInstance("AES");
       	kgen.init(128);

       	SecretKey aesKey = kgen.generateKey();
        ciph.init(256,aesKey); // for example

        ciph.update(new byte[5]);

        ciph.doFinal();
    } 
} 
