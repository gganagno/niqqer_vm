import javax.crypto.*;
import java.util.Base64;
public class key { 
  
    public static void main (String args[]) throws Exception  { 
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();


        String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println(encodedKey);


    } 
} 
