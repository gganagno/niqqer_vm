
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import java.security.SecureRandom;
import java.util.Arrays;
import java.io.*;


// Java 8 example for RSA encryption/decryption.
// Uses strong encryption with 2048 key size.
public class RSAEncryptionJava8 {

    public static void main(String[] args) throws Exception {
        
        int num_bytes;
        num_bytes = Integer.parseInt(args[0]);
        byte [] b = new byte[num_bytes];
        Arrays.fill(b, (byte)1);

        String plainText = new String(b);

        int keysize = Integer.parseInt(args[1]);
        // Generate public and private keys using RSA
        Map<String, Object> keys = getRSAKeys(keysize);
        PrivateKey privateKey = (PrivateKey) keys.get("private");
        PublicKey publicKey = (PublicKey) keys.get("public");

        long enc_start = System.nanoTime();

        String encryptedText = encryptMessage(plainText, privateKey);

        long enc_time = System.nanoTime() - enc_start;

        

        long dec_start = System.nanoTime();

        String descryptedText = decryptMessage(encryptedText, publicKey);

        if(!plainText.equals(descryptedText))System.out.println("prob");
        long dec_time = System.nanoTime() - dec_start;

        // System.out.println("input: " + plainText);
        // System.out.println("encrypted:" + encryptedText);
        // System.out.println("decrypted:" + descryptedText);

        File file = new File("RSA_"+num_bytes+"_"+keysize+".txt");
        FileWriter fr = new FileWriter(file, true);
        BufferedWriter br = new BufferedWriter(fr);
        br.write(num_bytes+","+keysize+","+enc_time+","+dec_time+"\n");
        br.close();
        fr.close();
        System.out.println(num_bytes+","+keysize+","+enc_time+","+dec_time);
        

    }

    // Get RSA keys. Uses key size of 2048.
    private static Map<String,Object> getRSAKeys(int keysize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keysize);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Map<String, Object> keys = new HashMap<String,Object>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }

    // Decrypt using RSA public key
    private static String decryptMessage(String encryptedText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }

    // Encrypt using RSA private key
    private static String encryptMessage(String plainText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

}
