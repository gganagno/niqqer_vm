import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.*;                                   
import java.security.interfaces.RSAPrivateCrtKey;        
import java.security.interfaces.RSAPrivateKey;           
import java.math.BigInteger;                             
import java.security.spec.PKCS8EncodedKeySpec;           
import java.security.spec.RSAPrivateCrtKeySpec;          
import java.security.GeneralSecurityException;           
import java.security.Key;                                
import java.security.KeyFactory;                         
import java.security.KeyPair;                            
import java.security.KeyPairGenerator;                   
import java.security.PrivateKey;                         
import java.security.PublicKey;                          
import java.security.SecureRandom;                       
import java.security.spec.RSAPrivateKeySpec;             
import java.security.spec.RSAPublicKeySpec;              

import javax.crypto.spec.SecretKeySpec;                  
import java.security.*;                                  
import javax.crypto.KeyGenerator;                        
import java.security.Provider;                           
import java.security.Security;                           
import java.security.KeyFactory;                         
import java.security.KeyPair;                            
import java.security.KeyPairGenerator;                   
import java.security.PrivateKey;                         
import java.security.PublicKey;                          
import java.security.spec.EncodedKeySpec;                
import java.security.spec.PKCS8EncodedKeySpec;           
import java.security.spec.X509EncodedKeySpec;            
import java.security.*;                                  
import java.util.*;                                      
import java.util.Enumeration;                            
import java.io.IOException;                              
import java.net.URISyntaxException;                      
import java.nio.file.Files;                              
import java.nio.file.Paths;                              
import java.security.KeyFactory;                         
import java.security.NoSuchAlgorithmException;           
import java.security.PrivateKey;                         
import java.security.interfaces.RSAPublicKey;            
import java.security.spec.InvalidKeySpecException;       



public class rsa {

	public static void main(String [] args) throws Exception {
		// generate public and private keys
		KeyPair keyPair = buildKeyPair();
		PublicKey pubKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();


		// sign the message
		byte [] signed = encrypt(privateKey, "This is a secret message");     
		//System.out.println(new String(signed));  // <<signed message>>

		// verify the message
		byte[] verified = decrypt(pubKey, signed);                                 
		System.out.println(new String(verified));     // This is a secret message
	}

	public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
		final int keySize = 2048;
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(keySize);      
		return keyPairGenerator.genKeyPair();
	}

	public static byte[] encrypt(PrivateKey privateKey, String message) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");  
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);  

		return cipher.doFinal(message.getBytes());  
	}

	public static byte[] decrypt(PublicKey publicKey, byte [] encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");  
		cipher.init(Cipher.DECRYPT_MODE, publicKey);

		return cipher.doFinal(encrypted);
	}
}
