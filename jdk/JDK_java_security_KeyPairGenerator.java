package com.sun.max.vm.jdk;
import javax.crypto.*;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;
import java.nio.charset.StandardCharsets;
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
import com.sun.max.annotate.*;
import com.sun.max.vm.jni.*;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@METHOD_SUBSTITUTIONS(java.security.KeyPairGenerator.class)




final class JDK_java_security_KeyPairGenerator {



	@SUBSTITUTE
	public void initialize(int keysize) {
		System.loadLibrary("hello");
		custom_info c = new custom_info();
		c.id = -1;
		c.type = -1;
		c.keysize = keysize;
		JDK_java_security_KeyPair.addkey(this, c);
	}

	public static PrivateKey readPrivateKey(String key) {

		try {
			String content = new String(key);
			content = content.replaceAll("\\n", "").replace("-----BEGIN RSA PRIVATE KEY-----", "")
				.replace("-----END RSA PRIVATE KEY-----", "");
			//System.out.println("'" + content + "'");
			byte[] bytes = Base64.getDecoder().decode(content);

			DerInputStream derReader = new DerInputStream(bytes);
			DerValue[] seq = derReader.getSequence(0);
			// skip version seq[0];
			BigInteger modulus = seq[1].getBigInteger();
			BigInteger publicExp = seq[2].getBigInteger();
			BigInteger privateExp = seq[3].getBigInteger();
			BigInteger prime1 = seq[4].getBigInteger();
			BigInteger prime2 = seq[5].getBigInteger();
			BigInteger exp1 = seq[6].getBigInteger();
			BigInteger exp2 = seq[7].getBigInteger();
			BigInteger crtCoef = seq[8].getBigInteger();
			RSAPrivateCrtKeySpec keySpec =
				new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
			return privateKey;
		} catch (Exception e) {
			System.out.println("XDD ta pia\n");
		}
		return null;
	}






	@SUBSTITUTE
	public final KeyPair genKeyPair() {	
		int id;
		String privKeyPem, publicKeyContent;
		jni_rsa_helper n = new jni_rsa_helper();
	
		custom_info c = JDK_java_security_KeyPair.myhash.get(this);
		c.algo = 1;
		c.type = -1;




		id = n.SGX_KeyPairGenerator_generateKey(c.keysize);

		c.id = id;
		publicKeyContent = n.SGX_KeyPairGenerator_get_pubkey(id);
		privKeyPem = n.SGX_KeyPairGenerator_get_privkey(id);
		KeyPairGenerator p = null;
		try {
			p = KeyPairGenerator.getInstance("RSA");
			p.initialize(c.keysize);
			publicKeyContent = publicKeyContent.replace("-----END RSA PUBLIC KEY-----", "");
			publicKeyContent = publicKeyContent.replace("-----BEGIN RSA PUBLIC KEY-----", "");
			publicKeyContent = publicKeyContent.replace("\n", "");

			PrivateKey privatekey = readPrivateKey(privKeyPem);
			RSAPrivateCrtKey privk = (RSAPrivateCrtKey)privatekey;

			RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec
				(privk.getModulus(), privk.getPublicExponent());

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey myPublicKey = keyFactory.generatePublic(publicKeySpec);
			JDK_java_security_KeyPair.addkey(this, c);
			JDK_java_security_KeyPair.addkey(privatekey, c);
			JDK_java_security_KeyPair.addkey(myPublicKey, c);
			KeyPair p1 = new KeyPair(myPublicKey, privatekey);
			return p1;
		} catch (Exception e) {
			System.out.println(e);
		}
		return null;
	}
}
