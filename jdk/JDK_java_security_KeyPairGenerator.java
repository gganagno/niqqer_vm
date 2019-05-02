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

	static String algo;
	static int key_size;
	static int id;


	@SUBSTITUTE
	public void initialize(int keysize) {
		System.loadLibrary("hello");
		key_size = keysize;
	}






	//
	//
	//
	//
	//
	//
	//	static final int SEQUENCE_TAG = 0x30;
	//	private static final int BIT_STRING_TAG = 0x03;
	//	private static final byte[] NO_UNUSED_BITS = new byte[] { 0x00 };
	//	private static final byte[] RSA_ALGORITHM_IDENTIFIER_SEQUENCE =
	//	{(byte) 0x30, (byte) 0x0d,
	//		(byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x01, (byte) 0x01,
	//		(byte) 0x05, (byte) 0x00};
	//
	//
	//	public static RSAPublicKey decodePKCS1PublicKey(byte[] pkcs1PublicKeyEncoding)
	//			throws NoSuchAlgorithmException, InvalidKeySpecException
	//		{
	//			byte[] subjectPublicKeyInfo2 = createSubjectPublicKeyInfoEncoding(pkcs1PublicKeyEncoding);
	//			KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
	//			RSAPublicKey generatePublic = (RSAPublicKey) rsaKeyFactory.generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo2));
	//			return generatePublic;
	//		}
	//
	//	public static byte[] createSubjectPublicKeyInfoEncoding(byte[] pkcs1PublicKeyEncoding)
	//	{
	//		byte[] subjectPublicKeyBitString = createDEREncoding(BIT_STRING_TAG, concat(NO_UNUSED_BITS, pkcs1PublicKeyEncoding));
	//		byte[] subjectPublicKeyInfoValue = concat(RSA_ALGORITHM_IDENTIFIER_SEQUENCE, subjectPublicKeyBitString);
	//		byte[] subjectPublicKeyInfoSequence = createDEREncoding(SEQUENCE_TAG, subjectPublicKeyInfoValue);
	//
	//		return subjectPublicKeyInfoSequence;
	//	}
	//
	//	private static byte[] concat(byte[] ... bas)
	//	{
	//		int len = 0;
	//		for (int i = 0; i < bas.length; i++)
	//		{
	//			len += bas[i].length;
	//		}
	//
	//		byte[] buf = new byte[len];
	//		int off = 0;
	//		for (int i = 0; i < bas.length; i++)
	//		{
	//			System.arraycopy(bas[i], 0, buf, off, bas[i].length);
	//			off += bas[i].length;
	//		}
	//
	//		return buf;
	//	}
	//
	//	private static byte[] createDEREncoding(int tag, byte[] value)
	//	{
	//		if (tag < 0 || tag >= 0xFF)
	//		{
	//			throw new IllegalArgumentException("Currently only single byte tags supported");
	//		}
	//
	//		byte[] lengthEncoding = createDERLengthEncoding(value.length);
	//
	//		int size = 1 + lengthEncoding.length + value.length;
	//		byte[] derEncodingBuf = new byte[size];
	//
	//		int off = 0;
	//		derEncodingBuf[off++] = (byte) tag;
	//		System.arraycopy(lengthEncoding, 0, derEncodingBuf, off, lengthEncoding.length);
	//		off += lengthEncoding.length;
	//		System.arraycopy(value, 0, derEncodingBuf, off, value.length);
	//
	//		return derEncodingBuf;
	//	}   
	//
	//	private static byte[] createDERLengthEncoding(int size)
	//	{
	//		if (size <= 0x7F)
	//		{
	//			// single byte length encoding
	//			return new byte[] { (byte) size };
	//		}
	//		else if (size <= 0xFF)
	//		{
	//			// double byte length encoding
	//			return new byte[] { (byte) 0x81, (byte) size };
	//		}
	//		else if (size <= 0xFFFF)
	//		{
	//			// triple byte length encoding
	//			return new byte[] { (byte) 0x82, (byte) (size >> Byte.SIZE), (byte) size };
	//		}
	//
	//		throw new IllegalArgumentException("size too large, only up to 64KiB length encoding supported: " + size);
	//	}
	//
	//
	//




	public static PrivateKey readPrivateKey(String key) {

		try {
			String content = new String(key);
			content = content.replaceAll("\\n", "").replace("-----BEGIN RSA PRIVATE KEY-----", "")
				.replace("-----END RSA PRIVATE KEY-----", "");
			System.out.println("'" + content + "'");
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
			//System.out.println("|" + privateKey.toString() + "|");


			return privateKey;
		} catch (Exception e) {
			System.out.println("XDD ta pia\n");
		}
		return null;
	}








	@SUBSTITUTE
	public final KeyPair genKeyPair() {	

		String privKeyPem, publicKeyContent;
		jni_rsa_helper n = new jni_rsa_helper();
		id = n.SGX_KeyPairGenerator_generateKey(key_size);
		publicKeyContent = n.SGX_KeyPairGenerator_get_pubkey(id);
		privKeyPem = n.SGX_KeyPairGenerator_get_privkey(id);
		//System.out.println("NIQQER_VM generateKey id" + id);
		KeyPairGenerator p = null;
		try {
			p = KeyPairGenerator.getInstance("RSA");
			p.initialize(key_size);
			publicKeyContent = publicKeyContent.replace("-----END RSA PUBLIC KEY-----", "");
			publicKeyContent = publicKeyContent.replace("-----BEGIN RSA PUBLIC KEY-----", "");
			publicKeyContent = publicKeyContent.replace("\n", "");
			//System.out.println(publicKeyContent);

			PrivateKey privatekey = readPrivateKey(privKeyPem);
			RSAPrivateCrtKey privk = (RSAPrivateCrtKey)privatekey;

			RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec
				(privk.getModulus(), privk.getPublicExponent());

			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey myPublicKey = keyFactory.generatePublic(publicKeySpec);
			JDK_java_security_KeyPair.addkey(myPublicKey, id);
			KeyPair p1 = new KeyPair(myPublicKey, privatekey);
			return p1;
		} catch (Exception e) {
			System.out.println(e);
		}
		return null;
	}
}
