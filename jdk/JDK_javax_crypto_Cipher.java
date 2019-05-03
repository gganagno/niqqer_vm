
package com.sun.max.vm.jdk;

import javax.crypto.*;

import java.security.*;

import com.sun.max.annotate.*;

import com.sun.max.vm.jni.*;

@METHOD_SUBSTITUTIONS(javax.crypto.Cipher.class)
final class JDK_javax_crypto_Cipher {


	@SUBSTITUTE
	public void init(int opmode, Key key) {
		System.loadLibrary("hello");

		jni_cipher_helper n = new jni_cipher_helper();
		custom_info p = JDK_java_security_KeyPair.myhash.get(key);
		p.type = opmode;
		if (key.getAlgorithm().equals("AES"))
			p.algo = 0;
		else 
			p.algo = 1;	
		JDK_java_security_KeyPair.myhash.put((Object)this, p);

	}
	/* Used for RSA*/
	@SUBSTITUTE
	public byte[] doFinal(byte[] b) {                                            
		int id = 0; 
		custom_info c = new custom_info();
		System.loadLibrary("hello");              

		c = JDK_java_security_KeyPair.myhash.get((Object)this);
		id = c.id;

		jni_cipher_helper n = new jni_cipher_helper();                           
		byte[] n1 = n.SGX_Cipher_dofinal_xd(id, b, c.type, c.algo);	
		System.out.println("@@" +  n1.toString());
		return n1;
	}                                                                           

}


class jni_cipher_helper {

	public native int SGX_Cipher_init();

	public native char SGX_Cipher_update();

	public native char SGX_Cipher_dofinal();
	public native byte[] SGX_Cipher_dofinal_xd(int id, byte[] b, int type, int algo);

}
