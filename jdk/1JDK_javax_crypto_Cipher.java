
package com.sun.max.vm.jdk;

import javax.crypto.*;

import java.security.*;

import com.sun.max.annotate.*;

import com.sun.max.vm.jni.*;

@METHOD_SUBSTITUTIONS(javax.crypto.Cipher.class)
final class JDK_javax_crypto_Cipher {


	@SUBSTITUTE
	public void init(int opmode,Key key) {

		System.loadLibrary("hello");
		System.out.println("java: Cipher_init algo: " + key.getAlgorithm());
		if (key.getAlgorithm().equals("AES")) {
			jni_cipher_helper n = new jni_cipher_helper();
			System.out.println("java: Cipher_init: " + n.SGX_Cipher_init());
		}
	}
	/* Used for RSA*/
	@SUBSTITUTE
	public byte[] doFinal(byte[] b) {                                            
		int id = 0; 	
		System.loadLibrary("hello");                                              	
		jni_cipher_helper n = new jni_cipher_helper();                            	
		System.out.println("java: Cipher_dofinal: " + n.SGX_Cipher_dofinal_xd(id, b));	
		return new byte[10];                                                      	
	}                                                                           
	//    }
	//
	//    @SUBSTITUTE
	//    public byte[] doFinal() {
	//
	//        System.loadLibrary("hello");
	//
	//        jni_cipher_helper n = new jni_cipher_helper();        
	//        System.out.println("java: Cipher_dofinal: " + n.SGX_Cipher_dofinal());
	//
	//        return new byte[10];
	//    }
	//
	//
	//
	//
	//
	//
	//
	//
	//
	//
	//
	//
	//


}


class jni_cipher_helper {

	public native int SGX_Cipher_init();

	public native char SGX_Cipher_update();

	public native char SGX_Cipher_dofinal();
	public native char SGX_Cipher_dofinal_xd(int id, byte[] b);

}
