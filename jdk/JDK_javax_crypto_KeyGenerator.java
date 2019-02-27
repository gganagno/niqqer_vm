
package com.sun.max.vm.jdk;

import javax.crypto.*;

import com.sun.max.annotate.*;

import com.sun.max.vm.jni.*;

@METHOD_SUBSTITUTIONS(javax.crypto.KeyGenerator.class)
final class JDK_javax_crypto_KeyGenerator {
   
    @SUBSTITUTE
    public void init(int keySize) {

        System.loadLibrary("hello");

    	jni_keygenerator_helper n = new jni_keygenerator_helper();
    	
    	n.SGX_KeyGenerator_init(5);
    	
    }

    @SUBSTITUTE
    public SecretKey generateKey() {

        System.loadLibrary("hello");

        jni_keygenerator_helper n = new jni_keygenerator_helper();
        
        int java_key = n.SGX_KeyGenerator_generateKey();
        
        return null;
    }

}


class jni_keygenerator_helper {
    
    public native int SGX_KeyGenerator_init(int keySize);

  	public native int SGX_KeyGenerator_generateKey();

}
