
package com.sun.max.vm.jdk;

import javax.crypto.*;

import com.sun.max.annotate.*;
import com.sun.max.vm.jni.*;

@METHOD_SUBSTITUTIONS(javax.crypto.KeyGenerator.class)
final class JDK_javax_crypto_KeyGenerator {
   
    @SUBSTITUTE
    public SecretKey generateKey() {

        System.loadLibrary("hello");

    	jni_helper n = new jni_helper();
    	
    	System.out.println("java: key is: " + n.SGX_KeyGenerator());
    	
        return null;
    }
}


class jni_helper {
    
  	public native int SGX_KeyGenerator();

}
