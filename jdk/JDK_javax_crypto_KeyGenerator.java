
package com.sun.max.vm.jdk;

import javax.crypto.*;

import com.sun.max.annotate.*;
import com.sun.max.vm.jni.*;

@METHOD_SUBSTITUTIONS(javax.crypto.KeyGenerator.class)
final class JDK_javax_crypto_KeyGenerator {
   
    @SUBSTITUTE
    public SecretKey generateKey() {
    	System.loadLibrary("hello");
    	jni  n = new jni();
    	n.sayHello();
        return null;
    }
}


class jni {
    
  	public native void sayHello();

}
