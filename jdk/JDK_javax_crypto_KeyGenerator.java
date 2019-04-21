package com.sun.max.vm.jdk;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import com.sun.max.annotate.*;
import com.sun.max.vm.jni.*;
@METHOD_SUBSTITUTIONS(javax.crypto.KeyGenerator.class)
final class JDK_javax_crypto_KeyGenerator {


    // @SUBSTITUTE
    // public void init(int keySize) {

    //     System.loadLibrary("hello");

    // 	jni_keygenerator_helper n = new jni_keygenerator_helper();

    // 	n.SGX_KeyGenerator_init(5);

    // }

    @SUBSTITUTE
    public SecretKey generateKey() {
        System.loadLibrary("hello");
        jni_keygenerator_helper n = new jni_keygenerator_helper();
        String java_key = n.SGX_KeyGenerator_generateKey();
        System.out.println("keygen.java: " + java_key);
        SecretKeySpec ss = new SecretKeySpec(java_key.getBytes(), "AES");
        return ss;
    }

}


class jni_keygenerator_helper {

    public native String SGX_KeyGenerator_generateKey();

}
