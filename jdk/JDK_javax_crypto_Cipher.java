
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

        jni_cipher_helper n = new jni_cipher_helper();
        System.out.println("java: Cipher_init: " + n.SGX_Cipher_init());
    }

    @SUBSTITUTE
    public byte[] update(byte[] input) {

        System.loadLibrary("hello");

        jni_cipher_helper n = new jni_cipher_helper();        
        System.out.println("java: Cipher_update: " + n.SGX_Cipher_update());

        return new byte[5];
    }

    @SUBSTITUTE
    public byte[] doFinal() {

        System.loadLibrary("hello");

        jni_cipher_helper n = new jni_cipher_helper();        
        System.out.println("java: Cipher_dofinal: " + n.SGX_Cipher_dofinal());

        return new byte[10];
    }

}


class jni_cipher_helper {

    public native int SGX_Cipher_init();

    public native char SGX_Cipher_update();

    public native char SGX_Cipher_dofinal();

}
