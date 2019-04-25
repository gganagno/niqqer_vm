package com.sun.max.vm.jdk;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import com.sun.max.annotate.*;
import com.sun.max.vm.jni.*;
import javax.crypto.KeyGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.Enumeration;
@METHOD_SUBSTITUTIONS(javax.crypto.KeyGenerator.class)




final class JDK_javax_crypto_KeyGenerator {

    static String algo;
    static int key_size;

    @SUBSTITUTE
    public final void init(int keysize) {
        System.out.println("NIQQER_VM keysize ->" + keysize);
        key_size = keysize;
    }


    @SUBSTITUTE
    static KeyGenerator getInstance(String algorithm) {
        algo = algorithm;
        KeyGenerator k = null;   
        try {
            Provider p[] = Security.getProviders();
            int has_aes = 0;
            int found = -1;
            int i = 0;
            for (i = 0; i < p.length && found == -1; i++) {
                has_aes = 0;
                for (Enumeration e = p[i].keys(); e.hasMoreElements();) {
                    String el = e.nextElement().toString();
                    if(el.contains("AES")) {
                        has_aes = 1;
                        //System.out.println("\t" + el);

                    }
                    if (has_aes == 1) {
                        found = i;
                        break;
                    }
                }
            }


            k = KeyGenerator.getInstance(algorithm, p[found]);//k.getProvider().toString(), algorithm);
            algo = algorithm;
        } catch (Exception e) {
            System.out.println(e);
        }
        return k;
    }

    @SUBSTITUTE
    public SecretKey generateKey() {
        System.loadLibrary("hello");
        jni_keygenerator_helper n = new jni_keygenerator_helper();
        
        String java_key = n.SGX_KeyGenerator_generateKey(key_size);
        SecretKeySpec ss = new SecretKeySpec(java_key.getBytes(), "AES");
        System.out.println("NIQQER_VM generateKey Algorithm = " + algo);

        return ss;
    }

}


class jni_keygenerator_helper {

    public native String SGX_KeyGenerator_generateKey(int size);

}
