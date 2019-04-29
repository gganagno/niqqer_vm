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
@METHOD_SUBSTITUTIONS(java.security.KeyPairGenerator.class)




final class JDK_java_security_KeyPairGenerator {

    static String algo;
    static int key_size;

//    @SUBSTITUTE
//    static KeyGenerator getInstance(String algorithm) {
//        algo = algorithm;
//        KeyGenerator k = null;   
//        try {
//            Provider p[] = Security.getProviders();
//            int has_aes = 0;
//            int found = -1;
//            int i = 0;
//            for (i = 0; i < p.length && found == -1; i++) {
//                has_aes = 0;
//                for (Enumeration e = p[i].keys(); e.hasMoreElements();) {
//                    String el = e.nextElement().toString();
//                    if(el.contains("AES")) {
//                        has_aes = 1;
//                        //System.out.println("\t" + el);
//
//                    }
//                    if (has_aes == 1) {
//                        found = i;
//                        break;
//                    }
//                }
//            }
//
//
//            k = KeyGenerator.getInstance(algorithm, p[found]);//k.getProvider().toString(), algorithm);
//            algo = algorithm;
//        } catch (Exception e) {
//            System.out.println(e);
//        }
//        return k;
//    }

    @SUBSTITUTE
    public void initialize(int keysize) {
        System.loadLibrary("hello");
        jni_rsa_helper n = new jni_rsa_helper();
        System.out.println("NIQQER_VM Keysize: " + keysize);
        String java_key = n.SGX_KeyPairGenerator_generateKey(keysize);
        //SecretKeySpec ss = new SecretKeySpec(java_key.getBytes(), "AES");
        System.out.println("NIQQER_VM generateKey Algorithm = RSA");
        //return ss;
    }
}

class jni_rsa_helper {
    public native String SGX_KeyPairGenerator_generateKey(int size);
}
