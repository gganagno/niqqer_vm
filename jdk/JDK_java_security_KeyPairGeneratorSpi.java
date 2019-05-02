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
@METHOD_SUBSTITUTIONS(java.security.KeyPairGeneratorSpi.class)




final class JDK_java_security_KeyPairGeneratorSpi {

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
    public KeyPair generateKeyPair() {
		            throw new NullPointerException("demo"); 
//
//        System.out.println("XDD");
//        jni_rsa_helper n = new jni_rsa_helper();
//        System.out.println("NIQQER_VM Keysize: " + key_size);
//        String java_key = n.SGX_KeyPairGenerator_generateKey(key_size);
//        System.out.println("NIQQER_VM generateKey Algorithm = RSA");
//        return null;
    }

}

class jni_rsa_helper {
    public native int SGX_KeyPairGenerator_generateKey(int size);
    public native String SGX_KeyPairGenerator_get_pubkey (int id);
    public native String SGX_KeyPairGenerator_get_privkey(int id);
}
