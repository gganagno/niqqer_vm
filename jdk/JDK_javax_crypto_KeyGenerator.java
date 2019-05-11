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


    @SUBSTITUTE
    public final void init(int keysize) {
        custom_info p = new custom_info();
        p.keysize = keysize;
        p.id = -1;
        p.type = -1;
        p.algo = 0;
        JDK_java_security_KeyPair.myhash.put(this, p);
    }


    @SUBSTITUTE
    static KeyGenerator getInstance(String algorithm) {
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
        } catch (Exception e) {
            System.out.println(e);
        }
        return k;
    }

    @SUBSTITUTE
    public SecretKey generateKey() {
        int keysize;
        int id;
        custom_info p = JDK_java_security_KeyPair.myhash.get(this);
        keysize = p.keysize;
        System.loadLibrary("hello");
        jni_keygenerator_helper n = new jni_keygenerator_helper();
        id = n.SGX_KeyGenerator_getid(keysize);
        String java_key = n.SGX_KeyGenerator_generateKey(keysize, id);
        System.out.println("JAVA KEY --> " + java_key);
        SecretKeySpec ss = new SecretKeySpec(java_key.getBytes(), "AES");
        System.out.println("NIQQER_VM generateKey Algorithm = " + p.algo);

        p.id = id;
        JDK_java_security_KeyPair.myhash.put(ss, p);
        return ss;
    }

}


class jni_keygenerator_helper {

    public native String SGX_KeyGenerator_generateKey(int size, int id);
    public native int SGX_KeyGenerator_getid(int size);

}
