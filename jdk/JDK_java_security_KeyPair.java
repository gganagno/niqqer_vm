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
import java.lang.reflect.*;                      
 
import com.sun.max.vm.actor.holder.*; 
                                                
import com.sun.max.annotate.*;                   
import com.sun.max.program.*;                    
import com.sun.max.vm.actor.holder.*;            
import com.sun.max.vm.classfile.constant.*;      
import com.sun.max.vm.methodhandle.*;            
import com.sun.max.vm.thread.*;                  
import com.sun.max.vm.type.*;                    
import com.sun.max.vm.value.*;                   
                                                 

                                               
import java.lang.reflect.*;                    
                                               
import com.sun.max.annotate.*;                 
import com.sun.max.program.*;                  
import com.sun.max.vm.actor.holder.*;          
import com.sun.max.vm.classfile.constant.*;    
import com.sun.max.vm.methodhandle.*;          
import com.sun.max.vm.thread.*;                
import com.sun.max.vm.type.*;                  
import com.sun.max.vm.value.*;                 
import java.util.*;
@METHOD_SUBSTITUTIONS(java.security.KeyPair.class)



final class JDK_java_security_KeyPair {
	@ALIAS(declaringClass = java.security.KeyPair.class)
	private PrivateKey privateKey;
	@ALIAS(declaringClass = java.security.KeyPair.class)
	private PublicKey publicKey;
	private static HashMap<PublicKey, Integer> myhash = new HashMap<PublicKey, Integer>();


	public static void addkey(PublicKey pk, int id) {
		myhash.put(pk, id);
	}
//	public static JDK_java_security_KeyPair b(PublicKey pubk, PrivateKey privk, int id) {
//		this.privateKey = privk;
//		this.publicKey = pubk;
//
//	}

//	public KeyPair KeyPairC() {
//		return new KeyPair(this.publicKey, this.privateKey);
//	}
	@SUBSTITUTE
	public PrivateKey getPrivate() {
		System.out.println(myhash.get(publicKey));
		return this.privateKey;
	}

	//	@SUBSTITUTE
	//	public PublicKey getPublic() {	
	//		jni_rsa_helper n = new jni_rsa_helper();
	//		System.out.println("NIQQER_VM Keysize:");
	//		//String java_key = n.SGX_KeyPairGenerator_generateKey(5);
	//		System.out.println("NIQQER_VM generateKey Algorithm = RSA");
	//		return null;
	//	}

}

