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
	public static HashMap<Object, custom_info> myhash = new HashMap<Object, custom_info>();
	public static void addkey(Object pk, custom_info c) {
		myhash.put(pk, c);
	}
	@SUBSTITUTE
	public PrivateKey getPrivate() {
		return this.privateKey;
	}
}

/**
 @ id is the enclave specific entry
 @ type is encrpytion/decryption
 @ algo is aes = 0 / rsa = 1
 @ keysize is the keysize :P
**/

class custom_info {
	int id;
	int type;
	int algo;
	int keysize;
};


