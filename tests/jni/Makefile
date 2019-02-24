all:
	javac JNI_KeyGenerator.java
	javah JNI_KeyGenerator
	gcc -I$JAVA_HOME/include -I$JAVA_HOME/include/linux JNI_KeyGenerator.c -L $MAXINE_HOME/com.oracle.max.vm.native/generated/linux/ -lsgx_keygen -shared -fPIC -o libhello.so -lenclave.signed
	cp libhello.so $MAXINE_HOME/com.oracle.max.vm.native/generated/linux/
clean:
	rm -rf *.h *.class *.so