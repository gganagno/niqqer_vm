cd $WORKDIR
cd mytests/jdk/
cp JDK_javax* $MAXINE_HOME/com.sun.max/src/com/sun/max/vm/jdk
cd ../sgx_keygen/
make clean
make
cp *.so $MAXINE_HOME/com.oracle.max.vm.native/generated/linux/
cd ../jni/
make clean
javac JNI_KeyGenerator.java
javah JNI_KeyGenerator
gcc -I$JAVA_HOME/include -I$JAVA_HOME/include/linux JNI_KeyGenerator.c -L $MAXINE_HOME/com.oracle.max.vm.native/generated/linux/ -lsgx_keygen -shared -fPIC -o libhello.so -lenclave.signed
cp libhello.so $MAXINE_HOME/com.oracle.max.vm.native/generated/linux/
cd $MAXINE_HOME
