cd $WORKDIR
cd niqqer_vm/jdk/
cp JDK_javax* $MAXINE_HOME/com.sun.max/src/com/sun/max/vm/jdk
cp JDK_java_s* $MAXINE_HOME/com.sun.max/src/com/sun/max/vm/jdk
cd ../code/sgx/test_app
make clean
make
cp *.so $MAXINE_HOME/com.oracle.max.vm.native/generated/linux/

echo $PWD
cd $WORKDIR/niqqer_vm/tests/jni
make clean
javac JNI_*.java
javah JNI_Cipher
javah JNI_KeyGenerator
gcc -I$JAVA_HOME/include -I$JAVA_HOME/include/linux JNI_*.c -L $MAXINE_HOME/com.oracle.max.vm.native/generated/linux/ -lsgx_keygen -shared -fPIC -o libhello.so -lenclave.signed
cp libhello.so $MAXINE_HOME/com.oracle.max.vm.native/generated/linux/
cd $MAXINE_HOME
mx build
mx image
