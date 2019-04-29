public class JNI_KeyGenerator {

  public native int SGX_KeyGenerator_init(int keySize);

  public native int SGX_KeyGenerator_generateKey(int size);
}
