public class JNI_KeyGenerator {

   // static {
   //  System.loadLibrary("hello"); 
   // }
	//auto edw den xreiazetai
 
   private native void SGX_KeyGenerator();

   public static void main(String[] args) {
      new JNI_KeyGenerator().SGX_KeyGenerator();  // Create an instance and invoke the native method
   }
}
