#### niqqer_vm
The safer maxine vm :)


  
# TRAVERSAL

maxine vm path =  maxine/com.sun.max/src/com/sun/max/

First(Maybe?) file that is executed is vm/MaxineVM.java //VMOptions.parsePristine(argc, argv); 




## Building

mx build
mx image



## Function Hooking
put JDK/JDK_java_util_Random.java into /maxine/com.sun.max/src/com/sun/max/vm/jdk

ousiastika hookarw edw apo tin Random class to nextInt().
mx build
mx image

javac tests/thread.java
maxvm tests/thread !!!!
