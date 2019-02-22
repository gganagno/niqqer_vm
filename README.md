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

source = https://maxine-vm.readthedocs.io/en/latest/JDK-Interoperation.html#method-substitution

javac tests/thread.java

### Searching in folders
grep -nra sinaritis_pou_psaxnw_i_kati_allo -I .
