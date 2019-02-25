
To app einai vivliothiki

Allagh sto makefile me 

@$(CXX) $^ -o libsgx_keygen.so  $(App_Link_Flags)  -shared -fPIC

otan paei na ftiaksei to app_name

make

cp *.so $MAXINE_HOME/com.oracle.max.vm.native/generated/linux/

allagh sto create_enclave gia to path


