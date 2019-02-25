export WORKDIR=$(pwd)
export JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
export MAXINE_HOME=$WORKDIR/maxine
export PATH=$PATH:$MAXINE_HOME/com.oracle.max.vm.native/generated/linux/
export LD_LIBRARY_PATH=$MAXINE_HOME/com.oracle.max.vm.native/generated/linux/
export PATH=$PATH:$(pwd)/mx


