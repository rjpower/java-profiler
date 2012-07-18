INCLUDE=-I$(JAVA_HOME)/include
LIBS=-lrt
CXXOPTS=-O2 -fPIC -fno-omit-frame-pointer -g2

all: profiler_hook.cc
	$(CXX) $(CXXOPTS) $(INCLUDE) -shared profiler_hook.cc -o libsampling_profiler.so $(LIBS)

test: all
	javac TestJVMTI.java
	java -cp . -agentpath:libsampling_profiler.so TestJVMTI
	java -cp . -agentpath:libsampling_profiler.so=file=./jvmprof.txt TestJVMTI

clean:
	rm -f *.so *.o *.class *hprof*.txt jvmprof.txt
