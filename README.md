javaprof - An Accurate Sampling Profiler for Java
=================================================

Newer JDK versions come with a builtin hprof agent for profiling, but it lags
when you are trying to do distributed profiling of long running systems.  It 
starts when your program starts, and continues until the program exits.  In the
meantime, you can't collect any information you need.

This project provides a sampling based profiler for Java using the JVMTI
interface.  You must have a version of the Java JDK installed to use this;
for Debian based systems use:

apt-get install openjdk-6-jdk

Run 'make' to build the project.  The profiling library will be generated 
in libsampling\_profiler.so; copy it to wherever you need to use it.
You can use the profiler with any java program via the agent path directive:

java -agentpath:libsampling\_profiler.so=file=/tmp/jvmprof.txt -jar MyProgram.jar

By default, the profiler will behave the same way as the hprof profiler,
producing an hprof compatible profile in the /tmp/jvmprof.txt 
directory.

## Network usage
javaprof supports starting and stopping of a profiler while your program 
is running.  A very simple HTTP interface is provided, by default on port 
19999.  To start profiling:

    curl http://myhost:19999/profile-start?time=30

If no time argument is given, the profiler will run indefinitely.  To pause
profiling:

   curl http://myhost:19999/profile-stop

To fetch the current profile data:

   curl http://myhost:19999/profile-fetch > hprof.txt

To clear the profile data:

   curl http://myhost:19999/profile-clear

## Viewing profiles
The HPROF format can be difficult to use directly, but the 
excellent gprof2dot script can generate a graphviz output
suitable for humans.
 
http://code.google.com/p/jrfonseca/wiki/Gprof2Dot
