#include <signal.h>
#include <sys/time.h>

#include <sys/types.h>

#include <unistd.h>
#include <ucontext.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include <string>
#include <vector>
#include <map>
#include <algorithm>

#include <jvmti.h>
#include <jni.h>

using namespace std;

// Frequency, in interrupts/sec
static const int kProfileFrequency = 50;

// Helper functions and macros.
static void do_log(const char* file, int line, const char* fmt, ...) {
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);

  struct tm local;
  localtime_r(&now.tv_sec, &local);

  char nowStr[1000];

  strftime(nowStr, 1000, "%Y%m%d %H:%M:%S", &local);
  fprintf(stderr, "%s:%d [%s%0.2f] :: ", file, line, nowStr, now.tv_nsec / 1e9);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
}

#define LOG(fmt, ...) do_log(__FILE__, __LINE__, fmt, ##__VA_ARGS__);

#define JVMTI_CALL(stmt, onError)\
  do {\
    jvmtiError err = (stmt);\
    if (err != JVMTI_ERROR_NONE) {\
      LOG("ERROR: In JVMTI call: %s -- %d", #stmt, err);\
      onError;\
    }\
  } while(0);

#define JVMTI_ASSERT(stmt)\
    if (!(stmt)) { fprintf(stderr, "Assertion %s failed; exiting.", #stmt); exit(1); }

#define JVMTI_EXIT(fmt, args...)\
    { fprintf(stderr, "ERROR: "); fprintf(stderr, fmt, ## args); exit(1); }

static vector<string> Split(const string& in, char splitter) {
  vector<string> result;
  size_t pos = 0;
  size_t next = 0;
  while (pos < in.size()) {
    next = in.find(splitter, pos);
    if (next == string::npos) {
      next = in.size();
    }
    result.push_back(in.substr(pos, next));
    pos = next + 1;
  }
  return result;
}

struct ProfilerOptions {
  string destFile;
};

// Struct definitions for AsyncGetCallTrace
struct ASGCT_CallFrame {
  jint lineno;
  jmethodID method_id;
};

struct ASGCT_CallTrace {
  JNIEnv *env_id;
  jint num_frames;
  ASGCT_CallFrame *frames;
};

extern "C" void AsyncGetCallTrace(ASGCT_CallTrace *trace, jint depth, void* ucontext);

static const int kMaxTraceDepth = 100;

struct AddressInfo {
  jmethodID method;
  uint64_t start;
  uint64_t end;
  uint32_t lineno;
};
typedef map<uint64_t, AddressInfo> AddressMap;

struct JavaTraceInfo {
  int count;
  int id;
  ASGCT_CallTrace trace;
  ASGCT_CallFrame frames[kMaxTraceDepth];

  JavaTraceInfo() {
    trace.num_frames = 0;
    trace.frames = frames;
    trace.env_id = NULL;
    id = -1;
    count = 0;

    memset(frames, 0, sizeof(ASGCT_CallFrame) * kMaxTraceDepth);
  }

  JavaTraceInfo(const JavaTraceInfo& other) {
    memcpy(this, &other, sizeof(JavaTraceInfo));
    trace.frames = frames;
  }

  JavaTraceInfo& operator=(const JavaTraceInfo& other) {
    memcpy(this, &other, sizeof(JavaTraceInfo));
    trace.frames = frames;
    return *this;
  }

  uint64_t hash() {
    uint64_t hash_val = 0;
    for (int i = 0; i < trace.num_frames; ++i) {
      const ASGCT_CallFrame& f = trace.frames[i];
      hash_val ^= (uint64_t) f.method_id;
    }

    return hash_val;
  }

  bool operator<(const JavaTraceInfo& b) const {
    return count < b.count;
  }
};
typedef map<uint64_t, JavaTraceInfo> JavaTraceMap;

struct AgentData {
  JavaTraceMap traceMap;
  AddressMap codeMap;

  JavaVM *VM;
  jvmtiEnv *jvmti;
  jrawMonitorID lock;

  ProfilerOptions opts;
  bool shuttingDown;

  pthread_key_t jniTLKey;
};

static AgentData gData;

struct ScopedLock {
  ScopedLock() {
    gData.jvmti->RawMonitorEnter(gData.lock);
  }

  ~ScopedLock() {
    gData.jvmti->RawMonitorExit(gData.lock);
  }
};

extern "C" {
jint Agent_OnLoad(JavaVM *vm, char *options, void *reserved);
void Agent_OnUnload(JavaVM *vm);
}

static void OnThreadStart(jvmtiEnv *jvmti_env, JNIEnv* jni_env, jthread thread) {
  pthread_setspecific(gData.jniTLKey, jni_env);
}

static void OnClassLoad(jvmtiEnv *jvmti, JNIEnv* jni_env, jthread thread, jclass klass) {
  ScopedLock sl;
}

// Force realization of method ids to ensure we get proper stack traces and can
// do method name lookups. See:
// http://jeremymanson.blogspot.com/2007/05/profiling-with-jvmtijvmpi-sigprof-and.html
static void OnClassPrepare(jvmtiEnv *jvmti, JNIEnv* jni_env, jthread thread, jclass klass) {
  ScopedLock sl;
  jint methodCount;
  jmethodID *methods;
  JVMTI_CALL(jvmti->GetClassMethods(klass, &methodCount, &methods), return);
  jvmti->Deallocate((unsigned char*) methods);
}

// Extract the first line number of a compiled method, to allow for partial
// stack traces inside of JIT-compiled methods.
static void OnCompiledMethodLoad(jvmtiEnv *jvmti,
                                 jmethodID methodId,
                                 jint codeSize,
                                 const void *codeAddr,
                                 jint mapLength,
                                 const jvmtiAddrLocationMap* map,
                                 const void* compileInfo) {
  AddressInfo codeInfo;
  codeInfo.start = (uint64_t) codeAddr;
  codeInfo.end = (uint64_t) codeAddr + codeSize;
  codeInfo.method = methodId;
  codeInfo.lineno = 0;

  jboolean is_native;
  JVMTI_CALL(jvmti->IsMethodNative(methodId, &is_native),
      LOG("Invalid method?"); return);

  if (!is_native) {
    jint lineNumberCount = 0;
    jvmtiLineNumberEntry *lineNumberTable;
    JVMTI_CALL(jvmti->GetLineNumberTable(methodId, &lineNumberCount, &lineNumberTable),
        LOG("Failed to extract line number from method %p", methodId));

    if (lineNumberCount > 0) {
      codeInfo.lineno = lineNumberTable[0].line_number;
    }
  }

  gData.codeMap[(uint64_t) codeInfo.start] = codeInfo;
  gData.codeMap[(uint64_t) codeInfo.end] = codeInfo;
}

// NB -- The OpenJDK JVM does not handle profile events triggered during
// the execution of compiled blobs (it fails to return a stack trace).  To get
// accurate profiles in this case, we consult the saved instruction pointer
// from the signal context.
static void OnProfTimer(int sig, siginfo_t *sigInfo, void *ctx) {
  ucontext_t* currentContext = (ucontext_t*) ctx;
  uint64_t ip = (uint64_t) currentContext->uc_mcontext.gregs[REG_RIP];

  JavaTraceInfo cInfo;
  AddressMap::iterator codeStart;

  codeStart = gData.codeMap.lower_bound(ip);
  if (codeStart != gData.codeMap.end()) {
    const AddressInfo& codeBlock = codeStart->second;
    if (codeBlock.start <= ip && codeBlock.end >= ip) {
      cInfo.trace.num_frames = 1;
      ASGCT_CallFrame& top = cInfo.trace.frames[0];
      top.lineno = codeBlock.lineno;
      top.method_id = codeBlock.method;
    }
  } else {
    cInfo.trace.env_id = (JNIEnv*)pthread_getspecific(gData.jniTLKey);
//    gData.VM->AttachCurrentThread(, NULL);
    AsyncGetCallTrace(&cInfo.trace, kMaxTraceDepth, &currentContext);
  }

  if (cInfo.trace.num_frames <= 0) {
    return;
  }

  uint64_t hashValue = cInfo.hash();

  if (gData.traceMap.find(hashValue) == gData.traceMap.end()) {
    cInfo.id = gData.traceMap.size() + 1;
    gData.traceMap[hashValue] = cInfo;
  }

  gData.traceMap[hashValue].count += 1;
}

static string GetMethodName(jvmtiEnv *jvmti, jmethodID methodId) {
  string methodName = "(unknown method)";
  if (methodId == NULL) {
    return methodName;
  }

  char* mName, *mSig, *mGeneric;
  mName = mSig = mGeneric = NULL;

  JVMTI_CALL(jvmti->GetMethodName(methodId, &mName, &mSig, &mGeneric), return methodName);

  methodName = mName;
  jvmti->Deallocate((unsigned char*) mName);
  jvmti->Deallocate((unsigned char*) mSig);
  jvmti->Deallocate((unsigned char*) mGeneric);
  return methodName;
}

static string GetClassName(jvmtiEnv *jvmti, jclass klass) {
  char *kSig, *kGeneric;
  kSig = kGeneric = NULL;
  JVMTI_CALL(jvmti->GetClassSignature(klass, &kSig, &kGeneric),
      return "UnknownClass");

  string sig = kSig;

  jvmti->Deallocate((unsigned char*) kSig);
  jvmti->Deallocate((unsigned char*) kGeneric);

  // Convert the signature to a class name.
  if (sig[sig.size() - 1] == ';') {
    sig = sig.substr(0, sig.size() - 1);
  };
  
  while (sig[0] == '[' || sig[0] == 'L') {
    sig = sig.substr(1, sig.size() - 1);
  }

  for (size_t i = 0; i < sig.size(); ++i) {
    if (sig[i] == '/') { sig[i] = '.'; } 
  }

  return sig;
}

static string GetSourceFile(jvmtiEnv *jvmti, jclass klass) {
  char *sourceFile;
  JVMTI_CALL(jvmti->GetSourceFileName(klass, &sourceFile), return "<Unknown Source>");
  string res = sourceFile;
  jvmti->Deallocate((unsigned char*) sourceFile);
  return res;
}

static void GetMethodInfo(jvmtiEnv *jvmti, jmethodID methodId,
                          string* klassName, string* methodName, string* fileName) {
  *methodName = "UnknownMethod";
  *klassName = "UnknownClass";
  *fileName = "<Unknown Source>";
  jclass klass;

  if (!methodId) {
    *methodName = "*native method*";
    *klassName = "";
    *fileName = "<Native>";
    return;
  }

  jboolean isNative;
  JVMTI_CALL(jvmti->IsMethodNative(methodId, &isNative),
      return);

  if (isNative) {
    *methodName = "*native method*";
    *klassName = "";
    *fileName = "<Native>";
  }

  *methodName = GetMethodName(jvmti, methodId).c_str();

  jint lineNumberCount;
  jvmtiLineNumberEntry *lineNumberTable;
  JVMTI_CALL(jvmti->GetLineNumberTable(methodId, &lineNumberCount, &lineNumberTable),
      return);

  JVMTI_CALL(jvmti->GetMethodDeclaringClass(methodId, &klass),
      return);

  *klassName = GetClassName(jvmti, klass);
  *fileName = GetSourceFile(jvmti, klass);
}

static void DumpProfilerData(jvmtiEnv *jvmti, JNIEnv *jni_env) {
  string outputFile;

  ScopedLock sl;

  if (!gData.opts.destFile.empty()) {
    outputFile = gData.opts.destFile;
  } else {
    char hostName[256];
    char tmpBuf[1024];
    gethostname(hostName, 255);
    sprintf(tmpBuf, "hprof.%s.%d.txt", hostName, getpid());
    outputFile = tmpBuf;
  }

  FILE *traceOut = fopen(outputFile.c_str(), "w");

  LOG("Profile writing to %s.", outputFile.c_str());

  if (traceOut == NULL) {
    LOG("Failed to open trace output file.  Exiting.");
    return;
  }

#define WT(fmt, ...) fprintf(traceOut, fmt, ##__VA_ARGS__); fwrite("\n", 1, 1, traceOut)

  WT("JAVA PROFILE 1.0.1");
  WT("");
  WT("--------");
  WT("");
  int sampleCount = 0;
  vector<JavaTraceInfo> traceVector;
  for (JavaTraceMap::iterator i = gData.traceMap.begin(); i != gData.traceMap.end(); ++i) {
    const JavaTraceInfo& callTrace = i->second;
    traceVector.push_back(callTrace);
    sampleCount += callTrace.count;

    WT("TRACE %d:", callTrace.id);
    for (int j = callTrace.trace.num_frames - 1; j >= 0; --j) {
      jmethodID methodId = callTrace.trace.frames[j].method_id;
//      LOG("%d %d -- %p", j, callTrace.trace.num_frames, methodId);
      int lineNo = callTrace.trace.frames[j].lineno;
      string klassName, methodName, fileName;
      GetMethodInfo(jvmti, methodId, &klassName, &methodName, &fileName);

      WT("\t%s.%s (%s:%d)", klassName.c_str(), methodName.c_str(),
          fileName.c_str(), lineNo)
      ;
    }
  }

  const char* now = asctime(NULL);
  WT("CPU TIME (ms) BEGIN (total = %d) %s", sampleCount, now);
  WT("rank\tself\taccum\tcount\ttrace\tmethod");
  int runningCount = 0;

  sort(traceVector.begin(), traceVector.end());
  reverse(traceVector.begin(), traceVector.end());

  for (size_t i = 0; i < traceVector.size(); ++i) {
    const JavaTraceInfo& callTrace = traceVector[i];
    int count = callTrace.count;
    jmethodID methodId = callTrace.trace.frames[0].method_id;
    string klassName, methodName, fileName;
    GetMethodInfo(jvmti, methodId, &klassName, &methodName, &fileName);

    runningCount += count;
    double pct = 100. * count / sampleCount;
    double totalPct = 100. * runningCount / sampleCount;
    WT("%zd\t%.3f%%\t%.3f%%\t%d\t%d\t%s.%s", i, pct, totalPct, count, callTrace.id,
        klassName.c_str(), methodName.c_str())
    ;
  }
  WT("CPU TIME END");

  WT("STAT SAMPLE BEGIN");
  WT("id\ttime\trx\ttx");
  WT("STAT SAMPLE END");
  fclose(traceOut);

  LOG("Profile dump finished.");
}

static void RegisterTimer() {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_sigaction = &OnProfTimer;
  action.sa_flags = SA_SIGINFO;

  if (sigaction(SIGPROF, &action, NULL) != 0) {
    perror("Failed to register profiler handler.\n");
    JVMTI_EXIT("Exiting.");
  }
  LOG("Registered signal handlers.");

  struct timeval tv = { 0, 1000000 / kProfileFrequency };
  struct itimerval profSpec = { tv, tv };
  if (setitimer(ITIMER_PROF, &profSpec, NULL) != 0) {
    perror("Failed to set profiler timer.");
  }
  LOG("Registered timers.");
}

static void UnregisterTimer() {
  LOG("Stopping timer.");
  struct timeval tv = { 0, 0 };
  struct itimerval profSpec = { tv, tv };
  
  setitimer(ITIMER_PROF, &profSpec, NULL);
  
  LOG("Removing signal handler.");
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = SIG_DFL;
  sigaction(SIGPROF, &action, NULL);
}

static void OnVMInit(jvmtiEnv *jvmti, JNIEnv *jni, jthread t) {
  RegisterTimer();
}

// Map method id's from stack traces to class+method name, and write
// output to hprof.pid.txt.
static void OnVMDeath(jvmtiEnv *jvmti, JNIEnv *jni_env) {
  LOG("VM Shutdown");
  gData.shuttingDown = true;
  DumpProfilerData(jvmti, jni_env);
}

static void SetupCallbacks() {
  jvmtiEventCallbacks *callbacks = new jvmtiEventCallbacks();
  callbacks->ClassLoad = &OnClassLoad;
  callbacks->ClassPrepare = &OnClassPrepare;
  callbacks->VMDeath = &OnVMDeath;
  callbacks->VMInit = &OnVMInit;
  callbacks->CompiledMethodLoad = &OnCompiledMethodLoad;
  callbacks->ThreadStart = &OnThreadStart;

  JVMTI_CALL(gData.jvmti->SetEventCallbacks(callbacks, sizeof(jvmtiEventCallbacks)), return);
  JVMTI_CALL(gData.jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_LOAD, NULL), return);
  JVMTI_CALL(gData.jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_PREPARE, NULL), return);
  JVMTI_CALL(gData.jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_DEATH, NULL), return);
  JVMTI_CALL(gData.jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_VM_INIT, NULL), return);
  JVMTI_CALL(gData.jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, NULL), return);
  JVMTI_CALL(gData.jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_THREAD_START, NULL), return);
}

static void SetupCapabilities() {
  jvmtiCapabilities caps;
  memset((void*) &caps, 0, sizeof(jvmtiCapabilities));
  caps.can_get_source_file_name = 1;
  caps.can_get_line_numbers = 1;
  caps.can_generate_compiled_method_load_events = 1;

  JVMTI_CALL(gData.jvmti->AddCapabilities(&caps), return);
}

jint Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
  LOG("Loading agent with options: %s", options);
  if (options != NULL) {
    vector<string> args = Split(options, ',');
    for (size_t i = 0; i < args.size(); ++i) {
      vector<string> kv = Split(args[i], '=');
      JVMTI_ASSERT(kv.size() == 2);
      string k = kv[0];
      string v = kv[1];
      if (k == "file") {
        gData.opts.destFile = v;
      } else {
        JVMTI_EXIT("Unknown option %s", k.c_str());
      }
    }
  }

  gData.shuttingDown = false;
  gData.VM = vm;

  pthread_key_create(&gData.jniTLKey, NULL);
  jint err = vm->GetEnv((void **) &gData.jvmti, JVMTI_VERSION);
  if (err != JNI_OK) {
    JVMTI_EXIT("Failed to acquire JVMTI environment.  Exiting.");
  }

  JVMTI_CALL(gData.jvmti->CreateRawMonitor("ProfilerAgentLock", &gData.lock),
      JVMTI_EXIT("Failed to create profiler lock."));

  SetupCapabilities();
  SetupCallbacks();
  return 0;
}

void Agent_OnUnload(JavaVM *vm) {
  LOG("Agent unloading...");
}
