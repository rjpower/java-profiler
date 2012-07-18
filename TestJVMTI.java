import java.util.*;

public class TestJVMTI {
  public static void a() { b(); }
  public static void b() { c(); } 
  public static void c() {
    long start = System.currentTimeMillis();
    long counter = 0;
    while (true) {
      for (int i = 0; i < 1e8; ++i) {
        counter += i;
      }

      if (System.currentTimeMillis() - start > 1000) {        
        break;
      }
    }
  }

  public static void main(String[] args) {
    ArrayList<Thread> threads = new ArrayList<Thread>();
    for (int i = 0; i < 10; ++i) {
      final int threadIdx = i;
      Thread t = new Thread() {
        public void run() {
          System.err.println("Thread " + threadIdx + " starting.");
          a();
          System.err.println("Thread " + threadIdx + " exiting.");
        }
      };

      threads.add(t);
      t.start();
    }
    
    for (Thread t : threads) {
      try {
        t.join();
      } catch (InterruptedException e) {}
    }
  }
}
