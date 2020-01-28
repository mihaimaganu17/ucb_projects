Design Document for Project 1: User Programs
============================================

## Group Members

* Mihai Maganu <maganu.mihu@gmail.com>

# Getting Acquainted with Pintos

1. Program tried to access virtual address `0xc0000008` from userspace.
2. Virtual address of instruction that resulted in the crash is `eip=0x8048757`.
3. Using `objdump -x -d do-nothing` we found function causing the page fault: `_start`
   Program crashed at instruction: `mov 0x24(%esp), %eax`

6. Name of thread running process_execute is `Thread<main>` at address `0xc0007d50`
  0xc000e000 {tid = 1, status = THREAD_RUNNING, name = "main", '\000' <repeats 11 times>, stack = 0xc000edec <incomplete sequence \357>, priority = 31, 
    allelem = {prev = 0xc0035910 <all_list>, next = 0xc0104020}, elem = {prev = 0xc0035920 <ready_list>, next = 0xc0035928 <ready_list+8>}, pagedir = 0x0, magic = 3446325067}
  0xc0104000 {tid = 2, status = THREAD_BLOCKED, name = "idle", '\000' <repeats 11 times>, stack = 0xc0104f34 "", priority = 0, 
    allelem = {prev = 0xc000e020, next = 0xc0035918 <all_list+8>}, elem = {prev = 0xc0035920 <ready_list>, next = 0xc0035928 <ready_list+8>}, pagedir = 0x0, magic = 3446325067}


7.    Backtrace of current thread
  
#0  process_execute (file_name=file_name@entry=0xc0007d50 "do-nothing") at ../../userprog/process.c:36
    tid_t process_execute(const char *file_name)
#1  0xc0020268 in run_task (argv=0xc00357cc <argv+12>) at ../../threads/init.c:288
    ***static void run_task(char **argv)***
#2  0xc0020921 in run_actions (argv=0xc00357cc <argv+12>) at ../../threads/init.c:340
    ***static void run_actions(char **argv)***
#3  main () at ../../threads/init.c:133
    ***int main(void)***

8. Thread name running `start_process` is `main` at address `0xc0109000`
   Other threads present:

  #0: 0xc000e000 {tid = 1, status = THREAD_BLOCKED, name = "main", '\000' <repeats 11 times>, stack = 0xc000eeac "\001", priority = 31, allelem = {prev = 0xc0035910 <all_list>, next = 0xc0104020}, elem
    = {prev = 0xc0037314 <temporary+4>, next = 0xc003731c <temporary+12>}, pagedir = 0x0, magic = 3446325067}
    pintos-debug: 
  #1: 0xc0104000 {tid = 2, status = THREAD_BLOCKED, name = "idle", '\000' <repeats 11 time
   s>, stack = 0xc0104f34 "", priority = 0, allelem = {prev = 0xc000e020, next = 0xc010a020}, elem = {prev = 0xc00
     35920 <ready_list>, next = 0xc0035928 <ready_list+8>}, pagedir = 0x0, magic = 3446325067}
     pintos-debug: dumplist 
  #2: 0xc010a000 {tid = 3, status = THREAD_RUNNING, name = "do-nothing\000\000\000\000\000
       ", stack = 0xc010afd4 "", priority = 31, allelem = {prev = 0xc0104020, next = 0xc0035918 <all_list+8>}, elem =
       {prev = 0xc0035920 <ready_list>, next = 0xc0035928 <ready_list+8>}, pagedir = 0x0, magic = 3446325067}

9. start_process is created by the line `45` in `src/userprog/process.c`

  ***tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);***

10. Values of `if_` structure:
  eip = 0x8048754 and esp = 0xc0000000
