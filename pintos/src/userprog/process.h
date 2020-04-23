#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);


/* MAG: list to hold argv */
typedef struct args {
  char *value;
  unsigned int vaddr;
  struct list_elem elem;
} argv_t;
typedef struct list args_list_t;


typedef int pid_t;
#define PID_ERROR ((pid_t) -1)  // Error when the process cannot be loaded
#define PID_CRASH ((pid_t) -2)  // Error when the process terminated due to kernel crash 


/* MAG: PCB: Process control block */
struct process_control_block{
  pid_t pid;                    /* unique number that identifies process,
                                   mapped 1:1 with tid */
  struct list_elem elem;        /* used to iterate over child_list from thread.h */
  int exit_status;
  char *executing_file;         /* Name/path of the file to execute */
  
  
  struct thread *parent_thread; /* Thread that runs for this process*/
  bool waiting;                 /* Flag to check if the process is already waiting */
  bool exited;                  /* Flag to check if the process already exited */
  bool is_orphan;               /* Flag to check if the parent process exited before this process */
  struct semaphore proc_init;   /* Semaphore that blocks until 
                                   start_process loads the process into memory */
  struct semaphore wait;        /* Semaphore used for process_wait */
  int last_fd;                  /* Last file descriptor opened */
}; 

/* FD: File descriptor struct */
struct file_descriptor{
  int fd;                       /* Int representing handle for the file */
  struct file *file;            /* Link to struct file for file.c */
  struct list_elem elem;        /* Used to iterate over file_descriptors list in thread.h */
};

argv_t *add_argv(args_list_t *args, char *argv, unsigned int vaddr);

#endif /* userprog/process.h */
