#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t ;

void syscall_init (void);

/* Process system calls */
/* Practice adds one to the argument -> just a silly syscall */
int sys_practice(int i);

/* Terminates pintos */
void sys_halt(void);

/* Terminates the current user program, returning status to the kernel */
void sys_exit(int status);

/* Runs the executable whose name is given in cmd_line,
   passing any given arguments, and returns the new process’s program id (pid)*/
pid_t sys_exec(const char *cmdline);

/* Waits for a child process pid and retrieves the child’s exit status. */
int wait(pid_t pid);

/* File system calls */
int sys_write(int fd, const void *buffer, unsigned size);

#endif /* userprog/syscall.h */
