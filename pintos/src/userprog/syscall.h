#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

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
int sys_wait(pid_t pid);


/* File system calls */
/* Creates a file with name <file> and size <initial_size> */
bool sys_create(const char *file, unsigned initial_size);
/* Delete the file called file. 
   Returns true if successful, false otherwise. 
   A file may be removed regardless of whether it is open or closed, 
   and removing an open file does not close it. */
bool sys_remove (const char *file);
/* Opens the file called file. i
   Returns a fd handle > 0 or -1 if the file cannot be opened */
int sys_open(const char *file);
/* Returns the size in bytes of the file opened as fd */
int sys_filesize(int fd);
/* Reads size bytes from the file open as fd into buffer. 
   Returns the number of bytes actually read (0 at end of file), 
   or -1 if the file could not be read */
int sys_read(int fd, void *buffer, unsigned size);
/* Writes size bytes from buffer to the open file fd. 
   Returns the number of bytes actually written, 
   which may be less than size if some bytes could not be written. */
int sys_write(int fd, const void *buffer, unsigned size);
/* Changes the next byte to be read or written in open file fd to position
   expressed in bytes from the beginning of the file */
void sys_seek(int fd, unsigned position);
/* Returns the position of the next byte to be read or written in open file fd 
   expressed in bytes from the beginning of the file.*/
unsigned sys_tell(int fd);
/* closes file descriptor fd. 
   Exiting or terminating a process implicitly closes all its open file descriptors, 
   as if by calling this function for each one. */
void sys_close(int fd);

#endif /* userprog/syscall.h */
