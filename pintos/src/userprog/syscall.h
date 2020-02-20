#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* Process system calls */
/* Practice adds one to the argument -> just a silly syscall */
int practice(int i);

/* File system calls */
int write(int fd, const void *buffer, unsigned size);

#endif /* userprog/syscall.h */
