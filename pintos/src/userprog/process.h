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
argv_t *add_argv(args_list_t *args, char *argv, unsigned int vaddr);

#endif /* userprog/process.h */
