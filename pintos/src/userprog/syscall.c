#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  uint32_t* args = ((uint32_t*) f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", &thread_current ()->name, args[1]);
    thread_exit();
  }

  /* Implement write syscall */
  if(args[0] == SYS_WRITE){
    /* f->eax if we want to return any value */
    /* args[1] = fd
       args[2] = pointer to the buffer
       args[3] = size of the buffer */
    f->eax = write(args[1], args[2], args[3]);
  }
}

int write(int fd, const void *buffer, unsigned size){
  /* Print to console */
  if(fd == 1){
    const char *buff = buffer;
    putbuf(buff, size);
    return size;
  }
}
