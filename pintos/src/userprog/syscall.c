#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"

#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);
/* MAG: Function to check validity of a user-provided pointer 
     Pointer is invalid if:
      1. is NULL
      2. is UNMAPPED to Virtual Memory
      3. is pointing to Kernele Vaddr */
static bool is_valid_esp (uint32_t *esp);
static void check_pointer(uint32_t *ptr);

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
  /* MAG: Check the validity of the pointer */
  check_pointer(args); 

  if (args[0] == SYS_EXIT) {
    check_pointer(args+1);
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
    check_pointer(args+1);
    check_pointer(args+2);
    check_pointer((uint32_t *)args[2]);
    check_pointer(args+3);
    f->eax = write(args[1], args[2], args[3]);
  }

  if(args[0] == SYS_PRACTICE){
    check_pointer(args+1);
    f->eax = practice(args[1]);
  }

  if(args[0] == SYS_HALT){
    shutdown_power_off();
  }
}

/* Process syscalls */
int practice(int i){
  return (i+1);
}

static void check_pointer(uint32_t *ptr){
  if (!is_valid_esp(ptr)){
    printf("%s: exit(-1)\n", &thread_current ()->name);
    thread_exit();
  }
}

static bool is_valid_esp (uint32_t *esp){
  /* Check if pointer is within user space */
  if(is_user_vaddr(esp)){
    /* Check if the pointer is in a mapped page */
    uint32_t *curr_pd = thread_current()->pagedir;
    /* Because a 32-bit integer may lay on a page boundary
       ex: a part of the int may be on a mapped page and a part on an unmapped page.
       We need to verfiy that each byte is on a mapped page*/
    uint8_t *single_byte = (uint8_t *)esp;
    for(int i = 0; i < 4; i++){
      if(pagedir_get_page(curr_pd, (single_byte+i)) == NULL){
        return 0;
      }
    }
    return 1;
  }
  return 0;

  /* Check if it is in a mapped page and if is not NULL
TODO: Check if value pointed by esp is a pointer or just a value
    void *curr_pg_no = pg_round_down((const void *)esp);
    if(curr_pg_no && pagedir_get_page((uint32_t *)curr_pg_no, esp)){
      return true;
    }
  }
  return false;
  */
}

/* File syscalls */
int write(int fd, const void *buffer, unsigned size){
  /* Print to console */
  if(fd == 1){
    const char *buff = buffer;
    putbuf(buff, size);
    return size;
  }
}
