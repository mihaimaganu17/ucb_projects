#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "devices/shutdown.h"
#include "devices/input.h"

#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
/* MAG: Function to check validity of a user-provided pointer 
     Pointer is invalid if:
      1. is NULL
      2. is UNMAPPED to Virtual Memory
      3. is pointing to Kernele Vaddr */
static bool is_valid_esp (uint32_t *esp);
static void check_pointer(uint32_t *ptr);
static struct file_descriptor *get_file_descriptor(int fd);

static struct lock file_lock;

void
syscall_init (void)
{
  lock_init(&file_lock);
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

  /* TODO: replace ifs with switch case statement */

  if (args[0] == SYS_EXIT) {
    check_pointer(args+1);
    f->eax = args[1];
    sys_exit(args[1]);
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
    f->eax = sys_write(args[1], (const void *)args[2], args[3]);
  }

  if(args[0] == SYS_PRACTICE){
    check_pointer(args+1);
    f->eax = sys_practice(args[1]);
  }

  if(args[0] == SYS_HALT){
    shutdown_power_off();
  }

  if(args[0] == SYS_EXEC){
    /* MAG: args[1] is a pointer to a string i
       We need to check both the pointer and the strings that it points to */
    check_pointer(args+1);
    check_pointer((uint32_t *)args[1]);
    f->eax = sys_exec((const char *)args[1]);
  }

  if(args[0] == SYS_WAIT){
    check_pointer(args+1);
    f->eax = sys_wait(args[1]);
  }

  if(args[0] == SYS_CREATE){
    check_pointer(args+1);
    check_pointer((uint32_t *)args[1]);
    check_pointer(args+2);
    f->eax = sys_create((const char *)args[1], args[2]);
  }

  if (args[0] == SYS_REMOVE) {
    check_pointer(args+1);
    check_pointer((uint32_t *)args[1]);
    f->eax = sys_remove((const char *)args[1]);
  }

  if(args[0] == SYS_OPEN){
    check_pointer(args+1);
    check_pointer((uint32_t *)args[1]);
    f->eax = sys_open((const char *)args[1]);
  }

  if (args[0] == SYS_FILESIZE) {
    check_pointer(args+1);
    f->eax = sys_filesize(args[1]);
  }

  if (args[0] == SYS_READ) {
    check_pointer(args+1);
    check_pointer(args+2);
    check_pointer((uint32_t *)args[2]);
    check_pointer(args+3);
    f->eax = sys_read(args[1], (void *)args[2], args[3]);
  }

  if (args[0] == SYS_SEEK) {
    check_pointer(args+1);
    check_pointer(args+2);
    sys_seek(args[1], args[2]);
  }

  if (args[0] == SYS_TELL) {
    check_pointer(args+1);
    f->eax = sys_tell(args[1]);
  }

  if (args[0] == SYS_CLOSE) {
    check_pointer(args+1);
    sys_close(args[1]);
  }
}

/* File system calls */
bool sys_create(const char *file, unsigned initial_size){
  lock_acquire(&file_lock);
  bool creation_status = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return creation_status;
}

int sys_open(const char *file){
  lock_acquire(&file_lock);
  struct file_descriptor *fd = NULL;
  fd = palloc_get_page(0);
  if (fd == NULL) {
    lock_release(&file_lock);
    return -1;
  }

  fd->file = filesys_open(file);
  if (fd->file == NULL) {
    palloc_free_page(fd);
    lock_release(&file_lock);
    return -1;
  }
  /* Assign fd value to our file structure */
  struct thread *curr_th = thread_current();
  fd->fd = curr_th->pcb->last_fd++;
  /* Add it to the file descriptors list */
  list_push_back(&curr_th->fd_list, &fd->elem);
  lock_release(&file_lock);

  return fd->fd;
}

bool sys_remove(const char *file){
  return filesys_remove(file); 
}

int sys_filesize(int fd){
  struct file_descriptor *curr_fd = get_file_descriptor(fd);
  if (curr_fd != NULL) {
    return file_length(curr_fd->file);
  }
  return -1;
}

int sys_read(int fd, void *buffer, unsigned size){
  char *buff = buffer;
  if (fd == 1) {
    return -1;
  }

  if (fd == 0) {
    unsigned i = 0;
    for(i = 0; i < size; i++){
      buff[i] = input_getc();
    }
    return i;
  }

  struct file_descriptor *curr_fd = get_file_descriptor(fd);
  if (curr_fd == NULL) {
    return -1;
  } else {
    /* Number of bytes read */
    int nbytes = 0;
    lock_acquire(&file_lock);
    nbytes = file_read(curr_fd->file, buffer, size);
    lock_release(&file_lock);
    return nbytes;
  }
}

/* File syscalls */
int sys_write(int fd, const void *buffer, unsigned size){
  /* Print to console */
  if (fd == 0) {
    return -1;
  }
  if (fd == 1) {
    const char *buff = buffer;
    putbuf(buff, size);
    return size;
  }
  
  /* Search the given fd in the current fd_list */
  struct file_descriptor *curr_fd = get_file_descriptor(fd);
  if (curr_fd == NULL) {
    return -1;
  } else {
    /* Number of bytes written */
    int nbytes = 0;
    lock_acquire(&file_lock);
    nbytes = file_write(curr_fd->file, buffer, size);
    lock_release(&file_lock);
    return nbytes;
  }  
}

void sys_seek(int fd, unsigned position){
  struct file_descriptor *curr_fd = get_file_descriptor(fd);
  if (curr_fd != NULL) {
    file_seek(curr_fd->file, position);
  }
}

unsigned sys_tell(int fd){
  struct file_descriptor *curr_fd = get_file_descriptor(fd);
  if (curr_fd != NULL) {
    return file_tell(curr_fd->file);
  } else {
    return -1;
  }
}

void sys_close(int fd){
  struct file_descriptor *curr_fd = get_file_descriptor(fd);
  if (curr_fd != NULL) {
    /* Check if file has been closed before */
    if (curr_fd->file != NULL) {
      file_close(curr_fd->file);
    }
    /* Remove file from fd list */
    list_remove(&curr_fd->elem);
    palloc_free_page(curr_fd);
  }
}
/* Function to check if fd is in our file descriptors list
   Return a struct file_descriptor or NULL is it does not find fd */
struct file_descriptor *get_file_descriptor(int fd){
  struct thread *curr_th = thread_current();
  struct list_elem *e = NULL;
  if (!list_empty(&curr_th->fd_list)) {
    for (e = list_begin(&curr_th->fd_list);
         e != list_end(&curr_th->fd_list);
         e = list_next(e)) {
      struct file_descriptor *curr_fd = list_entry(e, struct file_descriptor, elem);
      if (curr_fd->fd == fd) {
        return curr_fd;
      }
    }
  }
  return NULL;
}

/* Process syscalls */
int sys_practice(int i){
  return (i+1);
}

void sys_exit(int status){
  thread_current()->pcb->exit_status = status;
  //printf("%s: exit(%d)\n", &thread_current ()->name, status);
  thread_exit();
}

pid_t sys_exec(const char *cmd_line){
  /* MAG: Map tid_t and pid_t 1:1 */
  return process_execute(cmd_line);
}

int sys_wait(pid_t pid){
  return process_wait(pid);
}

static void check_pointer(uint32_t *ptr){
  /* MAG: check the stack pointer for validity */
  if (!is_valid_esp(ptr)){
    //printf("%s: exit(-1)\n", &thread_current ()->name);
    /* Release lock if is currently hold by thread */
    if (lock_held_by_current_thread(&file_lock)) {
      lock_release(&file_lock);
    }
    sys_exit(-1);
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

