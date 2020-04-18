#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
/* Take an const char argument representing the call command 
   Returns a pintos list */
static void create_args_list(args_list_t *argsl, char *cmd, unsigned int *argv_size);
/* Takes a pintos list of argvs
   Pushes them on the stack represented by esp */
static void push_args(args_list_t *args_list, void **esp, unsigned int argv_size);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  if (file_name == NULL){
    goto err_create;
  }
 
  struct process_control_block *pcb = palloc_get_page(0);
  if (pcb == NULL){
    goto err_create; 
  }

  pcb->parent_thread = thread_current(); 
  list_init(&pcb->parent_thread->child_list);

  /* Lock both semaphores */
  sema_init (&pcb->proc_init, 0);
  sema_init (&pcb->wait, 0);
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    goto err_create;
  strlcpy (fn_copy, file_name, PGSIZE);

  char *th_name = palloc_get_page(0);
  if(th_name == NULL){
    goto err_create;
  }
  unsigned int i = 0;
  while(file_name[i] != ' ' && i < strlen(file_name)){
    th_name[i] = file_name[i];
    i += 1;
  }
  th_name[i] = '\0';
  pcb->executing_file = fn_copy;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (th_name, PRI_DEFAULT, start_process, pcb);

  /* This waits for process initialization */
  sema_down(&pcb->proc_init);

  if (pcb->pid == PID_ERROR)
    goto err_create;
  else {
    pcb->pid = tid;
  }

  return pcb->pid;

err_create:
  if(pcb) palloc_free_page(pcb);
  if(fn_copy) palloc_free_page(fn_copy);
  return TID_ERROR;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *pcb_)
{
  struct process_control_block *pcb = pcb_;
  /* Make file_name a struct based on pintos lists
     Each argv will be represented as a list node
     And argc will be the size of the list */
  char *file_name = pcb->executing_file;
  struct intr_frame if_;
  bool success;

  /* MAG: parse argvs before loading file*/
  args_list_t args_l;
  unsigned int argv_size = 0;
  create_args_list(&args_l, file_name, &argv_size);

  /* MAG: last element of list is the filename */
  struct list_elem *e;
  e = list_rbegin(&args_l);
  argv_t *filename;
  filename = list_entry(e, argv_t, elem);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (filename->value, &if_.eip, &if_.esp);

  /* Add the current thread as a child to the parent thread */
  thread_current()->pcb = pcb;
  list_push_back(&pcb->parent_thread->child_list, &pcb->elem); 
  
  if (!success){
    pcb->pid = PID_ERROR;
  }

  /* Release lock after the process has/has not been successfully loaded */
  sema_up(&pcb->proc_init);

  /* If load failed, quit. */
  if(pcb->pid == PID_ERROR){
    sys_exit(-1);
  }
  /* Push args before calling the process */
  push_args(&args_l, &if_.esp, argv_size);
  

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

void push_args(args_list_t *args_list, void **esp, unsigned int argv_size){
  /* Compute stack alignment to 16-byte(0x10) 
     Since the stack "grows" downward we sub 0x10
     to get the previous multiple of 16*/
  unsigned int total_arg_size = argv_size + (list_size(args_list) + 3) * sizeof(char*);
  unsigned int align_stack = ((total_arg_size - 1) | (0x10 - 1)) + 1;
  unsigned int diff_align = align_stack - total_arg_size;
  /* Iterate through the list, push the argv string on stack and save pointer*/
  argv_t *arg;
  struct list_elem *e;
  /* Len of the string to be pushed */
  unsigned int nargv;
  for(e = list_begin(args_list); e != list_end(args_list); e = list_next(e)){
    arg = list_entry(e, argv_t, elem);
    nargv = strlen(arg->value) + 1;
    *esp -= nargv;
    memcpy(*esp, arg->value, nargv);
    arg->vaddr = (unsigned int) *esp; 
  }

  /* Align stack */
  *esp -= diff_align;
  /* Push sentinel on the stack -> argv[argc] */
  *esp -= sizeof(char *);
  memset(*esp, 0, sizeof(char*));
  
  /* Push argv address pointers */
  for(e = list_begin(args_list); e != list_end(args_list); e = list_next(e)){
    arg = list_entry(e, argv_t, elem);
    *esp -= sizeof(unsigned int);
    memcpy(*esp, &(arg->vaddr), sizeof(unsigned int));
  }
  /* Push argv = address of argv[0] pointer, 
     argc and return address */
  unsigned int argv_start = (unsigned int) *esp;
  *esp -= sizeof(unsigned int);
  memcpy(*esp, &argv_start, sizeof(unsigned int));

  size_t argc = list_size(args_list);
  *esp -= sizeof(unsigned int);
  memcpy(*esp, &argc, sizeof(unsigned int));

  *esp -= sizeof(void *);
}

/* Parses cmd and created a new pintos list with argv */
void create_args_list(args_list_t *argvl, char *cmd, unsigned int *argv_size){
  if(cmd == NULL){
    return;
  }
  list_init(argvl);

  char *delim = " \t";
  char *str1 = cmd;
  char *token;
  char *saveptr;
  /* Total size of strings pushed used to align memory */
  *argv_size = 0;
  //add_argv(argvl, tkn);
  for(token = strtok_r(str1, delim, &saveptr);
    token != NULL;
    token = strtok_r(NULL, delim, &saveptr)){
    /* Push string with virtual address
       Until it is pushed on the stack */
    *argv_size += strlen(token) + 1;
    if(add_argv(argvl, token, 0) == NULL){
      printf("ERR: Could not add argv to list\n");
    }
  }
 
  // TODO: free argvl page
  // TODO: add args to list
  // TODO: need to make a single function
}

argv_t *add_argv(args_list_t *args, char *argv, unsigned int vaddr){
  argv_t *arg = palloc_get_page(0);
  arg->value = palloc_get_page(0);
  strlcpy(arg->value, argv, (strlen(argv) + 1));
  /* Check vaddr to not access kernel */
  if(vaddr < (unsigned int)PHYS_BASE){
    arg->vaddr = vaddr;
  } else {
    printf("Virtual address exceeds userspace bounds -> %d\n", vaddr);
    return NULL;
  }
  /* Push front so that the last argv becomes the first */
  list_push_front(args, &(arg->elem));
  return arg;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED)
{
  struct process_control_block *child_proc = NULL;
  /* Get the child process of the current thread by child_tid */
  struct thread *curr_th = thread_current();
  struct list_elem *e;

  if(!list_empty(&curr_th->child_list)) {
    for(e = list_begin(&curr_th->child_list);
        e != list_end(&curr_th->child_list);
        e = list_next(e)){
      struct process_control_block *pcb = list_entry(e, struct process_control_block, elem);
      if(pcb->pid == child_tid){
        child_proc = pcb;
        break;
      }
    }
  } else {
    goto err_wait;
  }

  /* Check if there was an error with the process we are waiting */
  if(child_proc->pid == -1){
    goto err_wait;
  }
  if(!child_proc){
    goto err_wait;
  }

  /* MAG: Check if wait has already been called for this TID */
  if(child_proc->waiting == true){
    goto err_wait;
  } else {
    child_proc->waiting = true;
  }
  /* Wait for the child process to finish */
  sema_down(&child_proc->wait);

  return child_proc->exit_status; 
err_wait:
  if(child_proc) palloc_free_page(child_proc);
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();

  /* Add sema_up to release process_wait() */
  sema_up(&cur->pcb->wait);
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
