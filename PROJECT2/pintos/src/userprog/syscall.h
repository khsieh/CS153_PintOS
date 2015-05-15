#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

void syscall_init (void);

struct child_process
{
    int pid;
    bool wait;
    bool exit;
    int load;
    int status;
    struct lock child_lock;
    struct list_elem elem;    
};

struct child_process * add_child_process(int pid);
struct child_process * get_child_process(int pid);
void remove_child_process(struct child_process * cp);
void remove_child_processes(void);

void process_close_file(int fd);


#endif /* userprog/syscall.h */
