#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "userprog/syscall.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/*
 * funções introduzidas no projeto 2
 */

void process_init(void) ;
int process_open(const char *file) ;
int process_filesize(int fd) ;
bool process_create(const char *file, unsigned initial_size) ;
bool process_remove (const char *file) ;
int process_read(int fd, void *buffer, unsigned size) ;
int process_write(int fd, const void *buffer, unsigned size) ;
void process_seek (int fd, unsigned position) ;
unsigned process_tell(int fd) ;
void process_close(int fd) ;
void process_fecharArquivosAbertos(void) ;
void process_desmapearTodos(void) ;

/*
 * funções introduzidads no projeto 3
 */

#ifdef VM
void *process_crescerPilha(void *uAddr) ;
mapid_t process_mmap(int fd, void *addr) ;
void process_munmap(mapid_t mid) ;
struct mapeamentoArquivo *process_getMapArqCur(mapid_t mid) ;
struct mapeamentoArquivo *process_getMapArqAddr(struct thread *t, void *uAddr) ;
#endif

#ifdef FILESYS
bool process_chdir(const char *dir) ;
bool process_mkdir(const char *dir) ;
bool process_isdir(int fd) ;
int process_inumber(int fd) ;
bool process_readdir(int fd, char *name) ;
#endif

#endif /* userprog/process.h */
