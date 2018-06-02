#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/thread.h"


/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
	fs_device = block_get_role (BLOCK_FILESYS);
	if (fs_device == NULL)
		PANIC ("No file system device found, can't initialize file system.");

	inode_init ();
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
	free_map_close() ;
	cache_escreverDisco() ;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
	block_sector_t inode_sector = 0 ;
	char *resto ;
	bool success = false ;
	struct dir *dir = dir_processarCaminho(name, &resto, NULL) ;
	if (dir == NULL)
		return false ;

	lock_acquire(&dir->inode->lock) ;
	bool removido = dir->inode->removed ;
	lock_release(&dir->inode->lock) ;
	if (removido)
		goto saida ;

	success = (resto != NULL
				&& free_map_allocate (1, &inode_sector)
				&& inode_create (inode_sector, initial_size, 0)
				&& dir_add (dir, resto, inode_sector)) ;
		if (!success && inode_sector != 0)
			free_map_release(inode_sector, 1) ;

saida:
	if (dir != thread_current()->currentDir)
		dir_close(dir) ;
	free(resto) ;

	return success ;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
	struct inode *inode = NULL ;
	struct file *f = NULL ;
	struct thread *cur = thread_current() ;
	struct dir *d ;
	char *resto ;
	d = dir_processarCaminho(name, &resto, NULL) ;
	if (d == NULL)
		return false ;

	lock_acquire(&d->inode->lock) ;
	bool removido = d->inode->removed ;
	lock_release(&d->inode->lock) ;
	if (removido)
		goto saida ;

	if (resto != NULL)
	{
		dir_lookup(d, resto, &inode) ;
		f = file_open(inode) ;

	saida:
		if (d != cur->currentDir)
			dir_close(d) ;
		free(resto) ;
	}
	else
		f = file_open(d->inode) ;

	return f ;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
	bool success = false ;
	struct thread *cur = thread_current() ;
	struct dir *d ;
	struct dir *anterior = NULL ;
	char *resto ;
	d = dir_processarCaminho(name, &resto, &anterior) ;
	if (d == NULL)
		return false ;

	if (resto != NULL)
	{
		success = dir_remove(d, resto) ;
	}
	else
	{
		lock_acquire(&d->inode->lock) ;
		bool removido = d->inode->removed ;
		lock_release(&d->inode->lock) ;
		if (removido)
			goto saida ;

		char n[NAME_MAX + 1] ;
		d->pos = 0 ;
		while (dir_readdir(d, n))
		{
			if (strcmp(n, ".") != 0
				&& strcmp(n, "..") != 0)
			{
				goto saida ;
			}
		}

		if (d->inode->sector == ROOT_DIR_SECTOR)
			goto saida ;

		char *str = strrchr(name, '/') ;
		if (str != NULL)
			str++ ;
		success = dir_remove(anterior, (str != 0) ? str : name) ;
	}

saida:
	if (d != cur->currentDir)
		dir_close(d) ;
	if (anterior != NULL && anterior != cur->currentDir)
		dir_close(anterior) ;
	free(resto) ;

	return success ;
}

/* Formats the file system. */
static void
do_format (void)
{
	printf("Formatting file system...") ;
	free_map_create() ;
	if (!dir_createRoot())
		PANIC("root directory creation failed") ;
	free_map_close() ;
	printf("done.\n") ;
}
