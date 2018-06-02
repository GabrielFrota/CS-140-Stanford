#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/*
 * Cria o diretório root com as entradas "." e "..".
 * Função chamada no processo de formatação do disco do sistema.
 */
bool dir_createRoot(void)
{
	struct dir_entry dot ;
	strlcpy(dot.name, ".", 2) ;
	dot.inode_sector = ROOT_DIR_SECTOR ;
	dot.in_use = true ;

	struct dir_entry dotdot ;
	strlcpy(dotdot.name, "..", 3) ;
	dotdot.inode_sector = ROOT_DIR_SECTOR ;
	dotdot.in_use = true ;

	if (!inode_create(ROOT_DIR_SECTOR, 0, 1))
		return false ;
	struct inode *ind = inode_open(ROOT_DIR_SECTOR) ;
	if (ind == NULL)
		return false ;
	if (inode_write_at(ind, &dot, sizeof(struct dir_entry), 0) != sizeof(struct dir_entry))
		return false ;
	if (inode_write_at(ind, &dotdot, sizeof(struct dir_entry), sizeof(struct dir_entry)) != sizeof(struct dir_entry))
		return false ;

	return true ;
}

/*
Todo caminho vindo de parametro pelo usuário é processado pela funçao dir_processarCaminho(),
que possui a idéia de retornar o ultimo diretório possível de se chegar com aquela string,
o diretório anterior ao último caso desejado, e o que sobrou da string quando o "traversing"
acabou, que indica o pedaço do caminho que não representa diretórios já existentes. Com essas
tres informações é possível realizar todas as operações necessárias. Por exemplo,
a chamada mkdir("/abc") retornará o diretório root como ultimo diretório no caminho, e a string
"abc" de resto. Com isso é possível adicionar a entrada de diretório "abc" no diretório root. Em
seguida, a chamada remove("/abc") retornará o diretório abc como último no caminho, o diretório
root de anterior, e resto == NULL. Com isso é possível ver que o caminho de parametro é 100%
válido (pois resto == NULL) e deletar a entrada "abc" do diretório root.
Um caminho que começa com o caracter '/' inicia no diretório root, um caminho que não começa
com o caracter '/' inicia no thread_current()->currentDir. Inicia-se então um loop, aonde a
idéia é retirar o próximo token delimitado por '/' da string, procurar no diretório atual uma
entrada que tenha nome == token, e abrir o diretório caso o inode encontrado represente
um diretório. Ao sair do loop, tem-se o ultimo diretório do caminho, o diretório anterior
ao último e o resto da string.
*/
struct dir *dir_processarCaminho(const char *caminho, char **resto, struct dir **anterior)
{
	struct thread *cur = thread_current() ;
	struct dir *d ;
	struct inode *ind ;
	size_t len = strlen(caminho) ;
	if (len == 0)
		return NULL ;

	char *str = malloc(len + 1) ;
	if (str == NULL)
		return NULL ;
	strlcpy(str, caminho, len + 1) ;

	if (str[0] == '/')
		d = dir_open_root() ;
	else
	{
		lock_acquire(&cur->currentDir->inode->lock) ;
		bool removido = cur->currentDir->inode->removed ;
		lock_release(&cur->currentDir->inode->lock) ;
		if (removido)
		{
			free(str) ;
			return NULL ;

		}
		d = cur->currentDir ;
	}

	char *savePtr ;
	char *tok ;
	for (tok = strtok_r(str, "/", &savePtr) ;
		tok != NULL ;
		tok = strtok_r(NULL, "/", &savePtr))
	{
		if (dir_lookup(d, tok, &ind))
		{
			if (inode_isDirectory(ind))
			{
				if (anterior != NULL)
					*anterior = d ;
				else
					if (d != cur->currentDir)
						dir_close(d) ;

				d = dir_open(ind) ;
			}
			else
				break ;
		}
		else
			break ;
	}

	if (tok != NULL)
	{
		*resto = malloc(strlen(savePtr) + strlen(tok) + 1) ;
		if (*savePtr != 0)
			*(savePtr - 1) = '/' ;
		strlcpy(*resto, tok, strlen(tok) + 1) ;
	}
	else
		*resto = NULL ;

	free(str) ;
	return d ;
}


/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create(block_sector_t sector, size_t entry_cnt)
{
	return inode_create(sector, entry_cnt * sizeof(struct dir_entry), 1) ;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
	struct dir *dir = malloc(sizeof(struct dir)) ;
	if (inode != NULL && dir != NULL)
	{
		dir->inode = inode ;
		dir->pos = 0 ;
		return dir ;
	}
	else
	{
		inode_close(inode) ;
		free(dir) ;
		return NULL ;
	}
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
	return dir_open(inode_open(ROOT_DIR_SECTOR)) ;
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
	return dir_open(inode_reopen(dir->inode)) ;
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
	struct dir_entry e ;
	size_t ofs ;

	ASSERT(dir != NULL) ;
	ASSERT(name != NULL) ;

	for (ofs = 0 ;
		inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e ;
		ofs += sizeof e)
	{
		if (e.in_use && !strcmp(name, e.name))
		{
			if (ep != NULL)
				*ep = e ;
			if (ofsp != NULL)
				*ofsp = ofs ;
			return true ;
		}
	}
	return false ;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
	struct dir_entry e ;
	off_t ofs ;
	bool success = false ;

	ASSERT(dir != NULL) ;
	ASSERT(name != NULL) ;

	/* Check NAME for validity. */
	if (*name == '\0' || strlen(name) > NAME_MAX)
		return false ;

	/* Check that NAME is not in use. */
	if (lookup(dir, name, NULL, NULL))
		goto done ;

	/* Set OFS to offset of free slot.
	 If there are no free slots, then it will be set to the
	 current end-of-file.

	 inode_read_at() will only return a short read at end of file.
	 Otherwise, we'd need to verify that we didn't get a short
	 read due to something intermittent such as low memory. */
	for (ofs = 0 ; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (!e.in_use)
			break ;

	/* Write slot. */
	e.in_use = true ;
	strlcpy(e.name, name, sizeof e.name) ;
	e.inode_sector = inode_sector ;
	success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e ;

done:
	return success ;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
	struct dir_entry e ;
	struct inode *inode = NULL ;
	bool success = false ;
	off_t ofs ;

	ASSERT(dir != NULL) ;
	ASSERT(name != NULL) ;

	/* Find directory entry. */
	if (!lookup(dir, name, &e, &ofs))
		goto done ;

	/* Open inode. */
	inode = inode_open(e.inode_sector) ;
	if (inode == NULL)
		goto done ;

	/* Erase directory entry. */
	e.in_use = false ;
	if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e)
		goto done ;

	/* Remove inode. */
	inode_remove(inode) ;
	success = true ;

	done:
	inode_close(inode) ;
	return success ;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}
