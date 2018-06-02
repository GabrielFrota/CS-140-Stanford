#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"
#include <stdio.h>
#include "threads/thread.h"
#include "threads/synch.h"


/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44


/*
 * Setor de 512 bytes zerados. Usado para quando é dado
 * um read em um setor do arquivo que ainda não foi alocado.
 * Um setor ainda não alocado é obrigatóriamente um setor de zeros,
 * e não é necessário escrever isso no disco. Foi implementado
 * a técnica de "sparse files". O setor só é alocado
 * no disco caso seja feito um write.
 */
static char zeros[BLOCK_SECTOR_SIZE] ;

/*
 * lock da lista de inodes abertos
 */
static struct lock openInodesLock ;


/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
	return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE) ;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. Retorna 0 se o offset pos se refere a um setor de 512 zeros. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
	ASSERT(inode != NULL) ;

	struct inode_disk *ind = cache_getInode(inode->sector, 0) ;
	if (pos < ind->length)
	{
		block_sector_t ret = 0 ;
		block_sector_t idxSetor = pos / BLOCK_SECTOR_SIZE ;

		if (idxSetor < 8)
		{
			ret = ind->setores[idxSetor] ;
			goto saida ;
		}

		if (idxSetor < 8 + 128)
		{
			if (ind->setores[8] == 0)
				goto saida ;

			block_sector_t *idxs = cache_getSetor(ind->setores[8], 0) ;
			ret = idxs[idxSetor - 8] ;
			cache_releaseSetor(idxs, 0) ;
			goto saida ;
		}

		if (idxSetor < 8 + 128 + (128 * 128))
		{
			if (ind->setores[9] == 0)
				goto saida ;

			block_sector_t *idxs = cache_getSetor(ind->setores[9], 0) ;

			if (idxs[(idxSetor - 8 - 128) / 128] == 0)
			{
				cache_releaseSetor(idxs, 0) ;
				goto saida ;
			}

			block_sector_t setorIndirect = idxs[(idxSetor - 8 - 128) / 128] ;
			cache_releaseSetor(idxs, 0) ;
			idxs = cache_getSetor(setorIndirect, 0) ;
			ret = idxs[(idxSetor - 8 - 128) % 128] ;
			cache_releaseSetor(idxs, 0) ;
			goto saida ;
		}

		PANIC("byte_to_sector chegou aonde nao deveria") ;

	saida:
		cache_releaseInode(ind, 0) ;
		return ret ;
	}
	else
	{
		cache_releaseInode(ind, 0) ;
		return -1 ;
	}
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
	list_init(&open_inodes) ;
	lock_init(&openInodesLock) ;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool flagIsDir)
{
	struct inode_disk *disk_inode = NULL ;
	bool ret = 0 ;

	ASSERT(length >= 0) ;

	/* If this assertion fails, the inode structure is not exactly
	one sector in size, and you should fix that. */
	ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE) ;

	disk_inode = cache_getInode(sector, 1) ;

	memset(disk_inode->setores, 0, sizeof(block_sector_t) * 10) ;
	disk_inode->length = length ;
	disk_inode->magic = INODE_MAGIC ;
	disk_inode->flags = (flagIsDir) ? INODE_FLAG_IS_DIR : 0 ;
	size_t setoresQuant = bytes_to_sectors(length) ;

	if (setoresQuant == 0)
	{
		ret = true ;
		goto saida ;
	}

	if (setoresQuant <= 8)
	{
		if (!free_map_alocarNaoContinuo(setoresQuant, disk_inode->setores))
			goto saida ;

		for (size_t i = 0; i < setoresQuant; i++)
			cache_escreverSetor(disk_inode->setores[i], zeros) ;

		ret = true ;
		goto saida ;
	}

	if (setoresQuant <= 8 + 128)
	{
		block_sector_t setoresIndirect = setoresQuant - 8 ;
		block_sector_t setoresZero = setoresIndirect % 128 ;
		block_sector_t *setores = malloc(sizeof(block_sector_t) * (setoresQuant + 1 + setoresZero)) ;
		if (setores == NULL)
			goto saida ;

		if (!free_map_alocarNaoContinuo(setoresQuant + 1, setores))
		{
			free(setores) ;
			goto saida ;
		}

		for (size_t i = 0 ; i < 8 ; i++)
		{
			disk_inode->setores[i] = setores[i] ;
			cache_escreverSetor(setores[i], zeros) ;
		}

		disk_inode->setores[8] = setores[8] ;
		memset(setores + setoresQuant + 1, 0, setoresZero * sizeof(block_sector_t)) ;
		cache_escreverSetor(setores[8], setores + 8 + 1) ;

		for (size_t i = 0; i < setoresIndirect; i++)
			cache_escreverSetor(setores[8 + 1 + i], zeros) ;

		free(setores) ;
		ret = true ;
		goto saida ;
	}

	if (setoresQuant <= 8 + 128 + (128 * 128))
	{
		block_sector_t setoresDoubleIndirect = DIV_ROUND_UP((setoresQuant - 8 - 128), 128) ;
		block_sector_t setoresZero = 128 - ((setoresQuant - 8 - 128) % 128) ;
		size_t setoresAlocar = setoresQuant + 2 + setoresDoubleIndirect ;

		block_sector_t *setores = malloc((setoresAlocar + setoresZero) * sizeof(block_sector_t)) ;
		if (setores == NULL)
			goto saida ;
		memset(setores + setoresAlocar, 0, sizeof(block_sector_t) * setoresZero) ;

		if (!free_map_alocarNaoContinuo(setoresAlocar, setores))
		{
			free(setores) ;
			goto saida ;
		}

		block_sector_t *b = setores ;

		for (size_t i = 0 ; i < 8 ; i++)
		{
			disk_inode->setores[i] = *b++ ;
			cache_escreverSetor(disk_inode->setores[i], zeros) ;
		}

		disk_inode->setores[8] = *b++ ;
		cache_escreverSetor(disk_inode->setores[8], b) ;

		for (size_t i = 0 ; i < 128 ; i++)
			cache_escreverSetor(*b++, zeros) ;

		disk_inode->setores[9] = *b++ ;
		block_sector_t bufferDoubleIndirect[128] ;

		size_t pos = 0 ;
		for ( ; pos < setoresDoubleIndirect - 1 ; pos++)
		{
			bufferDoubleIndirect[pos] = *b++ ;
			cache_escreverSetor(bufferDoubleIndirect[pos], b) ;

			for (size_t i = 0 ; i < 128 ; i++)
				cache_escreverSetor(*b++, zeros) ;
		}

		bufferDoubleIndirect[pos] = *b++ ;
		cache_escreverSetor(bufferDoubleIndirect[pos], b) ;

		for (size_t i = 0 ; i < 128 - setoresZero ; i++)
			cache_escreverSetor(*b++, zeros) ;

		for (size_t i = setoresDoubleIndirect ; i < 128 ; i++)
			bufferDoubleIndirect[i] = 0 ;

		cache_escreverSetor(disk_inode->setores[9], bufferDoubleIndirect) ;
		free(setores) ;
		ret = true ;
		goto saida ;
	}

	PANIC("inode_create chegou aonde nao deveria") ;

saida:
	cache_releaseInode(disk_inode, 1) ;
	return ret ;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
	struct list_elem *e ;
	struct inode *inode ;

	lock_acquire(&openInodesLock) ;

	/* Check whether this inode is already open. */
	for (e = list_begin(&open_inodes) ; e != list_end(&open_inodes) ;
		 e = list_next(e))
	{
		inode = list_entry(e, struct inode, elem) ;

		if (inode->sector == sector)
		{
			inode_reopen(inode) ;
			lock_release(&openInodesLock) ;

			return inode ;
		}
	}

	/* Allocate memory. */
	inode = malloc(sizeof *inode) ;
	if (inode == NULL)
	{
		lock_release(&openInodesLock) ;
		return NULL ;
	}

	/* Initialize. */
	list_push_front(&open_inodes, &inode->elem) ;
	inode->sector = sector ;
	inode->open_cnt = 1 ;
	inode->deny_write_cnt = 0 ;
	inode->removed = false ;
	lock_init(&inode->lock) ;

	lock_release(&openInodesLock) ;

	return inode ;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
	if (inode == NULL)
		return NULL ;

	lock_acquire(&inode->lock) ;
	inode->open_cnt++ ;
	lock_release(&inode->lock) ;

	return inode ;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
	return inode->sector ;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
	/* Ignore null pointer. */
	if (inode == NULL)
		return ;

	lock_acquire(&inode->lock) ;

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0)
	{
		/* Remove from inode list and release lock. */
		lock_acquire(&openInodesLock) ;
		list_remove(&inode->elem) ;
		lock_release(&openInodesLock) ;

		/* Deallocate blocks if removed. */
		if (inode->removed)
		{
			struct inode_disk *ind = cache_getInode(inode->sector, 0) ;

			for (size_t i = 0 ; i < 8 ; i++)
			{
				if (ind->setores[i] != 0)
					free_map_release(ind->setores[i], 1) ;
			}

			if (ind->setores[8] != 0)
			{
				block_sector_t *idxs = cache_getSetor(ind->setores[8], 0) ;

				for (size_t i = 0 ; i < 128 ; i++)
				{
					if (idxs[i] != 0)
						free_map_release(idxs[i], 1) ;
				}
				cache_releaseSetor(idxs, 0) ;
			}

			if (ind->setores[9] != 0)
			{
				block_sector_t *idxs = cache_getSetor(ind->setores[9], 0) ;

				for (size_t i = 0 ; i < 128 ; i++)
				{
					if (idxs[i] != 0)
					{
						block_sector_t *idxs2 = cache_getSetor(idxs[i], 0) ;

						for (size_t j = 0 ; j < 128 ; j++)
						{
							if (idxs2[j] != 0)
								free_map_release(idxs2[j], 1) ;
						}
						cache_releaseSetor(idxs2, 0) ;
					}
				}
				cache_releaseSetor(idxs, 0) ;
			}

			cache_releaseInode(ind, 0) ;
			free_map_release(inode->sector, 1) ;
		}

		lock_release(&inode->lock) ;
		free(inode) ;
	}
	else
		lock_release(&inode->lock) ;
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
	ASSERT(inode != NULL) ;

	lock_acquire(&inode->lock) ;
	inode->removed = true ;
	lock_release(&inode->lock) ;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
	uint8_t *buffer = buffer_ ;
	off_t bytes_read = 0 ;

	while (size > 0)
	{
		/* Disk sector to read, starting byte offset within sector. */
		block_sector_t sector_idx = byte_to_sector(inode, offset) ;
		int sector_ofs = offset % BLOCK_SECTOR_SIZE ;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length(inode) - offset ;
		int sector_left = BLOCK_SECTOR_SIZE - sector_ofs ;
		int min_left = inode_left < sector_left ? inode_left : sector_left ;

		if (sector_idx == (block_sector_t) -1)
			break ;

		/* Number of bytes to actually copy out of this sector. */
		int chunk_size = size < min_left ? size : min_left ;
		if (chunk_size <= 0)
			break ;

		if (sector_idx == 0)
		{
			memcpy(buffer + bytes_read, zeros, chunk_size) ;
		}
		else
		{
			if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
			{
				/* Read full sector directly into caller's buffer. */
				cache_lerSetor(sector_idx, buffer + bytes_read) ;
			}
			else
			{
				/* Read sector into bounce buffer, then partially copy
				 into caller's buffer. */
				cache_lerSetorParcial(sector_idx, buffer + bytes_read, sector_ofs, chunk_size) ;
			}
		}

		/* Advance. */
		size -= chunk_size ;
		offset += chunk_size ;
		bytes_read += chunk_size ;
	}

	return bytes_read ;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
	const uint8_t *buffer = buffer_ ;
	off_t bytes_written = 0 ;
	struct inode_disk *ind = NULL ;

	if (inode->deny_write_cnt)
		return 0 ;

	while (size > 0)
	{
		/* Sector to write, starting byte offset within sector. */
		volatile block_sector_t sector_idx = byte_to_sector(inode, offset) ;
		int sector_ofs = offset % BLOCK_SECTOR_SIZE ;
		int sector_left = BLOCK_SECTOR_SIZE - sector_ofs ;
		/* Number of bytes to actually write into this sector. */
		int chunk_size = size < sector_left ? size : sector_left ;

		if (sector_idx == (block_sector_t) 0
			|| sector_idx == (block_sector_t) -1)
		{
			block_sector_t idxSetor = offset / BLOCK_SECTOR_SIZE ;
			ind = cache_getInode(inode->sector, 1) ;

			if (idxSetor < 8)
			{
				if (ind->setores[idxSetor] == 0)
				{
					if (!free_map_alocarNaoContinuo(1, ind->setores + idxSetor))
						goto saidaErro ;

					cache_escreverSetor(ind->setores[idxSetor], zeros) ;
				}

				sector_idx = ind->setores[idxSetor] ;
			}
			else if (idxSetor < 8 + 128)
			{
				if (ind->setores[8] == 0)
				{
					if (!free_map_alocarNaoContinuo(1, ind->setores + 8))
						goto saidaErro ;

					cache_escreverSetor(ind->setores[8], zeros) ;
				}

				block_sector_t *idxs = cache_getSetor(ind->setores[8], 1) ;

				if (idxs[idxSetor - 8] == 0)
				{
					if (!free_map_alocarNaoContinuo(1, idxs + (idxSetor - 8)))
						goto saidaErro ;

					cache_escreverSetor(idxs[idxSetor - 8], zeros) ;
				}

				sector_idx = idxs[idxSetor - 8] ;
				cache_releaseSetor(idxs, 1) ;
			}
			else if (idxSetor < 8 + 128 + (128 * 128))
			{
				if (ind->setores[9] == 0)
				{
					if (!free_map_alocarNaoContinuo(1, ind->setores + 9))
						goto saidaErro ;

					cache_escreverSetor(ind->setores[9], zeros) ;
				}

				block_sector_t *idxs = cache_getSetor(ind->setores[9], 1) ;

				if (idxs[(idxSetor - 8 - 128) / 128] == 0)
				{
					if (!free_map_alocarNaoContinuo(1, idxs + (idxSetor - 8 - 128) / 128))
						goto saidaErro ;

					cache_escreverSetor(idxs[(idxSetor - 8 - 128) / 128], zeros) ;
				}

				block_sector_t setorIndirect = idxs[(idxSetor - 8 - 128) / 128] ;
				cache_releaseSetor(idxs, 1) ;
				idxs = cache_getSetor(setorIndirect, 1) ;

				if (idxs[(idxSetor - 8 - 128) % 128] == 0)
				{
					if (!free_map_alocarNaoContinuo(1, idxs + (idxSetor - 8 - 128) % 128))
						goto saidaErro ;

					cache_escreverSetor(idxs[(idxSetor - 8 - 128) % 128], zeros) ;
				}

				sector_idx = idxs[(idxSetor - 8 - 128) % 128] ;
				cache_releaseSetor(idxs, 1) ;
			}
			else
				PANIC("inode_write_at chegou aonde nao deveria") ;
		}

		if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
		{
			/* Write full sector directly to disk. */
			cache_escreverSetor(sector_idx, buffer + bytes_written) ;
		}
		else
		{
			/* If the sector contains data before or after the chunk
			 we're writing, then we need to read in the sector
			 first.  Otherwise we start with a sector of all zeros. */
			cache_escreverSetorParcial(sector_idx, buffer + bytes_written, sector_ofs, chunk_size) ;
		}

		/* Advance. */
		size -= chunk_size ;
		offset += chunk_size ;
		bytes_written += chunk_size ;

		if (ind != NULL)
		{
			if (offset > ind->length)
				ind->length = offset ;

			cache_releaseInode(ind, 1) ;
			ind = NULL ;
		}
	}

	return bytes_written ;

saidaErro:
	cache_releaseInode(ind, 1) ;
	return bytes_written ;
}

/* Writes SIZE bytes from BUFFER into FILE,
   starting at offset FILE_OFS in the file.
   Returns the number of bytes actually written,
   which may be less than SIZE if end of file is reached.
   The file's current position is unaffected. */
off_t inode_write_at_semExtend (struct inode *inode, const void *buffer_, off_t size, off_t offset)
{
	const uint8_t *buffer = buffer_ ;
	off_t bytes_written = 0 ;
	struct inode_disk *ind = NULL ;

	if (inode->deny_write_cnt)
		return 0 ;

	while (size > 0)
	{
		/* Sector to write, starting byte offset within sector. */
		volatile block_sector_t sector_idx = byte_to_sector(inode, offset) ;
		int sector_ofs = offset % BLOCK_SECTOR_SIZE ;
		int sector_left = BLOCK_SECTOR_SIZE - sector_ofs ;
		/* Number of bytes to actually write into this sector. */
		int chunk_size = size < sector_left ? size : sector_left ;

		if (sector_idx == (block_sector_t) -1
			|| chunk_size <= 0)
			break ;

		if (sector_idx == (block_sector_t) 0)
		{
			block_sector_t idxSetor = offset / BLOCK_SECTOR_SIZE ;
			ind = cache_getInode(inode->sector, 1) ;

			if (idxSetor < 8)
			{
				if (ind->setores[idxSetor] == 0)
				{
					if (!free_map_alocarNaoContinuo(1, ind->setores + idxSetor))
						goto saidaErro ;

					cache_escreverSetor(ind->setores[idxSetor], zeros) ;
				}

				sector_idx = ind->setores[idxSetor] ;
			}
			else if (idxSetor < 8 + 128)
			{
				if (ind->setores[8] == 0)
				{
					if (!free_map_alocarNaoContinuo(1, ind->setores + 8))
						goto saidaErro ;

					cache_escreverSetor(ind->setores[8], zeros) ;
				}

				block_sector_t *idxs = cache_getSetor(ind->setores[8], 1) ;

				if (idxs[idxSetor - 8] == 0)
				{
					if (!free_map_alocarNaoContinuo(1, idxs + (idxSetor - 8)))
						goto saidaErro ;

					cache_escreverSetor(idxs[idxSetor - 8], zeros) ;
				}

				sector_idx = idxs[idxSetor - 8] ;
				cache_releaseSetor(idxs, 1) ;
			}
			else if (idxSetor < 8 + 128 + (128 * 128))
			{
				if (ind->setores[9] == 0)
				{
					if (!free_map_alocarNaoContinuo(1, ind->setores + 9))
						goto saidaErro ;

					cache_escreverSetor(ind->setores[9], zeros) ;
				}

				block_sector_t *idxs = cache_getSetor(ind->setores[9], 1) ;

				if (idxs[(idxSetor - 8 - 128) / 128] == 0)
				{
					if (!free_map_alocarNaoContinuo(1, idxs + (idxSetor - 8 - 128) / 128))
						goto saidaErro ;

					cache_escreverSetor(idxs[(idxSetor - 8 - 128) / 128], zeros) ;
				}

				block_sector_t setorIndirect = idxs[(idxSetor - 8 - 128) / 128] ;
				cache_releaseSetor(idxs, 1) ;
				idxs = cache_getSetor(setorIndirect, 1) ;

				if (idxs[(idxSetor - 8 - 128) % 128] == 0)
				{
					if (!free_map_alocarNaoContinuo(1, idxs + (idxSetor - 8 - 128) % 128))
						goto saidaErro ;

					cache_escreverSetor(idxs[(idxSetor - 8 - 128) % 128], zeros) ;
				}

				sector_idx = idxs[(idxSetor - 8 - 128) % 128] ;
				cache_releaseSetor(idxs, 1) ;
			}
			else
				PANIC("inode_write_at chegou aonde nao deveria") ;
		}

		if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
		{
			/* Write full sector directly to disk. */
			cache_escreverSetor(sector_idx, buffer + bytes_written) ;
		}
		else
		{
			/* If the sector contains data before or after the chunk
			 we're writing, then we need to read in the sector
			 first.  Otherwise we start with a sector of all zeros. */
			cache_escreverSetorParcial(sector_idx, buffer + bytes_written, sector_ofs, chunk_size) ;
		}

		/* Advance. */
		size -= chunk_size ;
		offset += chunk_size ;
		bytes_written += chunk_size ;

		if (ind != NULL)
		{
			cache_releaseInode(ind, 1) ;
			ind = NULL ;
		}
	}

	return bytes_written ;

saidaErro:
	cache_releaseInode(ind, 1) ;
	return bytes_written ;
}


/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
	lock_acquire(&inode->lock) ;
	inode->deny_write_cnt++ ;
	ASSERT(inode->deny_write_cnt <= inode->open_cnt) ;
	lock_release(&inode->lock) ;
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
	lock_acquire(&inode->lock) ;
	ASSERT(inode->deny_write_cnt > 0) ;
	ASSERT(inode->deny_write_cnt <= inode->open_cnt) ;
	inode->deny_write_cnt-- ;
	lock_release(&inode->lock) ;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
	struct inode_disk *ind = cache_getInode(inode->sector, 0) ;
	off_t ret = ind->length ;
	cache_releaseInode(ind, 0) ;
	return ret ;
}


bool inode_isDirectory(const struct inode *inode)
{
	struct inode_disk *ind = cache_getInode(inode->sector, 0) ;
	bool ret = ind->flags & INODE_FLAG_IS_DIR ;
	cache_releaseInode(ind, 0) ;
	return ret ;
}


block_sector_t inode_getSector(struct inode *inode)
{
	lock_acquire(&inode->lock) ;
	block_sector_t ret = inode->sector ;
	lock_release(&inode->lock) ;
	return ret ;
}
