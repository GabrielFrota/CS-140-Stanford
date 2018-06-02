#ifndef FILESYS_CACHE_H_
#define FILESYS_CACHE_H_

#include <hash.h>
#include "devices/block.h"
#include <list.h>
#include "threads/synch.h"
#include "filesys/off_t.h"
#include "threads/malloc.h"


void cache_init(void) ;
void cache_escreverDisco(void) ;

struct inode_disk *cache_getInode(block_sector_t inodeSector, bool flagEscrever) ;
void cache_releaseInode(struct inode_disk *inode, bool flagEscrever) ;

block_sector_t *cache_getSetor(block_sector_t idx, bool flagEscrever) ;
void cache_releaseSetor(block_sector_t *setor, bool flagEscrever) ;

void cache_lerSetor(block_sector_t idx, void *dest) ;
void cache_lerSetorParcial(block_sector_t idx, void *dest, off_t sector_ofs, off_t chunk_size) ;

void cache_escreverSetor(block_sector_t idx, const void *src) ;
void cache_escreverSetorParcial(block_sector_t idx, const void *src, off_t sector_ofs, off_t chunk_size) ;


#endif /* FILESYS_CACHE_H_ */
