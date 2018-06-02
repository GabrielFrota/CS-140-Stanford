#ifndef VM_SWAP_H_
#define VM_SWAP_H_

#include <stddef.h>

void swap_init(void) ;
void swap_swapIn(size_t idx, void *kpage) ;
size_t swap_swapOut(void *kpage) ;

#endif /* VM_SWAP_H_ */
