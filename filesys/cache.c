#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"
#include <debug.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/interrupt.h"
#include <debug.h>

/*
 * Quantidade de setores de 512 bytes no cache
 */
#define CACHE_QUANT_SETORES 60

/*
 * Quantidade máxima de setores sujos que uma chamada write behind irá tentar escrever
 */
#define WRITE_BEHIND_QUANT_SETORES 4

/*
 * Milisegundos que write behind bloqueia
 */
#define WRITE_BEHIND_SLEEP 200

/*
 * Milisegundos que escrever bloqueia
 */
#define ESCREVER_SLEEP 1000

/*
 * Valor que indica que um desc foi removido da LRU. A função list_remove(elem) liga
 * o elem->prev no elem->next, e olhando apenas para elem não tem como saber se ele foi
 * removido da lista. Esse foi um valor sentinela que eu criei, para indicar que elem foi
 * removido da lista LRU.
 */
#define REMOVIDO_LRU (struct list_elem*)0x1111

/*
 * Indica que o setor de 512 bytes foi escrito
 */
#define DESC_FLAG_DIRTY 0x01

/*
 * Descritor de um bloco do cache
 */
struct descSetor
{
	block_sector_t idx ;			/* index do setor do disco */
	struct lock lock ;				/* lock que protege as variáveis de estado */
	struct condition okLer ;		/* condição desbloqueia leitores */
	struct condition okEscrever ;	/* condição desbloqueia escritores */
	struct list_elem lElem ;		/* encadeado na listaLRU */
	struct hash_elem hElem ;		/* encadeado na hashDescs */
	int flags ;						/* flags */
	int leitoresAtivos ;			/* quantidade de leitores ativos */
	int leitoresBloqueados ;		/* quantidade de leitores bloqueados */
	int escritoresAtivos ;			/* quantidade de escritores ativos */
	int escritoresBloqueados ;		/* quantidade de escritores bloqueados */
} ;

/*
 * struct de 512 bytes para acessos em endereços multiplos de 512 bytes.
 */
struct setorCache
{
	char c[BLOCK_SECTOR_SIZE] ;
} ;

/*
 * Representa um setor que será processado pela thread readAhead.
 */
struct itemListaSetores
{
	block_sector_t idx ;		/* indice do setor para leitura */
	struct list_elem elem ;		/* encadeado na listaReadAhead */
} ;

/*
 *
 */
struct bufferCache
{
	struct setorCache set ;
	block_sector_t idx ;
};


static void lockAcquireLer(struct descSetor *desc) ;
static void lockReleaseLer(struct descSetor *desc) ;
static void lockAcquireEscrever(struct descSetor *desc) ;
static void lockReleaseEscrever(struct descSetor *desc) ;

static struct descSetor *buscarSetor(block_sector_t idx, bool flagLerDisco,
									 bool flagLockEscrever, bool flagRemoverLRU,
									 bool flagChamadaReadAhead) ;
static unsigned hashFunc(const struct hash_elem *e, void *aux) ;
static bool compFunc(const struct hash_elem *a, const struct hash_elem *b, void *aux) ;
static thread_func readAhead NO_RETURN ;
static void enfileirarReadAhead(block_sector_t idx) ;
static thread_func writeBehind NO_RETURN ;
static thread_func escrever NO_RETURN ;

static bool cacheInicializado = 0 ;
static struct setorCache setores[CACHE_QUANT_SETORES] ;
static struct descSetor descs[CACHE_QUANT_SETORES] ;

static struct hash hashDescs ;
static struct lock lockHash ;
static struct list listaLRU ;
static struct list listaReadAhead ;
static struct lock lockListaReadAhead ;
static struct semaphore semaReadAhead ;

/*
 * Inicializa o módulo do cache
 */
void cache_init(void)
{
	list_init(&listaLRU) ;
	hash_init(&hashDescs, hashFunc, compFunc, NULL) ;
	lock_init(&lockHash) ;
	list_init(&listaReadAhead) ;
	lock_init(&lockListaReadAhead) ;
	sema_init(&semaReadAhead, 0) ;

	for (int i = 0 ; i < CACHE_QUANT_SETORES; i++)
	{
		descs[i].flags = 0 ;
		descs[i].leitoresAtivos = 0 ;
		descs[i].leitoresBloqueados = 0 ;
		descs[i].escritoresAtivos = 0 ;
		descs[i].escritoresBloqueados = 0 ;
		lock_init(&descs[i].lock) ;
		cond_init(&descs[i].okLer) ;
		cond_init(&descs[i].okEscrever) ;
		list_push_front(&listaLRU, &descs[i].lElem) ;
	}

	thread_create("readAhead", PRI_DEFAULT, readAhead, NULL) ;
	thread_create("writeBehind", PRI_DEFAULT, writeBehind, NULL) ;
	thread_create("escrever", PRI_DEFAULT, escrever, NULL) ;
	cacheInicializado = 1 ;
}

/*
 * Função é usada quando se deseja fazer uma operação de leitura/escrita no inode
 * contido no inodeSector. Irá buscar no cache o setor inodeSector, lendo-o do disco
 * caso necessário, e retornar o endereço do bloco do cache que contém o setor inodeSector,
 * além de obter o read/write lock do bloco.
 */
struct inode_disk *cache_getInode(block_sector_t inodeSector, bool flagEscrever)
{
	if (!cacheInicializado)
	{
		struct bufferCache *buf = malloc(sizeof(struct bufferCache)) ;
		block_read(fs_device, inodeSector, &buf->set) ;
		buf->idx = inodeSector ;
		return (struct inode_disk*) &buf->set ;
	}

	struct descSetor *desc = buscarSetor(inodeSector, 1, flagEscrever, 1, 0) ;

	return (struct inode_disk*) setores + (desc - descs) ;
}

/*
 * Função é chamada no término de uma operação de leitura/escrita em um struct inode_disk*
 * préviamente retornado por cache_getInode(), que é a base de um bloco do cache aonde contém
 * um inode. Devolve o read/write lock do bloco, e recoloca o desc na LRU
 * caso ele esteja fora.
 */
void cache_releaseInode(struct inode_disk *inode, bool flagEscrever)
{
	if (!cacheInicializado)
	{
		if (flagEscrever)
			block_write(fs_device, ((struct bufferCache*)inode)->idx, inode) ;

		free(inode) ;
		return ;
	}

	struct descSetor *desc = descs + ((struct setorCache*)inode - setores) ;

	if (flagEscrever)
	{
		desc->flags |= DESC_FLAG_DIRTY ;
		lockReleaseEscrever(desc) ;
	}
	else
		lockReleaseLer(desc) ;

	lock_acquire(&lockHash) ;
	if (desc->lElem.next == REMOVIDO_LRU)
		list_push_front(&listaLRU, &desc->lElem) ;
	lock_release(&lockHash) ;
}

/*
 * Função é usada quando se deseja fazer uma operação de leitura/escrita no setor idx.
 * Irá buscar no cache o setor idx, lendo-o do disco caso necessário, e retornar o endereço
 * do bloco do cache que contém o setor idx, além de obter o read/write lock do bloco.
 * Essa função é usada exclusivamente no processo de caminhar pelos ponteiros do inode,
 * aonde o setor idx será um setor com 128 block_sector_t, e a função retorna block_sector_t*
 * para poder usar o endereço de retorno sem precisar ficar dando cast.
 */
block_sector_t *cache_getSetor(block_sector_t idx, bool flagEscrever)
{
	if (!cacheInicializado)
	{
		struct bufferCache *buf = malloc(sizeof(struct bufferCache)) ;
		block_read(fs_device, idx, &buf->set) ;
		buf->idx = idx ;
		return (block_sector_t*)&buf->set ;
	}

	struct descSetor *desc = buscarSetor(idx, 1, flagEscrever, 1, 0) ;

	return (block_sector_t*) (setores + (desc - descs)) ;
}

/*
 * Função é chamada no término de uma operação de leitura/escrita em um block_sector_t*
 * préviamente retornado por cache_getSetor(), que é a base de um bloco do cache aonde contém
 * 128 block_sector_t. Devolve o read/write lock do bloco, e recoloca o desc na LRU caso ele
 * esteja fora.
 */
void cache_releaseSetor(block_sector_t *setor, bool flagEscrever)
{
	if (!cacheInicializado)
	{
		if (flagEscrever)
			block_write(fs_device, ((struct bufferCache*)setor)->idx, setor) ;

		free(setor) ;
		return ;
	}

	struct descSetor *desc = descs + ((struct setorCache*)setor - setores) ;

	if (flagEscrever)
	{
		desc->flags |= DESC_FLAG_DIRTY ;
		lockReleaseEscrever(desc) ;
	}
	else
		lockReleaseLer(desc) ;

	lock_acquire(&lockHash) ;
	if (desc->lElem.next == REMOVIDO_LRU)
		list_push_front(&listaLRU, &desc->lElem) ;
	lock_release(&lockHash) ;
}

/*
 * Implementação de um read/write lock (na forma de um monitor) que favorece escritores.
 * Os 4 inteiros expressam o estado do read/write lock, desc->lock protege o acesso aos 4 inteiros,
 * e a idéia é sempre pegar o desc->lock, olhar as variáveis para decidir o que vai ser feito,
 * escrever a decisão tomada, seguir em frente ou bloquear.
 * - Leitores simultâneos sem limite
 * - Apenas 1 escritor por vez
 * - Leitor segue em frente caso escritoresAtivos == 0 e escritoresBloqueados == 0
 * - Escritor segue em frente caso leitoresAtivos == 0 e escritoresAtivos == 0
 * - 1 Leitor devolvendo o lock desbloqueia 1 Escritor caso leitoresAtivos == 0 e escritoresBloqueados > 0
 * - 1 Escritor devolvendo o lock desbloqueia 1 Escritor caso escritoresBloqueados > 0
 * - 1 Escritor devolvendo o lock desbloqueia todos Leitores caso leitoresBloqueados > 0 e escritoresBloqueados == 0
 */

static void lockAcquireLer(struct descSetor *desc)
{
	lock_acquire(&desc->lock) ;
	while (desc->escritoresAtivos > 0
		   || desc->escritoresBloqueados > 0)
	{
		desc->leitoresBloqueados++ ;
		cond_wait(&desc->okLer, &desc->lock) ;
		desc->leitoresBloqueados-- ;
	}
	desc->leitoresAtivos++ ;
	lock_release(&desc->lock) ;
}


static void lockReleaseLer(struct descSetor *desc)
{
	lock_acquire(&desc->lock) ;
	desc->leitoresAtivos-- ;
	if (desc->leitoresAtivos == 0
		&& desc->escritoresBloqueados > 0)
	{
		cond_signal(&desc->okEscrever, &desc->lock) ;
	}
	lock_release(&desc->lock) ;
}


static void lockAcquireEscrever(struct descSetor *desc)
{
	lock_acquire(&desc->lock) ;
	while(desc->escritoresAtivos > 0
		  || desc->leitoresAtivos > 0)
	{
		desc->escritoresBloqueados++ ;
		cond_wait(&desc->okEscrever, &desc->lock) ;
		desc->escritoresBloqueados-- ;
	}
	desc->escritoresAtivos++ ;
	lock_release(&desc->lock) ;
}


static void lockReleaseEscrever(struct descSetor *desc)
{
	lock_acquire(&desc->lock) ;
	desc->escritoresAtivos-- ;
	if (desc->escritoresBloqueados > 0)
	{
		cond_signal(&desc->okEscrever, &desc->lock) ;
	}
	else if (desc->leitoresBloqueados > 0)
	{
		cond_broadcast(&desc->okLer, &desc->lock) ;
	}
	lock_release(&desc->lock) ;
}

/*
 * Escreve no disco todos os blocos sujos do cache.
 */
void cache_escreverDisco(void)
{
	if (!cacheInicializado)
		return ;

	for (int i = 0 ; i < CACHE_QUANT_SETORES ; i++)
	{
		lockAcquireLer(&descs[i]) ;
		if ((descs[i].flags & DESC_FLAG_DIRTY) != 0)
		{
			block_write(fs_device, descs[i].idx, setores + ((descs + i) - descs)) ;
			descs[i].flags &= ~DESC_FLAG_DIRTY ;
		}
		lockReleaseLer(&descs[i]) ;
	}
}

/*
 * Função é a alma do cache, todas operações passam por aqui. A idéia é retornar
 * o descritor que contém o setor idx, segurando o read/write lock do bloco. Caso idx
 * não esteja no cache, função irá chutar o fim da LRU, e mapear idx nesse bloco, lendo idx
 * do disco caso necessário. As 4 flags ditam o comportamento da função, pois diferentes
 * operações exigem diferentes comportamentos.
 *
 * flagLerDisco == 1 : caso idx não esteja no cache, ler do disco idx no bloco que levou evict.
 * flagLerDisco == 0 : caso idx não esteja no cache, escrever 512 zeros no bloco que levou evict.
 *
 * flagLockEscrever == 1 : retornar da função segurando o lock de escrita do bloco que contém idx.
 * flagLockEscrever == 0 : retornar da função segurando o lock de leitura do bloco que contém idx.
 *
 * flagRemoverLRU == 1 : retornar da função com o descritor do bloco que contém idx fora da listaLRU.
 * flagRemoverLRU == 0 : retornar da função com o descritor do bloco que contém idx na cabeça da listaLRU.
 *
 * flagChamadaReadAhead == 1 : estou dentro de uma chamada readAhead, portanto não retornar da função segurando
 * o read/write lock do bloco, pois readAhead apenas tem a função de carregar um bloco no cache.
 * flagChamadaReadAhead == 0 : não estou dentro de uma chamada readAhead, portanto retornar da função segurando
 * o read/write lock do bloco, pois vou ler/escrever no bloco.
 */
static struct descSetor *buscarSetor(block_sector_t idx,
									 bool flagLerDisco,
									 bool flagLockEscrever,
									 bool flagRemoverLRU,
									 bool flagChamadaReadAhead)
{
	block_sector_t idxChutado ;
	struct descSetor *desc ;
	struct descSetor aux ;
	aux.idx = idx ;

comeco:
	lock_acquire(&lockHash) ;

	struct hash_elem *e = hash_find(&hashDescs, &aux.hElem) ;
	if (e != NULL)
	{
		desc = hash_entry(e, struct descSetor, hElem) ;

		if (flagChamadaReadAhead)
		{
			lock_release(&lockHash) ;
			return NULL ;
		}

		if (desc->lElem.next != REMOVIDO_LRU)
		{
			list_remove(&desc->lElem) ;
			desc->lElem.next = REMOVIDO_LRU ;
			desc->lElem.prev = REMOVIDO_LRU ;
		}
		if (!flagRemoverLRU)
			list_push_front(&listaLRU, &desc->lElem) ;

		lock_release(&lockHash) ;

		if (flagLockEscrever)
			lockAcquireEscrever(desc) ;
		else
			lockAcquireLer(desc) ;

		if (desc->idx != idx)
		{
			if (flagLockEscrever)
				lockReleaseEscrever(desc) ;
			else
				lockReleaseLer(desc) ;

			goto comeco ;
		}
	}
	else
	{
		desc = list_entry(list_back(&listaLRU), struct descSetor, lElem) ;

		list_remove(&desc->lElem) ;
		desc->lElem.next = REMOVIDO_LRU ;
		desc->lElem.prev = REMOVIDO_LRU ;
		if (!flagRemoverLRU)
			list_push_front(&listaLRU, &desc->lElem) ;

		hash_delete(&hashDescs, &desc->hElem) ;
		lockAcquireEscrever(desc) ;
		idxChutado = desc->idx ;
		desc->idx = idx ;
		hash_insert(&hashDescs, &desc->hElem) ;

		if ((desc->flags & DESC_FLAG_DIRTY) != 0)
		{
			block_write(fs_device, idxChutado, setores + (desc - descs)) ;
			desc->flags &= ~DESC_FLAG_DIRTY ;
		}

		if (flagLerDisco)
			block_read(fs_device, desc->idx, setores + (desc - descs)) ;
		else
			memset(setores + (desc - descs), 0, BLOCK_SECTOR_SIZE) ;

		lock_release(&lockHash) ;

		if (flagChamadaReadAhead)
		{
			lockReleaseEscrever(desc) ;
			return NULL ;
		}

		if (!flagLockEscrever)
		{
			lockReleaseEscrever(desc) ;
			lockAcquireLer(desc) ;
			if (desc->idx != idx)
			{
				lockReleaseLer(desc) ;
				goto comeco ;
			}
		}
	}

	return desc ;
}

/*
 * Le o setor idx. Busca no cache o setor idx, escreve em dest os 512 bytes
 * que estão no cache.
 */
void cache_lerSetor(block_sector_t idx, void *dest)
{
	if (!cacheInicializado)
	{
		block_read(fs_device, idx, dest) ;
		return ;
	}

	struct descSetor *desc = buscarSetor(idx, 1, 0, 0, 0) ;
	memcpy(dest, setores + (desc - descs), BLOCK_SECTOR_SIZE) ;
	lockReleaseLer(desc) ;

	if (idx + 1 < block_size(fs_device))
		enfileirarReadAhead(idx + 1) ;
}

/*
 * Le um pedaço do setor idx. Busca no cache o setor idx, escreve em dest
 * chunk_size bytes que estão em set + sector_ofs.
 */
void cache_lerSetorParcial(block_sector_t idx, void *dest, off_t sector_ofs, off_t chunk_size)
{
	if (!cacheInicializado)
	{
		void *bounce = malloc(BLOCK_SECTOR_SIZE) ;
		block_read(fs_device, idx, bounce) ;
		memcpy(dest, bounce + sector_ofs, chunk_size) ;
		free(bounce) ;
		return ;
	}

	struct descSetor *desc = buscarSetor(idx, 1, 0, 0, 0) ;
	void *set = setores + (desc - descs) ;
	memcpy(dest, set + sector_ofs, chunk_size) ;
	lockReleaseLer(desc) ;

	if (idx + 1 < block_size(fs_device))
		enfileirarReadAhead(idx + 1) ;
}

/*
 * Escreve o setor idx. Busca no cache o setor idx, escreve os 512 bytes que estão em
 * src no bloco do cache.
 */
void cache_escreverSetor(block_sector_t idx, const void *src)
{
	if (!cacheInicializado)
	{
		block_write(fs_device, idx, src) ;
		return ;
	}

	struct descSetor *desc = buscarSetor(idx, 0, 1, 0, 0) ;
	memcpy(setores + (desc - descs), src, BLOCK_SECTOR_SIZE) ;
	desc->flags |= DESC_FLAG_DIRTY ;
	lockReleaseEscrever(desc) ;

	if (idx + 1 < block_size(fs_device))
		enfileirarReadAhead(idx + 1) ;
}

/*
 * Escreve um pedaço do setor idx. Busca no cache o setor idx, escreve chunk_size bytes que estão
 * em src, no endereço set + sector_ofs.
 */
void cache_escreverSetorParcial(block_sector_t idx, const void *src, off_t sector_ofs, off_t chunk_size)
{
	if (!cacheInicializado)
	{
		void *bounce = malloc(BLOCK_SECTOR_SIZE) ;

		if (sector_ofs > 0 || chunk_size < BLOCK_SECTOR_SIZE - sector_ofs)
			block_read(fs_device, idx, bounce) ;
		else
			memset(bounce, 0, BLOCK_SECTOR_SIZE) ;

		memcpy(bounce + sector_ofs, src, chunk_size) ;
		block_write(fs_device, idx, bounce) ;
		free(bounce) ;
		return ;
	}

	struct descSetor *desc = buscarSetor(idx, 1, 1, 0, 0) ;
	void *set = setores + (desc - descs) ;
	memcpy(set + sector_ofs, src, chunk_size) ;
	desc->flags |= DESC_FLAG_DIRTY ;
	lockReleaseEscrever(desc) ;

	if (idx + 1 < block_size(fs_device))
		enfileirarReadAhead(idx + 1) ;
}

/*
 * Adiciona um item na lista de setores da thread readAhead
 */
static void enfileirarReadAhead(block_sector_t idx)
{
	struct itemListaSetores *set = malloc(sizeof(struct itemListaSetores)) ;
	if (set == NULL)
		return ;
	set->idx = idx ;

	lock_acquire(&lockListaReadAhead) ;
	list_push_back(&listaReadAhead, &set->elem) ;
	lock_release(&lockListaReadAhead) ;

	sema_up(&semaReadAhead) ;
}

/*
 * Pega o próximo item da listaReadAhead e carrega no cache.
 */
static void readAhead(void *param UNUSED)
{
	while (1)
	{
		sema_down(&semaReadAhead) ;

		lock_acquire(&lockListaReadAhead) ;
		struct list_elem *e = list_pop_front(&listaReadAhead) ;
		lock_release(&lockListaReadAhead) ;

		struct itemListaSetores *set = list_entry(e, struct itemListaSetores, elem) ;
		buscarSetor(set->idx, 1, 0, 0, 1) ;
		free(set) ;
	}
}

/*
 * Tenta escrever WRITE_BEHIND_QUANT_SETORES sujos a cada iteração, bloqueando
 * WRITE_BEHIND_SLEEP entre as iterações.
 */
static void writeBehind(void *param UNUSED)
{
	while (1)
	{
		timer_msleep(WRITE_BEHIND_SLEEP) ;
		if (!cacheInicializado)
			continue ;

		struct list_elem *e ;
		int i = 0 ;

		lock_acquire(&lockHash) ;

		for (e = list_rbegin(&listaLRU) ;
			 e != list_rend(&listaLRU) && i < WRITE_BEHIND_QUANT_SETORES ; )
		{
			struct descSetor *desc = list_entry(e, struct descSetor, lElem) ;

			if ((desc->flags & DESC_FLAG_DIRTY) != 0)
			{
				lock_release(&lockHash) ;
				lockAcquireLer(desc) ;
				if ((desc->flags & DESC_FLAG_DIRTY) == 0)
				{
					lockReleaseLer(desc) ;
					lock_acquire(&lockHash) ;
					goto proximo ;
				}
				block_write(fs_device, desc->idx, setores + (desc - descs)) ;
				desc->flags &= ~DESC_FLAG_DIRTY ;
				i++ ;
				lockReleaseLer(desc) ;
				lock_acquire(&lockHash) ;
			}

		proximo:
			if (e->prev != REMOVIDO_LRU)
				e = list_prev(e) ;
			else
				break ;
		}

		lock_release(&lockHash) ;
	}
}

/*
 * Escreve todos os blocos sujos do cache e bloqueia por ESCREVER_SLEEP milisegundos a cada iteração.
 */
static void escrever(void *param UNUSED)
{
	while (1)
	{
		timer_msleep(ESCREVER_SLEEP) ;
		cache_escreverDisco() ;
	}
}

/*
 * "Hasheia" um descritor para decidir aonde coloca-lo na hash table.
 * Nesse caso não faz nada complicado, o resultado do hashing é o idx do bloco.
 */
static unsigned hashFunc(const struct hash_elem *e, void *aux UNUSED)
{
	return hash_entry(e, struct descSetor, hElem)->idx ;
}

/*
 * Comparador entre duas entradas da hashDescs. Retorna verdadeiro se a < b, falso caso a >= b.
 */
static bool compFunc(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
	return hash_entry(a, struct descSetor, hElem)->idx < hash_entry(b, struct descSetor, hElem)->idx ;
}
