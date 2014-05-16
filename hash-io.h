#ifndef HASH_IO_H
#define HASH_IO_H

#include "vmac.h"

#include SHA1_HEADER
#ifndef git_SHA_CTX
#define git_SHA_CTX	SHA_CTX
#define git_SHA1_Init	SHA1_Init
#define git_SHA1_Update	SHA1_Update
#define git_SHA1_Final	SHA1_Final
#endif

enum hash_io_type {
	HASH_IO_VMAC,
	HASH_IO_SHA1
};


//must be a multiple of VMAC_NHBYTES
#define HASH_IO_WRITE_BUFFER_SIZE 8192

struct hash_context {
	enum hash_io_type ty;
	union {
		vmac_ctx_t *vc;
		git_SHA_CTX *sc;
	} c;
	unsigned long write_buffer_len;
	unsigned char write_buffer[HASH_IO_WRITE_BUFFER_SIZE];
};

const unsigned char *VMAC_KEY;

void hash_context_init(struct hash_context *ctx, enum hash_io_type ty);
void hash_context_release(struct hash_context *ctx);

int write_with_hash(struct hash_context *context, int fd, const void *data, unsigned int len);
int write_with_hash_flush(struct hash_context *context, int fd);

/* These are some helper functions to make the vmac interface closer
 * to the SHA interface. vmac_update_unaligned is necessary because
 * vmac operates on 128-byte chunks. */

void vmac_update_unaligned(const void *buf, unsigned int len, vmac_ctx_t *context);
void vmac_final(unsigned char *buf, vmac_ctx_t *context);

#endif
