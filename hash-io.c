#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "git-compat-util.h"
#include "hash-io.h"
#include "vmac.h"

const unsigned char *VMAC_KEY = (const unsigned char*) "abcdefghijklmnop";

extern ssize_t write_in_full(int fd, const void *buf, size_t count);

static int write_buf_with_hash(struct hash_context *ctx, int fd)
{
	unsigned int buffered = ctx->write_buffer_len;
	switch (ctx->ty) {
	case HASH_IO_VMAC:
		vhash_update(ctx->write_buffer, buffered, ctx->c.vc);
		break;
	case HASH_IO_SHA1:
		git_SHA1_Update(ctx->c.sc, ctx->write_buffer, buffered);
		break;
	default:
		error("Bad hash type");
	}

	if (write_in_full(fd, ctx->write_buffer, buffered) != buffered)
		return -1;
	ctx->write_buffer_len = 0;
	return 0;
}

int write_with_hash(struct hash_context *ctx, int fd, const void *data, unsigned int len)
{
	while (len) {
		unsigned int buffered = ctx->write_buffer_len;
		unsigned int partial = HASH_IO_WRITE_BUFFER_SIZE - buffered;
		if (partial > len)
			partial = len;
		memcpy(ctx->write_buffer + buffered, data, partial);
		buffered += partial;
		if (buffered == HASH_IO_WRITE_BUFFER_SIZE) {
			ctx->write_buffer_len = buffered;
			if (write_buf_with_hash(ctx, fd))
				return -1;
			buffered = 0;
		}
		ctx->write_buffer_len = buffered;
		len -= partial;
		data = (char *) data + partial;
	}
	return 0;
}

void vmac_final(unsigned char *buf, vmac_ctx_t *ctx)
{
	uint64_t tagl;
	uint64_t tagh = htonll(vhash(NULL, 0, &tagl, ctx));
	tagl = htonll(tagl);

	memcpy(buf, &tagl, 8);
	memcpy(buf + 8, &tagh, 8);
	memset(buf + 16, 0, 4);
}

static int write_with_vmac_flush(struct hash_context *ctx, int fd)
{
	unsigned int left = ctx->write_buffer_len;

	if (left) {
		int unaligned = left % VMAC_NHBYTES;
		int bytes_to_hash = left;
		ctx->write_buffer_len = 0;
		if (unaligned) {
			int zeros = VMAC_NHBYTES - unaligned;
			memset(ctx->write_buffer + left, 0, zeros);
			bytes_to_hash += zeros;
		}
		vhash_update(ctx->write_buffer, bytes_to_hash, ctx->c.vc);
	}

	/* Flush first if not enough space for SHA1 signature */
	if (left + 20 > HASH_IO_WRITE_BUFFER_SIZE) {
		if (write_in_full(fd, ctx->write_buffer, left) != left)
			return -1;
		left = 0;
	}

	/* Append the VMAC signature at the end */
	vmac_final(ctx->write_buffer + left, ctx->c.vc);
	left += 20;
	return (write_in_full(fd, ctx->write_buffer, left) != left) ? -1 : 0;
}

static int write_with_sha1_flush(struct hash_context *ctx, int fd)
{
	unsigned int left = ctx->write_buffer_len;

	if (left) {
		git_SHA1_Update(ctx->c.sc, ctx->write_buffer, left);
	}

	/* Flush first if not enough space for SHA1 signature */
	if (left + 20 > HASH_IO_WRITE_BUFFER_SIZE) {
		if (write_in_full(fd, ctx->write_buffer, left) != left)
			return -1;
		left = 0;
	}

	/* Append the SHA1 signature at the end */
	git_SHA1_Final(ctx->write_buffer + left, ctx->c.sc);
	left += 20;
	return (write_in_full(fd, ctx->write_buffer, left) != left) ? -1 : 0;
}


int write_with_hash_flush(struct hash_context *ctx, int fd) {
	switch (ctx->ty) {
	case HASH_IO_VMAC:
		return write_with_vmac_flush(ctx, fd);
		break;
	case HASH_IO_SHA1:
		return write_with_sha1_flush(ctx, fd);
		break;
	default:
		error("Bad hash type");
		return -1;
	}

}

static unsigned char extra[VMAC_NHBYTES];

void vmac_update_unaligned(const void *buf, unsigned int len, vmac_ctx_t *ctx)
{
	size_t first_len = len;
	size_t extra_bytes = first_len % VMAC_NHBYTES;

	if (first_len - extra_bytes)
		vhash_update(buf, first_len - extra_bytes, ctx);

	if (extra_bytes) {
		first_len -= extra_bytes;
		memcpy(extra, (const unsigned char *) buf + first_len,
		       extra_bytes);
		memset(extra + extra_bytes, 0, VMAC_NHBYTES - extra_bytes);
		vhash_update(extra, VMAC_NHBYTES, ctx);
	}
}

void hash_context_init(struct hash_context *ctx, enum hash_io_type type)
{
	ctx->ty = type;
	ctx->write_buffer_len = 0;
	switch (type) {
	case HASH_IO_VMAC:
		ctx->c.vc = xmalloc(sizeof *ctx->c.vc);
		vmac_set_key(VMAC_KEY, ctx->c.vc);
		break;
	case HASH_IO_SHA1:
		ctx->c.sc = xmalloc(sizeof *ctx->c.sc);
		git_SHA1_Init(ctx->c.sc);
		break;
	default:
		error("Bad hash type");
	}
}

void hash_context_release(struct hash_context *ctx)
{
	switch (ctx->ty) {
	case HASH_IO_VMAC:
		free(ctx->c.vc);
		break;
	case HASH_IO_SHA1:
		free(ctx->c.sc);
		break;
	default:
		error("Bad hash type");
	}
}
