#include "cache.h"
#include "fs_cache.h"
#include "strbuf.h"
#include "hashmap.h"
#include "hash-io.h"

#define FS_CACHE_SIGNATURE 0x4D4F4443	/* "MODC" */

static int fe_entry_cmp(const struct fsc_entry *f1,
			const struct fsc_entry *f2,
			const char *name)
{
	if (f1->pathlen != f2->pathlen)
		return 1;
	name = name ? name : f2->path;
	return ignore_case ? strncasecmp(f1->path, name, f1->pathlen) :
		strncmp(f1->path, name, f1->pathlen);

}

unsigned char fe_dtype(struct fsc_entry *file)
{
	if (fe_is_reg(file)) {
		return DT_REG;
	}
	if (fe_is_dir(file)) {
		return DT_DIR;
	}
	if (fe_is_lnk(file)) {
		return DT_LNK;
	}
	return DT_UNKNOWN;
}

#define FS_CACHE_FORMAT_LB 1
#define FS_CACHE_FORMAT_UB 2

static int verify_hdr(struct fs_cache_header *hdr, unsigned long size)
{
	vmac_ctx_t c;
	unsigned char sha1[20];
	int hdr_version;

	if (hdr->hdr_signature != htonl(FS_CACHE_SIGNATURE)) {
		warning("bad fs_cache signature");
		return -1;
	}
	hdr_version = ntohl(hdr->hdr_version);
	if (hdr_version < FS_CACHE_FORMAT_LB || FS_CACHE_FORMAT_UB < hdr_version) {
		warning("bad fs_cache version %d", hdr_version);
		return -1;
	}

	unsigned char *key = (unsigned char *)"abcdefghijklmnop";
	vmac_set_key(key, &c);
	vmac_update_unaligned(hdr, size - 20, &c);
	vmac_final(sha1, &c);
	if (hashcmp(sha1, (unsigned char *)hdr + size - 20)) {
		warning("bad fs_cache file vmac signature");
		return -1;
	}

	return 0;
}

static struct fsc_entry *create_from_disk(struct fs_cache *fs_cache, struct ondisk_fsc_entry *disk_fe, unsigned long *consumed)
{
	struct fsc_entry *fe;
	int pathlen = strlen(disk_fe->path);

	fe = obstack_alloc(&fs_cache->obs, sizeof(*fe) + pathlen + 1);

	fe->size = ntohl(disk_fe->size);
	fe->mode = ntohl(disk_fe->mode);
	fe->flags = ntohl(disk_fe->flags);

	fe->ctime.sec = ntohl(disk_fe->ctime.sec);
	fe->mtime.sec = ntohl(disk_fe->mtime.sec);
	fe->ctime.nsec = ntohl(disk_fe->ctime.nsec);
	fe->mtime.nsec = ntohl(disk_fe->mtime.nsec);

	fe->ino = ntohl(disk_fe->ino);
	fe->dev = ntohl(disk_fe->dev);

	fe->uid = ntohl(disk_fe->uid);
	fe->gid = ntohl(disk_fe->gid);

	fe->parent = NULL;
	fe->first_child = NULL;
	fe->next_sibling = NULL;
	memcpy(fe->path, disk_fe->path, pathlen + 1);
	fe->pathlen = pathlen;

	hashmap_entry_init(fe, memihash(fe->path, pathlen));
	*consumed = sizeof(*disk_fe) + pathlen + 1;
	return fe;
}

static void copy_fs_cache_entry_to_ondisk(
	struct ondisk_fsc_entry *ondisk,
	struct fsc_entry *fe)
{

	ondisk->size = htonl(fe->size);
	ondisk->mode = htonl(fe->mode);
	ondisk->flags = htonl(fe->flags & ~FE_NEW);

	ondisk->ctime.sec = htonl(fe->ctime.sec);
	ondisk->mtime.sec = htonl(fe->mtime.sec);
	ondisk->ctime.nsec = htonl(fe->ctime.nsec);
	ondisk->mtime.nsec = htonl(fe->mtime.nsec);

	ondisk->ino = htonl(fe->ino);
	ondisk->dev = htonl(fe->dev);

	ondisk->uid = htonl(fe->uid);
	ondisk->gid = htonl(fe->gid);

	memcpy(ondisk->path, fe->path, fe->pathlen + 1);

}

static int fe_write_entry(struct fsc_entry *fe, int fd, struct hash_context *context)
{
	int result;
	static struct ondisk_fsc_entry *ondisk = NULL;
	static size_t max_size = sizeof(*ondisk) + 1 + PATH_MAX;
	size_t size;

	size = sizeof(*ondisk) + fe->pathlen + 1;
	if (size > max_size) {
		max_size = size;
		if (ondisk) {
			ondisk = xrealloc(ondisk, max_size);
			memset(ondisk, 0, max_size);
		}
	}


	if (!ondisk)
		ondisk = xcalloc(1, max_size);

	copy_fs_cache_entry_to_ondisk(ondisk, fe);

	result = write_with_hash(context, fd, ondisk, size);

	return result ? -1 : 0;
}

static int fe_write_entry_recursive(struct fsc_entry *fe, int fd, struct hash_context *c)
{
	if (fe_write_entry(fe, fd, c))
		return error("failed to write some file of fs_cache");
	fe = fe->first_child;
	while (fe) {
		fe_write_entry_recursive(fe, fd, c);
		fe = fe->next_sibling;
	}

	return 0;
}

static char *xstrcpy(char *dest, const char *src)
{
	while ((*dest++ = *src++)) {
	}

	return dest;
}

int write_fs_cache(struct fs_cache *fs_cache)
{
	struct hash_context c;
	struct fs_cache_header *hdr;
	int hdr_size;
	struct stat st;
	int fd;
	const char *path;
	char *cur;
	int string_size;

	path = get_fs_cache_file();

	fd = open(path, O_WRONLY|O_TRUNC|O_CREAT, 0666);
	if (fd < 0)
		die_errno("failed to open fs_cache file %s", path);

	string_size = strlen(fs_cache->last_update) +
		strlen(fs_cache->repo_path) +
		strlen(fs_cache->excludes_file) + 3;

	hdr_size = sizeof(*hdr) + string_size;
	hdr = xmalloc(hdr_size);
	hdr->hdr_signature = htonl(FS_CACHE_SIGNATURE);
	hdr->hdr_version = htonl(fs_cache->version);
	hdr->hdr_entries = htonl(fs_cache->nr);
	hdr->flags = htonl(fs_cache->flags);
	hashcpy(hdr->git_excludes_sha1, fs_cache->git_excludes_sha1);
	hashcpy(hdr->user_excludes_sha1, fs_cache->user_excludes_sha1);
	cur = xstrcpy(hdr->strings, fs_cache->last_update);
	cur = xstrcpy(cur, fs_cache->repo_path);
	cur = xstrcpy(cur, fs_cache->excludes_file);

	hash_context_init(&c, HASH_IO_VMAC);

	if (write_with_hash(&c, fd, hdr, hdr_size) < 0)
		die_errno("failed to write header of fs_cache");

	fe_write_entry_recursive(fs_cache_file_exists(fs_cache, "", 0), fd, &c);
	if (write_with_hash_flush(&c, fd) || fstat(fd, &st))
		return error("Failed to flush/fstat fs_cache file");

	hash_context_release(&c);
	free(hdr);
	return 0;
}

void *mmap_fs_cache(size_t *mmap_size)
{
	struct stat st;
	void *mmap;
	const char *path = get_fs_cache_file();
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return NULL;
		die_errno("fs_cache file open failed");
	}

	if (fstat(fd, &st))
		die_errno("cannot stat the open fs_cache");

	*mmap_size = xsize_t(st.st_size);
	if (*mmap_size < sizeof(struct fs_cache_header) + 20) {
		warning("fs_cache file smaller than expected");
		return NULL;
	}

	mmap = xmmap(NULL, *mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mmap == MAP_FAILED)
		die_errno("unable to map fs_cache file");
	close(fd);
	return mmap;
}

/* Loading the fs_cache can take some time, and we might want to thread
 * it with other loads; we need the last-update time and the repo path
 * to check whether this is a good idea, so this function will preload
 * it.  Note that the caller must free the returned strings.
 */
void fs_cache_preload_metadata(char **last_update, char **repo_path)
{
	size_t mmap_size;
	void *mmap;
	struct fs_cache_header *hdr;
	int version;

	mmap = mmap_fs_cache(&mmap_size);
	if (!mmap) {
		*last_update = *repo_path = NULL;
		return;
	}
	hdr = mmap;
	version = ntohl(hdr->hdr_version);
	if (version < FS_CACHE_FORMAT_LB || FS_CACHE_FORMAT_UB < version) {
		warning("bad fs_cache version %d", version);
		goto unmap;
	}

	*last_update = xstrdup(hdr->strings);
	*repo_path = xstrdup(hdr->strings + strlen(*last_update) + 1);

unmap:
	munmap(mmap, mmap_size);
}

static void write_fs_cache_if_necessary(void)
{
	struct fs_cache *fs_cache = the_index.fs_cache;
	if (fs_cache && fs_cache->needs_write && fs_cache->fully_loaded) {
		write_fs_cache(fs_cache);
		the_index.fs_cache = 0;
	}
}

static void fe_set_parent(struct fsc_entry *fe, struct fsc_entry *parent)
{
	fe->parent = parent;
	fe->next_sibling = fe->parent->first_child;
	fe->parent->first_child = fe;
}

void set_up_parent(struct fs_cache *fs_cache, struct fsc_entry *fe)
{
	char *last_slash;
	int parent_len;
	struct fsc_entry *parent;
	if (fe->pathlen == 0)
		return;

	last_slash = strrchr(fe->path, '/');

	if (last_slash) {
		parent_len = last_slash - fe->path;
	} else {
		parent_len = 0;
	}

	parent = fs_cache_file_exists(fs_cache, fe->path, parent_len);
	if (!parent) {
		die("Missing parent directory for %s", fe->path);
	}
	fe_set_parent(fe, parent);
}

static char *read_string(char **out, char *in)
{
	int len = strlen(in);
	*out = xstrdup(in);
	return in + len + 1;
}

/* Load the modified file cache from disk.  If the cache is corrupt,
 * prints a warning and returns NULL; we can safely recreate it.  If
 * the cache is missing, also returns NULL.  If there is some other
 * problem reading the cache (say it's read-only, or we get an io
 * error), die with an error message. */
struct fs_cache *read_fs_cache(void)
{
	struct fs_cache *fs_cache;
	struct fs_cache_header *hdr;
	int i;
	unsigned int nr;
	void *mmap;
	void *mmap_cur;
	size_t mmap_size;

	mmap = mmap_fs_cache(&mmap_size);
	if (!mmap) {
		return NULL;
	}

	hdr = mmap;
	if (verify_hdr(hdr, mmap_size) < 0)
		goto unmap;

	fs_cache = xcalloc(1, sizeof(*fs_cache));
	obstack_init(&fs_cache->obs);
	nr = ntohl(hdr->hdr_entries);
	fs_cache->flags = ntohl(hdr->flags);
	fs_cache->version = ntohl(hdr->hdr_version);
	hashmap_init(&fs_cache->paths, (hashmap_cmp_fn) fe_entry_cmp, nr);
	fs_cache->nr = 0;
	hashcpy(fs_cache->git_excludes_sha1, hdr->git_excludes_sha1);
	hashcpy(fs_cache->user_excludes_sha1, hdr->user_excludes_sha1);

	mmap_cur = hdr->strings;
	mmap_cur = read_string(&fs_cache->last_update, mmap_cur);
	mmap_cur = read_string(&fs_cache->repo_path, mmap_cur);
	mmap_cur = read_string(&fs_cache->excludes_file, mmap_cur);

	struct fsc_entry *parent_stack[PATH_MAX];
	int parent_top = -1;

	for (i = 0; i < nr; i++) {
		struct ondisk_fsc_entry *disk_fe;
		struct fsc_entry *fe;
		unsigned long consumed;

		disk_fe = (struct ondisk_fsc_entry *) mmap_cur;
		fe = create_from_disk(fs_cache, disk_fe, &consumed);
		/*
		 * We eliminate deleted cache entries on read because
		 * otherwise we have to count them in advance to fill
		 * in nr, and that would be expensive.
		 */
		if (!fe_deleted(fe)) {
			fs_cache_insert(fs_cache, fe);
			if (parent_top == -1) {
				parent_top = 0;
				parent_stack[0] = fe;
			} else {
				char *p = parent_stack[parent_top]->path;
				char *c = fe->path;
				parent_top = 1;
				for (; *p && *c; ++p, ++c) {
					if (*p != *c)
						break;
					if (*p == '/')
						parent_top ++;
				}
				if (*p == 0 && *c == '/')
					parent_top ++;
				parent_stack[parent_top] = fe;
				fe_set_parent(fe, parent_stack[parent_top - 1]);
			}
		}
		mmap_cur += consumed;
	}

	fs_cache->fully_loaded = 1;

	munmap(mmap, mmap_size);

	atexit(write_fs_cache_if_necessary);
	return fs_cache;

unmap:
	munmap(mmap, mmap_size);
	return NULL;
}

struct fs_cache *empty_fs_cache(void)
{
	struct fs_cache *fs_cache = xcalloc(1, sizeof(*fs_cache));
	fs_cache->version = 1;
	fs_cache->needs_write = 1;
	fs_cache->fully_loaded = 1;
	hashmap_init(&fs_cache->paths, (hashmap_cmp_fn) fe_entry_cmp, 1);
	atexit(write_fs_cache_if_necessary);
	return fs_cache;
}

struct fsc_entry *fs_cache_file_exists(const struct fs_cache *fs_cache,
				       const char *name, int namelen)
{
	return fs_cache_file_exists_prehash(fs_cache, name, namelen,
					  memihash(name, namelen));
}

struct fsc_entry *fs_cache_file_exists_prehash(const struct fs_cache *fs_cache, const char *path, int pathlen, unsigned int hash)
{
	struct fsc_entry key;

	hashmap_entry_init(&key, hash);
	key.pathlen = pathlen;
	return hashmap_get(&fs_cache->paths, &key, path);
}

struct fsc_entry *make_fs_cache_entry(const char *path)
{
	return make_fs_cache_entry_len(path, strlen(path));
}

struct fsc_entry *make_fs_cache_entry_len(const char *path, int len)
{
	struct fsc_entry *fe = xcalloc(1, sizeof(*fe) + len + 1);
	fe_set_new(fe);
	memcpy(fe->path, path, len);
	fe->pathlen = len;
	hashmap_entry_init(fe, memihash(fe->path, fe->pathlen));
	return fe;
}

void fs_cache_insert(struct fs_cache *fs_cache, struct fsc_entry *fe)
{
	hashmap_add(&fs_cache->paths, fe);
	fs_cache->nr ++;
}

static void fs_cache_remove_recursive(struct fs_cache *fs_cache,
				    struct fsc_entry *fe)
{
	struct fsc_entry *cur, *next;
	for (cur = fe->first_child; cur; cur = next) {
		fs_cache_remove_recursive(fs_cache, cur);
		next = cur->next_sibling;
		cur->next_sibling = NULL;
		cur->parent = NULL;
		cur->first_child = NULL;
	}

	hashmap_remove(&fs_cache->paths, fe, fe);
	fs_cache->nr --;
}

static void fe_remove_from_parent(struct fsc_entry *fe)
{
	struct fsc_entry *prev, *cur;
	if (fe->parent) {
		prev = NULL;
		for (cur = fe->parent->first_child; cur; cur = cur->next_sibling) {
			if (cur == fe) {
				if (prev)
					prev->next_sibling = fe->next_sibling;
				else
					fe->parent->first_child = fe->next_sibling;
				break;
			}
			prev = cur;
		}
	}
}

void fe_delete_children(struct fsc_entry *fe)
{
	for (fe = fe->first_child; fe; fe = fe->next_sibling) {
		fe_set_deleted(fe);
	}
}

void fe_clear_children(struct fs_cache *fs_cache, struct fsc_entry *fe)
{
	for (fe = fe->first_child; fe; fe = fe->next_sibling) {
		fs_cache_remove(fs_cache, fe);
	}

}

void fe_set_deleted(struct fsc_entry *fe)
{
	fe->flags |= FE_DELETED;
	fe_delete_children(fe);
}

void fs_cache_remove_nonrecursive(struct fs_cache *fs_cache,
				  struct fsc_entry *fe)
{

	hashmap_remove(&fs_cache->paths, fe, fe);
	fs_cache->nr --;

	fe_remove_from_parent(fe);
}

void fs_cache_remove(struct fs_cache *fs_cache,
		   struct fsc_entry *fe)
{

	fs_cache_remove_recursive(fs_cache, fe);

	fe_remove_from_parent(fe);
}

void free_fs_cache(struct fs_cache *fs_cache)
{
	obstack_free(&fs_cache->obs, NULL);
	free(fs_cache->last_update);
	free(fs_cache->repo_path);
	free(fs_cache->excludes_file);
}

void fe_to_stat(struct fsc_entry *fe, struct stat *st)
{
	st->st_mtime = fe->mtime.sec;
	st->st_ctime = fe->ctime.sec;
#ifndef NO_NSEC
#ifdef USE_ST_TIMESPEC
	st->st_mtimespec.tv_nsec = fe->mtime.nsec;
	st->st_ctimespec.tv_nsec = fe->ctime.nsec;
#else
	st->st_mtim.tv_nsec = fe->mtime.nsec;
	st->st_ctim.tv_nsec = fe->ctime.nsec;
#endif
#endif
	st->st_mode  = fe->mode;
	st->st_ino  = fe->ino;
	st->st_dev  = fe->dev;
	st->st_uid  = fe->uid;
	st->st_gid  = fe->gid;
	st->st_size  = fe->size;
}

int is_in_dot_git(const char *name)
{
	char *evil = ".git";
	char *cur = evil;
	while (*name) {
		if (*name == *cur++) {
			name++;
			if (*cur == 0) {
				if (*name == 0 || *name == '/') {
					return 1;
				}
			}
		} else {
			if (*name == '/') {
				cur = evil;
			} else {
				cur = "";
			}
			name++;
		}
	}
	return 0;
}

static int is_path_prefix(const char *putative_parent, const char *fname)
{
	const char* c;
	for (c = putative_parent; *c && *fname; ++c, ++fname) {
		if (*c != *fname) {
			return 0;
		}
	}
	return *c == 0 && (*fname == 0 || *fname == '/');
}

int fs_cache_open(struct fs_cache *fs_cache, const char *fname, int flags)
{
	if (fs_cache && fname[0] != '/' && !is_path_prefix(get_git_dir(), fname)) {
		struct fsc_entry *fe = fs_cache_file_exists(fs_cache, fname, strlen(fname));
		if (!fe || fe_deleted(fe)) {
			errno = ENOENT;
			return -1;
		}
	}
	return open(fname, flags);
}

static const int topological_rank[256] = {
	0, /* slash moved here */ 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
	1 /* slash is special */,
	48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
	63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78,
	79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94,
	95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106,
	107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
	121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
	135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
	149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162,
	163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176,
	177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190,
	191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204,
	205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218,
	219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232,
	233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246,
	247, 248, 249, 250, 251, 252, 253, 254, 255
};

/*
 * Compare fsc_entry structs topologically -- that is, so that parent
 * directories come before their children.
 */
int cmp_fsc_entry(const void *a, const void *b)
{
	struct fsc_entry* const * sa = a;
	struct fsc_entry* const * sb = b;
	const unsigned char* pa = (unsigned char *)(*sa)->path;
	const unsigned char* pb = (unsigned char *)(*sb)->path;
	while (*pa && *pb) {
		int ca = topological_rank[*pa++];
		int cb = topological_rank[*pb++];
		int diff = ca - cb;
		if (diff)
			return diff;
	}
	return topological_rank[*pa] - topological_rank[*pb];
}
