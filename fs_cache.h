#ifndef FS_CACHE_H
#define FS_CACHE_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "compat/obstack.h"

#include "git-compat-util.h"
#include "strbuf.h"
#include "hashmap.h"

#define obstack_chunk_alloc xmalloc
#define obstack_chunk_free free

/* The filesystem cache (fs_cache) stores the state of every file
 * inside the root directory (excluding those in .git).  The state
 * includes whether or not the file exists, as well as most of what
 * lstat returns.
 */

#define fe_is_reg(fe) (S_ISREG((fe)->mode))
#define fe_is_dir(fe) (S_ISDIR((fe)->mode))
#define fe_is_lnk(fe) (S_ISLNK((fe)->mode))

/* Directories get very different treatment generally; the normal bits
 * don't apply to them, since they have no independent existence in
 * git.  Also, they are subject to spooky action at a distance -- if a
 * file called x/a/b/c is created (and added to the index), then x
 * suddenly must get added to the index.
 */

struct fsc_entry {
	struct hashmap_entry ent;
	unsigned int mode;
	off_t size;
	unsigned int flags;
	struct cache_time ctime;
	struct cache_time mtime;
	ino_t ino;
	dev_t dev;
	uid_t uid;
	gid_t gid;
	struct fsc_entry *parent;
	struct fsc_entry *first_child;
	struct fsc_entry *next_sibling;
	int pathlen;
	char path[FLEX_ARRAY];
};

#define FE_DELETED           (1 << 0)

/* Excluded by the standard set of gitexcludes */
#define FE_EXCLUDED          (1 << 8)

/* Not yet saved to disk */
#define FE_NEW               (1 << 10)

void fe_set_deleted(struct fsc_entry *fe);
#define fe_clear_deleted(fe) ((fe)->flags &= ~FE_DELETED)
#define fe_deleted(fe) ((fe)->flags & FE_DELETED)

#define fe_excluded(fe) ((fe)->flags & FE_EXCLUDED)
#define fe_set_excluded(fe) ((fe)->flags |= FE_EXCLUDED)
#define fe_clear_excluded(fe) ((fe)->flags &= ~FE_EXCLUDED)

#define fe_new(fe) ((fe)->flags & FE_NEW)
#define fe_set_new(fe) ((fe)->flags |= FE_NEW)
#define fe_clear_new(fe) ((fe)->flags &= ~FE_NEW)

struct fs_cache {
	char *last_update;
	char *repo_path;
	char *excludes_file;
	unsigned char git_excludes_sha1[20]; /* for .git/info/exclude */
	unsigned char user_excludes_sha1[20]; /* for core.excludesfile */
	unsigned int version;
	struct hashmap paths;
	int nr;
	unsigned invalid : 1; /* A commit hook might have made fs
			       * changes, necessitating a reload. */
	unsigned needs_write : 1;
	unsigned fully_loaded : 1;
	uint32_t flags;
	struct obstack obs;
};

struct fs_cache_header {
	uint32_t hdr_signature;
	uint32_t hdr_version;
	uint32_t hdr_entries;
	uint32_t flags;
	unsigned char git_excludes_sha1[20];
	unsigned char user_excludes_sha1[20];
	char strings[FLEX_ARRAY];
};

struct ondisk_fsc_entry {
	uint64_t ino;
	uint64_t dev;
	struct cache_time ctime;
	struct cache_time mtime;
	uint32_t mode;
	uint32_t size;
	uint32_t flags;
	uint32_t uid;
	uint32_t gid;
	char path[FLEX_ARRAY];
};

extern char *get_fs_cache_file(void);

unsigned char fe_dtype(struct fsc_entry *file);
void fe_to_stat(struct fsc_entry *fe, struct stat *st);
void fe_delete_children(struct fsc_entry *fe);
void fe_clear_children(struct fs_cache *fs_cache, struct fsc_entry *fe);

struct fs_cache *read_fs_cache(void);
int fs_cache_open(struct fs_cache *fs_cache, const char *fname, int flags);
int write_fs_cache(struct fs_cache *fs_cache);
struct fs_cache *empty_fs_cache(void);
struct fsc_entry *fs_cache_file_exists(const struct fs_cache *fs_cache, const char *name, int namelen);
struct fsc_entry *fs_cache_file_exists_prehash(const struct fs_cache *fs_cache, const char *name, int namelen, unsigned int hash);
struct fsc_entry *make_fs_cache_entry(const char *path);
struct fsc_entry *make_fs_cache_entry_len(const char *path, int len);
void fs_cache_preload_metadata(char **last_update, char **repo_path);

void fs_cache_remove(struct fs_cache *fs_cache, struct fsc_entry *fe);
void fs_cache_insert(struct fs_cache *fs_cache, struct fsc_entry *fe);
void free_fs_cache(struct fs_cache *fs_cache);
void set_up_parent(struct fs_cache *fs_cache, struct fsc_entry *fe);

int is_in_dot_git(const char *name);

int cmp_fsc_entry(const void *a, const void *b);

#endif /* FS_CACHE_H */
