#include <dirent.h>

#include "git-compat-util.h"
#include "cache.h"
#include "dir.h"
#include "fs_cache.h"
#include "strbuf.h"
#include "pathspec.h"
#include "watchman-support.h"

#define NS_PER_SEC 1000000000L

#define SET_TIME_FROM_NS(time, ns)	      \
	do {				      \
		(time).sec = (ns) / NS_PER_SEC;      \
		(time).nsec = (ns) % NS_PER_SEC;     \
	} while(0)

static inline unsigned int create_fe_mode(unsigned int mode)
{
	if (S_ISLNK(mode))
		return S_IFLNK;
	if (S_ISDIR(mode))
		return S_IFDIR;
	return S_IFREG | ce_permissions(mode);
}

static void copy_wm_stat_to_fe(struct watchman_stat *wm, struct fsc_entry *fe)
{
	if (!wm->exists) {
		fe_set_deleted(fe);
		return;
	} else
		fe_clear_deleted(fe);
	fe->size = wm->size;
	fe->mode = create_fe_mode(wm->mode);
	fe->ino = wm->ino;
	fe->dev = wm->dev;
	fe->uid = wm->uid;
	fe->gid = wm->gid;
	SET_TIME_FROM_NS(fe->mtime, wm->mtime_ns);
	SET_TIME_FROM_NS(fe->ctime, wm->ctime_ns);
	return;
}

static struct fsc_entry *wm_stat_to_fe(struct watchman_stat *wm)
{
	struct fsc_entry *fe = make_fs_cache_entry(wm->name);
	fe_set_new(fe);
	copy_wm_stat_to_fe(wm, fe);
	return fe;
}

static void update_exclude(struct dir_struct *dir, struct fsc_entry *fe)
{
	int dtype = fe_dtype(fe);
	if (is_excluded(dir, fe->path, &dtype)) {
		fe_set_excluded(fe);
	} else {
		fe_clear_excluded(fe);
	}
	for (fe = fe->first_child; fe; fe = fe->next_sibling) {
		update_exclude(dir, fe);
	}
}

static struct fsc_entry *fs_cache_file_deleted(struct fs_cache *fs_cache,
					       struct watchman_stat *wm)
{
	int namelen = strlen(wm->name);
	struct fsc_entry *fe;

	fe = fs_cache_file_exists(fs_cache, wm->name, namelen);

	if (fe) {
		fe_set_deleted(fe);
		fe_clear_children(fs_cache, fe);
	}

	return fe;
}

static struct fsc_entry *fs_cache_file_modified(struct fs_cache *fs_cache,
						struct watchman_stat *wm)
{
	int namelen = strlen(wm->name);
	struct fsc_entry *fe;
	fe = fs_cache_file_exists(fs_cache, wm->name, namelen);
	if (!fe) {
		fe = wm_stat_to_fe(wm);
		fs_cache_insert(fs_cache, fe);
		set_up_parent(fs_cache, fe);
	} else {
		int was_dir = fe_is_dir(fe);
		if (fe_deleted(fe))
			fe_set_new(fe);
		copy_wm_stat_to_fe(wm, fe);
		if (was_dir && !fe_is_dir(fe)) {
			fe_clear_children(fs_cache, fe);
		}
	}
	return fe;
}

static struct watchman_expression *make_expression()
{
	struct watchman_expression *types[3];
	types[0] = watchman_type_expression('f');
	types[1] = watchman_type_expression('d');
	types[2] = watchman_type_expression('l');
	struct watchman_expression *expr = watchman_anyof_expression(3, types);

	return expr;
}

struct watchman_query *make_query(const char *last_update)
{
	struct watchman_query *query = watchman_query();

	watchman_query_set_fields(query,
				  WATCHMAN_FIELD_NAME |
				  WATCHMAN_FIELD_MTIME_NS |
				  WATCHMAN_FIELD_CTIME_NS |
				  WATCHMAN_FIELD_INO |
				  WATCHMAN_FIELD_DEV |
				  WATCHMAN_FIELD_UID |
				  WATCHMAN_FIELD_GID |
				  WATCHMAN_FIELD_EXISTS |
				  WATCHMAN_FIELD_MODE |
				  WATCHMAN_FIELD_SIZE);
	watchman_query_set_empty_on_fresh(query, 1);

	query->sync_timeout = core_watchman_sync_timeout;

	if (last_update) {
		watchman_query_set_since_oclock(query, last_update);
	}
	return query;
}

enum path_treatment {
	path_recurse,
	path_file
};

void fe_from_stat(struct fsc_entry *fe, struct stat *st)
{
	fe->mode = create_fe_mode(st->st_mode);
	fe->size = st->st_size;
	fe->ino = st->st_ino;
	fe->dev = st->st_dev;
	fe->ctime.sec = st->st_ctime;
	fe->ctime.nsec = ST_CTIME_NSEC(*st);
	fe->mtime.sec = st->st_mtime;
	fe->mtime.nsec = ST_MTIME_NSEC(*st);
	fe->uid = st->st_uid;
	fe->gid = st->st_gid;
}

static void update_all_excludes(struct fs_cache *fs_cache)
{
	struct fsc_entry *root = fs_cache_file_exists(fs_cache, "", 0);
	struct dir_struct dir;
	char original_path[PATH_MAX + 1];
	const char *fs_path = get_git_work_tree();

	if (!getcwd(original_path, PATH_MAX + 1))
			die_errno("failed to get working directory\n");
	if (chdir(fs_path))
			die_errno("failed to chdir to git work tree\n");

	assert (root);

	memset(&dir, 0, sizeof(dir));
	setup_standard_excludes(&dir);
	update_exclude(&dir, root);
	clear_directory(&dir);

	if (chdir(original_path))
			die_errno("failed to chdir back to original path\n");
}

static enum path_treatment watchman_handle(struct index_state *istate, struct strbuf *path, struct dirent *de, int rootlen, struct fsc_entry **out)
{
	struct fs_cache *fs_cache = istate->fs_cache;
	struct fsc_entry *fe;
	struct stat st;
	int dtype;

	fe = make_fs_cache_entry(path->buf + rootlen);
	*out = fe;
	fs_cache_insert(fs_cache, fe);
	set_up_parent(fs_cache, fe);
	lstat(path->buf, &st);
	fe_from_stat(fe, &st);

	dtype = DTYPE(de);
	if (dtype == DT_UNKNOWN) {
		/* this involves an extra stat call, but only on
		 * Cygwin, which watchman doesn't support anyway. */
		dtype = get_dtype(de, path->buf, path->len);
	}
	if (dtype == DT_DIR) {
		return path_recurse;
	}

	return path_file;
}

static void path_set_last_component(struct strbuf *path, int baselen, const char *add)
{
	strbuf_setlen(path, baselen);
	if (baselen) {
		strbuf_addch(path, '/');
	}
	strbuf_addstr(path, add);
}

static int preload_wt_recursive(struct index_state *istate, struct strbuf *path, int rootlen)
{
	DIR *fdir;
	struct dirent *de;
	int baselen = path->len;

	fdir = opendir(path->buf);
	if (!fdir) {
		return error("Failed to open %s", path->buf);
	}

	while ((de = readdir(fdir)) != NULL) {
		struct fsc_entry *fe;
		if (is_dot_or_dotdot(de->d_name) || is_in_dot_git(de->d_name))
			continue;

		path_set_last_component(path, baselen, de->d_name);

		/* recurse into subdir if necessary */
		if (watchman_handle(istate, path, de, rootlen, &fe) == path_recurse) {
			int result = preload_wt_recursive(istate, path, rootlen);
			if (result) {
				closedir(fdir);
				return result;
			}
		}
	}

	closedir(fdir);
	return 0;
}

static void init_excludes_config()
{
	char *xdg_path;
	if (!excludes_file) {
		home_config_paths(NULL, &xdg_path, "ignore");
		excludes_file = xdg_path;
	}
}

static void compute_sha1(const char *path, unsigned char *sha1)
{
	struct stat st;
	if (stat(path, &st)) {
		memset(sha1, 0, 20);
	} else {
		if (index_path(sha1, path, &st, 0)) {
			memset(sha1, 0, 20);
		}
	}
}

static void init_excludes_files(struct fs_cache *fs_cache)
{
	init_excludes_config();
	if (fs_cache->excludes_file) {
		free(fs_cache->excludes_file);
	}
	if (excludes_file) {
		fs_cache->excludes_file = xstrdup(excludes_file);
		compute_sha1(excludes_file, fs_cache->user_excludes_sha1);
	} else {
		fs_cache->excludes_file = xstrdup("");
		memset(fs_cache->user_excludes_sha1, 0, 20);
	}
	compute_sha1(git_path("info/excludes"), fs_cache->git_excludes_sha1);
}

static int git_excludes_file_changed(struct fs_cache *fs_cache)
{
	unsigned char sha1[20];

	compute_sha1(git_path("info/exclude"), sha1);
	if (!hashcmp(fs_cache->git_excludes_sha1, sha1))
		return 0;
	hashcpy(fs_cache->git_excludes_sha1, sha1);
	return 1;
}

static int user_excludes_file_changed(struct fs_cache *fs_cache)
{
	unsigned char sha1[20] = {0};
	struct stat st;

	init_excludes_config();

	if (!excludes_file) {
		if (strlen(fs_cache->excludes_file) == 0) {
			return 0;
		}

		fs_cache->excludes_file[0] = 0;
		if (is_null_sha1(fs_cache->user_excludes_sha1))
			return 0;

		memset(fs_cache->user_excludes_sha1, 0, 20);
		return 1;
	}

	/* A change in exclude filename forces an exclude reload */
	if (strcmp(fs_cache->excludes_file, excludes_file)) {
		init_excludes_files(fs_cache);
		return 1;
	}

	if (!strlen(fs_cache->excludes_file)) {
		return 0;
	}

	if (stat(excludes_file, &st)) {
		/* There is a problem reading the excludes file; this
		 * could be a persistent condition, so we need to
		 * check if the file is presently marked as invalid */
		if (is_null_sha1(fs_cache->user_excludes_sha1))
			return 0;
		else {
			memset(fs_cache->user_excludes_sha1, 0, 20);
			return 1;
		}
	}

	if (index_path(sha1, excludes_file, &st, 0)) {
		if (is_null_sha1(fs_cache->user_excludes_sha1)) {
			return 0;
		} else {
			memset(fs_cache->user_excludes_sha1, 0, 20);
			return 1;
		}
	} else {
		if (!hashcmp(fs_cache->user_excludes_sha1, sha1))
			return 0;
		hashcpy(fs_cache->user_excludes_sha1, sha1);
		return 1;
	}
}

static void create_fs_cache(struct index_state *istate)
{
	struct strbuf buf = STRBUF_INIT;
	const char *fs_path = get_git_work_tree();
	struct fsc_entry *root;

	strbuf_addstr(&buf, fs_path);
	istate->fs_cache = empty_fs_cache();
	root = make_fs_cache_entry("");
	root->mode = 040644;
	fs_cache_insert(istate->fs_cache, root);
	preload_wt_recursive(istate, &buf, buf.len + 1);
	strbuf_release(&buf);

	init_excludes_files(istate->fs_cache);
	update_all_excludes(istate->fs_cache);
}

static void load_fs_cache(struct index_state *istate)
{
	if (istate->fs_cache)
		return;
	istate->fs_cache = read_fs_cache();
	if (!istate->fs_cache) {
		create_fs_cache(istate);
	}
}

static struct watchman_query_result *watchman_fs_cache_query(struct watchman_connection *connection, const char *fs_path, const char *last_update)
{
	struct watchman_error wm_error;
	struct watchman_expression *expr;
	struct watchman_query *query;
	struct watchman_query_result *result = NULL;
	struct stat st;
	int fs_path_len = strlen(fs_path);
	char *git_path;

	expr = make_expression();
	query = make_query(last_update);
	if (lstat(fs_path, &st)) {
		return NULL;
	}

	git_path = xmalloc(fs_path_len + 6);
	strcpy(git_path, fs_path);
	strcpy(git_path + fs_path_len, "/.git");

	if (lstat(git_path, &st)) {
		/* Watchman gets confused if we delete the .git
		 * directory out from under it, since that's where it
		 * stores its cookies.  So we'll need to delete the
		 * watch and then recreate it. It's OK for this to
		 * fail, as the watch might have already been
		 * deleted. */
		watchman_watch_del(connection, fs_path, &wm_error);

		if (watchman_watch(connection, fs_path, &wm_error)) {
			warning("Watchman watch error: %s", wm_error.message);
			goto out;
		}
	}
	result = watchman_do_query(connection, fs_path, query, expr, &wm_error);
	if (!result) {
		warning("Watchman query error: %s (at %s)", wm_error.message, last_update);
		goto out;
	}
	watchman_free_expression(expr);
	watchman_free_query(query);

out:
	free(git_path);
	return result;
}

static int cmp_stat(const void *a, const void *b)
{
	const struct watchman_stat* sa = a;
	const struct watchman_stat* sb = b;
	return strcmp(sa->name, sb->name);
}

static void append(struct fsc_entry ***list, int* cap, int* len, struct fsc_entry *entry)
{
	if (*len >= *cap) {
		int sz;
		*cap = *cap ? *cap * 2 : 10;
		sz = *cap * sizeof(**list);
		*list = xrealloc(*list, sz);
	}
	(*list)[(*len)++] = entry;
}

static int is_child_of(struct fsc_entry *putative_child, struct fsc_entry *parent)
{
	while (putative_child) {
		putative_child = putative_child->parent;
		if (putative_child == parent) {
			return 1;
		}
	}
	return 0;
}

static void update_fs_cache(struct index_state *istate, struct watchman_query_result *result)
{
	struct fs_cache *fs_cache = istate->fs_cache;
	struct fsc_entry *fe;
	int i;
	struct fsc_entry **exclude_dirty = NULL;
	int cap = 0, len = 0, all_dirty = 0;
	/* note that we always want to call both of these functions,
	 * since they update the fs_cache's view of files which are
	 * not watched by watchman */
	int user_changed = user_excludes_file_changed(fs_cache);
	int git_changed = git_excludes_file_changed(fs_cache);

	all_dirty = user_changed || git_changed;

	qsort(result->stats, result->nr, sizeof(*result->stats), cmp_stat);

	for (i = 0; i < result->nr; ++i) {
		/*for each result in the changed set, we need to check
		  it against the index and HEAD */

		struct watchman_stat *wm = result->stats + i;

		if (is_in_dot_git(wm->name)) {
			continue;
		}
		fs_cache->needs_write = 1;
		if (wm->exists) {
			fe = fs_cache_file_modified(fs_cache, wm);
		} else {
			fe = fs_cache_file_deleted(fs_cache, wm);
		}
		if (fe && !all_dirty) {
			if (ends_with(wm->name, "/.gitignore") ||
			    !strcmp(wm->name, ".gitignore")) {
				append(&exclude_dirty, &cap, &len, fe->parent);
			} else if (fe_new(fe)) {
				append(&exclude_dirty, &cap, &len, fe);
			}
		}
	}

	if (exclude_dirty) {
		struct dir_struct dir;
		struct fsc_entry *last = NULL;
		char original_path[PATH_MAX + 1];
		qsort(exclude_dirty, len, sizeof(*exclude_dirty), cmp_fsc_entry);

		if (!getcwd(original_path, PATH_MAX + 1))
			die_errno("failed to get working directory\n");
		if (chdir(get_git_work_tree()))
			die_errno("failed to chdir to git work tree\n");

		memset(&dir, 0, sizeof(dir));
		setup_standard_excludes(&dir);

		for (i = 0; i < len; i++) {
			struct fsc_entry *fe = exclude_dirty[i];

			if (i == 0 || !is_child_of(fe, last)) {
				update_exclude(&dir, fe);
				last = fe;
			}
		}
		clear_directory(&dir);
		free(exclude_dirty);
		if (chdir(original_path))
			die_errno("failed to chdir back to original path\n");
	} else if (all_dirty) {
		update_all_excludes(fs_cache);
	}

}

int watchman_reload_fs_cache(struct index_state *istate)
{
	struct watchman_error wm_error;
	struct watchman_query_result *result;
	struct watchman_connection *connection;
	int ret = -1;
	const char *fs_path;
	const char *last_update = istate->fs_cache->last_update;

	fs_path = get_git_work_tree();
	if (!fs_path)
		return -1;

	connection = watchman_connect(&wm_error);

	if (!connection) {
		warning("Watchman watch error: %s", wm_error.message);
		return -1;
	}

	result = watchman_fs_cache_query(connection, fs_path, last_update);
	if (!result) {
		goto done;
	}
	istate->fs_cache->last_update = xstrdup(result->clock);

	update_fs_cache(istate, result);
	watchman_free_query_result(result);
	ret = 0;
done:
	watchman_connection_close(connection);
	return ret;
}

int watchman_load_fs_cache(struct index_state *istate)
{
	struct watchman_error wm_error;
	int ret = -1;
	const char *fs_path;
	char *last_update = NULL;
	char *stored_repo_path = NULL;
	struct watchman_query_result *result;
	struct watchman_connection *connection;

	fs_path = get_git_work_tree();
	if (!fs_path)
		return -1;

	connection = watchman_connect(&wm_error);

	if (!connection) {
		warning("Watchman watch error: %s", wm_error.message);
		return -1;
	}

	if (watchman_watch(connection, fs_path, &wm_error)) {
		warning("Watchman watch error: %s", wm_error.message);
		goto done;
	}

	fs_cache_preload_metadata(&last_update, &stored_repo_path);
	if (!last_update || strcmp(stored_repo_path, fs_path)) {
		if (istate->fs_cache) {
			free_fs_cache(istate->fs_cache);
			istate->fs_cache = NULL;
		}
		/* fs_cache is corrupt, or refers to another repo path;
		 * let's try recreating it. */
		if (last_update)
			free(last_update);
		last_update = NULL;
		/* now we continue, because we need to get the
		 * a last-update time from watchman. */
	}
	free(stored_repo_path);

	result = watchman_fs_cache_query(connection, fs_path, last_update);
	if (last_update) {
		free(last_update);
		last_update = NULL;
	}
	if (!result) {
		goto done;
	}

	if (result->is_fresh_instance) {
		if (istate->fs_cache) {
			free_fs_cache(istate->fs_cache);
			istate->fs_cache = NULL;
		}
		create_fs_cache(istate);
		istate->fs_cache->repo_path = xstrdup(fs_path);
	} else {
		load_fs_cache(istate);
		update_fs_cache(istate, result);
	}

	istate->fs_cache->last_update = xstrdup(result->clock);

	watchman_free_query_result(result);
	ret = 0;

done:
	watchman_connection_close(connection);
	return ret;

}
