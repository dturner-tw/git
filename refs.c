/*
 * The backend-independent part of the reference module.
 */

#include "cache.h"
#include "lockfile.h"
#include "refs.h"
#include "refs/refs-internal.h"
#include "object.h"
#include "tag.h"

static const char split_transaction_fail_warning[] = N_(
	"A ref transaction was split across two refs backends.  Part of the "
	"transaction succeeded, but then the update to the per-worktree refs "
	"failed.  Your repository may be in an inconsistent state.");

static struct ref_storage_be *the_refs_backend = &refs_be_files;
/*
 * List of all available backends
 */
static struct ref_storage_be *refs_backends;

const char *ref_storage_backend = "files";

static struct ref_storage_be *find_ref_storage_backend(const char *name)
{
	struct ref_storage_be *be;
	for (be = refs_backends; be; be = be->next)
		if (!strcmp(be->name, name))
			return be;
	return NULL;
}

int set_ref_storage_backend(const char *name)
{
	struct ref_storage_be *be = find_ref_storage_backend(name);
	if (!be)
		return -1;
	the_refs_backend = be;
	return 0;
}

int ref_storage_backend_exists(const char *name)
{
	return find_ref_storage_backend(name) != NULL;
}

static void register_ref_storage_backend(struct ref_storage_be *be)
{
	be->next = refs_backends;
	refs_backends = be;
}

void register_ref_storage_backends(void)
{
	if (refs_backends)
		return;
	/*
	 * Add register_ref_storage_backend(ptr-to-backend)
	 * entries below when you add a new backend.
	 */
	register_ref_storage_backend(&refs_be_files);
#ifdef USE_LIBLMDB
	register_ref_storage_backend(&refs_be_lmdb);
#endif
}

/*
 * How to handle various characters in refnames:
 * 0: An acceptable character for refs
 * 1: End-of-component
 * 2: ., look for a preceding . to reject .. in refs
 * 3: {, look for a preceding @ to reject @{ in refs
 * 4: A bad character: ASCII control characters, and
 *    ":", "?", "[", "\", "^", "~", SP, or TAB
 * 5: *, reject unless REFNAME_REFSPEC_PATTERN is set
 */
static unsigned char refname_disposition[256] = {
	1, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
	4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 2, 1,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 4,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 0, 4, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 4, 4
};

/*
 * Try to read one refname component from the front of refname.
 * Return the length of the component found, or -1 if the component is
 * not legal.  It is legal if it is something reasonable to have under
 * ".git/refs/"; We do not like it if:
 *
 * - any path component of it begins with ".", or
 * - it has double dots "..", or
 * - it has ASCII control characters, or
 * - it has ":", "?", "[", "\", "^", "~", SP, or TAB anywhere, or
 * - it has "*" anywhere unless REFNAME_REFSPEC_PATTERN is set, or
 * - it ends with a "/", or
 * - it ends with ".lock", or
 * - it contains a "@{" portion
 */
static int check_refname_component(const char *refname, int *flags)
{
	const char *cp;
	char last = '\0';

	for (cp = refname; ; cp++) {
		int ch = *cp & 255;
		unsigned char disp = refname_disposition[ch];
		switch (disp) {
		case 1:
			goto out;
		case 2:
			if (last == '.')
				return -1; /* Refname contains "..". */
			break;
		case 3:
			if (last == '@')
				return -1; /* Refname contains "@{". */
			break;
		case 4:
			return -1;
		case 5:
			if (!(*flags & REFNAME_REFSPEC_PATTERN))
				return -1; /* refspec can't be a pattern */

			/*
			 * Unset the pattern flag so that we only accept
			 * a single asterisk for one side of refspec.
			 */
			*flags &= ~ REFNAME_REFSPEC_PATTERN;
			break;
		}
		last = ch;
	}
out:
	if (cp == refname)
		return 0; /* Component has zero length. */
	if (refname[0] == '.')
		return -1; /* Component starts with '.'. */
	if (cp - refname >= LOCK_SUFFIX_LEN &&
	    !memcmp(cp - LOCK_SUFFIX_LEN, LOCK_SUFFIX, LOCK_SUFFIX_LEN))
		return -1; /* Refname ends with ".lock". */
	return cp - refname;
}

int check_refname_format(const char *refname, int flags)
{
	int component_len, component_count = 0;

	if (!strcmp(refname, "@"))
		/* Refname is a single character '@'. */
		return -1;

	while (1) {
		/* We are at the start of a path component. */
		component_len = check_refname_component(refname, &flags);
		if (component_len <= 0)
			return -1;

		component_count++;
		if (refname[component_len] == '\0')
			break;
		/* Skip to next component. */
		refname += component_len + 1;
	}

	if (refname[component_len - 1] == '.')
		return -1; /* Refname ends with '.'. */
	if (!(flags & REFNAME_ALLOW_ONELEVEL) && component_count < 2)
		return -1; /* Refname has only one component. */
	return 0;
}

int refname_is_safe(const char *refname)
{
	if (starts_with(refname, "refs/")) {
		char *buf;
		int result;

		buf = xmallocz(strlen(refname));
		/*
		 * Does the refname try to escape refs/?
		 * For example: refs/foo/../bar is safe but refs/foo/../../bar
		 * is not.
		 */
		result = !normalize_path_copy(buf, refname + strlen("refs/"));
		free(buf);
		return result;
	}
	while (*refname) {
		if (!isupper(*refname) && *refname != '_')
			return 0;
		refname++;
	}
	return 1;
}

char *resolve_refdup(const char *refname, int resolve_flags,
		     unsigned char *sha1, int *flags)
{
	return xstrdup_or_null(resolve_ref_unsafe(refname, resolve_flags,
						  sha1, flags));
}

/* The argument to filter_refs */
struct ref_filter {
	const char *pattern;
	each_ref_fn *fn;
	void *cb_data;
};

int read_ref_full(const char *refname, int resolve_flags, unsigned char *sha1, int *flags)
{
	if (resolve_ref_unsafe(refname, resolve_flags, sha1, flags))
		return 0;
	return -1;
}

int read_ref(const char *refname, unsigned char *sha1)
{
	return read_ref_full(refname, RESOLVE_REF_READING, sha1, NULL);
}

int ref_exists(const char *refname)
{
	unsigned char sha1[20];
	return !!resolve_ref_unsafe(refname, RESOLVE_REF_READING, sha1, NULL);
}

static int filter_refs(const char *refname, const struct object_id *oid,
			   int flags, void *data)
{
	struct ref_filter *filter = (struct ref_filter *)data;

	if (wildmatch(filter->pattern, refname, 0, NULL))
		return 0;
	return filter->fn(refname, oid, flags, filter->cb_data);
}

enum peel_status peel_object(const unsigned char *name, unsigned char *sha1)
{
	struct object *o = lookup_unknown_object(name);

	if (o->type == OBJ_NONE) {
		int type = sha1_object_info(name, NULL);
		if (type < 0 || !object_as_type(o, type, 0))
			return PEEL_INVALID;
	}

	if (o->type != OBJ_TAG)
		return PEEL_NON_TAG;

	o = deref_tag_noverify(o);
	if (!o)
		return PEEL_INVALID;

	hashcpy(sha1, o->oid.hash);
	return PEEL_PEELED;
}

struct warn_if_dangling_data {
	FILE *fp;
	const char *refname;
	const struct string_list *refnames;
	const char *msg_fmt;
};

static int warn_if_dangling_symref(const char *refname, const struct object_id *oid,
				   int flags, void *cb_data)
{
	struct warn_if_dangling_data *d = cb_data;
	const char *resolves_to;
	struct object_id junk;

	if (!(flags & REF_ISSYMREF))
		return 0;

	resolves_to = resolve_ref_unsafe(refname, 0, junk.hash, NULL);
	if (!resolves_to
	    || (d->refname
		? strcmp(resolves_to, d->refname)
		: !string_list_has_string(d->refnames, resolves_to))) {
		return 0;
	}

	fprintf(d->fp, d->msg_fmt, refname);
	fputc('\n', d->fp);
	return 0;
}

void warn_dangling_symref(FILE *fp, const char *msg_fmt, const char *refname)
{
	struct warn_if_dangling_data data;

	data.fp = fp;
	data.refname = refname;
	data.refnames = NULL;
	data.msg_fmt = msg_fmt;
	for_each_rawref(warn_if_dangling_symref, &data);
}

void warn_dangling_symrefs(FILE *fp, const char *msg_fmt, const struct string_list *refnames)
{
	struct warn_if_dangling_data data;

	data.fp = fp;
	data.refname = NULL;
	data.refnames = refnames;
	data.msg_fmt = msg_fmt;
	for_each_rawref(warn_if_dangling_symref, &data);
}

int for_each_tag_ref(each_ref_fn fn, void *cb_data)
{
	return for_each_ref_in("refs/tags/", fn, cb_data);
}

static int submodule_backend(const char *key, const char *value, void *data)
{
	const char **path = data;
	char *old_path = *(char **)data;
	if (!strcmp(key, "extensions.refstorage") &&
	    !git_config_string(path, key, value))
		free(old_path);

	return 0;
}

/*
 * Check that a submodule exists. If its ref storage backend differs
 * from the current backend, die.  If the submodule exists, return
 * 0. Else return -1.
 */
static int check_submodule_backend(const char *submodule)
{
	struct strbuf sb = STRBUF_INIT;
	char *submodule_storage_backend;
	int result = -1;

	if (!submodule)
		return 0;

	submodule_storage_backend = xstrdup("files");

	strbuf_addstr(&sb, submodule);
	if (!is_nonbare_repository_dir(&sb))
		goto done;

	strbuf_reset(&sb);
	strbuf_git_path_submodule(&sb, submodule, "config");

	git_config_from_file(submodule_backend, sb.buf,
			     &submodule_storage_backend);
	if (strcmp(submodule_storage_backend, ref_storage_backend))
		die(_("Ref storage '%s' for submodule '%s' does not match our storage, '%s'"),
		    submodule_storage_backend, submodule, ref_storage_backend);

	result = 0;
done:
	free(submodule_storage_backend);
	strbuf_release(&sb);

	return result;
}

int for_each_tag_ref_submodule(const char *submodule, each_ref_fn fn, void *cb_data)
{
	return for_each_ref_in_submodule(submodule, "refs/tags/", fn, cb_data);
}

int for_each_branch_ref(each_ref_fn fn, void *cb_data)
{
	return for_each_ref_in("refs/heads/", fn, cb_data);
}

int for_each_branch_ref_submodule(const char *submodule, each_ref_fn fn, void *cb_data)
{
	check_submodule_backend(submodule);
	return for_each_ref_in_submodule(submodule, "refs/heads/", fn, cb_data);
}

int for_each_remote_ref(each_ref_fn fn, void *cb_data)
{
	return for_each_ref_in("refs/remotes/", fn, cb_data);
}

int for_each_remote_ref_submodule(const char *submodule, each_ref_fn fn, void *cb_data)
{
	check_submodule_backend(submodule);
	return for_each_ref_in_submodule(submodule, "refs/remotes/", fn, cb_data);
}

int head_ref_namespaced(each_ref_fn fn, void *cb_data)
{
	struct strbuf buf = STRBUF_INIT;
	int ret = 0;
	struct object_id oid;
	int flag;

	strbuf_addf(&buf, "%sHEAD", get_git_namespace());
	if (!read_ref_full(buf.buf, RESOLVE_REF_READING, oid.hash, &flag))
		ret = fn(buf.buf, &oid, flag, cb_data);
	strbuf_release(&buf);

	return ret;
}

int for_each_glob_ref_in(each_ref_fn fn, const char *pattern,
	const char *prefix, void *cb_data)
{
	struct strbuf real_pattern = STRBUF_INIT;
	struct ref_filter filter;
	int ret;

	if (!prefix && !starts_with(pattern, "refs/"))
		strbuf_addstr(&real_pattern, "refs/");
	else if (prefix)
		strbuf_addstr(&real_pattern, prefix);
	strbuf_addstr(&real_pattern, pattern);

	if (!has_glob_specials(pattern)) {
		/* Append implied '/' '*' if not present. */
		strbuf_complete(&real_pattern, '/');
		/* No need to check for '*', there is none. */
		strbuf_addch(&real_pattern, '*');
	}

	filter.pattern = real_pattern.buf;
	filter.fn = fn;
	filter.cb_data = cb_data;
	ret = for_each_ref(filter_refs, &filter);

	strbuf_release(&real_pattern);
	return ret;
}

int for_each_glob_ref(each_ref_fn fn, const char *pattern, void *cb_data)
{
	return for_each_glob_ref_in(fn, pattern, NULL, cb_data);
}

const char *prettify_refname(const char *name)
{
	return name + (
		starts_with(name, "refs/heads/") ? 11 :
		starts_with(name, "refs/tags/") ? 10 :
		starts_with(name, "refs/remotes/") ? 13 :
		0);
}

static const char *ref_rev_parse_rules[] = {
	"%.*s",
	"refs/%.*s",
	"refs/tags/%.*s",
	"refs/heads/%.*s",
	"refs/remotes/%.*s",
	"refs/remotes/%.*s/HEAD",
	NULL
};

int refname_match(const char *abbrev_name, const char *full_name)
{
	const char **p;
	const int abbrev_name_len = strlen(abbrev_name);

	for (p = ref_rev_parse_rules; *p; p++) {
		if (!strcmp(full_name, mkpath(*p, abbrev_name_len, abbrev_name))) {
			return 1;
		}
	}

	return 0;
}

/*
 * *string and *len will only be substituted, and *string returned (for
 * later free()ing) if the string passed in is a magic short-hand form
 * to name a branch.
 */
static char *substitute_branch_name(const char **string, int *len)
{
	struct strbuf buf = STRBUF_INIT;
	int ret = interpret_branch_name(*string, *len, &buf);

	if (ret == *len) {
		size_t size;
		*string = strbuf_detach(&buf, &size);
		*len = size;
		return (char *)*string;
	}

	return NULL;
}

int dwim_ref(const char *str, int len, unsigned char *sha1, char **ref)
{
	char *last_branch = substitute_branch_name(&str, &len);
	const char **p, *r;
	int refs_found = 0;

	*ref = NULL;
	for (p = ref_rev_parse_rules; *p; p++) {
		char fullref[PATH_MAX];
		unsigned char sha1_from_ref[20];
		unsigned char *this_result;
		int flag;

		this_result = refs_found ? sha1_from_ref : sha1;
		mksnpath(fullref, sizeof(fullref), *p, len, str);
		r = resolve_ref_unsafe(fullref, RESOLVE_REF_READING,
				       this_result, &flag);
		if (r) {
			if (!refs_found++)
				*ref = xstrdup(r);
			if (!warn_ambiguous_refs)
				break;
		} else if ((flag & REF_ISSYMREF) && strcmp(fullref, "HEAD")) {
			warning("ignoring dangling symref %s.", fullref);
		} else if ((flag & REF_ISBROKEN) && strchr(fullref, '/')) {
			warning("ignoring broken ref %s.", fullref);
		}
	}
	free(last_branch);
	return refs_found;
}

int dwim_log(const char *str, int len, unsigned char *sha1, char **log)
{
	char *last_branch = substitute_branch_name(&str, &len);
	const char **p;
	int logs_found = 0;

	*log = NULL;
	for (p = ref_rev_parse_rules; *p; p++) {
		unsigned char hash[20];
		char path[PATH_MAX];
		const char *ref, *it;

		mksnpath(path, sizeof(path), *p, len, str);
		ref = resolve_ref_unsafe(path, RESOLVE_REF_READING,
					 hash, NULL);
		if (!ref)
			continue;
		if (reflog_exists(path))
			it = path;
		else if (strcmp(ref, path) && reflog_exists(ref))
			it = ref;
		else
			continue;
		if (!logs_found++) {
			*log = xstrdup(it);
			hashcpy(sha1, hash);
		}
		if (!warn_ambiguous_refs)
			break;
	}
	free(last_branch);
	return logs_found;
}

static int is_per_worktree_ref(const char *refname)
{
	return !strcmp(refname, "HEAD") ||
		starts_with(refname, "refs/bisect/");
}

static int is_pseudoref_syntax(const char *refname)
{
	const char *c;

	for (c = refname; *c; c++) {
		if (!isupper(*c) && *c != '-' && *c != '_')
			return 0;
	}

	return 1;
}

enum ref_type ref_type(const char *refname)
{
	if (is_per_worktree_ref(refname))
		return REF_TYPE_PER_WORKTREE;
	if (is_pseudoref_syntax(refname))
		return REF_TYPE_PSEUDOREF;
       return REF_TYPE_NORMAL;
}

static int write_pseudoref(const char *pseudoref, const unsigned char *sha1,
			   const unsigned char *old_sha1, struct strbuf *err)
{
	const char *filename;
	int fd;
	static struct lock_file lock;
	struct strbuf buf = STRBUF_INIT;
	int ret = -1;

	strbuf_addf(&buf, "%s\n", sha1_to_hex(sha1));

	filename = git_path("%s", pseudoref);
	fd = hold_lock_file_for_update(&lock, filename, LOCK_DIE_ON_ERROR);
	if (fd < 0) {
		strbuf_addf(err, "Could not open '%s' for writing: %s",
			    filename, strerror(errno));
		return -1;
	}

	if (old_sha1) {
		unsigned char actual_old_sha1[20];

		if (read_ref(pseudoref, actual_old_sha1))
			die("could not read ref '%s'", pseudoref);
		if (hashcmp(actual_old_sha1, old_sha1)) {
			strbuf_addf(err, "Unexpected sha1 when writing %s", pseudoref);
			rollback_lock_file(&lock);
			goto done;
		}
	}

	if (write_in_full(fd, buf.buf, buf.len) != buf.len) {
		strbuf_addf(err, "Could not write to '%s'", filename);
		rollback_lock_file(&lock);
		goto done;
	}

	commit_lock_file(&lock);
	ret = 0;
done:
	strbuf_release(&buf);
	return ret;
}

static int delete_pseudoref(const char *pseudoref, const unsigned char *old_sha1)
{
	static struct lock_file lock;
	const char *filename;

	filename = git_path("%s", pseudoref);

	if (old_sha1 && !is_null_sha1(old_sha1)) {
		int fd;
		unsigned char actual_old_sha1[20];

		fd = hold_lock_file_for_update(&lock, filename,
					       LOCK_DIE_ON_ERROR);
		if (fd < 0)
			die_errno(_("Could not open '%s' for writing"), filename);
		if (read_ref(pseudoref, actual_old_sha1))
			die("could not read ref '%s'", pseudoref);
		if (hashcmp(actual_old_sha1, old_sha1)) {
			warning("Unexpected sha1 when deleting %s", pseudoref);
			rollback_lock_file(&lock);
			return -1;
		}

		unlink(filename);
		rollback_lock_file(&lock);
	} else {
		unlink(filename);
	}

	return 0;
}

int delete_ref(const char *refname, const unsigned char *old_sha1,
	       unsigned int flags)
{
	struct ref_transaction *transaction;
	struct strbuf err = STRBUF_INIT;

	if (ref_type(refname) == REF_TYPE_PSEUDOREF)
		return delete_pseudoref(refname, old_sha1);

	transaction = ref_transaction_begin(&err);
	if (!transaction ||
	    ref_transaction_delete(transaction, refname, old_sha1,
				   flags, NULL, &err) ||
	    ref_transaction_commit(transaction, &err)) {
		error("%s", err.buf);
		ref_transaction_free(transaction);
		strbuf_release(&err);
		return 1;
	}
	ref_transaction_free(transaction);
	strbuf_release(&err);
	return 0;
}

int copy_reflog_msg(char *buf, const char *msg)
{
	char *cp = buf;
	char c;
	int wasspace = 1;

	*cp++ = '\t';
	while ((c = *msg++)) {
		if (wasspace && isspace(c))
			continue;
		wasspace = isspace(c);
		if (wasspace)
			c = ' ';
		*cp++ = c;
	}
	while (buf < cp && isspace(cp[-1]))
		cp--;
	*cp++ = '\n';
	return cp - buf;
}

int should_autocreate_reflog(const char *refname)
{
	if (!log_all_ref_updates)
		return 0;
	return starts_with(refname, "refs/heads/") ||
		starts_with(refname, "refs/remotes/") ||
		starts_with(refname, "refs/notes/") ||
		!strcmp(refname, "HEAD");
}

int is_branch(const char *refname)
{
	return !strcmp(refname, "HEAD") || starts_with(refname, "refs/heads/");
}

struct read_ref_at_cb {
	const char *refname;
	unsigned long at_time;
	int cnt;
	int reccnt;
	unsigned char *sha1;
	int found_it;

	unsigned char osha1[20];
	unsigned char nsha1[20];
	int tz;
	unsigned long date;
	char **msg;
	unsigned long *cutoff_time;
	int *cutoff_tz;
	int *cutoff_cnt;
};

static int read_ref_at_ent(unsigned char *osha1, unsigned char *nsha1,
		const char *email, unsigned long timestamp, int tz,
		const char *message, void *cb_data)
{
	struct read_ref_at_cb *cb = cb_data;

	cb->reccnt++;
	cb->tz = tz;
	cb->date = timestamp;

	if (timestamp <= cb->at_time || cb->cnt == 0) {
		if (cb->msg)
			*cb->msg = xstrdup(message);
		if (cb->cutoff_time)
			*cb->cutoff_time = timestamp;
		if (cb->cutoff_tz)
			*cb->cutoff_tz = tz;
		if (cb->cutoff_cnt)
			*cb->cutoff_cnt = cb->reccnt - 1;
		/*
		 * we have not yet updated cb->[n|o]sha1 so they still
		 * hold the values for the previous record.
		 */
		if (!is_null_sha1(cb->osha1)) {
			hashcpy(cb->sha1, nsha1);
			if (hashcmp(cb->osha1, nsha1))
				warning("Log for ref %s has gap after %s.",
					cb->refname, show_date(cb->date, cb->tz, DATE_MODE(RFC2822)));
		}
		else if (cb->date == cb->at_time)
			hashcpy(cb->sha1, nsha1);
		else if (hashcmp(nsha1, cb->sha1))
			warning("Log for ref %s unexpectedly ended on %s.",
				cb->refname, show_date(cb->date, cb->tz,
						       DATE_MODE(RFC2822)));
		hashcpy(cb->osha1, osha1);
		hashcpy(cb->nsha1, nsha1);
		cb->found_it = 1;
		return 1;
	}
	hashcpy(cb->osha1, osha1);
	hashcpy(cb->nsha1, nsha1);
	if (cb->cnt > 0)
		cb->cnt--;
	return 0;
}

static int read_ref_at_ent_oldest(unsigned char *osha1, unsigned char *nsha1,
				  const char *email, unsigned long timestamp,
				  int tz, const char *message, void *cb_data)
{
	struct read_ref_at_cb *cb = cb_data;

	if (cb->msg)
		*cb->msg = xstrdup(message);
	if (cb->cutoff_time)
		*cb->cutoff_time = timestamp;
	if (cb->cutoff_tz)
		*cb->cutoff_tz = tz;
	if (cb->cutoff_cnt)
		*cb->cutoff_cnt = cb->reccnt;
	hashcpy(cb->sha1, osha1);
	if (is_null_sha1(cb->sha1))
		hashcpy(cb->sha1, nsha1);
	/* We just want the first entry */
	return 1;
}

int read_ref_at(const char *refname, unsigned int flags, unsigned long at_time, int cnt,
		unsigned char *sha1, char **msg,
		unsigned long *cutoff_time, int *cutoff_tz, int *cutoff_cnt)
{
	struct read_ref_at_cb cb;

	memset(&cb, 0, sizeof(cb));
	cb.refname = refname;
	cb.at_time = at_time;
	cb.cnt = cnt;
	cb.msg = msg;
	cb.cutoff_time = cutoff_time;
	cb.cutoff_tz = cutoff_tz;
	cb.cutoff_cnt = cutoff_cnt;
	cb.sha1 = sha1;

	for_each_reflog_ent_reverse(refname, read_ref_at_ent, &cb);

	if (!cb.reccnt) {
		if (flags & GET_SHA1_QUIETLY)
			exit(128);
		else
			die("Log for %s is empty.", refname);
	}
	if (cb.found_it)
		return 0;

	for_each_reflog_ent(refname, read_ref_at_ent_oldest, &cb);

	return 1;
}

struct ref_transaction *ref_transaction_begin(struct strbuf *err)
{
	assert(err);

	return xcalloc(1, sizeof(struct ref_transaction));
}

void ref_transaction_free(struct ref_transaction *transaction)
{
	int i;

	if (!transaction)
		return;

	for (i = 0; i < transaction->nr; i++) {
		free(transaction->updates[i]->msg);
		free(transaction->updates[i]);
	}
	free(transaction->updates);
	free(transaction);
}

static void add_update_obj(struct ref_transaction *transaction,
			   struct ref_update *update)
{
	ALLOC_GROW(transaction->updates, transaction->nr + 1, transaction->alloc);
	transaction->updates[transaction->nr++] = update;
}

static struct ref_update *add_update(struct ref_transaction *transaction,
				     const char *refname)
{
	struct ref_update *update;
	FLEX_ALLOC_STR(update, refname, refname);
	add_update_obj(transaction, update);
	return update;
}

int ref_transaction_update(struct ref_transaction *transaction,
			   const char *refname,
			   const unsigned char *new_sha1,
			   const unsigned char *old_sha1,
			   unsigned int flags, const char *msg,
			   struct strbuf *err)
{
	struct ref_update *update;

	assert(err);

	if (transaction->state != REF_TRANSACTION_OPEN)
		die("BUG: update called for transaction that is not open");

	if (new_sha1 && !is_null_sha1(new_sha1) &&
	    check_refname_format(refname, REFNAME_ALLOW_ONELEVEL)) {
		strbuf_addf(err, "refusing to update ref with bad name %s",
			    refname);
		return -1;
	}

	update = add_update(transaction, refname);
	if (new_sha1) {
		hashcpy(update->new_sha1, new_sha1);
		flags |= REF_HAVE_NEW;
	}
	if (old_sha1) {
		hashcpy(update->old_sha1, old_sha1);
		flags |= REF_HAVE_OLD;
	}
	update->flags = flags;
	if (msg)
		update->msg = xstrdup(msg);
	return 0;
}

int ref_transaction_create(struct ref_transaction *transaction,
			   const char *refname,
			   const unsigned char *new_sha1,
			   unsigned int flags, const char *msg,
			   struct strbuf *err)
{
	if (!new_sha1 || is_null_sha1(new_sha1))
		die("BUG: create called without valid new_sha1");
	return ref_transaction_update(transaction, refname, new_sha1,
				      null_sha1, flags, msg, err);
}

int ref_transaction_delete(struct ref_transaction *transaction,
			   const char *refname,
			   const unsigned char *old_sha1,
			   unsigned int flags, const char *msg,
			   struct strbuf *err)
{
	if (old_sha1 && is_null_sha1(old_sha1))
		die("BUG: delete called with old_sha1 set to zeros");
	return ref_transaction_update(transaction, refname,
				      null_sha1, old_sha1,
				      flags, msg, err);
}

int ref_transaction_verify(struct ref_transaction *transaction,
			   const char *refname,
			   const unsigned char *old_sha1,
			   unsigned int flags,
			   struct strbuf *err)
{
	if (!old_sha1)
		die("BUG: verify called with old_sha1 set to NULL");
	return ref_transaction_update(transaction, refname,
				      NULL, old_sha1,
				      flags, NULL, err);
}

int update_ref(const char *msg, const char *refname,
	       const unsigned char *new_sha1, const unsigned char *old_sha1,
	       unsigned int flags, enum action_on_err onerr)
{
	struct ref_transaction *t = NULL;
	struct strbuf err = STRBUF_INIT;
	int ret = 0;

	if (ref_type(refname) == REF_TYPE_PSEUDOREF) {
		ret = write_pseudoref(refname, new_sha1, old_sha1, &err);
	} else {
		t = ref_transaction_begin(&err);
		if (!t ||
		    ref_transaction_update(t, refname, new_sha1, old_sha1,
					   flags, msg, &err) ||
		    ref_transaction_commit(t, &err)) {
			ret = 1;
			ref_transaction_free(t);
		}
	}
	if (ret) {
		const char *str = "update_ref failed for ref '%s': %s";

		switch (onerr) {
		case UPDATE_REFS_MSG_ON_ERR:
			error(str, refname, err.buf);
			break;
		case UPDATE_REFS_DIE_ON_ERR:
			die(str, refname, err.buf);
			break;
		case UPDATE_REFS_QUIET_ON_ERR:
			break;
		}
		strbuf_release(&err);
		return 1;
	}
	strbuf_release(&err);
	if (t)
		ref_transaction_free(t);
	return 0;
}

char *shorten_unambiguous_ref(const char *refname, int strict)
{
	int i;
	static char **scanf_fmts;
	static int nr_rules;
	char *short_name;

	if (!nr_rules) {
		/*
		 * Pre-generate scanf formats from ref_rev_parse_rules[].
		 * Generate a format suitable for scanf from a
		 * ref_rev_parse_rules rule by interpolating "%s" at the
		 * location of the "%.*s".
		 */
		size_t total_len = 0;
		size_t offset = 0;

		/* the rule list is NULL terminated, count them first */
		for (nr_rules = 0; ref_rev_parse_rules[nr_rules]; nr_rules++)
			/* -2 for strlen("%.*s") - strlen("%s"); +1 for NUL */
			total_len += strlen(ref_rev_parse_rules[nr_rules]) - 2 + 1;

		scanf_fmts = xmalloc(st_add(st_mult(nr_rules, sizeof(char *)), total_len));

		offset = 0;
		for (i = 0; i < nr_rules; i++) {
			assert(offset < total_len);
			scanf_fmts[i] = (char *)&scanf_fmts[nr_rules] + offset;
			offset += snprintf(scanf_fmts[i], total_len - offset,
					   ref_rev_parse_rules[i], 2, "%s") + 1;
		}
	}

	/* bail out if there are no rules */
	if (!nr_rules)
		return xstrdup(refname);

	/* buffer for scanf result, at most refname must fit */
	short_name = xstrdup(refname);

	/* skip first rule, it will always match */
	for (i = nr_rules - 1; i > 0 ; --i) {
		int j;
		int rules_to_fail = i;
		int short_name_len;

		if (1 != sscanf(refname, scanf_fmts[i], short_name))
			continue;

		short_name_len = strlen(short_name);

		/*
		 * in strict mode, all (except the matched one) rules
		 * must fail to resolve to a valid non-ambiguous ref
		 */
		if (strict)
			rules_to_fail = nr_rules;

		/*
		 * check if the short name resolves to a valid ref,
		 * but use only rules prior to the matched one
		 */
		for (j = 0; j < rules_to_fail; j++) {
			const char *rule = ref_rev_parse_rules[j];
			char refname[PATH_MAX];

			/* skip matched rule */
			if (i == j)
				continue;

			/*
			 * the short name is ambiguous, if it resolves
			 * (with this previous rule) to a valid ref
			 * read_ref() returns 0 on success
			 */
			mksnpath(refname, sizeof(refname),
				 rule, short_name_len, short_name);
			if (ref_exists(refname))
				break;
		}

		/*
		 * short name is non-ambiguous if all previous rules
		 * haven't resolved to a valid ref
		 */
		if (j == rules_to_fail)
			return short_name;
	}

	free(short_name);
	return xstrdup(refname);
}

static struct string_list *hide_refs;

int parse_hide_refs_config(const char *var, const char *value, const char *section)
{
	if (!strcmp("transfer.hiderefs", var) ||
	    /* NEEDSWORK: use parse_config_key() once both are merged */
	    (starts_with(var, section) && var[strlen(section)] == '.' &&
	     !strcmp(var + strlen(section), ".hiderefs"))) {
		char *ref;
		int len;

		if (!value)
			return config_error_nonbool(var);
		ref = xstrdup(value);
		len = strlen(ref);
		while (len && ref[len - 1] == '/')
			ref[--len] = '\0';
		if (!hide_refs) {
			hide_refs = xcalloc(1, sizeof(*hide_refs));
			hide_refs->strdup_strings = 1;
		}
		string_list_append(hide_refs, ref);
	}
	return 0;
}

int ref_is_hidden(const char *refname, const char *refname_full)
{
	int i;

	if (!hide_refs)
		return 0;
	for (i = hide_refs->nr - 1; i >= 0; i--) {
		const char *match = hide_refs->items[i].string;
		const char *subject;
		int neg = 0;
		int len;

		if (*match == '!') {
			neg = 1;
			match++;
		}

		if (*match == '^') {
			subject = refname_full;
			match++;
		} else {
			subject = refname;
		}

		/* refname can be NULL when namespaces are used. */
		if (!subject || !starts_with(subject, match))
			continue;
		len = strlen(match);
		if (!subject[len] || subject[len] == '/')
			return !neg;
	}
	return 0;
}

const char *find_descendant_ref(const char *dirname,
				const struct string_list *extras,
				const struct string_list *skip)
{
	int pos;

	if (!extras)
		return NULL;

	/*
	 * Look at the place where dirname would be inserted into
	 * extras. If there is an entry at that position that starts
	 * with dirname (remember, dirname includes the trailing
	 * slash) and is not in skip, then we have a conflict.
	 */
	for (pos = string_list_find_insert_index(extras, dirname, 0);
	     pos < extras->nr; pos++) {
		const char *extra_refname = extras->items[pos].string;

		if (!starts_with(extra_refname, dirname))
			break;

		if (!skip || !string_list_has_string(skip, extra_refname))
			return extra_refname;
	}
	return NULL;
}

int rename_ref_available(const char *oldname, const char *newname)
{
	struct string_list skip = STRING_LIST_INIT_NODUP;
	struct strbuf err = STRBUF_INIT;
	int ret;

	string_list_insert(&skip, oldname);
	ret = !verify_refname_available(newname, NULL, &skip, &err);
	if (!ret)
		error("%s", err.buf);

	string_list_clear(&skip, 0);
	strbuf_release(&err);
	return ret;
}

int head_ref_submodule(const char *submodule, each_ref_fn fn, void *cb_data)
{
	struct object_id oid;
	int flag;

	if (submodule) {
		check_submodule_backend(submodule);
		if (resolve_gitlink_ref(submodule, "HEAD", oid.hash) == 0)
			return fn("HEAD", &oid, 0, cb_data);

		return 0;
	}

	if (!read_ref_full("HEAD", RESOLVE_REF_READING, oid.hash, &flag))
		return fn("HEAD", &oid, flag, cb_data);

	return 0;
}

int head_ref(each_ref_fn fn, void *cb_data)
{
	return head_ref_submodule(NULL, fn, cb_data);
}

/*
 * Return 1 if there are any duplicate refnames in the updates in
 * `transaction`, and fill in err with an appropriate error message.
 * Fill in `refnames` with the refnames from the transaction.
 */
static int get_affected_refnames(struct ref_transaction *transaction,
				 struct string_list *refnames,
				 struct strbuf *err)
{
	int i, n = transaction->nr;
	struct ref_update **updates;

	assert(err);

	updates = transaction->updates;
	/* Fail if a refname appears more than once in the transaction: */
	for (i = 0; i < n; i++)
		string_list_append(refnames, updates[i]->refname);
	string_list_sort(refnames);

	for (i = 1; i < n; i++)
		if (!strcmp(refnames->items[i - 1].string, refnames->items[i].string)) {
			strbuf_addf(err,
				    "Multiple updates for ref '%s' not allowed.",
				    refnames->items[i].string);
			return 1;
		}
	return 0;
}

/*
 * The common backend for the for_each_*ref* functions
 */
static int do_for_each_ref(const char *submodule, const char *base,
			   each_ref_fn fn, int trim, int flags,
			   void *cb_data)
{
	return the_refs_backend->do_for_each_ref(submodule, base, fn, trim,
						 flags, cb_data);
}

int for_each_ref(each_ref_fn fn, void *cb_data)
{
	return do_for_each_ref(NULL, "", fn, 0, 0, cb_data);
}

int for_each_ref_submodule(const char *submodule, each_ref_fn fn, void *cb_data)
{
	return do_for_each_ref(submodule, "", fn, 0, 0, cb_data);
}

int for_each_ref_in(const char *prefix, each_ref_fn fn, void *cb_data)
{
	return do_for_each_ref(NULL, prefix, fn, strlen(prefix), 0, cb_data);
}

int for_each_fullref_in(const char *prefix, each_ref_fn fn, void *cb_data, unsigned int broken)
{
	unsigned int flag = 0;

	if (broken)
		flag = DO_FOR_EACH_INCLUDE_BROKEN;
	return do_for_each_ref(NULL, prefix, fn, 0, flag, cb_data);
}

int for_each_ref_in_submodule(const char *submodule, const char *prefix,
		each_ref_fn fn, void *cb_data)
{
	return do_for_each_ref(submodule, prefix, fn, strlen(prefix), 0, cb_data);
}

int for_each_replace_ref(each_ref_fn fn, void *cb_data)
{
	return do_for_each_ref(NULL, git_replace_ref_base, fn,
			       strlen(git_replace_ref_base), 0, cb_data);
}

int for_each_namespaced_ref(each_ref_fn fn, void *cb_data)
{
	struct strbuf buf = STRBUF_INIT;
	int ret;
	strbuf_addf(&buf, "%srefs/", get_git_namespace());
	ret = do_for_each_ref(NULL, buf.buf, fn, 0, 0, cb_data);
	strbuf_release(&buf);
	return ret;
}

int for_each_rawref(each_ref_fn fn, void *cb_data)
{
	return do_for_each_ref(NULL, "", fn, 0,
			       DO_FOR_EACH_INCLUDE_BROKEN, cb_data);
}

static int read_raw_ref(const char *submodule, const char *refname,
			unsigned char *sha1, struct strbuf *symref,
			unsigned int *flags)
{
	return the_refs_backend->read_raw_ref(submodule, refname, sha1,
					      symref, flags);
}

/* This function needs to return a meaningful errno on failure */
const char *resolve_ref_unsafe_submodule(const char *submodule,
					 const char *refname,
					 int resolve_flags,
					 unsigned char *sha1,
					 int *flags)
{
	static struct strbuf sb_refname = STRBUF_INIT;
	int unused_flags;
	int symref_count;

	if (!flags)
		flags = &unused_flags;

	*flags = 0;

	if (check_refname_format(refname, REFNAME_ALLOW_ONELEVEL)) {
		if (!(resolve_flags & RESOLVE_REF_ALLOW_BAD_NAME) ||
		    !refname_is_safe(refname)) {
			errno = EINVAL;
			return NULL;
		}

		/*
		 * dwim_ref() uses REF_ISBROKEN to distinguish between
		 * missing refs and refs that were present but invalid,
		 * to complain about the latter to stderr.
		 *
		 * We don't know whether the ref exists, so don't set
		 * REF_ISBROKEN yet.
		 */
		*flags |= REF_BAD_NAME;
	}

	for (symref_count = 0; symref_count < SYMREF_MAXDEPTH; symref_count++) {
		unsigned int read_flags = 0;

		if (read_raw_ref(submodule, refname, sha1, &sb_refname, &read_flags)) {
			*flags |= read_flags;
			if (errno != ENOENT || (resolve_flags & RESOLVE_REF_READING))
				return NULL;
			hashclr(sha1);
			if (*flags & REF_BAD_NAME)
				*flags |= REF_ISBROKEN;
			return refname;
		}

		*flags |= read_flags;

		if (!(read_flags & REF_ISSYMREF)) {
			if (*flags & REF_BAD_NAME) {
				hashclr(sha1);
				*flags |= REF_ISBROKEN;
			}
			return refname;
		}

		refname = sb_refname.buf;
		if (resolve_flags & RESOLVE_REF_NO_RECURSE) {
			hashclr(sha1);
			return refname;
		}
		if (check_refname_format(refname, REFNAME_ALLOW_ONELEVEL)) {
			if (!(resolve_flags & RESOLVE_REF_ALLOW_BAD_NAME) ||
			    !refname_is_safe(refname)) {
				errno = EINVAL;
				return NULL;
			}

			*flags |= REF_ISBROKEN | REF_BAD_NAME;
		}
	}

	errno = ELOOP;
	return NULL;
}

const char *resolve_ref_unsafe(const char *refname, int resolve_flags,
			       unsigned char *sha1, int *flags)
{
	return resolve_ref_unsafe_submodule(NULL, refname, resolve_flags,
					    sha1, flags);
}

/* backend functions */
int refs_init_db(struct strbuf *err)
{
	return the_refs_backend->init_db(err);
}

/*
 * Special case for symbolic refs when REF_NODEREF is not turned on.
 * Dereference them here, mark them REF_LOG_ONLY, and add an update
 * for the underlying ref.
 */
static int dereference_symrefs(struct ref_transaction *transaction,
			       struct strbuf *err)
{
	int i;
	int nr = transaction->nr;

	for (i = 0; i < nr; i++) {
		struct ref_update *update = transaction->updates[i];
		const char *resolved;
		unsigned char sha1[20];
		int resolve_flags = 0;
		int mustexist = update->flags & REF_HAVE_OLD &&
			!is_null_sha1(update->old_sha1);
		int deleting = (update->flags & REF_HAVE_NEW) &&
			is_null_sha1(update->new_sha1);

		if (mustexist)
			resolve_flags |= RESOLVE_REF_READING;
		if (deleting)
			resolve_flags |= RESOLVE_REF_ALLOW_BAD_NAME |
				RESOLVE_REF_NO_RECURSE;

		if (strcmp(update->refname, "HEAD"))
			update->flags |= REF_IS_NOT_HEAD;

		resolved = resolve_ref_unsafe(update->refname, resolve_flags,
					      sha1, &update->type);
		if (!resolved) {
			/*
			 * We may notice this breakage later and die
			 * with a sensible error message
			 */
			update->type |= REF_ISBROKEN;
			continue;
		}

		hashcpy(update->read_sha1, sha1);

		if (update->flags & REF_NODEREF ||
		    !(update->type & REF_ISSYMREF))
			continue;

		/* Create a new transaction for the underlying ref */
		if (ref_transaction_update(transaction,
					   resolved,
					   update->new_sha1,
					   (update->flags & REF_HAVE_OLD) ?
					   update->old_sha1 : NULL,
					   update->flags & ~REF_IS_NOT_HEAD,
					   update->msg, err))
			return -1;

		/* Make the symbolic ref update non-recursive */
		update->flags |= REF_LOG_ONLY | REF_NODEREF;
		update->flags &= ~REF_HAVE_OLD;
	}

	return 0;
}

/*
 * Move all non-normal ref updates into a specially-created
 * files-backend transaction
 */
static int move_abnormal_ref_updates(struct ref_transaction *transaction,
				     struct ref_transaction *files_transaction,
				     struct strbuf *err)
{
	int i, normal_nr = 0;

	for (i = 0; i < transaction->nr; i++) {
		struct ref_update *update = transaction->updates[i];

		if (ref_type(update->refname) == REF_TYPE_NORMAL)
			transaction->updates[normal_nr++] = update;
		else
			add_update_obj(files_transaction, update);
	}

	transaction->nr = normal_nr;
	return 0;
}

static int do_ref_transaction_commit(struct ref_transaction *transaction,
				     struct strbuf *err,
				     ref_transaction_commit_fn *commit_fn)
{
	int ret = -1;
	struct string_list affected_refnames = STRING_LIST_INIT_NODUP;
	struct string_list files_affected_refnames = STRING_LIST_INIT_NODUP;
	struct ref_transaction *files_transaction = NULL;

	assert(err);

	if (transaction->state != REF_TRANSACTION_OPEN)
		die("BUG: commit called for transaction that is not open");

	if (!transaction->nr) {
		transaction->state = REF_TRANSACTION_CLOSED;
		return 0;
	}

	ret = dereference_symrefs(transaction, err);
	if (ret)
		goto done;

	if (the_refs_backend != &refs_be_files) {
		files_transaction = ref_transaction_begin(err);
		if (!files_transaction)
			goto done;

		ret = move_abnormal_ref_updates(transaction, files_transaction,
						err);
		if (ret)
			goto done;

		/* files backend commit */
		if (get_affected_refnames(files_transaction,
						 &files_affected_refnames,
						 err)) {
			ret = TRANSACTION_GENERIC_ERROR;
			goto done;
		}
	}

	/* main backend commit */
	if (get_affected_refnames(transaction, &affected_refnames, err)) {
		ret = TRANSACTION_GENERIC_ERROR;
		goto done;
	}

	ret = commit_fn(transaction, &affected_refnames, err);
	if (ret)
		goto done;

	if (files_transaction) {
		ret = refs_be_files.transaction_commit(files_transaction,
						       &files_affected_refnames,
						       err);
		if (ret) {
			warning(split_transaction_fail_warning);
			goto done;
		}
	}

done:
	string_list_clear(&affected_refnames, 0);
	string_list_clear(&files_affected_refnames, 0);
	if (files_transaction)
		ref_transaction_free(files_transaction);
	return ret;
}

int ref_transaction_commit(struct ref_transaction *transaction,
			   struct strbuf *err)
{
	return do_ref_transaction_commit(transaction, err,
					 the_refs_backend->transaction_commit);
}

int verify_refname_available(const char *refname, struct string_list *extra,
			     struct string_list *skip, struct strbuf *err)
{
	return the_refs_backend->verify_refname_available(refname, extra, skip, err);
}

int pack_refs(unsigned int flags)
{
	return the_refs_backend->pack_refs(flags);
}

int peel_ref(const char *refname, unsigned char *sha1)
{
	return the_refs_backend->peel_ref(refname, sha1);
}

int create_symref(const char *ref_target, const char *refs_heads_master,
		  const char *logmsg)
{
	if (ref_type(ref_target) != REF_TYPE_NORMAL)
		return refs_be_files.create_symref(ref_target, refs_heads_master,
						   logmsg);
	return the_refs_backend->create_symref(ref_target, refs_heads_master,
					       logmsg);
}

int resolve_gitlink_ref(const char *path, const char *refname,
			unsigned char *sha1)
{
	if (check_submodule_backend(path))
		return -1;

	return the_refs_backend->resolve_gitlink_ref(path, refname, sha1);
}

int for_each_reflog_ent_reverse(const char *refname, each_reflog_ent_fn fn,
				void *cb_data)
{
	return the_refs_backend->for_each_reflog_ent_reverse(refname, fn,
							     cb_data);
}

int for_each_reflog_ent(const char *refname, each_reflog_ent_fn fn,
			void *cb_data)
{
	return the_refs_backend->for_each_reflog_ent(refname, fn, cb_data);
}

int for_each_reflog(each_ref_fn fn, void *cb_data)
{
	return the_refs_backend->for_each_reflog(fn, cb_data);
}

int reflog_exists(const char *refname)
{
	return the_refs_backend->reflog_exists(refname);
}

int safe_create_reflog(const char *refname, int force_create,
		       struct strbuf *err)
{
	return the_refs_backend->create_reflog(refname, force_create, err);
}

int delete_reflog(const char *refname)
{
	if (ref_type(refname) != REF_TYPE_NORMAL)
		return refs_be_files.delete_reflog(refname);
	return the_refs_backend->delete_reflog(refname);
}

int reflog_expire(const char *refname, const unsigned char *sha1,
		  unsigned int flags,
		  reflog_expiry_prepare_fn prepare_fn,
		  reflog_expiry_should_prune_fn should_prune_fn,
		  reflog_expiry_cleanup_fn cleanup_fn,
		  void *policy_cb_data)
{
	return the_refs_backend->reflog_expire(refname, sha1, flags,
					       prepare_fn, should_prune_fn,
					       cleanup_fn, policy_cb_data);
}

int initial_ref_transaction_commit(struct ref_transaction *transaction,
				   struct strbuf *err)
{
	return do_ref_transaction_commit(transaction, err,
					 the_refs_backend->initial_transaction_commit);
}

int delete_refs(struct string_list *refnames)
{
	return the_refs_backend->delete_refs(refnames);
}

int rename_ref(const char *oldref, const char *newref, const char *logmsg)
{
	if ((ref_type(oldref) == REF_TYPE_NORMAL) !=
	    (ref_type(newref) == REF_TYPE_NORMAL)) {
		return error(
			_("Both ref arguments to rename_ref must be normal, "
			  "or both must be per-worktree/pseudorefs"));
	}
	if (ref_type(oldref) == REF_TYPE_NORMAL)
		/* The files backend always deals with non-normal refs */
		return the_refs_backend->rename_ref(oldref, newref, logmsg);
	else
		return refs_be_files.rename_ref(oldref, newref, logmsg);
}
