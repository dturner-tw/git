/*
 * This file implements a lmdb backend for refs.
 *
 * The design of this backend relies on lmdb's write lock -- that is, any
 * write transaction blocks all other writers.  Thus, as soon as a ref
 * transaction is opened, we know that any values we read won't
 * change out from under us, and we have a fully-consistent view of the
 * database.
 *
 * We store the content of refs including the trailing \0 so that
 * standard C string functions can handle them.  Just like struct
 * strbuf.
 */
#include <lmdb.h>
#include <sys/uio.h>
#include "cache.h"
#include "object.h"
#include "refs.h"
#include "tag.h"
#include "lockfile.h"
#include "run-command.h"

static struct trace_key db_trace = TRACE_KEY_INIT(LMDB);

static MDB_env *env;

struct lmdb_transaction {
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_cursor *cursor;
	struct hashmap updated_refs;
	unsigned int flags;
};

static struct lmdb_transaction transaction = {NULL};

struct ref_update {
	struct hashmap_entry ent;  /* must be first */
	size_t len;
	char refname[FLEX_ARRAY];
};

/*
 * Transaction states.
 * OPEN:   The transaction is in a valid state and can accept new updates.
 *         An OPEN transaction can be committed.
 * CLOSED: If an open transaction is successfully committed the state will
 *         change to CLOSED. No further changes can be made to a CLOSED
 *         transaction.
 *         CLOSED means that all updates have been successfully committed and
 *         the only thing that remains is to free the completed transaction.
 * ERROR:  The transaction has failed and is no longer committable.
 *         No further changes can be made to a CLOSED transaction and it must
 *         be rolled back using ref_transaction_free.
 */
enum transaction_state {
	TRANSACTION_OPEN   = 0,
	TRANSACTION_CLOSED = 1,
	TRANSACTION_ERROR  = 2,
};

int refdb_config(const char *var, const char *value, void *ptr)
{
       struct refdb_config_data *cdata = ptr;

       if (!strcmp(var, "core.refs-backend-type"))
	       cdata->refs_backend_type = strdup((char *)value);
       return 0;
}


static char *get_refdb_path(const char *base) {
	struct strbuf path_buf = STRBUF_INIT;
	strbuf_addf(&path_buf, "%s/refdb", base);
	return strbuf_detach(&path_buf, NULL);
}

static int in_write_transaction(void)
{
	return transaction.txn && !(transaction.flags & MDB_RDONLY);
}

static void init_env(MDB_env **env, const char *path)
{
	int rc;

	mkdir(path, 0775);
	if ((rc = mdb_env_create(env)) != MDB_SUCCESS)
		die("mdb_env_create failed: %s", mdb_strerror(rc));
	if ((rc = mdb_env_set_maxreaders(*env, 1000)) != MDB_SUCCESS)
		die("BUG: mdb_env_set_maxreaders failed: %s", mdb_strerror(rc));
	if ((rc = mdb_env_set_mapsize(*env, (1<<30))) != MDB_SUCCESS)
		die("BUG: mdb_set_mapsize failed: %s", mdb_strerror(rc));
	if ((rc = mdb_env_open(*env, path, 0 , 0664)) != MDB_SUCCESS)
		die("BUG: mdb_env_open (%s) failed: %s", path, mdb_strerror(rc));
}

static void lmdb_init_backend(struct refdb_config_data *data)
{
	char *path;

	if (env)
		return;

	path = get_refdb_path(data->refs_base);

	trace_printf_key(&db_trace, "Init backend\n");

	init_env(&env, path);
	free(path);
}

int ref_update_cmp(const void *entry, const void *entry_or_key, const void *keydata)
{

	const struct ref_update *existing = entry;
	const struct ref_update *incoming = entry_or_key;

	return existing->len != incoming->len ||
		memcmp(existing->refname, incoming->refname, existing->len);
}

/*
 * Call mdb_get on the current transaction.  On failure, die.
 */
static int mdb_get0(MDB_val *key, MDB_val *val)
{
	int rc = mdb_get(transaction.txn, transaction.dbi, key, val);
	if (rc) {
		if (rc != MDB_NOTFOUND)
			die("mdb_get failed: %s", mdb_strerror(rc));
		return rc;
	}
	assert(((char *)val->mv_data)[val->mv_size - 1] == 0);
	return 0;
}

/*
 * Begin a transaction. Because only one transaction per thread is
 * permitted, we use a global transaction object.  If a read-write
 * transaction is presently already in-progress, and a read-only
 * transaction is requested, the read-write transaction will be
 * returned instead.  If a read-write transaction is requested and a
 * read-only transaction is open, the read-only transaction will be
 * closed.
 *
 * It is a bug to request a read-write transaction during another
 * read-write transaction.
 *
 * As a result, it is unsafe to retain read-only transactions past the
 * point where a read-write transaction might be needed.  For
 * instance, any call that has callbacks outside this module must
 * conclude all of its reads from the database before calling those
 * callbacks, or must reacquire the transaction after its callbacks
 * are completed.
 */
int lmdb_transaction_begin_flags(struct strbuf *err, unsigned int flags)
{
	int rc;
	MDB_txn *txn;
	static int last_commands_run = 0;
	int force_restart = 0;

	if (total_commands_run != last_commands_run) {
		/*
		 * Since each transaction sees a consistent view of
		 * the db, downstream processes that write the db
		 * won't be seen in this transaction.  We don't know
		 * whether any given downstream process has made any
		 * writes, so if there have been any downstream processes,
		 * we had better reopen the transaction.
		 */
		force_restart = 1;
		last_commands_run = total_commands_run;
	}

	if (!transaction.txn) {
		hashmap_init(&transaction.updated_refs, ref_update_cmp, 0);
		if ((rc = mdb_txn_begin(env, NULL, flags, &txn)) != MDB_SUCCESS) {
			strbuf_addf(err, "mdb_txn_begin failed: %s",
				    mdb_strerror(rc));
			return -1;
		}
		if ((rc = mdb_dbi_open(txn, NULL, 0, &transaction.dbi)) != MDB_SUCCESS) {
			strbuf_addf(err, "mdb_txn_open failed: %s",
				    mdb_strerror(rc));
			return -1;
		}
		transaction.txn = txn;
		transaction.flags = flags;
		return 0;
	}

	if (transaction.flags == flags && !(flags & MDB_RDONLY)) {
		die("BUG: rw transaction started during another rw txn");
	}

	if (force_restart || (transaction.flags != flags && transaction.flags & MDB_RDONLY)) {
		/*
		 * RO -> RW, or forced restart due to possible changes
		 * from downstream processes.
		 */
		mdb_txn_abort(transaction.txn);
		if ((rc = mdb_txn_begin(env, NULL, flags, &txn)) != MDB_SUCCESS) {
			strbuf_addf(err, "restarting txn: mdb_txn_begin failed: %s",
				    mdb_strerror(rc));
			return -1;
		}
		if ((rc = mdb_dbi_open(txn, NULL, 0, &transaction.dbi)) != MDB_SUCCESS) {
			strbuf_addf(err, "mdb_txn_open failed: %s",
				    mdb_strerror(rc));
			return -1;
		}
		transaction.txn = txn;
		transaction.flags = flags;
	}
	/* RW -> RO just keeps the RW txn */
	return 0;
}

static void *lmdb_transaction_begin_flags_or_die(int flags)
{
	struct strbuf err = STRBUF_INIT;
	if (lmdb_transaction_begin_flags(&err, flags))
		die("%s", err.buf);
	return &transaction;
}

static void *lmdb_transaction_begin(struct strbuf *err)
{
	if (lmdb_transaction_begin_flags(err, 0))
		return NULL;
	return &transaction;
}

#define MAXDEPTH 5

static const char* parse_ref_data(MDB_txn *txn, MDB_dbi dbi, const char *refname,
				  const char *ref_data, unsigned char *sha1,
				  int resolve_flags, int* flags, int bad_name)
{
	int depth = MAXDEPTH;
	const char *buf;
	static char refname_buffer[256];
	static char refdata_buffer[256];
	MDB_val key, val;
	int rc;

	for (;;) {
		if (--depth < 0) {
			return NULL;
		}

		if (!starts_with(ref_data, "ref:")) {
			if (get_sha1_hex(ref_data, sha1) ||
			    (ref_data[40] != '\0' && !isspace(ref_data[40]))) {
				if (flags)
					*flags |= REF_ISBROKEN;
				errno = EINVAL;
				return NULL;
			}

			if (bad_name) {
				hashclr(sha1);
				if (flags)
					*flags |= REF_ISBROKEN;
			}

			return refname;
		}
		if (flags)
			*flags |= REF_ISSYMREF;
		buf = ref_data + 4;
		while (isspace(*buf))
			buf++;
		refname = strcpy(refname_buffer, buf);
		if (resolve_flags & RESOLVE_REF_NO_RECURSE) {
			hashclr(sha1);
			return refname;
		}
		if (check_refname_format(buf, REFNAME_ALLOW_ONELEVEL)) {
			if (flags)
				*flags |= REF_ISBROKEN;

			if (!(resolve_flags & RESOLVE_REF_ALLOW_BAD_NAME) ||
			    !refname_is_safe(buf)) {
				errno = EINVAL;
				return NULL;
			}
			bad_name = 1;
		}

		key.mv_data = (char *)refname;
		key.mv_size = strlen(refname) + 1;
		rc = mdb_get(txn, dbi, &key, &val);
		if (rc) {
			if (rc != MDB_NOTFOUND)
				die("%s", mdb_strerror(rc));
			hashclr(sha1);
			if (bad_name) {
				if (flags)
					*flags |= REF_ISBROKEN;
			}
			if (resolve_flags & RESOLVE_REF_READING)
				return NULL;

			return refname;
		}
		ref_data = memcpy(refdata_buffer, val.mv_data, val.mv_size);
	}
	return refname;
}

static int is_refname_available_txn(MDB_txn *txn, MDB_dbi dbi, const char *refname, struct string_list *skip)
{
	MDB_cursor *cursor;
	MDB_val key;
	MDB_val val;
	int rc;
	size_t refname_len;
	char *search_key;
	int res = 1;
	size_t i;

	if ((rc = mdb_cursor_open(txn, dbi, &cursor)))
		die("mdb_cursor_open failed: %s", mdb_strerror(rc));

	refname_len = strlen(refname) + 2;
	key.mv_size = refname_len;
	search_key = xmalloc(refname_len);
	memcpy(search_key, refname, refname_len - 2);
	search_key[refname_len - 2] = '/';
	search_key[refname_len - 1] = 0;
	key.mv_data = search_key;

	rc = mdb_cursor_get(cursor, &key, &val, MDB_SET_RANGE);

	/*
	 * Check for subdirs of refname: we start at refname/
	 */
	while (1) {
		if (rc) {
			if (rc == MDB_NOTFOUND) {
				break;
			}
			die("mdb_cursor_get failed: %s", mdb_strerror(rc));
		} else {
			if (starts_with(key.mv_data, refname) &&
			    ((char*)key.mv_data)[refname_len - 2] == '/') {
				if (skip && string_list_has_string(skip, key.mv_data))
					goto next;
				res = 0;
				goto done;
			}
			break;
		}
	next:
		rc = mdb_cursor_get(cursor, &key, &val, MDB_NEXT);
	}

	/* Check for superdirs of refname. */
	for (i = 0; i < refname_len - 2; ++i) {
		if (search_key[i] == '/') {
			search_key[i] = 0;
			if (skip && string_list_has_string(skip, search_key)) {
				search_key[i] = '/';
				continue;
			}

			key.mv_data = search_key;
			key.mv_size = i + 1;
			rc = mdb_cursor_get(cursor, &key, &val, MDB_SET);
			if (rc) {
				if (rc != MDB_NOTFOUND)
					die("mdb_cursor_get failed: %s",
					    mdb_strerror(rc));
			} else {
				res = 0;
				break;
			}
			search_key[i] = '/';
		}
	}
done:
	mdb_cursor_close(cursor);
	free(search_key);
	return res;
}

static const char *resolve_ref_unsafe_txn(MDB_txn *txn, MDB_dbi dbi,
					  const char *refname,
					  int resolve_flags,
					  unsigned char *sha1,
					  int *flags)
{
	int bad_name = 0;
	int result;
	char *ref_data;
	struct MDB_val key, val;

	val.mv_size = 0;
	val.mv_data = NULL;

	if (flags)
		*flags = 0;

	if (check_refname_format(refname, REFNAME_ALLOW_ONELEVEL)) {
		if (flags)
			*flags |= REF_BAD_NAME;

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
		bad_name = 1;
	}

	key.mv_data = (void *)refname;
	key.mv_size = strlen(refname) + 1;
	result = mdb_get(txn, dbi, &key, &val);
	if (result) {
		if (result != MDB_NOTFOUND)
			die("%s", mdb_strerror(result));

		if (bad_name) {
			hashclr(sha1);
			if (flags)
				*flags |= REF_ISBROKEN;
		}

		if (resolve_flags & RESOLVE_REF_READING)
			return NULL;

		if (!is_refname_available_txn(txn, dbi, refname, NULL))
			return NULL;

		hashclr(sha1);
		return refname;
	}

	ref_data = val.mv_data;
	assert(ref_data[val.mv_size - 1] == 0);

	return parse_ref_data(txn, dbi, refname, ref_data, sha1, resolve_flags,
			      flags, bad_name);
}

/*
 * We use this as a fallback for FETCH_HEAD on the assumption that
 * FETCH_HEAD will be a simple (non-symbolic) ref.
 */
const char *files_resolve_ref_unsafe(const char *refname,
				     int resolve_flags, unsigned char *sha1, int *flags);

static const char *lmdb_resolve_ref_unsafe(const char *refname, int resolve_flags,
					   unsigned char *sha1, int *flags)
{

	if (!strcmp("FETCH_HEAD", refname) ||
	    !strcmp("MERGE_HEAD", refname))
		return files_resolve_ref_unsafe(refname, resolve_flags, sha1, flags);

	lmdb_transaction_begin_flags_or_die(MDB_RDONLY);
	return resolve_ref_unsafe_txn(transaction.txn, transaction.dbi, refname,
				      resolve_flags, sha1, flags);
}

static void write_u64(char *buf, uint64_t number)
{
	int i;

	for (i = 0; i < 8; ++i)
		buf[i] = (number >> (i * 8)) & 0xff;
}

static int log_ref_write(const char *refname,
			 const unsigned char *old_sha1,
			 const unsigned char *new_sha1,
			 const char *msg,
			 struct strbuf *err)
{
	MDB_val key, val;
	int len;
	uint64_t now = getnanotime();
	int result;

	if (log_all_ref_updates < 0)
		log_all_ref_updates = !is_bare_repository();

	/* it is assumed that we are in a ref transaction here */
	assert(transaction.txn);

	/* "logs/" + \0 + 8-byte timestamp for sorting and expiry */
	key.mv_size = strlen(refname) + 14;
	key.mv_data = xcalloc(1, key.mv_size);
	sprintf(key.mv_data, "logs/%s", refname);

	result = create_reflog(refname, err);
	if (result)
		return result;

	/* check that a reflog exists */
	if (mdb_get0(&key, &val)) {
		free(key.mv_data);
		return 0;
	}

	write_u64(key.mv_data + key.mv_size - 8, htonll(now));

	val.mv_data = format_reflog_msg(old_sha1, new_sha1,
					git_committer_info(0), msg,
					&len);
	assert(len >= 85);
	((char *)val.mv_data)[len] = 0;
	val.mv_size = len + 1;

	if (mdb_put(transaction.txn, transaction.dbi, &key, &val, 0)) {
		return 1;
	}

	free(key.mv_data);
	free(val.mv_data);

	return 0;
}

/*
 * Return true iff a reference named refname could be created without
 * conflicting with the name of an existing reference.  If skip is
 * non-NULL, ignore potential conflicts with refs in skip (e.g.,
 * because they are scheduled for deletion in the same operation).
 *
 * Two reference names conflict if one of them exactly matches the
 * leading components of the other; e.g., "foo/bar" conflicts with
 * both "foo" and with "foo/bar/baz" but not with "foo/bar" or
 * "foo/barbados".
 *
 * skip must be sorted.
 */
static int lmdb_is_refname_available(const char *refname, struct string_list *skip) {
	lmdb_transaction_begin_flags_or_die(MDB_RDONLY);
	return is_refname_available_txn(transaction.txn, transaction.dbi, refname, skip);
}

static const char *check_ref(MDB_txn *txn, const char *refname,
			     const unsigned char *old_sha1,
			     unsigned char *resolved_sha1, int flags, int *type_p)
{
	int mustexist = (old_sha1 && !is_null_sha1(old_sha1));
	int resolve_flags = 0;
	int type;

	if (mustexist)
		resolve_flags |= RESOLVE_REF_READING;
	if (flags & REF_DELETING) {
		resolve_flags |= RESOLVE_REF_ALLOW_BAD_NAME;
		if (flags & REF_NODEREF)
			resolve_flags |= RESOLVE_REF_NO_RECURSE;
	}

	refname = resolve_ref_unsafe(refname, resolve_flags,
				     resolved_sha1, &type);
	if (type_p)
	    *type_p = type;
	if (!refname) {
		return NULL;
	}

	if (old_sha1) {
		if (flags & REF_NODEREF) {
			resolve_flags &= ~RESOLVE_REF_NO_RECURSE;
			resolve_ref_unsafe(refname, resolve_flags,
					   resolved_sha1, &type);
		}
		if (hashcmp(old_sha1, resolved_sha1)) {
			error("Ref %s is at %s but expected %s", refname,
			      sha1_to_hex(resolved_sha1), sha1_to_hex(old_sha1));

			return NULL;
		}
	}
	return refname;
}

int lmdb_transaction_create(void *transaction,
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


static int lmdb_transaction_delete(void *transaction,
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

static int lmdb_transaction_verify(void *transaction,
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

char *fmt_sha1(const unsigned char *sha1) {
	if (sha1 == NULL)
		return "(null)";
	char *f = sha1_to_hex(sha1);
	f[8] = 0;
	return f;
}

static int lmdb_delete_reflog(const char *refname);

static int lmdb_transaction_update(void *trans,
				   const char *refname,
				   const unsigned char *new_sha1,
				   const unsigned char *old_sha1,
				   unsigned int flags, const char *msg,
				   struct strbuf *err)
{
	struct lmdb_transaction *transaction = trans;
	const char *orig_refname = refname;
	MDB_val key, val;
	struct ref_update *update, *old;
	unsigned char resolved_sha1[20];
	size_t len;
	int type;
	int rc;

	if (new_sha1)
		flags |= REF_HAVE_NEW;
	if (old_sha1)
		flags |= REF_HAVE_OLD;

	if ((flags & REF_HAVE_NEW) && is_null_sha1(new_sha1))
		flags |= REF_DELETING;

	if (new_sha1 && !is_null_sha1(new_sha1) &&
	    check_refname_format(refname, REFNAME_ALLOW_ONELEVEL)) {
		strbuf_addf(err, "refusing to update ref with bad name %s",
			    refname);
		return TRANSACTION_GENERIC_ERROR;
	}

	len = strlen(orig_refname);
	update = xmalloc(sizeof(*update) + len + 1);
	update->len = len;
	strcpy(update->refname, orig_refname);
	hashmap_entry_init(update, memhash(update->refname, len));
	old = hashmap_put(&(transaction->updated_refs), update);
	if (old) {
		strbuf_addf(err, "Multiple updates for ref '%s' not allowed.",
			    orig_refname);
		free(old);
		return TRANSACTION_GENERIC_ERROR;
	}

	refname = check_ref(transaction->txn, orig_refname, old_sha1,
			    resolved_sha1, flags, &type);

	if (refname == NULL) {
		strbuf_addf(err, "Cannot lock the ref '%s'", orig_refname);
		return TRANSACTION_GENERIC_ERROR;
	}

	if (!(flags & REF_DELETING) && is_null_sha1(resolved_sha1) &&
	    !is_refname_available_txn(transaction->txn, transaction->dbi, refname, NULL))
		return TRANSACTION_NAME_CONFLICT;

	if (flags & REF_NODEREF)
		refname = orig_refname;

	key.mv_size = strlen(refname) + 1;
	key.mv_data = (void *)refname;

	if ((flags & REF_HAVE_NEW) && !is_null_sha1(new_sha1)) {
		int overwriting_symref = ((type & REF_ISSYMREF) &&
					  (flags & REF_NODEREF));

		struct object *o = parse_object(new_sha1);
		if (!o) {
			strbuf_addf(err,
				    "Trying to write ref %s with nonexistent object %s",
				    refname, sha1_to_hex(new_sha1));
			return -1;
		}
		if (o->type != OBJ_COMMIT && is_branch(refname)) {
			strbuf_addf(err,
				    "Trying to write non-commit object %s to branch %s",
				    sha1_to_hex(new_sha1), refname);
			return -1;
		}

		if (!overwriting_symref
		    && !hashcmp(resolved_sha1, new_sha1)) {
			/*
			 * The reference already has the desired
			 * value, so we don't need to write it.
			 */
			flags |= REF_NO_REFLOG;
		} else {
			char *new_sha1_hex;
			val.mv_size = 41;
			if (new_sha1)
				new_sha1_hex = sha1_to_hex(new_sha1);
			else
				new_sha1_hex = sha1_to_hex(null_sha1);
			val.mv_data = new_sha1_hex;

			if ((rc = mdb_put(transaction->txn, transaction->dbi, &key,
					 &val, 0))) {
				strbuf_addf(err,
					    "Cannot update the ref '%s': %s.",
					    update->refname, mdb_strerror(rc));
				return TRANSACTION_GENERIC_ERROR;
			}
		}
	}

	if (flags & REF_DELETING) {
		if ((rc = mdb_del(transaction->txn, transaction->dbi, &key, NULL))) {
			if (rc != MDB_NOTFOUND) {
				die("mdb_del failed: %s", mdb_strerror(rc));
			}
			if (old_sha1 && !is_null_sha1(old_sha1)) {
				strbuf_addf(err, "No such ref %s", refname);
				return TRANSACTION_GENERIC_ERROR;
			}
		}
		lmdb_delete_reflog(orig_refname);
	} else if (!(flags & REF_NO_REFLOG)) {
		if (log_ref_write(orig_refname,
				  resolved_sha1,
				  new_sha1 ? new_sha1 : null_sha1,
				  msg, err) < 0)
			return -1;
		if (strcmp (refname, orig_refname) &&
		    log_ref_write(refname,
				  resolved_sha1,
				  new_sha1 ? new_sha1 : null_sha1,
				  msg, err) < 0) {
			return -1;
		}
	}

	return 0;
}

static void lmdb_transaction_free0(struct lmdb_transaction *transaction)
{
	hashmap_free(&transaction->updated_refs, 1);
	transaction->txn = NULL;
}

static void lmdb_transaction_free(void *trans)
{
	struct lmdb_transaction *transaction = trans;
	if (!transaction->txn)
		return;

	mdb_txn_abort(transaction->txn);
	lmdb_transaction_free0(transaction);
	return;
}

static int lmdb_transaction_commit(void *trans, struct strbuf *err)
{
	struct lmdb_transaction *transaction = trans;
	int result;

	result = mdb_txn_commit(transaction->txn);
	lmdb_transaction_free0(transaction);
	return result;
}

static int rename_reflog_ent(unsigned char *osha1, unsigned char *nsha1,
			     const char *email, unsigned long timestamp, int tz,
			     const char *message, void *cb_data)
{

	const char *newrefname = cb_data;
	int rc;
	MDB_val key, new_key, val;

	assert(transaction.cursor);

	rc = mdb_cursor_get(transaction.cursor, &key, &val, MDB_GET_CURRENT);
	if (rc)
		die("renaming ref: mdb_cursor_get failed unexpectedly: %s", mdb_strerror(rc));

	new_key.mv_size = strlen(newrefname) + 5 + 1 + 8;
	new_key.mv_data = xmalloc(new_key.mv_size);
	strcpy(new_key.mv_data, "logs/");
	strcpy(new_key.mv_data + 5, newrefname);
	memcpy(new_key.mv_data + new_key.mv_size - 8, key.mv_data + key.mv_size - 8, 8);
	if ((rc = mdb_put(transaction.txn, transaction.dbi, &new_key, &val, 0)))
		die("renaming ref: mdb_put failed: %s", mdb_strerror(rc));

	if ((rc = mdb_cursor_del(transaction.cursor, 0)))
		die("renaming ref: mdb_cursor_del failed: %s", mdb_strerror(rc));

	return 0;
}

static int lmdb_rename_ref(const char *oldref, const char *newref, const char *logmsg)
{
	unsigned char orig_sha1[20];
	int flag = 0;
	int log = reflog_exists(oldref);
	const char *symref = NULL;
	struct strbuf err = STRBUF_INIT;

	assert(!in_write_transaction());

	if (!strcmp(oldref, newref))
		return 0;

	lmdb_transaction_begin_flags_or_die(0);

	symref = resolve_ref_unsafe(oldref, RESOLVE_REF_READING,
				    orig_sha1, &flag);
	if (flag & REF_ISSYMREF)
		return error("refname %s is a symbolic ref, renaming it is not supported",
			oldref);
	if (!symref)
		return error("refname %s not found", oldref);

	if (!rename_ref_available(oldref, newref))
		return 1;

	if (log) {
		struct strbuf old_log_sentinel = STRBUF_INIT;
		MDB_val key;
		int log_all;
		int rc;

		log_all = log_all_ref_updates;
		log_all_ref_updates = 1;
		if (create_reflog(newref, &err)) {
			error("can't create reflog for %s: %s", newref, err.buf);
			strbuf_release(&err);
			return 1;
		}
		log_all_ref_updates = log_all;

		for_each_reflog_ent(oldref, rename_reflog_ent, (void *) newref);
		strbuf_addf(&old_log_sentinel, "logs/%sxxxxxxxx", oldref);
		memset(old_log_sentinel.buf + old_log_sentinel.len - 8, 0, 8);

		key.mv_size = old_log_sentinel.len;
		key.mv_data = old_log_sentinel.buf;
		rc = mdb_del(transaction.txn, transaction.dbi, &key, NULL);
		/* It's OK if the old reflog is missing */
		if (rc && rc != MDB_NOTFOUND)
			die("renaming reflog: mdb_del failed: %s\n", mdb_strerror(rc));

		strbuf_release(&old_log_sentinel);
	}

	if (ref_transaction_delete(&transaction, oldref,
		orig_sha1, REF_NODEREF, NULL, &err)) {
		error("unable to delete old %s", oldref);
		return 1;
	}
/*
	if (!read_ref_full(newref, RESOLVE_REF_READING, sha1, NULL) &&
	    ref_transaction_delete(&transaction, newref, sha1, REF_NODEREF, NULL, &err)) {
		error("unable to delete existing %s: %s", newref, err.buf);
		strbuf_release(&err);
		return 1;
	}
*/
	if (lmdb_transaction_update(&transaction, newref, orig_sha1, NULL,
				    0, logmsg, &err)) {
		error("%s", err.buf);
		strbuf_release(&err);
		return 1;
	}

	if (lmdb_transaction_commit(&transaction, &err)) {
		error("%s", err.buf);
		strbuf_release(&err);
		return 1;
	}

	return 0;

}

static int lmdb_for_each_reflog_ent_order(const char *refname,
					  each_reflog_ent_fn fn,
					  void *cb_data, int reverse)
{
	MDB_val key, val;
	char *search_key;
	char *log_path;
	int len;
	MDB_cursor *cursor;
	int ret = 0;
	int rc;
	uint64_t zero = 0ULL;

	len = strlen(refname) + 6;
	log_path = xmalloc(len);
	search_key = xmalloc(len + 1);
	sprintf(log_path, "logs/%s", refname);
	strcpy(search_key, log_path);

	if (reverse) {
		/*
		 * For a reverse search, start at the key
		 * lexicographically after the searched-for key.
		 * That's the one with \001 appended to the key.
		 */

		search_key[len - 1] = 1;
		search_key[len] = 0;
		key.mv_size = len + 1;
	} else {
		key.mv_size = len;
	}

	key.mv_data = search_key;

	lmdb_transaction_begin_flags_or_die(MDB_RDONLY);

	if ((rc = mdb_cursor_open(transaction.txn, transaction.dbi, &cursor)))
		die("mdb_cursor_open failed: %s", mdb_strerror(rc));

	transaction.cursor = cursor;

	/*
	 * MDB's cursor API requires that the first mdb_cursor_get be
	 * called with MDB_SET_RANGE.  For reverse searches, this will
	 * give us the entry one-past the entry we're looking for, so
	 * we should jump back using MDB_PREV.  For forward searches,
	 * we skip the first (dummy) key by going straight to
	 * MDB_NEXT.
	 */
	rc = mdb_cursor_get(cursor, &key, &val, MDB_SET_RANGE);
	if (rc && rc != MDB_NOTFOUND) {
		die("mdb_cursor_get failed: %s\n", mdb_strerror(rc));
	}

	while (1) {
		struct strbuf sb = STRBUF_INIT;
		enum MDB_cursor_op direction = reverse ? MDB_PREV : MDB_NEXT;

		rc = mdb_cursor_get(cursor, &key, &val, direction);

		if (rc) {
			if (rc != MDB_NOTFOUND)
				die("mdb_cursor_get failed: %s", mdb_strerror(rc));
			break;
		}

		if (key.mv_size < len)
			break;

		if (!starts_with(key.mv_data, log_path) || ((char *)key.mv_data)[len - 1] != 0)
			break;

		if (!memcmp(&zero, ((char *)key.mv_data) + key.mv_size - 8, 8))
			continue;

		assert(val.mv_size != 0);

		strbuf_add(&sb, val.mv_data, val.mv_size - 1);
		ret = show_one_reflog_ent(&sb, fn, cb_data);

		strbuf_release(&sb);
		if (ret)
			break;
	}

	free(log_path);
	free(search_key);
	mdb_cursor_close(cursor);
	return ret;
}

static int lmdb_for_each_reflog_ent(const char *refname,
				    each_reflog_ent_fn fn,
				    void *cb_data)
{
	return lmdb_for_each_reflog_ent_order(refname, fn, cb_data, 0);
}

static int lmdb_for_each_reflog_ent_reverse(const char *refname,
					    each_reflog_ent_fn fn,
					    void *cb_data)
{
	return lmdb_for_each_reflog_ent_order(refname, fn, cb_data, 1);
}


static int lmdb_reflog_exists(const char *refname)
{
	MDB_val key, val;
	char *log_path;
	int len;
	MDB_cursor *cursor;
	int ret = 1;
	int rc;

	len = strlen(refname) + 6;
	log_path = xmalloc(len);
	sprintf(log_path, "logs/%s", refname);

	key.mv_data = log_path;
	key.mv_size = len;

	lmdb_transaction_begin_flags_or_die(MDB_RDONLY);

	if ((rc = mdb_cursor_open(transaction.txn, transaction.dbi, &cursor)))
		die("mdb_cursor_open failed: %s", mdb_strerror(rc));

	rc = mdb_cursor_get(cursor, &key, &val, MDB_NEXT);
	if (rc) {
		if (rc == MDB_NOTFOUND)
			ret = 0;
		else
			die("mdb_cursor_get failed: %s", mdb_strerror(rc));
	} else if (!starts_with(key.mv_data, log_path)) {
			ret = 1;
	}

	free(log_path);
	mdb_cursor_close(cursor);

	return ret;
}

struct wrapped_each_ref_fn {
	each_ref_fn *fn;
	void *cb_data;
};

static int check_reflog(const char *refname,
			const unsigned char *sha1, int flags, void *cb_data)
{
	struct wrapped_each_ref_fn *wrapped = cb_data;

	if (reflog_exists(refname))
		return wrapped->fn(refname, sha1, 0, wrapped->cb_data);

	return 0;
}

static int lmdb_for_each_reflog(each_ref_fn fn, void *cb_data)
{
	struct wrapped_each_ref_fn wrapped = {fn, cb_data};
	int result = head_ref(fn, cb_data);
	if (result)
	    return result;
	return for_each_ref(check_reflog, &wrapped);
}

static int lmdb_create_reflog(const char *refname, struct strbuf *err)
{
	/*
	 * We mark that there is a reflog by creating a key of the
	 * form logs/$refname followed by nine \0 (one for
	 * string-termination, 8 in lieu of a timestamp), with an empty
	 * value.
	 */

	int in_transaction = in_write_transaction();
	MDB_val key, val;
	int rc;

	if (!log_all_ref_updates)
		return 0;

	if (!in_transaction)
		lmdb_transaction_begin_flags_or_die(0);

	key.mv_size = strlen(refname) + 5 + 1 + 8;
	key.mv_data = xcalloc(1, key.mv_size);
	sprintf((char *)key.mv_data, "logs/%s", refname);
	val.mv_size = 0;
	val.mv_data = NULL;
	if ((rc = mdb_put(transaction.txn, transaction.dbi, &key, &val, 0))) {
		die("mdb_put unexpectedly failed: %s", mdb_strerror(errno));
	}

	free(key.mv_data);
	if (!in_transaction)
		return lmdb_transaction_commit(&transaction, err);
	return 0;
}


static int lmdb_delete_reflog(const char *refname)
{
	MDB_val key, val;
	char *log_path;
	int len;
	MDB_cursor *cursor;
	int ret = 0;
	int rc;
	struct strbuf err = STRBUF_INIT;
	int in_transaction = in_write_transaction();

	len = strlen(refname) + 6;
	log_path = xmalloc(len);
	sprintf(log_path, "logs/%s", refname);

	key.mv_data = log_path;
	key.mv_size = len;

	if (!in_transaction)
		lmdb_transaction_begin_flags_or_die(0);

	if ((rc = mdb_cursor_open(transaction.txn, transaction.dbi, &cursor)))
		die("mdb_cursor_open failed: %s", mdb_strerror(rc));

	rc = mdb_cursor_get(cursor, &key, &val, MDB_SET_RANGE);

	while (1) {
		if (rc) {
			if (rc != MDB_NOTFOUND)
				ret = -1;
			break;
		}

		if (key.mv_size < len)
			break;

		if (!starts_with(key.mv_data, log_path) || ((char*)key.mv_data)[len - 1] != 0)
			break;

		assert(mdb_cursor_del(cursor, 0) == 0);

		rc = mdb_cursor_get(cursor, &key, &val, MDB_NEXT);
	}

	free(log_path);
	mdb_cursor_close(cursor);
	transaction.cursor = NULL;

	if (!in_transaction)
		lmdb_transaction_commit(&transaction, &err);
	strbuf_release(&err);
	return ret;
}

struct expire_reflog_cb {
	unsigned int flags;
	reflog_expiry_should_prune_fn *should_prune_fn;
	void *policy_cb;
	unsigned char last_kept_sha1[20];
};

static int expire_reflog_ent(unsigned char *osha1, unsigned char *nsha1,
			     const char *email, unsigned long timestamp, int tz,
			     const char *message, void *cb_data)
{
	struct expire_reflog_cb *cb = cb_data;
	struct expire_reflog_policy_cb *policy_cb = cb->policy_cb;
	int rc;

	if (cb->flags & EXPIRE_REFLOGS_REWRITE)
		osha1 = cb->last_kept_sha1;

	if ((*cb->should_prune_fn)(osha1, nsha1, email, timestamp, tz,
				   message, policy_cb)) {
		if (cb->flags & EXPIRE_REFLOGS_DRY_RUN)
			printf("would prune %s", message);
		else {
			if (cb->flags & EXPIRE_REFLOGS_VERBOSE)
				printf("prune %s", message);

			if ((rc = mdb_cursor_del(transaction.cursor, 0)))
				die("mdb_cursor_del failed: %s", mdb_strerror(rc));
		}
	} else {
		hashcpy(cb->last_kept_sha1, nsha1);
		if (cb->flags & EXPIRE_REFLOGS_VERBOSE)
			printf("keep %s", message);
	}
	return 0;
}

static int write_ref(const char *refname, const unsigned char *sha1)
{
	struct strbuf err = STRBUF_INIT;
	void *transaction;

	transaction = lmdb_transaction_begin(&err);
	if (!transaction) {
		error("%s", err.buf);
		strbuf_release(&err);
		return -1;
	}

	if (lmdb_transaction_update(transaction, refname, sha1, NULL,
				    REF_NO_REFLOG, NULL, &err)) {
		error("%s", err.buf);
		strbuf_release(&err);
		return -1;
	}

	if (lmdb_transaction_commit(transaction, &err)) {
		error("%s", err.buf);
		strbuf_release(&err);
		return -1;
	}

	return 0;
}

int lmdb_reflog_expire(const char *refname, const unsigned char *sha1,
		       unsigned int flags,
		       reflog_expiry_prepare_fn prepare_fn,
		       reflog_expiry_should_prune_fn should_prune_fn,
		       reflog_expiry_cleanup_fn cleanup_fn,
		       void *policy_cb_data)
{
	struct expire_reflog_cb cb;
	int dry_run = flags & EXPIRE_REFLOGS_DRY_RUN;
	int status = 0;
	struct strbuf err = STRBUF_INIT;
	unsigned char resolved_sha1[20];
	int type;

	memset(&cb, 0, sizeof(cb));
	cb.flags = flags;
	cb.policy_cb = policy_cb_data;
	cb.should_prune_fn = should_prune_fn;

	lmdb_transaction_begin_flags_or_die(dry_run ? MDB_RDONLY : 0);

	check_ref(transaction.txn, refname, sha1,
		  resolved_sha1, 0, &type);

	(*prepare_fn)(refname, sha1, cb.policy_cb);
	lmdb_for_each_reflog_ent(refname, expire_reflog_ent, &cb);
	(*cleanup_fn)(cb.policy_cb);

	if (!dry_run) {
		/*
		 * It doesn't make sense to adjust a reference pointed
		 * to by a symbolic ref based on expiring entries in
		 * the symbolic reference's reflog. Nor can we update
		 * a reference if there are no remaining reflog
		 * entries.
		 */
		int update = (flags & EXPIRE_REFLOGS_UPDATE_REF) &&
			!(type & REF_ISSYMREF) &&
			!is_null_sha1(cb.last_kept_sha1);

		if (lmdb_transaction_commit(&transaction, &err)) {
			status |= error("couldn't write logs/%s: %s", refname,
					err.buf);
			strbuf_release(&err);
		} else if (update &&
			   write_ref(refname, cb.last_kept_sha1)) {
			status |= error("couldn't set %s",
					refname);
		}
	}
	return status;
}

static int lmdb_pack_refs(unsigned int flags)
{
	/* This concept does not exist in this backend. */
	return 0;
}

static int lmdb_peel_ref(const char *refname, unsigned char *sha1)
{
	int flag;
	unsigned char base[20];

	if (read_ref_full(refname, RESOLVE_REF_READING, base, &flag))
		return -1;

	return peel_object(base, sha1);
}

static int lmdb_create_symref(void *trans,
			      const char *ref_target,
			      const char *refs_heads_master,
			      const char *logmsg)
{

	struct strbuf err = STRBUF_INIT;
	unsigned char old_sha1[20], new_sha1[20];
	MDB_val key, val;
	char *valdata;
	int rc;
	struct lmdb_transaction *transaction = trans;

	if (logmsg && read_ref(ref_target, old_sha1))
		hashclr(old_sha1);

	key.mv_size = strlen(ref_target) + 1;
	key.mv_data = strdup(ref_target);

	val.mv_size = strlen(refs_heads_master) + 1 + 5;
	valdata = malloc(val.mv_size);
	sprintf(valdata, "ref: %s", refs_heads_master);
	val.mv_data = valdata;

	if ((rc = mdb_put(transaction->txn, transaction->dbi, &key, &val, 0)))
		die("mdb_put failed: %s", mdb_strerror(rc));

	if (logmsg && !read_ref(refs_heads_master, new_sha1) &&
	    log_ref_write(ref_target, old_sha1, new_sha1, logmsg, &err)) {
		error("log_ref_write failed: %s", err.buf);
		strbuf_release(&err);
	}

	free(key.mv_data);
	free(valdata);

	return 0;
}

MDB_env *submodule_txn_begin(const char *submodule, MDB_txn **txn, MDB_dbi *dbi)
{
	char *path;
	int rc;
	MDB_env *submodule_env = NULL;

	if (!is_directory(git_path_submodule(submodule, "refdb")))
		return NULL;

	path = git_path_submodule(submodule, "refdb");

	mkdir(path, 0775);

	init_env(&submodule_env, path);

	if ((rc = mdb_txn_begin(submodule_env, NULL, MDB_RDONLY, txn)) != MDB_SUCCESS) {
		die("mdb_txn_begin failed: %s", mdb_strerror(rc));

	}
	if ((rc = mdb_dbi_open(*txn, NULL, 0, dbi)) != MDB_SUCCESS) {
		die("mdb_txn_open failed: %s", mdb_strerror(rc));
	}

	return submodule_env;
}

static int lmdb_resolve_gitlink_ref(const char *submodule, const char *refname,
				     unsigned char *sha1)
{
	MDB_env *submodule_env;
	MDB_txn *submodule_txn = NULL;
	MDB_dbi submodule_dbi;
	int result;

	submodule_env = submodule_txn_begin(submodule, &submodule_txn,
					    &submodule_dbi);
	if (!submodule_env)
		return -1;
	result = !resolve_ref_unsafe_txn(submodule_txn, submodule_dbi, refname,
					 RESOLVE_REF_READING, sha1, NULL);

	mdb_txn_abort(submodule_txn);
	mdb_env_close(submodule_env);
	return result ? -1 : 0;
}

static int do_head_ref(const char *submodule, each_ref_fn fn, void *cb_data)
{
	unsigned char sha1[20];
	int flag;

	if (submodule) {
		if (resolve_gitlink_ref(submodule, "HEAD", sha1) == 0)
			return fn("HEAD", sha1, 0, cb_data);

		return 0;
	}

	if (!read_ref_full("HEAD", RESOLVE_REF_READING, sha1, &flag))
		return fn("HEAD", sha1, flag, cb_data);

	return 0;
}


static int lmdb_head_ref(each_ref_fn fn, void *cb_data)
{
	return do_head_ref(NULL, fn, cb_data);
}

static int lmdb_head_ref_submodule(const char *submodule, each_ref_fn fn,
				    void *cb_data)
{
	return do_head_ref(submodule, fn, cb_data);
}

/*
 * Call fn for each reference for which the refname begins with base.
 * If trim is non-zero, then trim that many characters off the
 * beginning of each refname before passing the refname to fn.  flags
 * can be DO_FOR_EACH_INCLUDE_BROKEN to include broken references in
 * the iteration.  If fn ever returns a non-zero value, stop the
 * iteration and return that value; otherwise, return 0.
 */
static int do_for_each_ref(MDB_txn *txn, MDB_dbi dbi,
			   const char *base, each_ref_fn fn, int trim,
			   int flags, void *cb_data)
{

	MDB_val key, val;
	MDB_cursor *cursor;
	int rc;
	int baselen;
	char *search_key;
	int retval = 0;

	if (!base || !*base) {
		base = "refs/";
		trim = 0;
	}

	baselen = strlen(base);
	search_key = xmalloc(baselen + 1);
	strcpy(search_key, base);
	key.mv_size = baselen + 1;
	key.mv_data = search_key;

	if ((rc = mdb_cursor_open(txn, dbi, &cursor)))
		die("mdb_cursor_open failed: %s", mdb_strerror(rc));

	rc = mdb_cursor_get(cursor, &key, &val, MDB_SET_RANGE);

	while (1) {
		unsigned char sha1[20];
		int parsed_flags = 0;

		if (rc) {
			if (rc != MDB_NOTFOUND)
				die("mdb_cursor_get failed");
			break;
		}

		/* skip logs */
		if (strlen(key.mv_data) != key.mv_size - 1)
			continue;

		if (memcmp(key.mv_data, base, baselen))
			break;

		parse_ref_data(txn, dbi, key.mv_data + (trim ? baselen : 0),
				    val.mv_data, sha1, 0, &parsed_flags, 0);

		if (flags & DO_FOR_EACH_INCLUDE_BROKEN ||
		    (!(parsed_flags & REF_ISBROKEN) &&
		     has_sha1_file(sha1))) {
			retval = fn(key.mv_data + (trim ? baselen : 0), sha1, flags, cb_data);
			if (retval)
				break;
		}

		rc = mdb_cursor_get(cursor, &key, &val, MDB_NEXT);
	}


	mdb_cursor_close(cursor);
	free(search_key);

	return retval;
}


static int lmdb_for_each_ref(each_ref_fn fn, void *cb_data)
{
	lmdb_transaction_begin_flags_or_die(MDB_RDONLY);
	return do_for_each_ref(transaction.txn, transaction.dbi, "", fn, 0, 0, cb_data);
}

static int lmdb_for_each_ref_submodule(const char *submodule, each_ref_fn fn,
					void *cb_data)
{
	MDB_txn *submodule_txn = NULL;
	MDB_dbi submodule_dbi;
	MDB_env *submodule_env;
	int result;

	if (!submodule)
		return for_each_ref(fn, cb_data);
	submodule_env = submodule_txn_begin(submodule, &submodule_txn, &submodule_dbi);
	if (!submodule_env)
		return 0;
	result = do_for_each_ref(submodule_txn, submodule_dbi, "", fn, 0, 0, cb_data);
	mdb_txn_abort(submodule_txn);
	mdb_env_close(submodule_env);
	return result;
}

static int lmdb_for_each_ref_in(const char *prefix, each_ref_fn fn,
				 void *cb_data)
{
	lmdb_transaction_begin_flags_or_die(MDB_RDONLY);
	return do_for_each_ref(transaction.txn, transaction.dbi, prefix, fn, strlen(prefix),
			       0, cb_data);
}

static int lmdb_for_each_ref_in_submodule(const char *submodule,
					   const char *prefix,
					   each_ref_fn fn, void *cb_data)
{
	MDB_txn *submodule_txn = NULL;
	MDB_dbi submodule_dbi;
	MDB_env *submodule_env;
	int result;

	if (!submodule)
		return for_each_ref_in(prefix, fn, cb_data);
	submodule_env = submodule_txn_begin(submodule, &submodule_txn, &submodule_dbi);
	if (!submodule_env)
		return 0;
	result = do_for_each_ref(submodule_txn, submodule_dbi, prefix, fn,
				 strlen(prefix), 0, cb_data);
	mdb_txn_abort(submodule_txn);
	mdb_env_close(submodule_env);
	return result;
}

static int lmdb_for_each_replace_ref(each_ref_fn fn, void *cb_data)
{
	lmdb_transaction_begin_flags_or_die(MDB_RDONLY);
	return do_for_each_ref(transaction.txn, transaction.dbi, "refs/replace/", fn, 13, 0, cb_data);
}

static int lmdb_for_each_namespaced_ref(each_ref_fn fn, void *cb_data)
{
	struct strbuf buf = STRBUF_INIT;
	int ret;
	strbuf_addf(&buf, "%srefs/", get_git_namespace());
	lmdb_transaction_begin_flags_or_die(MDB_RDONLY);
	ret = do_for_each_ref(transaction.txn, transaction.dbi, buf.buf, fn, 0, 0, cb_data);
	strbuf_release(&buf);
	return ret;
}

static int lmdb_for_each_rawref(each_ref_fn fn, void *cb_data)
{
	lmdb_transaction_begin_flags_or_die(MDB_RDONLY);
	return do_for_each_ref(transaction.txn, transaction.dbi, "", fn, 0,
			       DO_FOR_EACH_INCLUDE_BROKEN, cb_data);
}

int lmdb_begin_bulk_update(int flags)
{
	struct strbuf err = STRBUF_INIT;
	if (!lmdb_transaction_begin(&err)) {
		if (flags & LOCK_DIE_ON_ERROR)
			die("Failed to lock for bulk ref update");
		else {
			error("%s", err.buf);
			strbuf_release(&err);
			return -1;
		}
	}
	return 0;
}

void lmdb_bulk_update_add(const char *refname, const unsigned char *sha1)
{
	MDB_val key, val;
	int rc;

	key.mv_data = (char *)refname;
	key.mv_size = strlen(refname) + 1;
	val.mv_data = sha1_to_hex(sha1);
	val.mv_size = 41;
	rc = mdb_put(transaction.txn, transaction.dbi, &key, &val, 0);
	if (rc)
		die("Bulk ref update failed: %s", mdb_strerror(rc));
}

int lmdb_bulk_update_commit(void)
{
	struct strbuf err = STRBUF_INIT;
	if (lmdb_transaction_commit(&transaction, &err)) {
		error("%s", err.buf);
		strbuf_release(&err);
		return -1;
	}
	return 0;
}

/* For testing only! */
int test_refdb_raw_read(const char *key)
{
	MDB_val key_val, val;
	char *keydup;
	int rc;

	lmdb_transaction_begin_flags_or_die(MDB_RDONLY);
	keydup = strdup(key);
	key_val.mv_data = keydup;
	key_val.mv_size = strlen(key) + 1;

	rc = mdb_get0(&key_val, &val);
	free(keydup);
	switch (rc) {
	case 0:
		printf("%s\n", (char *)val.mv_data);
		return 0;
	case MDB_NOTFOUND:
		fprintf(stderr, "%s not found\n", key);
		return 1;
	default:
		return 2;
	}
}

/* For testing only! */
void test_refdb_raw_write(const char *key, const char *value)
{
	struct lmdb_transaction *transaction = lmdb_transaction_begin_flags_or_die(0);
	MDB_val key_val, val;
	char *keydup, *valdup;
	struct strbuf err = STRBUF_INIT;

	keydup = strdup(key);
	key_val.mv_data = keydup;
	key_val.mv_size = strlen(key) + 1;

	valdup = strdup(value);
	val.mv_data = valdup;
	val.mv_size = strlen(value) + 1;

	assert(mdb_put(transaction->txn, transaction->dbi, &key_val, &val, 0) == 0);
	assert(lmdb_transaction_commit(transaction, &err) == 0);

	free(keydup);
	free(valdup);
}

/* For testing only! */
int test_refdb_raw_delete(const char *key)
{
	MDB_val key_val;
	char *keydup;
	int rc;
	struct lmdb_transaction *transaction;
	struct strbuf err = STRBUF_INIT;

	transaction = lmdb_transaction_begin_flags_or_die(0);
	keydup = strdup(key);
	key_val.mv_data = keydup;
	key_val.mv_size = strlen(key) + 1;

	rc = mdb_del(transaction->txn, transaction->dbi, &key_val, NULL);
	assert(rc == 0 || rc == MDB_NOTFOUND);

	assert(lmdb_transaction_commit(transaction, &err) == 0);

	free(keydup);
	return rc;
}

/* For testing only! */
int test_refdb_raw_reflog(const char *refname)
{
	MDB_val key, val;
	char *search_key;
	char *log_path;
	int len;
	MDB_cursor *cursor;
	int rc;
	int result = 1;

	len = strlen(refname) + 5 + 1; /* logs/ + 0 */
	log_path = xmalloc(len);
	search_key = xmalloc(len);
	sprintf(log_path, "logs/%s", refname);
	strcpy(search_key, log_path);

	key.mv_data = search_key;
	key.mv_size = len;

	lmdb_transaction_begin_flags_or_die(MDB_RDONLY);

	if ((rc = mdb_cursor_open(transaction.txn, transaction.dbi, &cursor)))
		die("mdb_cursor_open failed: %s", mdb_strerror(rc));

	rc = mdb_cursor_get(cursor, &key, &val, MDB_SET_RANGE);
	if (rc) {
		if (rc != MDB_NOTFOUND)
			die("bad return from mdb_cursor_get");
		goto done;
	}

	while (1) {
		rc = mdb_cursor_get(cursor, &key, &val, MDB_NEXT);
		if (rc) {
			if (rc != MDB_NOTFOUND)
				die("bad return from mdb_cursor_get");
			break;
		}

		if (memcmp(key.mv_data, log_path, len))
			break;

		assert(((char *)val.mv_data)[val.mv_size - 1] == 0);

		result = 0;
		printf("%s", (char *)val.mv_data);
	}

done:
	free(log_path);
	free(search_key);
	mdb_cursor_close(cursor);
	return result;
}

/* For testing only! */
void test_refdb_raw_delete_reflog(char *refname)
{
	MDB_val key, val;
	char *search_key;
	MDB_cursor *cursor;
	int rc;
	int len;
	struct strbuf err = STRBUF_INIT;

	if (refname) {
		len = strlen(refname) + 5 + 1; /* logs/ + 0*/
		search_key = xmalloc(len);
		sprintf(search_key, "logs/%s", refname);
	} else {
		len = 6; /* logs/ + 0*/
		search_key = strdup("logs/");
	}
	key.mv_data = search_key;
	key.mv_size = len;

	lmdb_transaction_begin_flags_or_die(0);

	if ((rc = mdb_cursor_open(transaction.txn, transaction.dbi, &cursor)))
		die("mdb_cursor_open failed: %s", mdb_strerror(rc));

	rc = mdb_cursor_get(cursor, &key, &val, MDB_SET_RANGE);

	while (1) {
		if (rc) {
			if (rc != MDB_NOTFOUND)
				die("bad return from mdb_cursor_get");
			break;
		}

		assert(((char *)val.mv_data)[val.mv_size - 1] == 0);

		if (!starts_with(key.mv_data, search_key))
			break;
		if (refname && ((char *)val.mv_data)[len - 1] == 0)
			break;

		assert(mdb_cursor_del(cursor, 0) == 0);
		rc = mdb_cursor_get(cursor, &key, &val, MDB_NEXT);
	}

	free(search_key);
	mdb_cursor_close(cursor);

	assert(lmdb_transaction_commit(&transaction, &err) == 0);
	return;
}

/* For testing only! */
void test_refdb_raw_append_reflog(const char *refname)
{
	struct strbuf input = STRBUF_INIT;
	uint64_t now = getnanotime();
	MDB_val key, val;
	struct strbuf err = STRBUF_INIT;

	key.mv_size = strlen(refname) + 14;
	key.mv_data = xcalloc(1, key.mv_size);
	sprintf(key.mv_data, "logs/%s", refname);

	lmdb_transaction_begin_flags_or_die(0);

	/* ensure that header exists */
	if (mdb_get0(&key, &val)) {
		val.mv_size = 0;
		val.mv_data = NULL;
		mdb_put(transaction.txn, transaction.dbi, &key, &val, 0);
	}

	while (strbuf_getwholeline(&input, stdin, '\n') != EOF) {
		/* "logs/" + \0 + 8-byte timestamp for sorting and expiry */
		write_u64(key.mv_data + key.mv_size - 8, htonll(now++));
		val.mv_data = input.buf;
		val.mv_size = input.len + 1;
		mdb_put(transaction.txn, transaction.dbi, &key, &val, 0);
		input.len = 0;
	}

	assert(lmdb_transaction_commit(&transaction, &err) == 0);
	free(key.mv_data);
}

struct ref_be refs_be_db = {
	NULL,
	"db",
	lmdb_init_backend,
	lmdb_transaction_begin,
	lmdb_transaction_update,
	lmdb_transaction_create,
	lmdb_transaction_delete,
	lmdb_transaction_verify,
	lmdb_transaction_commit,
	lmdb_transaction_free,
	lmdb_rename_ref,
	lmdb_for_each_reflog_ent,
	lmdb_for_each_reflog_ent_reverse,
	lmdb_for_each_reflog,
	lmdb_reflog_exists,
	lmdb_create_reflog,
	lmdb_delete_reflog,
	lmdb_reflog_expire,
	lmdb_resolve_ref_unsafe,
	lmdb_is_refname_available,
	lmdb_pack_refs,
	lmdb_peel_ref,
	lmdb_create_symref,
	lmdb_resolve_gitlink_ref,
	lmdb_head_ref,
	lmdb_head_ref_submodule,
	lmdb_for_each_ref,
	lmdb_for_each_ref_submodule,
	lmdb_for_each_ref_in,
	lmdb_for_each_ref_in_submodule,
	lmdb_for_each_rawref,
	lmdb_for_each_namespaced_ref,
	lmdb_for_each_replace_ref,
	lmdb_begin_bulk_update,
	lmdb_bulk_update_add,
	lmdb_bulk_update_commit,
};
