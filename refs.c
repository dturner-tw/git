/*
 * Common refs code for all backends.
 */
#include "cache.h"
#include "refs.h"

int update_ref(const char *msg, const char *refname,
	       const unsigned char *new_sha1, const unsigned char *old_sha1,
	       unsigned int flags, enum action_on_err onerr)
{
	struct ref_transaction *t;
	struct strbuf err = STRBUF_INIT;

	t = ref_transaction_begin(&err);
	if (!t ||
	    ref_transaction_update(t, refname, new_sha1, old_sha1,
				   flags, msg, &err) ||
	    ref_transaction_commit(t, &err)) {
		const char *str = "update_ref failed for ref '%s': %s";

		ref_transaction_free(t);
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
	ref_transaction_free(t);
	return 0;
}
