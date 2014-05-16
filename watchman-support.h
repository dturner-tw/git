#ifndef WATCHMAN_SUPPORT_H
#define WATCHMAN_SUPPORT_H

#include "cache.h"
#include <watchman.h>

int watchman_load_fs_cache(struct index_state *index);
int watchman_reload_fs_cache(struct index_state *index);

#endif /* WATCHMAN_SUPPORT_H */
