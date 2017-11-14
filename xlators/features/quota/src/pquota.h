/*
   Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#ifndef _PQUOTA_H
#define _PQUOTA_H

#include "xlator.h"
#include "call-stub.h"
#include "defaults.h"
#include "common-utils.h"
#include "pquota-mem-types.h"
#include "glusterfs.h"
#include "compat.h"
#include "logging.h"
#include "dict.h"
#include "stack.h"
#include "event.h"
#include "globals.h"
#include "rpcsvc.h"
#include "rpc-clnt.h"
#include "byte-order.h"
#include "glusterfs3-xdr.h"
#include "glusterfs3.h"
#include "xdr-generic.h"
#include "compat-errno.h"
#include "protocol-common.h"
#include "quota-common-utils.h"
#include "quota-messages.h"

#define DIRTY                   "dirty"
#define SIZE                    "size"
#define VAL_LENGTH              8
#define READDIR_BUF             4096

#ifndef UUID_CANONICAL_FORM_LEN
#define UUID_CANONICAL_FORM_LEN 36
#endif

#define WIND_IF_QUOTAOFF(is_quota_on, label)     \
        if (!is_quota_on)                       \
                goto label;

#define DID_REACH_LIMIT(lim, prev_size, cur_size)               \
        ((cur_size) >= (lim) && (prev_size) < (lim))

#define PQUOTA_ALLOC_OR_GOTO(var, type, label)           \
        do {                                            \
                var = GF_CALLOC (sizeof (type), 1,      \
                                 gf_pquota_mt_##type);   \
                if (!var) {                             \
                        gf_msg ("", GF_LOG_ERROR,       \
                                ENOMEM, Q_MSG_ENOMEM,   \
				"out of memory");       \
                        ret = -1;                       \
                        goto label;                     \
                }                                       \
        } while (0);

#define QUOTA_STACK_WIND_TAIL(frame, params...)                         \
        do {                                                            \
                pquota_local_t *_local = NULL;                           \
                                                                        \
                if (frame) {                                            \
                        _local = frame->local;                          \
                        frame->local = NULL;                            \
                }                                                       \
                                                                        \
                STACK_WIND_TAIL (frame, params);                        \
                                                                        \
                if (_local)                                             \
                        pquota_local_cleanup (_local);                   \
        } while (0)

#define QUOTA_STACK_UNWIND(fop, frame, params...)                       \
        do {                                                            \
                pquota_local_t *_local = NULL;                           \
                if (frame) {                                            \
                        _local = frame->local;                          \
                        frame->local = NULL;                            \
                }                                                       \
                STACK_UNWIND_STRICT (fop, frame, params);               \
                pquota_local_cleanup (_local);                           \
        } while (0)

struct quota_project {
	uint16_t		ext_prj_id;
	uint16_t		prj_id;
	uint64_t		prj_limit;
	uint64_t		prj_usage;				/* last fetched usage */	
	struct timeval		prj_update_time;			/* Time the usage was last updated */
	uint32_t		prj_flags;
	uint64_t		refcount;
        gf_lock_t       	lock;
	struct list_head	next_prj;
 
	/*struct list_head	prj_list;*/
};
typedef struct quota_project quota_prj_t;

struct quota_prj_list {
        gf_lock_t		lock;
	struct list_head	prj_list;
};

typedef struct quota_prj_list quota_prj_list_t;

/*list of all projects*/

/* Flags for quota_project */
#define QUOTA_ENFORCEMENT_NEEDED 0x00000001
#define QUOTA_NEEDS_REFRESH	 0x00000002

/*
struct quota_prj_list {
	struct list_head	next;
};
*/

struct pquota_inode_ctx {
	quota_prj_t  	 *prj;
        struct list_head parents;
        struct timeval   tv;
        struct timeval   prev_log;
        gf_lock_t        lock;
};
typedef struct pquota_inode_ctx pquota_inode_ctx_t;

typedef void
(*quota_ancestry_built_t) (struct list_head *parents, inode_t *inode,
                           int32_t op_ret, int32_t op_errno, void *data);

typedef void
(*quota_fop_continue_t) (call_frame_t *frame);

struct pquota_local {
        gf_lock_t               lock;
        loc_t                   loc;
};
typedef struct pquota_local      pquota_local_t;

struct pquota_priv {

        uint32_t               soft_timeout;
        uint32_t               hard_timeout;
        uint32_t               log_timeout;
        double                 default_soft_lim;
        gf_boolean_t           is_quota_on;
        gf_boolean_t           consider_statfs;
        gf_lock_t              lock;
        rpc_clnt_prog_t       *quota_enforcer;
        struct rpcsvc_program *quotad_aggregator;
        struct rpc_clnt       *rpc_clnt;
        rpcsvc_t              *rpcsvc;
        inode_table_t         *itable;
        char                  *volume_uuid;
        int32_t                quotad_conn_status;

        quota_prj_list_t        projects;
};
typedef struct pquota_priv      pquota_priv_t;

int
quota_enforcer_lookup (call_frame_t *frame, xlator_t *this, dict_t *xdata,
                       fop_lookup_cbk_t cbk);

void
_quota_enforcer_lookup (void *data);

struct rpc_clnt *
quota_enforcer_init (xlator_t *this, dict_t *options);

void
quota_log_usage (xlator_t *this, pquota_inode_ctx_t *ctx, inode_t *inode,
                 int64_t delta);

int
quota_fill_inodectx (xlator_t *this, inode_t *inode, dict_t *dict,
                     loc_t *loc, struct iatt *buf, int32_t *op_errno);

#endif
