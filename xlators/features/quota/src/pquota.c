/*
   Copyright (c) 2008-2012 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/

/*
 * These functions are part of project quota.
 * For now project quota will be enabled with swtich in fop table from
 * the quota translator
 *
 */

#include <fnmatch.h>

#include "pquota.h"
#include "common-utils.h"
#include "defaults.h"
#include "statedump.h"
#include "quota-common-utils.h"
#include "quota-messages.h"
#include "events.h"

static quota_prj_t*
__prj_ref(quota_prj_t *prj)
{
	if (!prj)
		return NULL;
	prj->refcount++;
	return prj;
}

static quota_prj_t*
prj_ref(xlator_t *this, quota_prj_t *prj)
{
        pquota_priv_t           *priv;	
        quota_prj_list_t        *quota_projects;

        GF_ASSERT(this);
        GF_ASSERT(this->private);
        
        priv = (pquota_priv_t *)this->private;
        quota_projects = &priv->projects;

	if (!prj)
		return NULL;
	LOCK(&quota_projects->lock);
	__prj_ref(prj);
	UNLOCK(&quota_projects->lock);
	return prj;
}

static quota_prj_t*
__prj_unref(quota_prj_t *prj)
{

	if (!prj)
		return NULL;
	prj->refcount--;
	/* if ref count is 0 remove from projects list*/
	if (prj->refcount == 0) {
		list_del_init(&prj->next_prj);
		GF_FREE(prj);
	}
	return prj;
}

static quota_prj_t*
prj_unref(xlator_t *this, quota_prj_t *prj)
{
        pquota_priv_t           *priv;	
        quota_prj_list_t        *quota_projects;

        GF_ASSERT(this);
        GF_ASSERT(this->private);
        
        priv = (pquota_priv_t *)this->private;
        quota_projects = &priv->projects;

	if (!prj)
		return NULL;
	LOCK(&quota_projects->lock);
	__prj_unref(prj);
	UNLOCK(&quota_projects->lock);
	return prj;
}

static quota_prj_t*
prj_ref_get(xlator_t *this, uint16_t prj_id)
{
	quota_prj_t             *tmp_prj = NULL;
        pquota_priv_t           *priv;
        quota_prj_list_t        *quota_projects;

        GF_ASSERT(this);
        GF_ASSERT(this->private);
        
        priv = (pquota_priv_t *)this->private;
        quota_projects = &priv->projects;

        GF_ASSERT(quota_projects);

	LOCK(&quota_projects->lock);
	list_for_each_entry(tmp_prj, &quota_projects->prj_list, next_prj)
	{
		if (tmp_prj->prj_id == prj_id) {
			__prj_ref(tmp_prj);
			break;
		}
	}
	UNLOCK(&quota_projects->lock);
	if (tmp_prj->prj_id == prj_id)
		return tmp_prj;
	else 
		return NULL;
}

static quota_prj_t* 
prj_init(xlator_t *this, uint16_t ext_prj_id, uint16_t prj_id)
{
	quota_prj_t *prj;
        pquota_priv_t           *priv;	
        quota_prj_list_t        *quota_projects;

        GF_ASSERT(this);
        GF_ASSERT(this->private);
        
        priv = (pquota_priv_t *)this->private;
        quota_projects = &priv->projects;


	prj = GF_CALLOC(1, sizeof(quota_prj_t), gf_common_mt_prj_t);
	prj->ext_prj_id = ext_prj_id; 
	prj->prj_id = prj_id;
	prj->prj_limit = 0;		
	/* The limit should be initialised before setting enfoce,*/		
	prj->prj_usage = 0;
	prj->prj_flags = 0;
	/* Timeval init prj_update_time*/
	LOCK_INIT(&prj->lock);
	prj->refcount = 1;
	LOCK(&quota_projects->lock);
	list_add_tail(&prj->next_prj, &quota_projects->prj_list);
	UNLOCK(&quota_projects->lock);
	return prj;
}

static pquota_local_t * pquota_local_new()
{
        pquota_local_t *local = NULL;
        local = mem_get0 (THIS->local_pool);
        if (local == NULL)
                goto out;

        LOCK_INIT (&local->lock);
out:
        return local;
}

int32_t
pquota_local_cleanup (pquota_local_t *local)
{
        if (local == NULL) {
                goto out;
        }

        loc_wipe (&local->loc);

        LOCK_DESTROY (&local->lock);

        mem_put (local);
out:
        return 0;
}


static int32_t
__pquota_init_inode_ctx (inode_t *inode, xlator_t *this,
                        pquota_inode_ctx_t **context)
{
        int32_t            ret  = -1;
        pquota_inode_ctx_t *ctx  = NULL;

        if (inode == NULL) {
                goto out;
        }

        PQUOTA_ALLOC_OR_GOTO (ctx, pquota_inode_ctx_t, out);

        LOCK_INIT(&ctx->lock);

        if (context != NULL) {
                *context = ctx;
        }

        ret = __inode_ctx_put (inode, this, (uint64_t )(long)ctx);
        if (ret) {
                gf_msg (this->name, GF_LOG_WARNING, 0,
                        Q_MSG_INODE_CTX_SET_FAILED, "cannot set quota context "
                        "in inode (gfid:%s)", uuid_utoa (inode->gfid));
                GF_FREE (ctx);
        }
out:
        return ret;
}


static int32_t
pquota_inode_ctx_get (inode_t *inode, xlator_t *this,
                     pquota_inode_ctx_t **ctx, char create_if_absent)
{
        int32_t  ret = 0;
        uint64_t ctx_int;

        LOCK (&inode->lock);
        {
                ret = __inode_ctx_get (inode, this, &ctx_int);

                if ((ret == 0) && (ctx != NULL)) {
                        *ctx = (pquota_inode_ctx_t *) (unsigned long)ctx_int;
                } else if (create_if_absent) {
                        ret = __pquota_init_inode_ctx (inode, this, ctx);
                }
        }
        UNLOCK (&inode->lock);

        return ret;
}


int
pquota_fill_inodectx (xlator_t *this, inode_t *inode, dict_t *dict,
                     loc_t *loc, struct iatt *buf, int32_t *op_errno)
{
        int32_t            ret                  = -1;
        pquota_inode_ctx_t *ctx                  = NULL;
        quota_prj_t        *tmp                 = NULL;     
        uint64_t           prjid                = 0;
        pquota_priv_t           *priv;	
        quota_prj_list_t        *quota_projects;

        GF_ASSERT(this);
        GF_ASSERT(this->private);
        
        priv = (pquota_priv_t *)this->private;
        quota_projects = &priv->projects;

        GF_ASSERT(quota_projects);

        ret = dict_get_bin (dict, QUOTA_PROJECT_KEY, (void **) &prjid);
        if (ret) {
               ret = 0;
               goto out;
        }                         
 
        ret = pquota_inode_ctx_get (inode, this, &ctx, 1);
        if ((ret == -1) || (ctx == NULL)) {
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM,
                        Q_MSG_INODE_CTX_GET_FAILED, "cannot create quota "
                        "context in inode(gfid:%s)", uuid_utoa (inode->gfid));
                ret = -1;
                *op_errno = ENOMEM;
                goto out;
        }

       /* iterate over the projects list and find the project with same project id*/
        list_for_each_entry (tmp, &quota_projects->prj_list, next_prj) {
                /*should we use ref / unref to protect the list during iteration*/
                if (tmp->prj_id == prjid) {
                        LOCK (&ctx->lock);
                        ctx->prj = prj_ref(this, tmp);
                        UNLOCK (&ctx->lock);
                }
        }
        if (tmp == (void *)&quota_projects->prj_list) {
               /* Project id without corresponding entry in persistent tables. needs to be cleaned!! 
                 * should we have a GF_ASSERT here?
                 *      */ 
        }
      
out:
        return ret;
}

int32_t
pquota_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, inode_t *inode,
                  struct iatt *buf, dict_t *dict, struct iatt *postparent)
{
        pquota_local_t      *local        = NULL;
        inode_t            *this_inode   = NULL;

        local = frame->local;
        frame->local = NULL;

        if (op_ret >= 0 && inode) {
                this_inode = inode_ref (inode);

                op_ret = pquota_fill_inodectx (this, inode, dict, &local->loc,
                                              buf, &op_errno);
                if (op_ret < 0)
                        op_errno = ENOMEM;
        }

        QUOTA_STACK_UNWIND (lookup, frame, op_ret, op_errno, inode, buf,
                            dict, postparent);

        if (this_inode)
                inode_unref (this_inode);

        pquota_local_cleanup (local);

        return 0;
}



int32_t
pquota_lookup (call_frame_t *frame, xlator_t *this, loc_t *loc,
              dict_t *xattr_req)
{
        pquota_priv_t  *priv             = NULL;
        int32_t        ret              = -1;
        pquota_local_t *local            = NULL;

        priv = this->private;

        WIND_IF_QUOTAOFF (priv->is_quota_on, off);

        xattr_req = xattr_req ? dict_ref(xattr_req) : dict_new();
        if (!xattr_req)
                goto err;

        local = pquota_local_new();
        if (local == NULL) {
                goto err;
        }

        frame->local = local;
        loc_copy (&local->loc, loc);

        ret = dict_set_int8 (xattr_req, QUOTA_PROJECT_KEY, 1);
        if (ret < 0) {
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM,
			Q_MSG_ENOMEM, "dict set of key for "
                        "project failed");
                goto err;
        }

        STACK_WIND (frame, pquota_lookup_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->lookup, loc, xattr_req);

        ret = 0;

err:
        if (xattr_req)
                dict_unref (xattr_req);

        if (ret < 0) {
                QUOTA_STACK_UNWIND (lookup, frame, -1, ENOMEM,
                                    NULL, NULL, NULL, NULL);
        }

        return 0;

off:
        STACK_WIND_TAIL (frame, FIRST_CHILD(this),
                         FIRST_CHILD(this)->fops->lookup, loc, xattr_req);
        return 0;
}

int32_t
pquota_forget (xlator_t *this, inode_t *inode)
{
        int32_t               ret     = 0;
        uint64_t              ctx_int = 0;
        pquota_inode_ctx_t    *ctx     = NULL;

        ret = inode_ctx_del (inode, this, &ctx_int);

        if (ret < 0) {
                return 0;
        }

        ctx = (pquota_inode_ctx_t *) (long)ctx_int;

        LOCK (&ctx->lock);
        {
                /**/
        }
        UNLOCK (&ctx->lock);

        LOCK_DESTROY (&ctx->lock);

        GF_FREE (ctx);

        return 0;
}


#if (PROJECT_QUOTA == 1)
int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        if (!this)
                return ret;

        ret = xlator_mem_acct_init (this, gf_pquota_mt_end + 1);

        if (ret != 0) {
                gf_msg (this->name, GF_LOG_WARNING, ENOMEM, Q_MSG_ENOMEM,
                        "Memory accounting init failed");
                return ret;
        }

        return ret;
}


int32_t
init (xlator_t *this)
{
        int32_t       ret  = -1;
        pquota_priv_t *priv = NULL;
        rpc_clnt_t   *rpc  = NULL;
        quota_prj_list_t        *quota_projects;

        if ((this->children == NULL)
            || this->children->next) {
                gf_msg (this->name, GF_LOG_ERROR, 0,
                        Q_MSG_INVALID_VOLFILE,
                        "FATAL: quota (%s) not configured with "
                        "exactly one child", this->name);
                return -1;
        }

        if (this->parents == NULL) {
                gf_msg (this->name, GF_LOG_WARNING, 0,
                        Q_MSG_INVALID_VOLFILE,
                        "dangling volume. check volfile");
        }

        PQUOTA_ALLOC_OR_GOTO (priv, pquota_priv_t, err);

        LOCK_INIT (&priv->lock);

        this->private = priv;
        quota_projects = &priv->projects;
        LOCK_INIT (&quota_projects->lock);
        INIT_LIST_HEAD(&quota_projects->prj_list);

        GF_OPTION_INIT ("deem-statfs", priv->consider_statfs, bool, err);
        GF_OPTION_INIT ("server-quota", priv->is_quota_on, bool, err);
        GF_OPTION_INIT ("default-soft-limit", priv->default_soft_lim, percent,
                        err);
        GF_OPTION_INIT ("soft-timeout", priv->soft_timeout, time, err);
        GF_OPTION_INIT ("hard-timeout", priv->hard_timeout, time, err);
        GF_OPTION_INIT ("alert-time", priv->log_timeout, time, err);
        GF_OPTION_INIT ("volume-uuid", priv->volume_uuid, str, err);


        this->local_pool = mem_pool_new (pquota_local_t, 64);
        if (!this->local_pool) {
                ret = -1;
                gf_msg (this->name, GF_LOG_ERROR, ENOMEM,
			Q_MSG_ENOMEM, "failed to create local_t's memory pool");
                goto err;
        }

        if (priv->is_quota_on) {
                rpc = quota_enforcer_init (this, this->options);
                if (rpc == NULL) {
                        ret = -1;
                        gf_msg (this->name, GF_LOG_WARNING, 0,
				Q_MSG_QUOTA_ENFORCER_RPC_INIT_FAILED,
				"quota enforcer rpc init failed");
                        goto err;
                }

                LOCK (&priv->lock);
                {
                        priv->rpc_clnt = rpc;
                }
                UNLOCK (&priv->lock);
        }

        ret = 0;
err:
        return ret;
}

int
reconfigure (xlator_t *this, dict_t *options)
{
        int32_t       ret      = -1;
        pquota_priv_t *priv     = NULL;
        gf_boolean_t  quota_on = _gf_false;
        rpc_clnt_t   *rpc      = NULL;

        priv = this->private;

        GF_OPTION_RECONF ("deem-statfs", priv->consider_statfs, options, bool,
                          out);
        GF_OPTION_RECONF ("server-quota", quota_on, options, bool,
                          out);
        GF_OPTION_RECONF ("default-soft-limit", priv->default_soft_lim,
                          options, percent, out);
        GF_OPTION_RECONF ("alert-time", priv->log_timeout, options,
                          time, out);
        GF_OPTION_RECONF ("soft-timeout", priv->soft_timeout, options,
                          time, out);
        GF_OPTION_RECONF ("hard-timeout", priv->hard_timeout, options,
                          time, out);

        if (quota_on) {
                priv->rpc_clnt = quota_enforcer_init (this,
                                                      this->options);
                if (priv->rpc_clnt == NULL) {
                        ret = -1;
                        gf_msg (this->name, GF_LOG_WARNING, 0,
				Q_MSG_QUOTA_ENFORCER_RPC_INIT_FAILED,
				"quota enforcer rpc init failed");
                        goto out;
                }

        } else {
                LOCK (&priv->lock);
                {
                        rpc = priv->rpc_clnt;
                        priv->rpc_clnt = NULL;
                }
                UNLOCK (&priv->lock);

                if (rpc != NULL) {
                        // Quotad is shutdown when there is no started volume
                        // which has quota enabled. So, we should disable the
                        // enforcer client when quota is disabled on a volume,
                        // to avoid spurious reconnect attempts to a service
                        // (quotad), that is known to be down.
                        rpc_clnt_unref (rpc);
                }
        }

        priv->is_quota_on = quota_on;

        ret = 0;
out:
        return ret;
}

int32_t
pquota_priv_dump (xlator_t *this)
{
        pquota_priv_t *priv = NULL;
        int32_t       ret  = -1;


        GF_ASSERT (this);

        priv = this->private;

        gf_proc_dump_add_section ("xlators.features.quota.priv", this->name);

        ret = TRY_LOCK (&priv->lock);
        if (ret)
             goto out;
        else {
                gf_proc_dump_write("soft-timeout", "%d", priv->soft_timeout);
                gf_proc_dump_write("hard-timeout", "%d", priv->hard_timeout);
                gf_proc_dump_write("alert-time", "%d", priv->log_timeout);
                gf_proc_dump_write("quota-on", "%d", priv->is_quota_on);
                gf_proc_dump_write("statfs", "%d", priv->consider_statfs);
                gf_proc_dump_write("volume-uuid", "%s", priv->volume_uuid);
        }
        UNLOCK (&priv->lock);

out:
        return 0;
}

void
fini (xlator_t *this)
{
        return;
}

struct xlator_fops fops = {
//        .statfs       = quota_statfs,
        .lookup       = pquota_lookup,
/*        .writev       = quota_writev,
        .create       = quota_create,
        .mkdir        = quota_mkdir,
        .truncate     = quota_truncate,
        .ftruncate    = quota_ftruncate,
        .unlink       = quota_unlink,
        .symlink      = quota_symlink,
        .link         = quota_link,
        .rename       = quota_rename,
        .getxattr     = quota_getxattr,
        .fgetxattr    = quota_fgetxattr,
        .stat         = quota_stat,
        .fstat        = quota_fstat,
        .readlink     = quota_readlink,
        .readv        = quota_readv,
        .fsync        = quota_fsync,
        .setattr      = quota_setattr,
        .fsetattr     = quota_fsetattr,
        .mknod        = quota_mknod,
        .setxattr     = quota_setxattr,
        .fsetxattr    = quota_fsetxattr,
        .removexattr  = quota_removexattr,
        .fremovexattr = quota_fremovexattr,
        .readdirp     = quota_readdirp,
	.fallocate    = quota_fallocate,*/
};

struct xlator_cbks cbks = {
        .forget = pquota_forget
};

struct xlator_dumpops dumpops = {
        .priv    = pquota_priv_dump,
};

struct volume_options options[] = {
        {.key = {"limit-set"}},
        {.key = {"deem-statfs"},
         .type = GF_OPTION_TYPE_BOOL,
         .default_value = "on",
         .description = "If set to on, it takes quota limits into"
                        " consideration while estimating fs size. (df command)"
                        " (Default is on)."
        },
        {.key = {"server-quota"},
         .type = GF_OPTION_TYPE_BOOL,
         .default_value = "off",
         .description = "Skip the quota enforcement if the feature is"
                        " not turned on. This is not a user exposed option."
        },
        {.key = {"default-soft-limit"},
         .type = GF_OPTION_TYPE_PERCENT,
         .default_value = "80%",
        },
        {.key = {"soft-timeout"},
         .type = GF_OPTION_TYPE_TIME,
         .min = 0,
         .max = 1800,
         .default_value = "60",
         .description = "quota caches the directory sizes on client. "
                        "soft-timeout indicates the timeout for the validity of"
                        " cache before soft-limit has been crossed."
        },
        {.key = {"hard-timeout"},
         .type = GF_OPTION_TYPE_TIME,
         .min = 0,
         .max = 60,
         .default_value = "5",
         .description = "quota caches the directory sizes on client. "
                        "hard-timeout indicates the timeout for the validity of"
                        " cache after soft-limit has been crossed."
        },
        { .key   = {"username"},
          .type  = GF_OPTION_TYPE_ANY,
        },
        { .key   = {"password"},
          .type  = GF_OPTION_TYPE_ANY,
        },
        { .key   = {"transport-type"},
          .value = {"tcp", "socket", "ib-verbs", "unix", "ib-sdp",
                    "tcp/client", "ib-verbs/client", "rdma"},
          .type  = GF_OPTION_TYPE_STR,
        },
        { .key   = {"remote-host"},
          .type  = GF_OPTION_TYPE_INTERNET_ADDRESS,
        },
        { .key   = {"remote-port"},
          .type  = GF_OPTION_TYPE_INT,
        },
        { .key  = {"volume-uuid"},
          .type = GF_OPTION_TYPE_STR,
          .description = "uuid of the volume this brick is part of."
        },
        { .key  = {"alert-time"},
          .type = GF_OPTION_TYPE_TIME,
          .min = 0,
          .max = 7*86400,
          .default_value = "86400",
        },
        {.key = {NULL}}
};
#endif
