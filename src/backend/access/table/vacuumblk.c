/*-------------------------------------------------------------------------
 *
 * vacuumblk.c
 *	  The postgres block level functions.
 *
 * This file contains the commons functions for block level vacuum that
 * can be used by different storage engines.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/commands/vacuumblk.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/zheap.h"
#include "access/multixact.h"
#include "access/vacuumblk.h"
#include "catalog/storage.h"
#include "commands/progress.h"
#include "commands/vacuum.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/autovacuum.h"
#include "optimizer/paths.h"
#include "storage/bufmgr.h"
#include "storage/lmgr.h"
#include "tcop/tcopprot.h"
#include "utils/memutils.h"
#include "utils/pg_rusage.h"

/*
 * Space/time tradeoff parameters: do these need to be user-tunable?
 *
 * To consider truncating the relation, we want there to be at least
 * REL_TRUNCATE_MINIMUM or (relsize / REL_TRUNCATE_FRACTION) (whichever
 * is less) potentially-freeable pages.
 */
#define REL_TRUNCATE_MINIMUM	1000
#define REL_TRUNCATE_FRACTION	16

/*
 * Timing parameters for truncate locking heuristics.
 *
 * These were not exposed as user tunable GUC values because it didn't seem
 * that the potential for improvement was great enough to merit the cost of
 * supporting them.
 */
#define VACUUM_TRUNCATE_LOCK_CHECK_INTERVAL		20	/* ms */
#define VACUUM_TRUNCATE_LOCK_WAIT_INTERVAL		50	/* ms */
#define VACUUM_TRUNCATE_LOCK_TIMEOUT			5000	/* ms */

/*
 * Size of the prefetch window for lazy vacuum backwards truncation scan.
 * Needs to be a power of 2.
 */
#define PREFETCH_SIZE			((BlockNumber) 32)

/* elevel controls whole VACUUM's verbosity */
static int	elevel = -1;

static int	compute_parallel_vacuum_workers(LVRelState *vacrel,
											int nrequested,
											bool *can_parallel_vacuum);
static LVParallelState *begin_parallel_vacuum(LVRelState *vacrel,
											  BlockNumber nblocks,
											  int nrequested);
static bool lazy_tid_reaped(ItemPointer itemptr, void *state);
static int	vac_cmp_itemptr(const void *left, const void *right);
static BlockNumber count_nondeletable_pages(LVRelState *vacrel);
static long compute_max_dead_tuples(BlockNumber relblocks, bool hasindex,
									bool is_heap);
static void do_parallel_lazy_cleanup_all_indexes(LVRelState *vacrel);;

/*
 * lazy_space_alloc - space allocation decisions for lazy vacuum
 *
 * See the comments at the head of this file for rationale.
 */
void
lazy_space_alloc(LVRelState *vacrel, int nworkers, BlockNumber nblocks)
{
	LVDeadTuples *dead_tuples;
	long		maxtuples;

	/*
	 * Initialize state for a parallel vacuum.  As of now, only one worker can
	 * be used for an index, so we invoke parallelism only if there are at
	 * least two indexes on a table.
	 */
	if (nworkers >= 0 && vacrel->nindexes > 1 && vacrel->do_index_vacuuming)
	{
		/*
		 * Since parallel workers cannot access data in temporary tables, we
		 * can't perform parallel vacuum on them.
		 */
		if (RelationUsesLocalBuffers(vacrel->rel))
		{
			/*
			 * Give warning only if the user explicitly tries to perform a
			 * parallel vacuum on the temporary table.
			 */
			if (nworkers > 0)
				ereport(WARNING,
						(errmsg("disabling parallel option of vacuum on \"%s\" --- cannot vacuum temporary tables in parallel",
								vacrel->relname)));
		}
		else
			vacrel->lps = begin_parallel_vacuum(vacrel, nblocks, nworkers);

		/* If parallel mode started, we're done */
		if (ParallelVacuumIsActive(vacrel))
			return;
	}

	maxtuples = compute_max_dead_tuples(nblocks, vacrel->nindexes > 0,
										RelationStorageIsZHeap(vacrel->rel));

	dead_tuples = (LVDeadTuples *) palloc(SizeOfDeadTuples(maxtuples));
	dead_tuples->num_tuples = 0;
	dead_tuples->max_tuples = (int) maxtuples;

	vacrel->dead_tuples = dead_tuples;
}

/*
 * This function prepares and returns parallel vacuum state if we can launch
 * even one worker.  This function is responsible for entering parallel mode,
 * create a parallel context, and then initialize the DSM segment.
 */
static LVParallelState *
begin_parallel_vacuum(LVRelState *vacrel, BlockNumber nblocks,
					  int nrequested)
{
	LVParallelState *lps = NULL;
	Relation   *indrels = vacrel->indrels;
	int			nindexes = vacrel->nindexes;
	ParallelContext *pcxt;
	LVShared   *shared;
	LVDeadTuples *dead_tuples;
	BufferUsage *buffer_usage;
	WalUsage   *wal_usage;
	bool	   *can_parallel_vacuum;
	long		maxtuples;
	Size		est_shared;
	Size		est_deadtuples;
	int			nindexes_mwm = 0;
	int			parallel_workers = 0;
	int			querylen;

	/*
	 * A parallel vacuum must be requested and there must be indexes on the
	 * relation
	 */
	Assert(nrequested >= 0);
	Assert(nindexes > 0);

	/*
	 * Compute the number of parallel vacuum workers to launch
	 */
	can_parallel_vacuum = (bool *) palloc0(sizeof(bool) * nindexes);
	parallel_workers = compute_parallel_vacuum_workers(vacrel,
													   nrequested,
													   can_parallel_vacuum);

	/* Can't perform vacuum in parallel */
	if (parallel_workers <= 0)
	{
		pfree(can_parallel_vacuum);
		return lps;
	}

	lps = (LVParallelState *) palloc0(sizeof(LVParallelState));

	EnterParallelMode();
	pcxt = CreateParallelContext("postgres", "parallel_vacuum_main",
								 parallel_workers);
	Assert(pcxt->nworkers > 0);
	lps->pcxt = pcxt;

	/* Estimate size for shared information -- PARALLEL_VACUUM_KEY_SHARED */
	est_shared = MAXALIGN(add_size(SizeOfLVShared, BITMAPLEN(nindexes)));
	for (int idx = 0; idx < nindexes; idx++)
	{
		Relation	indrel = indrels[idx];
		uint8		vacoptions = indrel->rd_indam->amparallelvacuumoptions;

		/*
		 * Cleanup option should be either disabled, always performing in
		 * parallel or conditionally performing in parallel.
		 */
		Assert(((vacoptions & VACUUM_OPTION_PARALLEL_CLEANUP) == 0) ||
			   ((vacoptions & VACUUM_OPTION_PARALLEL_COND_CLEANUP) == 0));
		Assert(vacoptions <= VACUUM_OPTION_MAX_VALID_VALUE);

		/* Skip indexes that don't participate in parallel vacuum */
		if (!can_parallel_vacuum[idx])
			continue;

		if (indrel->rd_indam->amusemaintenanceworkmem)
			nindexes_mwm++;

		est_shared = add_size(est_shared, sizeof(LVSharedIndStats));

		/*
		 * Remember the number of indexes that support parallel operation for
		 * each phase.
		 */
		if ((vacoptions & VACUUM_OPTION_PARALLEL_BULKDEL) != 0)
			lps->nindexes_parallel_bulkdel++;
		if ((vacoptions & VACUUM_OPTION_PARALLEL_CLEANUP) != 0)
			lps->nindexes_parallel_cleanup++;
		if ((vacoptions & VACUUM_OPTION_PARALLEL_COND_CLEANUP) != 0)
			lps->nindexes_parallel_condcleanup++;
	}
	shm_toc_estimate_chunk(&pcxt->estimator, est_shared);
	shm_toc_estimate_keys(&pcxt->estimator, 1);

	/* Estimate size for dead tuples -- PARALLEL_VACUUM_KEY_DEAD_TUPLES */
	maxtuples = compute_max_dead_tuples(nblocks, true,
										RelationStorageIsZHeap(vacrel->rel));
	est_deadtuples = MAXALIGN(SizeOfDeadTuples(maxtuples));
	shm_toc_estimate_chunk(&pcxt->estimator, est_deadtuples);
	shm_toc_estimate_keys(&pcxt->estimator, 1);

	/*
	 * Estimate space for BufferUsage and WalUsage --
	 * PARALLEL_VACUUM_KEY_BUFFER_USAGE and PARALLEL_VACUUM_KEY_WAL_USAGE.
	 *
	 * If there are no extensions loaded that care, we could skip this.  We
	 * have no way of knowing whether anyone's looking at pgBufferUsage or
	 * pgWalUsage, so do it unconditionally.
	 */
	shm_toc_estimate_chunk(&pcxt->estimator,
						   mul_size(sizeof(BufferUsage), pcxt->nworkers));
	shm_toc_estimate_keys(&pcxt->estimator, 1);
	shm_toc_estimate_chunk(&pcxt->estimator,
						   mul_size(sizeof(WalUsage), pcxt->nworkers));
	shm_toc_estimate_keys(&pcxt->estimator, 1);

	/* Finally, estimate PARALLEL_VACUUM_KEY_QUERY_TEXT space */
	if (debug_query_string)
	{
		querylen = strlen(debug_query_string);
		shm_toc_estimate_chunk(&pcxt->estimator, querylen + 1);
		shm_toc_estimate_keys(&pcxt->estimator, 1);
	}
	else
		querylen = 0;			/* keep compiler quiet */

	InitializeParallelDSM(pcxt);

	/* Prepare shared information */
	shared = (LVShared *) shm_toc_allocate(pcxt->toc, est_shared);
	MemSet(shared, 0, est_shared);
	shared->relid = RelationGetRelid(vacrel->rel);
	shared->elevel = elevel;
	shared->maintenance_work_mem_worker =
		(nindexes_mwm > 0) ?
		maintenance_work_mem / Min(parallel_workers, nindexes_mwm) :
		maintenance_work_mem;

	pg_atomic_init_u32(&(shared->cost_balance), 0);
	pg_atomic_init_u32(&(shared->active_nworkers), 0);
	pg_atomic_init_u32(&(shared->idx), 0);
	shared->offset = MAXALIGN(add_size(SizeOfLVShared, BITMAPLEN(nindexes)));

	/*
	 * Initialize variables for shared index statistics, set NULL bitmap and
	 * the size of stats for each index.
	 */
	memset(shared->bitmap, 0x00, BITMAPLEN(nindexes));
	for (int idx = 0; idx < nindexes; idx++)
	{
		if (!can_parallel_vacuum[idx])
			continue;

		/* Set NOT NULL as this index does support parallelism */
		shared->bitmap[idx >> 3] |= 1 << (idx & 0x07);
	}

	shm_toc_insert(pcxt->toc, PARALLEL_VACUUM_KEY_SHARED, shared);
	lps->lvshared = shared;

	/* Prepare the dead tuple space */
	dead_tuples = (LVDeadTuples *) shm_toc_allocate(pcxt->toc, est_deadtuples);
	dead_tuples->max_tuples = maxtuples;
	dead_tuples->num_tuples = 0;
	MemSet(dead_tuples->itemptrs, 0, sizeof(ItemPointerData) * maxtuples);
	shm_toc_insert(pcxt->toc, PARALLEL_VACUUM_KEY_DEAD_TUPLES, dead_tuples);
	vacrel->dead_tuples = dead_tuples;

	/*
	 * Allocate space for each worker's BufferUsage and WalUsage; no need to
	 * initialize
	 */
	buffer_usage = shm_toc_allocate(pcxt->toc,
									mul_size(sizeof(BufferUsage), pcxt->nworkers));
	shm_toc_insert(pcxt->toc, PARALLEL_VACUUM_KEY_BUFFER_USAGE, buffer_usage);
	lps->buffer_usage = buffer_usage;
	wal_usage = shm_toc_allocate(pcxt->toc,
								 mul_size(sizeof(WalUsage), pcxt->nworkers));
	shm_toc_insert(pcxt->toc, PARALLEL_VACUUM_KEY_WAL_USAGE, wal_usage);
	lps->wal_usage = wal_usage;

	/* Store query string for workers */
	if (debug_query_string)
	{
		char	   *sharedquery;

		sharedquery = (char *) shm_toc_allocate(pcxt->toc, querylen + 1);
		memcpy(sharedquery, debug_query_string, querylen + 1);
		sharedquery[querylen] = '\0';
		shm_toc_insert(pcxt->toc,
					   PARALLEL_VACUUM_KEY_QUERY_TEXT, sharedquery);
	}

	pfree(can_parallel_vacuum);
	return lps;
}

/*
 * Compute the number of parallel worker processes to request.  Both index
 * vacuum and index cleanup can be executed with parallel workers.  The index
 * is eligible for parallel vacuum iff its size is greater than
 * min_parallel_index_scan_size as invoking workers for very small indexes
 * can hurt performance.
 *
 * nrequested is the number of parallel workers that user requested.  If
 * nrequested is 0, we compute the parallel degree based on nindexes, that is
 * the number of indexes that support parallel vacuum.  This function also
 * sets can_parallel_vacuum to remember indexes that participate in parallel
 * vacuum.
 */
static int
compute_parallel_vacuum_workers(LVRelState *vacrel, int nrequested,
								bool *can_parallel_vacuum)
{
	int			nindexes_parallel = 0;
	int			nindexes_parallel_bulkdel = 0;
	int			nindexes_parallel_cleanup = 0;
	int			parallel_workers;

	/*
	 * We don't allow performing parallel operation in standalone backend or
	 * when parallelism is disabled.
	 */
	if (!IsUnderPostmaster || max_parallel_maintenance_workers == 0)
		return 0;

	/*
	 * Compute the number of indexes that can participate in parallel vacuum.
	 */
	for (int idx = 0; idx < vacrel->nindexes; idx++)
	{
		Relation	indrel = vacrel->indrels[idx];
		uint8		vacoptions = indrel->rd_indam->amparallelvacuumoptions;

		if (vacoptions == VACUUM_OPTION_NO_PARALLEL ||
			RelationGetNumberOfBlocks(indrel) < min_parallel_index_scan_size)
			continue;

		can_parallel_vacuum[idx] = true;

		if ((vacoptions & VACUUM_OPTION_PARALLEL_BULKDEL) != 0)
			nindexes_parallel_bulkdel++;
		if (((vacoptions & VACUUM_OPTION_PARALLEL_CLEANUP) != 0) ||
			((vacoptions & VACUUM_OPTION_PARALLEL_COND_CLEANUP) != 0))
			nindexes_parallel_cleanup++;
	}

	nindexes_parallel = Max(nindexes_parallel_bulkdel,
							nindexes_parallel_cleanup);

	/* The leader process takes one index */
	nindexes_parallel--;

	/* No index supports parallel vacuum */
	if (nindexes_parallel <= 0)
		return 0;

	/* Compute the parallel degree */
	parallel_workers = (nrequested > 0) ?
		Min(nrequested, nindexes_parallel) : nindexes_parallel;

	/* Cap by max_parallel_maintenance_workers */
	parallel_workers = Min(parallel_workers, max_parallel_maintenance_workers);

	return parallel_workers;
}

/*
 *	lazy_vacuum_one_index() -- vacuum index relation.
 *
 *		Delete all the index entries pointing to tuples listed in
 *		dead_tuples, and update running statistics.
 *
 *		reltuples is the number of heap tuples to be passed to the
 *		bulkdelete callback.  It's always assumed to be estimated.
 *
 * Returns bulk delete stats derived from input stats
 */
IndexBulkDeleteResult *
lazy_vacuum_one_index(Relation indrel, IndexBulkDeleteResult *istat,
					  double reltuples, LVRelState *vacrel)
{
	IndexVacuumInfo ivinfo;
	PGRUsage	ru0;
	LVSavedErrInfo saved_err_info;

	pg_rusage_init(&ru0);

	ivinfo.index = indrel;
	ivinfo.analyze_only = false;
	ivinfo.report_progress = false;
	ivinfo.estimated_count = true;
	ivinfo.message_level = elevel;
	ivinfo.num_heap_tuples = reltuples;
	ivinfo.strategy = vacrel->bstrategy;

	/*
	 * Update error traceback information.
	 *
	 * The index name is saved during this phase and restored immediately
	 * after this phase.  See vacuum_error_callback.
	 */
	Assert(vacrel->indname == NULL);
	vacrel->indname = pstrdup(RelationGetRelationName(indrel));
	update_vacuum_error_info(vacrel, &saved_err_info,
							 VACUUM_ERRCB_PHASE_VACUUM_INDEX,
							 InvalidBlockNumber, InvalidOffsetNumber);

	/* Do bulk deletion */
	istat = index_bulk_delete(&ivinfo, istat, lazy_tid_reaped,
							  (void *) vacrel->dead_tuples);

	ereport(elevel,
			(errmsg("scanned index \"%s\" to remove %d row versions",
					vacrel->indname, vacrel->dead_tuples->num_tuples),
			 errdetail_internal("%s", pg_rusage_show(&ru0))));

	/* Revert to the previous phase information for error traceback */
	restore_vacuum_error_info(vacrel, &saved_err_info);
	pfree(vacrel->indname);
	vacrel->indname = NULL;

	return istat;
}

/*
 *	lazy_cleanup_all_indexes() -- cleanup all indexes of relation.
 */
void
lazy_cleanup_all_indexes(LVRelState *vacrel)
{
	Assert(!IsParallelWorker());
	Assert(vacrel->nindexes > 0);

	/* Report that we are now cleaning up indexes */
	pgstat_progress_update_param(PROGRESS_VACUUM_PHASE,
								 PROGRESS_VACUUM_PHASE_INDEX_CLEANUP);

	if (!ParallelVacuumIsActive(vacrel))
	{
		double		reltuples = vacrel->new_rel_tuples;
		bool		estimated_count =
		vacrel->tupcount_pages < vacrel->rel_pages;

		for (int idx = 0; idx < vacrel->nindexes; idx++)
		{
			Relation	indrel = vacrel->indrels[idx];
			IndexBulkDeleteResult *istat = vacrel->indstats[idx];

			vacrel->indstats[idx] =
				lazy_cleanup_one_index(indrel, istat, reltuples,
									   estimated_count, vacrel);
		}
	}
	else
	{
		/* Outsource everything to parallel variant */
		do_parallel_lazy_cleanup_all_indexes(vacrel);
	}
}

/*
 *	lazy_cleanup_one_index() -- do post-vacuum cleanup for index relation.
 *
 *		reltuples is the number of heap tuples and estimated_count is true
 *		if reltuples is an estimated value.
 *
 * Returns bulk delete stats derived from input stats
 */
IndexBulkDeleteResult *
lazy_cleanup_one_index(Relation indrel, IndexBulkDeleteResult *istat,
					   double reltuples, bool estimated_count,
					   LVRelState *vacrel)
{
	IndexVacuumInfo ivinfo;
	PGRUsage	ru0;
	LVSavedErrInfo saved_err_info;

	pg_rusage_init(&ru0);

	ivinfo.index = indrel;
	ivinfo.analyze_only = false;
	ivinfo.report_progress = false;
	ivinfo.estimated_count = estimated_count;
	ivinfo.message_level = elevel;

	ivinfo.num_heap_tuples = reltuples;
	ivinfo.strategy = vacrel->bstrategy;

	/*
	 * Update error traceback information.
	 *
	 * The index name is saved during this phase and restored immediately
	 * after this phase.  See vacuum_error_callback.
	 */
	Assert(vacrel->indname == NULL);
	vacrel->indname = pstrdup(RelationGetRelationName(indrel));
	update_vacuum_error_info(vacrel, &saved_err_info,
							 VACUUM_ERRCB_PHASE_INDEX_CLEANUP,
							 InvalidBlockNumber, InvalidOffsetNumber);

	istat = index_vacuum_cleanup(&ivinfo, istat);

	if (istat)
	{
		ereport(elevel,
				(errmsg("index \"%s\" now contains %.0f row versions in %u pages",
						RelationGetRelationName(indrel),
						(istat)->num_index_tuples,
						(istat)->num_pages),
				 errdetail("%.0f index row versions were removed.\n"
						   "%u index pages were newly deleted.\n"
						   "%u index pages are currently deleted, of which %u are currently reusable.\n"
						   "%s.",
						   (istat)->tuples_removed,
						   (istat)->pages_newly_deleted,
						   (istat)->pages_deleted, (istat)->pages_free,
						   pg_rusage_show(&ru0))));
	}

	/* Revert to the previous phase information for error traceback */
	restore_vacuum_error_info(vacrel, &saved_err_info);
	pfree(vacrel->indname);
	vacrel->indname = NULL;

	return istat;
}

/*
 * should_attempt_truncation - should we attempt to truncate the heap?
 *
 * Don't even think about it unless we have a shot at releasing a goodly
 * number of pages.  Otherwise, the time taken isn't worth it.
 *
 * Also don't attempt it if wraparound failsafe is in effect.  It's hard to
 * predict how long lazy_truncate_heap will take.  Don't take any chances.
 * There is very little chance of truncation working out when the failsafe is
 * in effect in any case.  lazy_scan_prune makes the optimistic assumption
 * that any LP_DEAD items it encounters will always be LP_UNUSED by the time
 * we're called.
 *
 * Also don't attempt it if we are doing early pruning/vacuuming, because a
 * scan which cannot find a truncated heap page cannot determine that the
 * snapshot is too old to read that page.
 *
 * This is split out so that we can test whether truncation is going to be
 * called for before we actually do it.  If you change the logic here, be
 * careful to depend only on fields that lazy_scan_heap updates on-the-fly.
 */
bool
should_attempt_truncation(LVRelState *vacrel, VacuumParams *params)
{
	BlockNumber possibly_freeable;

	if (params->truncate == VACOPT_TERNARY_DISABLED)
		return false;

	if (vacrel->do_failsafe)
		return false;

	possibly_freeable = vacrel->rel_pages - vacrel->nonempty_pages;
	if (possibly_freeable > 0 &&
		(possibly_freeable >= REL_TRUNCATE_MINIMUM ||
		 possibly_freeable >= vacrel->rel_pages / REL_TRUNCATE_FRACTION) &&
		old_snapshot_threshold < 0)
		return true;
	else
		return false;
}

/*
 * lazy_truncate_heap - try to truncate off any empty pages at the end
 */
void
lazy_truncate_heap(LVRelState *vacrel)
{
	BlockNumber old_rel_pages = vacrel->rel_pages;
	BlockNumber new_rel_pages;
	int			lock_retry;

	/* Report that we are now truncating */
	pgstat_progress_update_param(PROGRESS_VACUUM_PHASE,
								 PROGRESS_VACUUM_PHASE_TRUNCATE);

	/*
	 * Loop until no more truncating can be done.
	 */
	do
	{
		PGRUsage	ru0;

		pg_rusage_init(&ru0);

		/*
		 * We need full exclusive lock on the relation in order to do
		 * truncation. If we can't get it, give up rather than waiting --- we
		 * don't want to block other backends, and we don't want to deadlock
		 * (which is quite possible considering we already hold a lower-grade
		 * lock).
		 */
		vacrel->lock_waiter_detected = false;
		lock_retry = 0;
		while (true)
		{
			if (ConditionalLockRelation(vacrel->rel, AccessExclusiveLock))
				break;

			/*
			 * Check for interrupts while trying to (re-)acquire the exclusive
			 * lock.
			 */
			CHECK_FOR_INTERRUPTS();

			if (++lock_retry > (VACUUM_TRUNCATE_LOCK_TIMEOUT /
								VACUUM_TRUNCATE_LOCK_WAIT_INTERVAL))
			{
				/*
				 * We failed to establish the lock in the specified number of
				 * retries. This means we give up truncating.
				 */
				vacrel->lock_waiter_detected = true;
				ereport(elevel,
						(errmsg("\"%s\": stopping truncate due to conflicting lock request",
								vacrel->relname)));
				return;
			}

			pg_usleep(VACUUM_TRUNCATE_LOCK_WAIT_INTERVAL * 1000L);
		}

		/*
		 * Now that we have exclusive lock, look to see if the rel has grown
		 * whilst we were vacuuming with non-exclusive lock.  If so, give up;
		 * the newly added pages presumably contain non-deletable tuples.
		 */
		new_rel_pages = RelationGetNumberOfBlocks(vacrel->rel);
		if (new_rel_pages != old_rel_pages)
		{
			/*
			 * Note: we intentionally don't update vacrel->rel_pages with the
			 * new rel size here.  If we did, it would amount to assuming that
			 * the new pages are empty, which is unlikely. Leaving the numbers
			 * alone amounts to assuming that the new pages have the same
			 * tuple density as existing ones, which is less unlikely.
			 */
			UnlockRelation(vacrel->rel, AccessExclusiveLock);
			return;
		}

		/*
		 * Scan backwards from the end to verify that the end pages actually
		 * contain no tuples.  This is *necessary*, not optional, because
		 * other backends could have added tuples to these pages whilst we
		 * were vacuuming.
		 */
		new_rel_pages = count_nondeletable_pages(vacrel);
		vacrel->blkno = new_rel_pages;

		if (new_rel_pages >= old_rel_pages)
		{
			/* can't do anything after all */
			UnlockRelation(vacrel->rel, AccessExclusiveLock);
			return;
		}

		/*
		 * Okay to truncate.
		 */
		RelationTruncate(vacrel->rel, new_rel_pages);

		/*
		 * We can release the exclusive lock as soon as we have truncated.
		 * Other backends can't safely access the relation until they have
		 * processed the smgr invalidation that smgrtruncate sent out ... but
		 * that should happen as part of standard invalidation processing once
		 * they acquire lock on the relation.
		 */
		UnlockRelation(vacrel->rel, AccessExclusiveLock);

		/*
		 * Update statistics.  Here, it *is* correct to adjust rel_pages
		 * without also touching reltuples, since the tuple count wasn't
		 * changed by the truncation.
		 */
		vacrel->pages_removed += old_rel_pages - new_rel_pages;
		vacrel->rel_pages = new_rel_pages;

		ereport(elevel,
				(errmsg("\"%s\": truncated %u to %u pages",
						vacrel->relname,
						old_rel_pages, new_rel_pages),
				 errdetail_internal("%s",
									pg_rusage_show(&ru0))));
		old_rel_pages = new_rel_pages;
	} while (new_rel_pages > vacrel->nonempty_pages &&
			 vacrel->lock_waiter_detected);
}

/*
 * lazy_record_dead_tuple - remember one deletable tuple
 */
void
lazy_record_dead_tuple(LVDeadTuples *dead_tuples, ItemPointer itemptr)
{
	/*
	 * The array shouldn't overflow under normal behavior, but perhaps it
	 * could if we are given a really small maintenance_work_mem. In that
	 * case, just forget the last few tuples (we'll get 'em next time).
	 */
	if (dead_tuples->num_tuples < dead_tuples->max_tuples)
	{
		dead_tuples->itemptrs[dead_tuples->num_tuples] = *itemptr;
		dead_tuples->num_tuples++;
		pgstat_progress_update_param(PROGRESS_VACUUM_NUM_DEAD_TUPLES,
									 dead_tuples->num_tuples);
	}
}

/*
 *	lazy_tid_reaped() -- is a particular tid deletable?
 *
 *		This has the right signature to be an IndexBulkDeleteCallback.
 *
 *		Assumes dead_tuples array is in sorted order.
 */
static bool
lazy_tid_reaped(ItemPointer itemptr, void *state)
{
	LVDeadTuples *dead_tuples = (LVDeadTuples *) state;
	int64		litem,
				ritem,
				item;
	ItemPointer res;

	litem = itemptr_encode(&dead_tuples->itemptrs[0]);
	ritem = itemptr_encode(&dead_tuples->itemptrs[dead_tuples->num_tuples - 1]);
	item = itemptr_encode(itemptr);

	/*
	 * Doing a simple bound check before bsearch() is useful to avoid the
	 * extra cost of bsearch(), especially if dead tuples on the heap are
	 * concentrated in a certain range.  Since this function is called for
	 * every index tuple, it pays to be really fast.
	 */
	if (item < litem || item > ritem)
		return false;

	res = (ItemPointer) bsearch((void *) itemptr,
								(void *) dead_tuples->itemptrs,
								dead_tuples->num_tuples,
								sizeof(ItemPointerData),
								vac_cmp_itemptr);

	return (res != NULL);
}

/*
 * Comparator routines for use with qsort() and bsearch().
 */
static int
vac_cmp_itemptr(const void *left, const void *right)
{
	BlockNumber lblk,
				rblk;
	OffsetNumber loff,
				roff;

	lblk = ItemPointerGetBlockNumber((ItemPointer) left);
	rblk = ItemPointerGetBlockNumber((ItemPointer) right);

	if (lblk < rblk)
		return -1;
	if (lblk > rblk)
		return 1;

	loff = ItemPointerGetOffsetNumber((ItemPointer) left);
	roff = ItemPointerGetOffsetNumber((ItemPointer) right);

	if (loff < roff)
		return -1;
	if (loff > roff)
		return 1;

	return 0;
}

/*
 * Rescan end pages to verify that they are (still) empty of tuples.
 *
 * Returns number of nondeletable pages (last nonempty page + 1).
 */
static BlockNumber
count_nondeletable_pages(LVRelState *vacrel)
{
	BlockNumber blkno;
	BlockNumber prefetchedUntil;
	instr_time	starttime;

	/* Initialize the starttime if we check for conflicting lock requests */
	INSTR_TIME_SET_CURRENT(starttime);

	/*
	 * Start checking blocks at what we believe relation end to be and move
	 * backwards.  (Strange coding of loop control is needed because blkno is
	 * unsigned.)  To make the scan faster, we prefetch a few blocks at a time
	 * in forward direction, so that OS-level readahead can kick in.
	 */
	blkno = vacrel->rel_pages;
	StaticAssertStmt((PREFETCH_SIZE & (PREFETCH_SIZE - 1)) == 0,
					 "prefetch size must be power of 2");
	prefetchedUntil = InvalidBlockNumber;
	while (blkno > vacrel->nonempty_pages)
	{
		Buffer		buf;
		Page		page;
		OffsetNumber offnum,
					maxoff;
		bool		hastup;

		/*
		 * Check if another process requests a lock on our relation. We are
		 * holding an AccessExclusiveLock here, so they will be waiting. We
		 * only do this once per VACUUM_TRUNCATE_LOCK_CHECK_INTERVAL, and we
		 * only check if that interval has elapsed once every 32 blocks to
		 * keep the number of system calls and actual shared lock table
		 * lookups to a minimum.
		 */
		if ((blkno % 32) == 0)
		{
			instr_time	currenttime;
			instr_time	elapsed;

			INSTR_TIME_SET_CURRENT(currenttime);
			elapsed = currenttime;
			INSTR_TIME_SUBTRACT(elapsed, starttime);
			if ((INSTR_TIME_GET_MICROSEC(elapsed) / 1000)
				>= VACUUM_TRUNCATE_LOCK_CHECK_INTERVAL)
			{
				if (LockHasWaitersRelation(vacrel->rel, AccessExclusiveLock))
				{
					ereport(elevel,
							(errmsg("\"%s\": suspending truncate due to conflicting lock request",
									vacrel->relname)));

					vacrel->lock_waiter_detected = true;
					return blkno;
				}
				starttime = currenttime;
			}
		}

		/*
		 * We don't insert a vacuum delay point here, because we have an
		 * exclusive lock on the table which we want to hold for as short a
		 * time as possible.  We still need to check for interrupts however.
		 */
		CHECK_FOR_INTERRUPTS();

		blkno--;

		/* If we haven't prefetched this lot yet, do so now. */
		if (prefetchedUntil > blkno)
		{
			BlockNumber prefetchStart;
			BlockNumber pblkno;

			prefetchStart = blkno & ~(PREFETCH_SIZE - 1);
			for (pblkno = prefetchStart; pblkno <= blkno; pblkno++)
			{
				PrefetchBuffer(vacrel->rel, MAIN_FORKNUM, pblkno);
				CHECK_FOR_INTERRUPTS();
			}
			prefetchedUntil = prefetchStart;
		}

		buf = ReadBufferExtended(vacrel->rel, MAIN_FORKNUM, blkno, RBM_NORMAL,
								 vacrel->bstrategy);

		/* In this phase we only need shared access to the buffer */
		LockBuffer(buf, BUFFER_LOCK_SHARE);

		page = BufferGetPage(buf);

		if (PageIsNew(page) || PageIsEmpty(page))
		{
			UnlockReleaseBuffer(buf);
			continue;
		}

		hastup = false;
		maxoff = PageGetMaxOffsetNumber(page);
		for (offnum = FirstOffsetNumber;
			 offnum <= maxoff;
			 offnum = OffsetNumberNext(offnum))
		{
			ItemId		itemid;

			itemid = PageGetItemId(page, offnum);

			/*
			 * Note: any non-unused item should be taken as a reason to keep
			 * this page.  We formerly thought that DEAD tuples could be
			 * thrown away, but that's not so, because we'd not have cleaned
			 * out their index entries.
			 */
			if (ItemIdIsUsed(itemid))
			{
				hastup = true;
				break;			/* can stop scanning */
			}
		}						/* scan along page */

		UnlockReleaseBuffer(buf);

		/* Done scanning if we found a tuple here */
		if (hastup)
			return blkno + 1;
	}

	/*
	 * If we fall out of the loop, all the previously-thought-to-be-empty
	 * pages still are; we need not bother to look at the last known-nonempty
	 * page.
	 */
	return vacrel->nonempty_pages;
}

/*
 * Return the maximum number of dead tuples we can record.
 */
static long
compute_max_dead_tuples(BlockNumber relblocks, bool hasindex,
						bool is_zheap)
{
	long		maxtuples;
	int			vac_work_mem = IsAutoVacuumWorkerProcess() &&
	autovacuum_work_mem != -1 ?
	autovacuum_work_mem : maintenance_work_mem;

	if (hasindex)
	{
		int	tuples_per_page;

		tuples_per_page = !is_zheap ? MaxHeapTuplesPerPage :
			MaxZHeapTuplesPerPage;
		maxtuples = MAXDEADTUPLES(vac_work_mem * 1024L);
		maxtuples = Min(maxtuples, INT_MAX);
		maxtuples = Min(maxtuples, MAXDEADTUPLES(MaxAllocSize));

		/* curious coding here to ensure the multiplication can't overflow */
		if ((BlockNumber) (maxtuples / tuples_per_page) > relblocks)
			maxtuples = relblocks * tuples_per_page;

		/* stay sane if small maintenance_work_mem */
		maxtuples = Max(maxtuples, MaxHeapTuplesPerPage);
	}
	else
		maxtuples = MaxHeapTuplesPerPage;

	return maxtuples;
}

/*
 * Perform lazy_cleanup_all_indexes() steps in parallel
 */
static void
do_parallel_lazy_cleanup_all_indexes(LVRelState *vacrel)
{
	int			nworkers;

	/*
	 * If parallel vacuum is active we perform index cleanup with parallel
	 * workers.
	 *
	 * Tell parallel workers to do index cleanup.
	 */
	vacrel->lps->lvshared->for_cleanup = true;
	vacrel->lps->lvshared->first_time = (vacrel->num_index_scans == 0);

	/*
	 * Now we can provide a better estimate of total number of surviving
	 * tuples (we assume indexes are more interested in that than in the
	 * number of nominally live tuples).
	 */
	vacrel->lps->lvshared->reltuples = vacrel->new_rel_tuples;
	vacrel->lps->lvshared->estimated_count =
		(vacrel->tupcount_pages < vacrel->rel_pages);

	/* Determine the number of parallel workers to launch */
	if (vacrel->lps->lvshared->first_time)
		nworkers = vacrel->lps->nindexes_parallel_cleanup +
			vacrel->lps->nindexes_parallel_condcleanup;
	else
		nworkers = vacrel->lps->nindexes_parallel_cleanup;

	do_parallel_vacuum_or_cleanup(vacrel, nworkers);
}

/*
 * Updates the information required for vacuum error callback.  This also saves
 * the current information which can be later restored via restore_vacuum_error_info.
 */
void
update_vacuum_error_info(LVRelState *vacrel, LVSavedErrInfo *saved_vacrel,
						 int phase, BlockNumber blkno, OffsetNumber offnum)
{
	if (saved_vacrel)
	{
		saved_vacrel->offnum = vacrel->offnum;
		saved_vacrel->blkno = vacrel->blkno;
		saved_vacrel->phase = vacrel->phase;
	}

	vacrel->blkno = blkno;
	vacrel->offnum = offnum;
	vacrel->phase = phase;
}

/*
 * Restores the vacuum information saved via a prior call to update_vacuum_error_info.
 */
void
restore_vacuum_error_info(LVRelState *vacrel,
						  const LVSavedErrInfo *saved_vacrel)
{
	vacrel->blkno = saved_vacrel->blkno;
	vacrel->offnum = saved_vacrel->offnum;
	vacrel->phase = saved_vacrel->phase;
}

/*
 * Error context callback for errors occurring during vacuum.
 */
void
vacuum_error_callback(void *arg)
{
	LVRelState *errinfo = arg;

	switch (errinfo->phase)
	{
		case VACUUM_ERRCB_PHASE_SCAN_HEAP:
			if (BlockNumberIsValid(errinfo->blkno))
			{
				if (OffsetNumberIsValid(errinfo->offnum))
					errcontext("while scanning block %u and offset %u of relation \"%s.%s\"",
							   errinfo->blkno, errinfo->offnum, errinfo->relnamespace, errinfo->relname);
				else
					errcontext("while scanning block %u of relation \"%s.%s\"",
							   errinfo->blkno, errinfo->relnamespace, errinfo->relname);
			}
			else
				errcontext("while scanning relation \"%s.%s\"",
						   errinfo->relnamespace, errinfo->relname);
			break;

		case VACUUM_ERRCB_PHASE_VACUUM_HEAP:
			if (BlockNumberIsValid(errinfo->blkno))
			{
				if (OffsetNumberIsValid(errinfo->offnum))
					errcontext("while vacuuming block %u and offset %u of relation \"%s.%s\"",
							   errinfo->blkno, errinfo->offnum, errinfo->relnamespace, errinfo->relname);
				else
					errcontext("while vacuuming block %u of relation \"%s.%s\"",
							   errinfo->blkno, errinfo->relnamespace, errinfo->relname);
			}
			else
				errcontext("while vacuuming relation \"%s.%s\"",
						   errinfo->relnamespace, errinfo->relname);
			break;

		case VACUUM_ERRCB_PHASE_VACUUM_INDEX:
			errcontext("while vacuuming index \"%s\" of relation \"%s.%s\"",
					   errinfo->indname, errinfo->relnamespace, errinfo->relname);
			break;

		case VACUUM_ERRCB_PHASE_INDEX_CLEANUP:
			errcontext("while cleaning up index \"%s\" of relation \"%s.%s\"",
					   errinfo->indname, errinfo->relnamespace, errinfo->relname);
			break;

		case VACUUM_ERRCB_PHASE_TRUNCATE:
			if (BlockNumberIsValid(errinfo->blkno))
				errcontext("while truncating relation \"%s.%s\" to %u blocks",
						   errinfo->relnamespace, errinfo->relname, errinfo->blkno);
			break;

		case VACUUM_ERRCB_PHASE_UNKNOWN:
		default:
			return;				/* do nothing; the errinfo may not be
								 * initialized */
	}
}
