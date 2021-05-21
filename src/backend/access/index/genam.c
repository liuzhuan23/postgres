/*-------------------------------------------------------------------------
 *
 * genam.c
 *	  general index access method routines
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/index/genam.c
 *
 * NOTES
 *	  many of the old access method routines have been turned into
 *	  macros and moved to genam.h -cim 4/30/91
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/relscan.h"
#include "access/tableam.h"
#include "access/transam.h"
#include "catalog/index.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "storage/bufmgr.h"
#include "storage/procarray.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/rls.h"
#include "utils/ruleutils.h"
#include "utils/snapmgr.h"
#include "utils/syscache.h"


/* ----------------------------------------------------------------
 *		general access method routines
 *
 *		All indexed access methods use an identical scan structure.
 *		We don't know how the various AMs do locking, however, so we don't
 *		do anything about that here.
 *
 *		The intent is that an AM implementor will define a beginscan routine
 *		that calls RelationGetIndexScan, to fill in the scan, and then does
 *		whatever kind of locking he wants.
 *
 *		At the end of a scan, the AM's endscan routine undoes the locking,
 *		but does *not* call IndexScanEnd --- the higher-level index_endscan
 *		routine does that.  (We can't do it in the AM because index_endscan
 *		still needs to touch the IndexScanDesc after calling the AM.)
 *
 *		Because of this, the AM does not have a choice whether to call
 *		RelationGetIndexScan or not; its beginscan routine must return an
 *		object made by RelationGetIndexScan.  This is kinda ugly but not
 *		worth cleaning up now.
 * ----------------------------------------------------------------
 */

/* ----------------
 *	RelationGetIndexScan -- Create and fill an IndexScanDesc.
 *
 *		This routine creates an index scan structure and sets up initial
 *		contents for it.
 *
 *		Parameters:
 *				indexRelation -- index relation for scan.
 *				nkeys -- count of scan keys (index qual conditions).
 *				norderbys -- count of index order-by operators.
 *
 *		Returns:
 *				An initialized IndexScanDesc.
 * ----------------
 */
IndexScanDesc
RelationGetIndexScan(Relation indexRelation, int nkeys, int norderbys)
{
	IndexScanDesc scan;

	scan = (IndexScanDesc) palloc(sizeof(IndexScanDescData));

	scan->heapRelation = NULL;	/* may be set later */
	scan->xs_heapfetch = NULL;
	scan->indexRelation = indexRelation;
	scan->xs_snapshot = InvalidSnapshot;	/* caller must initialize this */
	scan->numberOfKeys = nkeys;
	scan->numberOfOrderBys = norderbys;

	/*
	 * We allocate key workspace here, but it won't get filled until amrescan.
	 */
	if (nkeys > 0)
		scan->keyData = (ScanKey) palloc(sizeof(ScanKeyData) * nkeys);
	else
		scan->keyData = NULL;
	if (norderbys > 0)
		scan->orderByData = (ScanKey) palloc(sizeof(ScanKeyData) * norderbys);
	else
		scan->orderByData = NULL;

	scan->xs_want_itup = false; /* may be set later */

	/*
	 * During recovery we ignore killed tuples and don't bother to kill them
	 * either. We do this because the xmin on the primary node could easily be
	 * later than the xmin on the standby node, so that what the primary
	 * thinks is killed is supposed to be visible on standby. So for correct
	 * MVCC for queries during recovery we must ignore these hints and check
	 * all tuples. Do *not* set ignore_killed_tuples to true when running in a
	 * transaction that was started during recovery. xactStartedInRecovery
	 * should not be altered by index AMs.
	 */
	scan->kill_prior_tuple = false;
	scan->xactStartedInRecovery = TransactionStartedDuringRecovery();
	scan->ignore_killed_tuples = !scan->xactStartedInRecovery;

	scan->opaque = NULL;

	scan->xs_itup = NULL;
	scan->xs_itupdesc = NULL;
	scan->xs_hitup = NULL;
	scan->xs_hitupdesc = NULL;

	return scan;
}

/* ----------------
 *	IndexScanEnd -- End an index scan.
 *
 *		This routine just releases the storage acquired by
 *		RelationGetIndexScan().  Any AM-level resources are
 *		assumed to already have been released by the AM's
 *		endscan routine.
 *
 *	Returns:
 *		None.
 * ----------------
 */
void
IndexScanEnd(IndexScanDesc scan)
{
	if (scan->keyData != NULL)
		pfree(scan->keyData);
	if (scan->orderByData != NULL)
		pfree(scan->orderByData);

	pfree(scan);
}

/*
 * BuildIndexValueDescription
 *
 * Construct a string describing the contents of an index entry, in the
 * form "(key_name, ...)=(key_value, ...)".  This is currently used
 * for building unique-constraint and exclusion-constraint error messages,
 * so only key columns of the index are checked and printed.
 *
 * Note that if the user does not have permissions to view all of the
 * columns involved then a NULL is returned.  Returning a partial key seems
 * unlikely to be useful and we have no way to know which of the columns the
 * user provided (unlike in ExecBuildSlotValueDescription).
 *
 * The passed-in values/nulls arrays are the "raw" input to the index AM,
 * e.g. results of FormIndexDatum --- this is not necessarily what is stored
 * in the index, but it's what the user perceives to be stored.
 *
 * Note: if you change anything here, check whether
 * ExecBuildSlotPartitionKeyDescription() in execMain.c needs a similar
 * change.
 */
char *
BuildIndexValueDescription(Relation indexRelation,
						   Datum *values, bool *isnull)
{
	StringInfoData buf;
	Form_pg_index idxrec;
	int			indnkeyatts;
	int			i;
	int			keyno;
	Oid			indexrelid = RelationGetRelid(indexRelation);
	Oid			indrelid;
	AclResult	aclresult;

	indnkeyatts = IndexRelationGetNumberOfKeyAttributes(indexRelation);

	/*
	 * Check permissions- if the user does not have access to view all of the
	 * key columns then return NULL to avoid leaking data.
	 *
	 * First check if RLS is enabled for the relation.  If so, return NULL to
	 * avoid leaking data.
	 *
	 * Next we need to check table-level SELECT access and then, if there is
	 * no access there, check column-level permissions.
	 */
	idxrec = indexRelation->rd_index;
	indrelid = idxrec->indrelid;
	Assert(indexrelid == idxrec->indexrelid);

	/* RLS check- if RLS is enabled then we don't return anything. */
	if (check_enable_rls(indrelid, InvalidOid, true) == RLS_ENABLED)
		return NULL;

	/* Table-level SELECT is enough, if the user has it */
	aclresult = pg_class_aclcheck(indrelid, GetUserId(), ACL_SELECT);
	if (aclresult != ACLCHECK_OK)
	{
		/*
		 * No table-level access, so step through the columns in the index and
		 * make sure the user has SELECT rights on all of them.
		 */
		for (keyno = 0; keyno < indnkeyatts; keyno++)
		{
			AttrNumber	attnum = idxrec->indkey.values[keyno];

			/*
			 * Note that if attnum == InvalidAttrNumber, then this is an index
			 * based on an expression and we return no detail rather than try
			 * to figure out what column(s) the expression includes and if the
			 * user has SELECT rights on them.
			 */
			if (attnum == InvalidAttrNumber ||
				pg_attribute_aclcheck(indrelid, attnum, GetUserId(),
									  ACL_SELECT) != ACLCHECK_OK)
			{
				/* No access, so clean up and return */
				return NULL;
			}
		}
	}

	initStringInfo(&buf);
	appendStringInfo(&buf, "(%s)=(",
					 pg_get_indexdef_columns(indexrelid, true));

	for (i = 0; i < indnkeyatts; i++)
	{
		char	   *val;

		if (isnull[i])
			val = "null";
		else
		{
			Oid			foutoid;
			bool		typisvarlena;

			/*
			 * The provided data is not necessarily of the type stored in the
			 * index; rather it is of the index opclass's input type. So look
			 * at rd_opcintype not the index tupdesc.
			 *
			 * Note: this is a bit shaky for opclasses that have pseudotype
			 * input types such as ANYARRAY or RECORD.  Currently, the
			 * typoutput functions associated with the pseudotypes will work
			 * okay, but we might have to try harder in future.
			 */
			getTypeOutputInfo(indexRelation->rd_opcintype[i],
							  &foutoid, &typisvarlena);
			val = OidOutputFunctionCall(foutoid, values[i]);
		}

		if (i > 0)
			appendStringInfoString(&buf, ", ");
		appendStringInfoString(&buf, val);
	}

	appendStringInfoChar(&buf, ')');

	return buf.data;
}

/*
 * Get the latestRemovedXid from the table entries pointed at by the index
 * tuples being deleted using an AM-generic approach.
 *
 * This is a table_index_delete_tuples() shim used by index AMs that have
 * simple requirements.  These callers only need to consult the tableam to get
 * a latestRemovedXid value, and only expect to delete tuples that are already
 * known deletable.  When a latestRemovedXid value isn't needed in index AM's
 * deletion WAL record, it is safe for it to skip calling here entirely.
 *
 * We assume that caller index AM uses the standard IndexTuple representation,
 * with table TIDs stored in the t_tid field.  We also expect (and assert)
 * that the line pointers on page for 'itemnos' offsets are already marked
 * LP_DEAD.
 */
TransactionId
index_compute_xid_horizon_for_tuples(Relation irel,
									 Relation hrel,
									 Buffer ibuf,
									 OffsetNumber *itemnos,
									 int nitems)
{
	TM_IndexDeleteOp delstate;
	TransactionId latestRemovedXid = InvalidTransactionId;
	Page		ipage = BufferGetPage(ibuf);
	IndexTuple	itup;

	Assert(nitems > 0);

	delstate.bottomup = false;
	delstate.bottomupfreespace = 0;
	delstate.ndeltids = 0;
	delstate.deltids = palloc(nitems * sizeof(TM_IndexDelete));
	delstate.status = palloc(nitems * sizeof(TM_IndexStatus));

	/* identify what the index tuples about to be deleted point to */
	for (int i = 0; i < nitems; i++)
	{
		ItemId		iitemid;

		iitemid = PageGetItemId(ipage, itemnos[i]);
		itup = (IndexTuple) PageGetItem(ipage, iitemid);

		Assert(ItemIdIsDead(iitemid));

		ItemPointerCopy(&itup->t_tid, &delstate.deltids[i].tid);
		delstate.deltids[i].id = delstate.ndeltids;
		delstate.status[i].idxoffnum = InvalidOffsetNumber; /* unused */
		delstate.status[i].knowndeletable = true;	/* LP_DEAD-marked */
		delstate.status[i].promising = false;	/* unused */
		delstate.status[i].freespace = 0;	/* unused */

		delstate.ndeltids++;
	}

	/* determine the actual xid horizon */
	latestRemovedXid = table_index_delete_tuples(hrel, &delstate);

	/* assert tableam agrees that all items are deletable */
	Assert(delstate.ndeltids == nitems);

	pfree(delstate.deltids);
	pfree(delstate.status);

	return latestRemovedXid;
}

/*
 * Specialized inlineable comparison function for index_delete_sort()
 */
static inline int
index_delete_sort_cmp(TM_IndexDelete *deltid1, TM_IndexDelete *deltid2)
{
	ItemPointer tid1 = &deltid1->tid;
	ItemPointer tid2 = &deltid2->tid;

	{
		BlockNumber blk1 = ItemPointerGetBlockNumber(tid1);
		BlockNumber blk2 = ItemPointerGetBlockNumber(tid2);

		if (blk1 != blk2)
			return (blk1 < blk2) ? -1 : 1;
	}
	{
		OffsetNumber pos1 = ItemPointerGetOffsetNumber(tid1);
		OffsetNumber pos2 = ItemPointerGetOffsetNumber(tid2);

		if (pos1 != pos2)
			return (pos1 < pos2) ? -1 : 1;
	}

	pg_unreachable();

	return 0;
}

/*
 * Sort deltids array from delstate by TID.  This prepares it for further
 * processing by heap_index_delete_tuples().
 *
 * This operation becomes a noticeable consumer of CPU cycles with some
 * workloads, so we go to the trouble of specialization/micro optimization.
 * We use shellsort for this because it's easy to specialize, compiles to
 * relatively few instructions, and is adaptive to presorted inputs/subsets
 * (which are typical here).
 */
void
index_delete_sort(TM_IndexDeleteOp *delstate)
{
	TM_IndexDelete *deltids = delstate->deltids;
	int			ndeltids = delstate->ndeltids;
	int			low = 0;

	/*
	 * Shellsort gap sequence (taken from Sedgewick-Incerpi paper).
	 *
	 * This implementation is fast with array sizes up to ~4500.  This covers
	 * all supported BLCKSZ values.
	 */
	const int	gaps[9] = {1968, 861, 336, 112, 48, 21, 7, 3, 1};

	/* Think carefully before changing anything here -- keep swaps cheap */
	StaticAssertStmt(sizeof(TM_IndexDelete) <= 8,
					 "element size exceeds 8 bytes");

	for (int g = 0; g < lengthof(gaps); g++)
	{
		for (int hi = gaps[g], i = low + hi; i < ndeltids; i++)
		{
			TM_IndexDelete d = deltids[i];
			int			j = i;

			while (j >= hi && index_delete_sort_cmp(&deltids[j - hi], &d) >= 0)
			{
				deltids[j] = deltids[j - hi];
				j -= hi;
			}
			deltids[j] = d;
		}
	}
}

/*
 * qsort comparison function for bottomup_sort_and_shrink()
 */
static int
bottomup_sort_and_shrink_cmp(const void *arg1, const void *arg2)
{
	const IndexDeleteCounts *group1 = (const IndexDeleteCounts *) arg1;
	const IndexDeleteCounts *group2 = (const IndexDeleteCounts *) arg2;

	/*
	 * Most significant field is npromisingtids (which we invert the order of
	 * so as to sort in desc order).
	 *
	 * Caller should have already normalized npromisingtids fields into
	 * power-of-two values (buckets).
	 */
	if (group1->npromisingtids > group2->npromisingtids)
		return -1;
	if (group1->npromisingtids < group2->npromisingtids)
		return 1;

	/*
	 * Tiebreak: desc ntids sort order.
	 *
	 * We cannot expect power-of-two values for ntids fields.  We should
	 * behave as if they were already rounded up for us instead.
	 */
	if (group1->ntids != group2->ntids)
	{
		uint32		ntids1 = pg_nextpower2_32((uint32) group1->ntids);
		uint32		ntids2 = pg_nextpower2_32((uint32) group2->ntids);

		if (ntids1 > ntids2)
			return -1;
		if (ntids1 < ntids2)
			return 1;
	}

	/*
	 * Tiebreak: asc offset-into-deltids-for-block (offset to first TID for
	 * block in deltids array) order.
	 *
	 * This is equivalent to sorting in ascending heap block number order
	 * (among otherwise equal subsets of the array).  This approach allows us
	 * to avoid accessing the out-of-line TID.  (We rely on the assumption
	 * that the deltids array was sorted in ascending heap TID order when
	 * these offsets to the first TID from each heap block group were formed.)
	 */
	if (group1->ifirsttid > group2->ifirsttid)
		return 1;
	if (group1->ifirsttid < group2->ifirsttid)
		return -1;

	pg_unreachable();

	return 0;
}

/*
 * Returns how many blocks should be considered favorable/contiguous for a
 * bottom-up index deletion pass.  This is a number of heap blocks that starts
 * from and includes the first block in line.
 *
 * There is always at least one favorable block during bottom-up index
 * deletion.  In the worst case (i.e. with totally random heap blocks) the
 * first block in line (the only favorable block) can be thought of as a
 * degenerate array of contiguous blocks that consists of a single block.
 * heap_index_delete_tuples() will expect this.
 *
 * Caller passes blockgroups, a description of the final order that deltids
 * will be sorted in for heap_index_delete_tuples() bottom-up index deletion
 * processing.  Note that deltids need not actually be sorted just yet (caller
 * only passes deltids to us so that we can interpret blockgroups).
 *
 * You might guess that the existence of contiguous blocks cannot matter much,
 * since in general the main factor that determines which blocks we visit is
 * the number of promising TIDs, which is a fixed hint from the index AM.
 * We're not really targeting the general case, though -- the actual goal is
 * to adapt our behavior to a wide variety of naturally occurring conditions.
 * The effects of most of the heuristics we apply are only noticeable in the
 * aggregate, over time and across many _related_ bottom-up index deletion
 * passes.
 *
 * Deeming certain blocks favorable allows heapam to recognize and adapt to
 * workloads where heap blocks visited during bottom-up index deletion can be
 * accessed contiguously, in the sense that each newly visited block is the
 * neighbor of the block that bottom-up deletion just finished processing (or
 * close enough to it).  It will likely be cheaper to access more favorable
 * blocks sooner rather than later (e.g. in this pass, not across a series of
 * related bottom-up passes).  Either way it is probably only a matter of time
 * (or a matter of further correlated version churn) before all blocks that
 * appear together as a single large batch of favorable blocks get accessed by
 * _some_ bottom-up pass.  Large batches of favorable blocks tend to either
 * appear almost constantly or not even once (it all depends on per-index
 * workload characteristics).
 *
 * Note that the blockgroups sort order applies a power-of-two bucketing
 * scheme that creates opportunities for contiguous groups of blocks to get
 * batched together, at least with workloads that are naturally amenable to
 * being driven by heap block locality.  This doesn't just enhance the spatial
 * locality of bottom-up heap block processing in the obvious way.  It also
 * enables temporal locality of access, since sorting by heap block number
 * naturally tends to make the bottom-up processing order deterministic.
 *
 * Consider the following example to get a sense of how temporal locality
 * might matter: There is a heap relation with several indexes, each of which
 * is low to medium cardinality.  It is subject to constant non-HOT updates.
 * The updates are skewed (in one part of the primary key, perhaps).  None of
 * the indexes are logically modified by the UPDATE statements (if they were
 * then bottom-up index deletion would not be triggered in the first place).
 * Naturally, each new round of index tuples (for each heap tuple that gets a
 * heap_update() call) will have the same heap TID in each and every index.
 * Since these indexes are low cardinality and never get logically modified,
 * heapam processing during bottom-up deletion passes will access heap blocks
 * in approximately sequential order.  Temporal locality of access occurs due
 * to bottom-up deletion passes behaving very similarly across each of the
 * indexes at any given moment.  This keeps the number of buffer misses needed
 * to visit heap blocks to a minimum.
 */
static int
bottomup_nblocksfavorable(IndexDeleteCounts *blockgroups, int nblockgroups,
						  TM_IndexDelete *deltids)
{
	int64		lastblock = -1;
	int			nblocksfavorable = 0;

	Assert(nblockgroups >= 1);
	Assert(nblockgroups <= BOTTOMUP_MAX_NBLOCKS);

	/*
	 * We tolerate heap blocks that will be accessed only slightly out of
	 * physical order.  Small blips occur when a pair of almost-contiguous
	 * blocks happen to fall into different buckets (perhaps due only to a
	 * small difference in npromisingtids that the bucketing scheme didn't
	 * quite manage to ignore).  We effectively ignore these blips by applying
	 * a small tolerance.  The precise tolerance we use is a little arbitrary,
	 * but it works well enough in practice.
	 */
	for (int b = 0; b < nblockgroups; b++)
	{
		IndexDeleteCounts *group = blockgroups + b;
		TM_IndexDelete *firstdtid = deltids + group->ifirsttid;
		BlockNumber block = ItemPointerGetBlockNumber(&firstdtid->tid);

		if (lastblock != -1 &&
			((int64) block < lastblock - BOTTOMUP_TOLERANCE_NBLOCKS ||
			 (int64) block > lastblock + BOTTOMUP_TOLERANCE_NBLOCKS))
			break;

		nblocksfavorable++;
		lastblock = block;
	}

	/* Always indicate that there is at least 1 favorable block */
	Assert(nblocksfavorable >= 1);

	return nblocksfavorable;
}

/*
 * heap_index_delete_tuples() helper function for bottom-up deletion callers.
 *
 * Sorts deltids array in the order needed for useful processing by bottom-up
 * deletion.  The array should already be sorted in TID order when we're
 * called.  The sort process groups heap TIDs from deltids into heap block
 * groupings.  Earlier/more-promising groups/blocks are usually those that are
 * known to have the most "promising" TIDs.
 *
 * Sets new size of deltids array (ndeltids) in state.  deltids will only have
 * TIDs from the BOTTOMUP_MAX_NBLOCKS most promising heap blocks when we
 * return.  This often means that deltids will be shrunk to a small fraction
 * of its original size (we eliminate many heap blocks from consideration for
 * caller up front).
 *
 * Returns the number of "favorable" blocks.  See bottomup_nblocksfavorable()
 * for a definition and full details.
 */
int
bottomup_sort_and_shrink(TM_IndexDeleteOp *delstate)
{
	IndexDeleteCounts *blockgroups;
	TM_IndexDelete *reordereddeltids;
	BlockNumber curblock = InvalidBlockNumber;
	int			nblockgroups = 0;
	int			ncopied = 0;
	int			nblocksfavorable = 0;

	Assert(delstate->bottomup);
	Assert(delstate->ndeltids > 0);

	/* Calculate per-heap-block count of TIDs */
	blockgroups = palloc(sizeof(IndexDeleteCounts) * delstate->ndeltids);
	for (int i = 0; i < delstate->ndeltids; i++)
	{
		TM_IndexDelete *ideltid = &delstate->deltids[i];
		TM_IndexStatus *istatus = delstate->status + ideltid->id;
		ItemPointer htid = &ideltid->tid;
		bool		promising = istatus->promising;

		if (curblock != ItemPointerGetBlockNumber(htid))
		{
			/* New block group */
			nblockgroups++;

			Assert(curblock < ItemPointerGetBlockNumber(htid) ||
				   !BlockNumberIsValid(curblock));

			curblock = ItemPointerGetBlockNumber(htid);
			blockgroups[nblockgroups - 1].ifirsttid = i;
			blockgroups[nblockgroups - 1].ntids = 1;
			blockgroups[nblockgroups - 1].npromisingtids = 0;
		}
		else
		{
			blockgroups[nblockgroups - 1].ntids++;
		}

		if (promising)
			blockgroups[nblockgroups - 1].npromisingtids++;
	}

	/*
	 * We're about ready to sort block groups to determine the optimal order
	 * for visiting heap blocks.  But before we do, round the number of
	 * promising tuples for each block group up to the next power-of-two,
	 * unless it is very low (less than 4), in which case we round up to 4.
	 * npromisingtids is far too noisy to trust when choosing between a pair
	 * of block groups that both have very low values.
	 *
	 * This scheme divides heap blocks/block groups into buckets.  Each bucket
	 * contains blocks that have _approximately_ the same number of promising
	 * TIDs as each other.  The goal is to ignore relatively small differences
	 * in the total number of promising entries, so that the whole process can
	 * give a little weight to heapam factors (like heap block locality)
	 * instead.  This isn't a trade-off, really -- we have nothing to lose. It
	 * would be foolish to interpret small differences in npromisingtids
	 * values as anything more than noise.
	 *
	 * We tiebreak on nhtids when sorting block group subsets that have the
	 * same npromisingtids, but this has the same issues as npromisingtids,
	 * and so nhtids is subject to the same power-of-two bucketing scheme. The
	 * only reason that we don't fix nhtids in the same way here too is that
	 * we'll need accurate nhtids values after the sort.  We handle nhtids
	 * bucketization dynamically instead (in the sort comparator).
	 *
	 * See bottomup_nblocksfavorable() for a full explanation of when and how
	 * heap locality/favorable blocks can significantly influence when and how
	 * heap blocks are accessed.
	 */
	for (int b = 0; b < nblockgroups; b++)
	{
		IndexDeleteCounts *group = blockgroups + b;

		/* Better off falling back on nhtids with low npromisingtids */
		if (group->npromisingtids <= 4)
			group->npromisingtids = 4;
		else
			group->npromisingtids =
				pg_nextpower2_32((uint32) group->npromisingtids);
	}

	/* Sort groups and rearrange caller's deltids array */
	qsort(blockgroups, nblockgroups, sizeof(IndexDeleteCounts),
		  bottomup_sort_and_shrink_cmp);
	reordereddeltids = palloc(delstate->ndeltids * sizeof(TM_IndexDelete));

	nblockgroups = Min(BOTTOMUP_MAX_NBLOCKS, nblockgroups);
	/* Determine number of favorable blocks at the start of final deltids */
	nblocksfavorable = bottomup_nblocksfavorable(blockgroups, nblockgroups,
												 delstate->deltids);

	for (int b = 0; b < nblockgroups; b++)
	{
		IndexDeleteCounts *group = blockgroups + b;
		TM_IndexDelete *firstdtid = delstate->deltids + group->ifirsttid;

		memcpy(reordereddeltids + ncopied, firstdtid,
			   sizeof(TM_IndexDelete) * group->ntids);
		ncopied += group->ntids;
	}

	/* Copy final grouped and sorted TIDs back into start of caller's array */
	memcpy(delstate->deltids, reordereddeltids,
		   sizeof(TM_IndexDelete) * ncopied);
	delstate->ndeltids = ncopied;

	pfree(reordereddeltids);
	pfree(blockgroups);

	return nblocksfavorable;
}

#ifdef USE_PREFETCH
/*
 * Helper function for heap_index_delete_tuples.  Issues prefetch requests for
 * prefetch_count buffers.  The prefetch_state keeps track of all the buffers
 * we can prefetch, and which have already been prefetched; each call to this
 * function picks up where the previous call left off.
 *
 * Note: we expect the deltids array to be sorted in an order that groups TIDs
 * by heap block, with all TIDs for each block appearing together in exactly
 * one group.
 */
void
index_delete_prefetch_buffer(Relation rel,
							 IndexDeletePrefetchState *prefetch_state,
							 int prefetch_count)
{
	BlockNumber cur_hblkno = prefetch_state->cur_hblkno;
	int			count = 0;
	int			i;
	int			ndeltids = prefetch_state->ndeltids;
	TM_IndexDelete *deltids = prefetch_state->deltids;

	for (i = prefetch_state->next_item;
		 i < ndeltids && count < prefetch_count;
		 i++)
	{
		ItemPointer htid = &deltids[i].tid;

		if (cur_hblkno == InvalidBlockNumber ||
			ItemPointerGetBlockNumber(htid) != cur_hblkno)
		{
			cur_hblkno = ItemPointerGetBlockNumber(htid);
			PrefetchBuffer(rel, MAIN_FORKNUM, cur_hblkno);
			count++;
		}
	}

	/*
	 * Save the prefetch position so that next time we can continue from that
	 * position.
	 */
	prefetch_state->next_item = i;
	prefetch_state->cur_hblkno = cur_hblkno;
}
#endif

/* ----------------------------------------------------------------
 *		heap-or-index-scan access to system catalogs
 *
 *		These functions support system catalog accesses that normally use
 *		an index but need to be capable of being switched to heap scans
 *		if the system indexes are unavailable.
 *
 *		The specified scan keys must be compatible with the named index.
 *		Generally this means that they must constrain either all columns
 *		of the index, or the first K columns of an N-column index.
 *
 *		These routines could work with non-system tables, actually,
 *		but they're only useful when there is a known index to use with
 *		the given scan keys; so in practice they're only good for
 *		predetermined types of scans of system catalogs.
 * ----------------------------------------------------------------
 */

/*
 * systable_beginscan --- set up for heap-or-index scan
 *
 *	rel: catalog to scan, already opened and suitably locked
 *	indexId: OID of index to conditionally use
 *	indexOK: if false, forces a heap scan (see notes below)
 *	snapshot: time qual to use (NULL for a recent catalog snapshot)
 *	nkeys, key: scan keys
 *
 * The attribute numbers in the scan key should be set for the heap case.
 * If we choose to index, we reset them to 1..n to reference the index
 * columns.  Note this means there must be one scankey qualification per
 * index column!  This is checked by the Asserts in the normal, index-using
 * case, but won't be checked if the heapscan path is taken.
 *
 * The routine checks the normal cases for whether an indexscan is safe,
 * but caller can make additional checks and pass indexOK=false if needed.
 * In standard case indexOK can simply be constant TRUE.
 */
SysScanDesc
systable_beginscan(Relation heapRelation,
				   Oid indexId,
				   bool indexOK,
				   Snapshot snapshot,
				   int nkeys, ScanKey key)
{
	SysScanDesc sysscan;
	Relation	irel;

	if (indexOK &&
		!IgnoreSystemIndexes &&
		!ReindexIsProcessingIndex(indexId))
		irel = index_open(indexId, AccessShareLock);
	else
		irel = NULL;

	sysscan = (SysScanDesc) palloc(sizeof(SysScanDescData));

	sysscan->heap_rel = heapRelation;
	sysscan->irel = irel;
	sysscan->slot = table_slot_create(heapRelation, NULL);

	if (snapshot == NULL)
	{
		Oid			relid = RelationGetRelid(heapRelation);

		snapshot = RegisterSnapshot(GetCatalogSnapshot(relid));
		sysscan->snapshot = snapshot;
	}
	else
	{
		/* Caller is responsible for any snapshot. */
		sysscan->snapshot = NULL;
	}

	if (irel)
	{
		int			i;

		/* Change attribute numbers to be index column numbers. */
		for (i = 0; i < nkeys; i++)
		{
			int			j;

			for (j = 0; j < IndexRelationGetNumberOfAttributes(irel); j++)
			{
				if (key[i].sk_attno == irel->rd_index->indkey.values[j])
				{
					key[i].sk_attno = j + 1;
					break;
				}
			}
			if (j == IndexRelationGetNumberOfAttributes(irel))
				elog(ERROR, "column is not in index");
		}

		sysscan->iscan = index_beginscan(heapRelation, irel,
										 snapshot, nkeys, 0);
		index_rescan(sysscan->iscan, key, nkeys, NULL, 0);
		sysscan->scan = NULL;
	}
	else
	{
		/*
		 * We disallow synchronized scans when forced to use a heapscan on a
		 * catalog.  In most cases the desired rows are near the front, so
		 * that the unpredictable start point of a syncscan is a serious
		 * disadvantage; and there are no compensating advantages, because
		 * it's unlikely that such scans will occur in parallel.
		 */
		sysscan->scan = table_beginscan_strat(heapRelation, snapshot,
											  nkeys, key,
											  true, false);
		sysscan->iscan = NULL;
	}

	/*
	 * If CheckXidAlive is set then set a flag to indicate that system table
	 * scan is in-progress.  See detailed comments in xact.c where these
	 * variables are declared.
	 */
	if (TransactionIdIsValid(CheckXidAlive))
		bsysscan = true;

	return sysscan;
}

/*
 * HandleConcurrentAbort - Handle concurrent abort of the CheckXidAlive.
 *
 * Error out, if CheckXidAlive is aborted. We can't directly use
 * TransactionIdDidAbort as after crash such transaction might not have been
 * marked as aborted.  See detailed comments in xact.c where the variable
 * is declared.
 */
static inline void
HandleConcurrentAbort()
{
	if (TransactionIdIsValid(CheckXidAlive) &&
		!TransactionIdIsInProgress(CheckXidAlive) &&
		!TransactionIdDidCommit(CheckXidAlive))
		ereport(ERROR,
				(errcode(ERRCODE_TRANSACTION_ROLLBACK),
				 errmsg("transaction aborted during system catalog scan")));
}

/*
 * systable_getnext --- get next tuple in a heap-or-index scan
 *
 * Returns NULL if no more tuples available.
 *
 * Note that returned tuple is a reference to data in a disk buffer;
 * it must not be modified, and should be presumed inaccessible after
 * next getnext() or endscan() call.
 *
 * XXX: It'd probably make sense to offer a slot based interface, at least
 * optionally.
 */
HeapTuple
systable_getnext(SysScanDesc sysscan)
{
	HeapTuple	htup = NULL;

	if (sysscan->irel)
	{
		if (index_getnext_slot(sysscan->iscan, ForwardScanDirection, sysscan->slot))
		{
			bool		shouldFree;

			htup = ExecFetchSlotHeapTuple(sysscan->slot, false, &shouldFree);
			Assert(!shouldFree);

			/*
			 * We currently don't need to support lossy index operators for
			 * any system catalog scan.  It could be done here, using the scan
			 * keys to drive the operator calls, if we arranged to save the
			 * heap attnums during systable_beginscan(); this is practical
			 * because we still wouldn't need to support indexes on
			 * expressions.
			 */
			if (sysscan->iscan->xs_recheck)
				elog(ERROR, "system catalog scans with lossy index conditions are not implemented");
		}
	}
	else
	{
		if (table_scan_getnextslot(sysscan->scan, ForwardScanDirection, sysscan->slot))
		{
			bool		shouldFree;

			htup = ExecFetchSlotHeapTuple(sysscan->slot, false, &shouldFree);
			Assert(!shouldFree);
		}
	}

	/*
	 * Handle the concurrent abort while fetching the catalog tuple during
	 * logical streaming of a transaction.
	 */
	HandleConcurrentAbort();

	return htup;
}

/*
 * systable_recheck_tuple --- recheck visibility of most-recently-fetched tuple
 *
 * In particular, determine if this tuple would be visible to a catalog scan
 * that started now.  We don't handle the case of a non-MVCC scan snapshot,
 * because no caller needs that yet.
 *
 * This is useful to test whether an object was deleted while we waited to
 * acquire lock on it.
 *
 * Note: we don't actually *need* the tuple to be passed in, but it's a
 * good crosscheck that the caller is interested in the right tuple.
 */
bool
systable_recheck_tuple(SysScanDesc sysscan, HeapTuple tup)
{
	Snapshot	freshsnap;
	bool		result;

	Assert(tup == ExecFetchSlotHeapTuple(sysscan->slot, false, NULL));

	/*
	 * Trust that table_tuple_satisfies_snapshot() and its subsidiaries
	 * (commonly LockBuffer() and HeapTupleSatisfiesMVCC()) do not themselves
	 * acquire snapshots, so we need not register the snapshot.  Those
	 * facilities are too low-level to have any business scanning tables.
	 */
	freshsnap = GetCatalogSnapshot(RelationGetRelid(sysscan->heap_rel));

	result = table_tuple_satisfies_snapshot(sysscan->heap_rel,
											sysscan->slot,
											freshsnap);

	/*
	 * Handle the concurrent abort while fetching the catalog tuple during
	 * logical streaming of a transaction.
	 */
	HandleConcurrentAbort();

	return result;
}

/*
 * systable_endscan --- close scan, release resources
 *
 * Note that it's still up to the caller to close the heap relation.
 */
void
systable_endscan(SysScanDesc sysscan)
{
	if (sysscan->slot)
	{
		ExecDropSingleTupleTableSlot(sysscan->slot);
		sysscan->slot = NULL;
	}

	if (sysscan->irel)
	{
		index_endscan(sysscan->iscan);
		index_close(sysscan->irel, AccessShareLock);
	}
	else
		table_endscan(sysscan->scan);

	if (sysscan->snapshot)
		UnregisterSnapshot(sysscan->snapshot);

	/*
	 * Reset the bsysscan flag at the end of the systable scan.  See detailed
	 * comments in xact.c where these variables are declared.
	 */
	if (TransactionIdIsValid(CheckXidAlive))
		bsysscan = false;

	pfree(sysscan);
}


/*
 * systable_beginscan_ordered --- set up for ordered catalog scan
 *
 * These routines have essentially the same API as systable_beginscan etc,
 * except that they guarantee to return multiple matching tuples in
 * index order.  Also, for largely historical reasons, the index to use
 * is opened and locked by the caller, not here.
 *
 * Currently we do not support non-index-based scans here.  (In principle
 * we could do a heapscan and sort, but the uses are in places that
 * probably don't need to still work with corrupted catalog indexes.)
 * For the moment, therefore, these functions are merely the thinest of
 * wrappers around index_beginscan/index_getnext_slot.  The main reason for
 * their existence is to centralize possible future support of lossy operators
 * in catalog scans.
 */
SysScanDesc
systable_beginscan_ordered(Relation heapRelation,
						   Relation indexRelation,
						   Snapshot snapshot,
						   int nkeys, ScanKey key)
{
	SysScanDesc sysscan;
	int			i;

	/* REINDEX can probably be a hard error here ... */
	if (ReindexIsProcessingIndex(RelationGetRelid(indexRelation)))
		elog(ERROR, "cannot do ordered scan on index \"%s\", because it is being reindexed",
			 RelationGetRelationName(indexRelation));
	/* ... but we only throw a warning about violating IgnoreSystemIndexes */
	if (IgnoreSystemIndexes)
		elog(WARNING, "using index \"%s\" despite IgnoreSystemIndexes",
			 RelationGetRelationName(indexRelation));

	sysscan = (SysScanDesc) palloc(sizeof(SysScanDescData));

	sysscan->heap_rel = heapRelation;
	sysscan->irel = indexRelation;
	sysscan->slot = table_slot_create(heapRelation, NULL);

	if (snapshot == NULL)
	{
		Oid			relid = RelationGetRelid(heapRelation);

		snapshot = RegisterSnapshot(GetCatalogSnapshot(relid));
		sysscan->snapshot = snapshot;
	}
	else
	{
		/* Caller is responsible for any snapshot. */
		sysscan->snapshot = NULL;
	}

	/* Change attribute numbers to be index column numbers. */
	for (i = 0; i < nkeys; i++)
	{
		int			j;

		for (j = 0; j < IndexRelationGetNumberOfAttributes(indexRelation); j++)
		{
			if (key[i].sk_attno == indexRelation->rd_index->indkey.values[j])
			{
				key[i].sk_attno = j + 1;
				break;
			}
		}
		if (j == IndexRelationGetNumberOfAttributes(indexRelation))
			elog(ERROR, "column is not in index");
	}

	sysscan->iscan = index_beginscan(heapRelation, indexRelation,
									 snapshot, nkeys, 0);
	index_rescan(sysscan->iscan, key, nkeys, NULL, 0);
	sysscan->scan = NULL;

	return sysscan;
}

/*
 * systable_getnext_ordered --- get next tuple in an ordered catalog scan
 */
HeapTuple
systable_getnext_ordered(SysScanDesc sysscan, ScanDirection direction)
{
	HeapTuple	htup = NULL;

	Assert(sysscan->irel);
	if (index_getnext_slot(sysscan->iscan, direction, sysscan->slot))
		htup = ExecFetchSlotHeapTuple(sysscan->slot, false, NULL);

	/* See notes in systable_getnext */
	if (htup && sysscan->iscan->xs_recheck)
		elog(ERROR, "system catalog scans with lossy index conditions are not implemented");

	/*
	 * Handle the concurrent abort while fetching the catalog tuple during
	 * logical streaming of a transaction.
	 */
	HandleConcurrentAbort();

	return htup;
}

/*
 * systable_endscan_ordered --- close scan, release resources
 */
void
systable_endscan_ordered(SysScanDesc sysscan)
{
	if (sysscan->slot)
	{
		ExecDropSingleTupleTableSlot(sysscan->slot);
		sysscan->slot = NULL;
	}

	Assert(sysscan->irel);
	index_endscan(sysscan->iscan);
	if (sysscan->snapshot)
		UnregisterSnapshot(sysscan->snapshot);
	pfree(sysscan);
}
