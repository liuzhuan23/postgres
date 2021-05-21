/*-------------------------------------------------------------------------
 *
 * vacuumblk.h
 *	  header file for postgres block level vacuum routines
 *
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/commands/vacuumblk.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef VACUUMBLK_H
#define VACUUMBLK_H

#include "catalog/index.h"
#include "commands/vacuum.h"
#include "storage/buf.h"

extern void lazy_space_alloc(LVRelState *vacrel, int nworkers,
							 BlockNumber nblocks);
extern IndexBulkDeleteResult *lazy_vacuum_one_index(Relation indrel,
													IndexBulkDeleteResult *istat,
													double reltuples,
													LVRelState *vacrel);
extern void lazy_cleanup_all_indexes(LVRelState *vacrel);
extern IndexBulkDeleteResult *lazy_cleanup_one_index(Relation indrel,
													 IndexBulkDeleteResult *istat,
													 double reltuples,
													 bool estimated_count,
													 LVRelState *vacrel);
extern bool should_attempt_truncation(LVRelState *vacrel, VacuumParams *params);
extern void lazy_truncate_heap(LVRelState *vacrel);
extern void lazy_record_dead_tuple(LVDeadTuples *dead_tuples, ItemPointer itemptr);
extern void do_parallel_vacuum_or_cleanup(LVRelState *vacrel, int nworkers);
extern void update_vacuum_error_info(LVRelState *vacrel,
									 LVSavedErrInfo *saved_vacrel,
									 int phase, BlockNumber blkno,
									 OffsetNumber offnum);
extern void restore_vacuum_error_info(LVRelState *vacrel,
									  const LVSavedErrInfo *saved_vacrel);
extern void vacuum_error_callback(void *arg);

#endif							/* VACUUMBLK_H */
