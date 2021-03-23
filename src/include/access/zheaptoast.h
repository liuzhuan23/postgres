/*-------------------------------------------------------------------------
 *
 * zheaptoast.h
 *	  Heap-specific definitions for external and compressed storage
 *	  of variable size attributes.
 *
 * TODO Consider moving some definitions to a header file (tuptoaster.h)
 * included by this as well as heaptoast.h.
 *
 * Copyright (c) 2000-2021, PostgreSQL Global Development Group
 *
 * src/include/access/zheaptoast.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef HEAPTOAST_H
#define HEAPTOAST_H

#include "access/zhtup.h"
#include "storage/lockdefs.h"
#include "utils/relcache.h"

/*
 * Find the maximum size of a tuple if there are to be N tuples per page.
 */
#define MaximumBytesPerTuple(tuplesPerPage) \
	MAXALIGN_DOWN((BLCKSZ - \
				   MAXALIGN(SizeOfPageHeaderData + (tuplesPerPage) * sizeof(ItemIdData))) \
				  / (tuplesPerPage))

/*
 * These symbols control toaster activation.  If a tuple is larger than
 * TOAST_TUPLE_THRESHOLD, we will try to toast it down to no more than
 * TOAST_TUPLE_TARGET bytes through compressing compressible fields and
 * moving EXTENDED and EXTERNAL data out-of-line.
 *
 * The numbers need not be the same, though they currently are.  It doesn't
 * make sense for TARGET to exceed THRESHOLD, but it could be useful to make
 * it be smaller.
 *
 * Currently we choose both values to match the largest tuple size for which
 * TOAST_TUPLES_PER_PAGE tuples can fit on a heap page.
 *
 * XXX while these can be modified without initdb, some thought needs to be
 * given to needs_toast_table() in toasting.c before unleashing random
 * changes.  Also see LOBLKSIZE in large_object.h, which can *not* be
 * changed without initdb.
 */
#define TOAST_TUPLES_PER_PAGE	4

#define TOAST_TUPLE_THRESHOLD	MaximumBytesPerTuple(TOAST_TUPLES_PER_PAGE)

#define TOAST_TUPLE_TARGET		TOAST_TUPLE_THRESHOLD

/*
 * The code will also consider moving MAIN data out-of-line, but only as a
 * last resort if the previous steps haven't reached the target tuple size.
 * In this phase we use a different target size, currently equal to the
 * largest tuple that will fit on a heap page.  This is reasonable since
 * the user has told us to keep the data in-line if at all possible.
 */
#define TOAST_TUPLES_PER_PAGE_MAIN	1

#define TOAST_TUPLE_TARGET_MAIN MaximumBytesPerTuple(TOAST_TUPLES_PER_PAGE_MAIN)

/*
 * If an index value is larger than TOAST_INDEX_TARGET, we will try to
 * compress it (we can't move it out-of-line, however).  Note that this
 * number is per-datum, not per-tuple, for simplicity in index_form_tuple().
 */
#define TOAST_INDEX_TARGET		(MaxHeapTupleSize / 16)

/* ----------
 * heap_toast_insert_or_update -
 *
 *	Called by heap_insert() and heap_update().
 * ----------
 */
extern ZHeapTuple zheap_toast_insert_or_update(Relation rel, ZHeapTuple newtup,
											   ZHeapTuple oldtup, int options);

/* ----------
 * heap_toast_delete -
 *
 *	Called by heap_delete().
 * ----------
 */
extern void zheap_toast_delete(Relation rel, ZHeapTuple oldtup,
							   bool is_speculative);

/* ----------
 * heap_fetch_toast_slice
 *
 *	Fetch a slice from a toast value stored in a heap table.
 * ----------
 */
extern void zheap_fetch_toast_slice(Relation toastrel, Oid valueid,
									int32 attrsize, int32 sliceoffset,
									int32 slicelength, struct varlena *result);

#endif							/* HEAPTOAST_H */
