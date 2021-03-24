/*-------------------------------------------------------------------------
 *
 * toast_internals.h
 *	  Internal definitions for the TOAST system.
 *
 * Copyright (c) 2000-2021, PostgreSQL Global Development Group
 *
 * src/include/access/toast_internals.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TOAST_INTERNALS_H
#define TOAST_INTERNALS_H

#include "access/toast_compression.h"
#include "storage/lockdefs.h"
#include "utils/relcache.h"
#include "utils/snapshot.h"

/*
 *	The information at the start of the compressed toast data.
 */
typedef struct toast_compress_header
{
	int32		vl_len_;		/* varlena header (do not touch directly!) */
	uint32		tcinfo;			/* 2 bits for compression method and 30 bits
								 * external size; see va_extinfo */
} toast_compress_header;

/*
 * Utilities for manipulation of header information for compressed
 * toast entries.
 */
#define TOAST_COMPRESS_HDRSZ		((int32) sizeof(toast_compress_header))
#define TOAST_COMPRESS_RAWSIZE(ptr) (((toast_compress_header *) (ptr))->rawsize)
#define TOAST_COMPRESS_SIZE(ptr)	((int32) VARSIZE_ANY(ptr) - TOAST_COMPRESS_HDRSZ)
#define TOAST_COMPRESS_RAWDATA(ptr) \
	(((char *) (ptr)) + TOAST_COMPRESS_HDRSZ)
#define TOAST_COMPRESS_SET_RAWSIZE(ptr, len) \
	(((toast_compress_header *) (ptr))->rawsize = (len))

/*
 * Find the maximum size of a tuple if there are to be N tuples per page.
 */
#define MaximumBytesPerTuple(tuplesPerPage) \
	MAXALIGN_DOWN((BLCKSZ - \
				   MAXALIGN(SizeOfPageHeaderData + (tuplesPerPage) * sizeof(ItemIdData))) \
				  / (tuplesPerPage))

/*
 * When we store an oversize datum externally, we divide it into chunks
 * containing at most TOAST_MAX_CHUNK_SIZE data bytes.  This number *must*
 * be small enough that the completed toast-table tuple (including the
 * ID and sequence fields and all overhead) will fit on a page.
 * The coding here sets the size on the theory that we want to fit
 * EXTERN_TUPLES_PER_PAGE tuples of maximum size onto a page.
 *
 * XXX TOAST_MAX_CHUNK_SIZE is derived from HeapTupleHeader, however we use
 * the same for the zheap AM. Is it worth introducing separate constants and
 * make the common TOAST code (toast_internals.c) distinguish?
 *
 * NB: Changing TOAST_MAX_CHUNK_SIZE requires an initdb.
 */
#define EXTERN_TUPLES_PER_PAGE	4	/* tweak only this */

#define EXTERN_TUPLE_MAX_SIZE	MaximumBytesPerTuple(EXTERN_TUPLES_PER_PAGE)

#define TOAST_MAX_CHUNK_SIZE	\
	(EXTERN_TUPLE_MAX_SIZE -							\
	 MAXALIGN(SizeofHeapTupleHeader) -					\
	 sizeof(Oid) -										\
	 sizeof(int32) -									\
	 VARHDRSZ)

#define TOAST_COMPRESS_EXTSIZE(ptr) \
	(((toast_compress_header *) (ptr))->tcinfo & VARLENA_EXTSIZE_MASK)
#define TOAST_COMPRESS_METHOD(ptr) \
	(((toast_compress_header *) (ptr))->tcinfo >> VARLENA_EXTSIZE_BITS)

#define TOAST_COMPRESS_SET_SIZE_AND_COMPRESS_METHOD(ptr, len, cm_method) \
	do { \
		Assert((len) > 0 && (len) <= VARLENA_EXTSIZE_MASK); \
		Assert((cm_method) == TOAST_PGLZ_COMPRESSION_ID || \
			   (cm_method) == TOAST_LZ4_COMPRESSION_ID); \
		((toast_compress_header *) (ptr))->tcinfo = \
			(len) | ((uint32) (cm_method) << VARLENA_EXTSIZE_BITS); \
	} while (0)

extern Datum toast_compress_datum(Datum value, char cmethod);
extern Oid	toast_get_valid_index(Oid toastoid, LOCKMODE lock);

extern void toast_delete_datum(Relation rel, Datum value, bool is_speculative);
extern Datum toast_save_datum(Relation rel, Datum value,
							  struct varlena *oldexternal, int options);

extern int	toast_open_indexes(Relation toastrel,
							   LOCKMODE lock,
							   Relation **toastidxs,
							   int *num_indexes);
extern void toast_close_indexes(Relation *toastidxs, int num_indexes,
								LOCKMODE lock);
extern void init_toast_snapshot(Snapshot toast_snapshot);

#endif							/* TOAST_INTERNALS_H */
