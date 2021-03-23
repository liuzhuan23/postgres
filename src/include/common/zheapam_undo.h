/*-------------------------------------------------------------------------
 *
 * zheapam_undo.h
 *	  undo support for the zheap AM
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/zheapam_undo.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ZUNDO_H
#define ZUNDO_H

#include "access/transam.h"
#include "access/undolog.h"
#include "common/zheapam_undo.h"
#include "lib/stringinfo.h"
#include "storage/block.h"
#include "storage/bufpage.h"
#include "storage/buf.h"
#include "storage/off.h"

typedef enum undorectype
{
	UNDO_ZHEAP_INSERT,
	UNDO_ZHEAP_MULTI_INSERT,
	UNDO_ZHEAP_DELETE,
	UNDO_ZHEAP_INPLACE_UPDATE,
	UNDO_ZHEAP_UPDATE,
	UNDO_ZHEAP_XID_LOCK_ONLY,
	UNDO_ZHEAP_XID_LOCK_FOR_UPDATE,
	UNDO_ZHEAP_XID_MULTI_LOCK_ONLY,
	UNDO_ZHEAP_ITEMID_UNUSED
} undorectype;

/*
 * Every undo record begins with an UndoRecordHeader structure, which is
 * followed by the additional structures indicated by the contents of
 * urec_info.  All structures are packed into the alignment without padding
 * bytes, and the undo record itself need not be aligned either, so care
 * must be taken when reading the header.
 */
typedef struct UndoRecordHeader
{
	uint8		urec_info;		/* flag bits */
	Oid			urec_reloid;	/* relation OID */

	/*
	 * Transaction id that has modified the tuple present in this undo record.
	 * If this is older than oldestXidWithEpochHavingUndo, then we can
	 * consider the tuple in this undo record as visible.
	 */
	TransactionId urec_prevxid;

	/*
	 * Transaction id that has modified the tuple for which this undo record
	 * is written.  We use this to skip the undo records.  See comments atop
	 * function UndoFetchRecord.
	 */
	TransactionId urec_xid;		/* Transaction id */
	CommandId	urec_cid;		/* command id */
} UndoRecordHeader;

#define SizeOfUndoRecordHeader	\
	(offsetof(UndoRecordHeader, urec_cid) + sizeof(CommandId))

/*
 * If UREC_INFO_RELATION_DETAILS is set, an UndoRecordRelationDetails structure
 * follows.
 *
 * If UREC_INFO_BLOCK is set, an UndoRecordBlock structure follows.
 *
 * If UREC_INFO_TRANSACTION is set, an UndoRecordTransaction structure
 * follows.
 *
 * If UREC_INFO_PAYLOAD is set, an UndoRecordPayload structure follows.
 *
 * When (as will often be the case) multiple structures are present, they
 * appear in the same order in which the constants are defined here.  That is,
 * UndoRecordRelationDetails appears first.
 */
#define UREC_INFO_RELATION_DETAILS			0x01
#define UREC_INFO_BLOCK						0x02
#define UREC_INFO_PAYLOAD					0x04
#define UREC_INFO_PAYLOAD_CONTAINS_SLOT		0x08
#define UREC_INFO_PAYLOAD_CONTAINS_SUBXACT	0x10
/*
 * Additional information about a relation to which this record pertains,
 * namely the fork number.  If the fork number is MAIN_FORKNUM, this structure
 * can (and should) be omitted.
 */
typedef struct UndoRecordRelationDetails
{
	ForkNumber	urec_fork;		/* fork number */
} UndoRecordRelationDetails;

#define SizeOfUndoRecordRelationDetails \
	(offsetof(UndoRecordRelationDetails, urec_fork) + sizeof(uint8))

/*
 * Identifying information for a block to which this record pertains, and
 * a pointer to the previous record for the same block.
 */
typedef struct UndoRecordBlock
{
	UndoRecPtr	urec_blkprev;	/* byte offset of previous undo for block */
	BlockNumber urec_block;		/* block number */
	OffsetNumber urec_offset;	/* offset number */
} UndoRecordBlock;

#define SizeOfUndoRecordBlock \
	(offsetof(UndoRecordBlock, urec_offset) + sizeof(OffsetNumber))

/*
 * Information about the amount of payload data and tuple data present
 * in this record.  The payload bytes immediately follow the structures
 * specified by flag bits in urec_info, and the tuple bytes follow the
 * payload bytes.
 */
typedef struct UndoRecordPayload
{
	uint16		urec_payload_len;	/* # of payload bytes */
	uint16		urec_tuple_len; /* # of tuple bytes */
} UndoRecordPayload;

#define SizeOfUndoRecordPayload \
	(offsetof(UndoRecordPayload, urec_tuple_len) + sizeof(uint16))

/*
 * PrepareXactUndoData() receives a chain of UndoRecData structs and turns it
 * int the actual record. This is the same concept that xloginsert.c uses to
 * construct the record out of XLogRecData items.
 */
typedef struct UndoRecData
{
	struct UndoRecData *next;	/* next struct in chain, or NULL */
	char	   *data;			/* start of rmgr data to include */
	Size		len;			/* length of rmgr data to include */
} UndoRecData;

/*
 * Information that can be used to create an undo record or that can be
 * extracted from one previously created.  The raw undo record format is
 * difficult to manage, so this structure provides a convenient intermediate
 * form that is easier for callers to manage.
 *
 * When creating an undo record from an UnpackedUndoRecord, caller should
 * set uur_info to 0.  It will be initialized by the first call to
 * UndoRecordSetInfo or InsertUndoRecord.  We do set it in
 * UndoRecordAllocate for transaction specific header information.
 *
 * When an undo record is decoded into an UnpackedUndoRecord, all fields
 * will be initialized, but those for which no information is available
 * will be set to invalid or default values, as appropriate.
 *
 * TODO Try to remove type (or initialize it during unpacking), xid, xidepoch
 * and maybe more.
 */
typedef struct UnpackedUndoRecord
{
	uint8		uur_type;		/* record type code */
	uint8		uur_info;		/* flag bits */
	Oid			uur_reloid;		/* relation OID */
	TransactionId uur_prevxid;	/* transaction id */
	TransactionId uur_xid;		/* transaction id */
	CommandId	uur_cid;		/* command id */
	ForkNumber	uur_fork;		/* fork number */
	UndoRecPtr	uur_blkprev;	/* byte offset of previous undo for block and
								 * XID*/
	BlockNumber uur_block;		/* block number */
	OffsetNumber uur_offset;	/* offset number */
	uint32		uur_xidepoch;	/* epoch of the inserting transaction. */

	StringInfoData uur_payload; /* payload bytes */
	StringInfoData uur_tuple;	/* tuple bytes */
	bool	data_copy;			/* do payload and tuple point to copies? */
} UnpackedUndoRecord;

extern UndoRecData *PrepareZHeapUndoRecord(UnpackedUndoRecord *uur);
extern void UnpackZHeapUndoRecord(char *readptr, bool header_only, bool copy,
								  UnpackedUndoRecord *uur);
extern Size UnpackedUndoRecordSize(UnpackedUndoRecord *uur);
extern void UndoRecordRelease(UnpackedUndoRecord *urec);
extern void ResetUndoRecord(UnpackedUndoRecord *urec);

extern void zheap_undo(const WrittenUndoNode *record, FullTransactionId fxid);
extern void zheap_undo_desc(StringInfo buf, const WrittenUndoNode *record);

/*
 * Typedef for callback function for UndoFetchRecord.
 *
 * This checks whether an undorecord satisfies the given conditions.
 */
typedef bool (*SatisfyUndoRecordCallback) (UnpackedUndoRecord *urec,
										   BlockNumber blkno,
										   OffsetNumber offset,
										   TransactionId xid);

extern UnpackedUndoRecord *UndoFetchRecord(UndoRecPtr urp, BlockNumber blkno,
										   OffsetNumber offset,
										   TransactionId xid,
										   UndoRecPtr *urec_ptr_out,
										   SatisfyUndoRecordCallback callback);
#endif							/* ZUNDO_H */
