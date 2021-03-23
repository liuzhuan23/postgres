/*-------------------------------------------------------------------------
 *
 * zheap_undo_record.c
 *	  Functions to construct and deconstruct an undo record for the zheap AM
 *
 * src/common/zheap_undo_record.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/undoread.h"
#include "common/relpath.h"
#include "common/zheapam_undo.h"

/* Workspace for PrepareZHeapUndoRecord and UnpackZHeapUndoRecord. */
static UndoRecordHeader work_hdr;
static UndoRecordRelationDetails work_rd;
static UndoRecordBlock work_blk;
static UndoRecordPayload work_payload;
/*
 * One item per the variable above + three extra ones for the payload and for
 * the tuple plus a common header for these, see PrepareZHeapUndoRecord().
 */
static UndoRecData	work_chain[6];

/*
 * Turn UnpackedUndoRecord into a chain of UndoRecData structures.
 *
 * The output chain can reference some fields of the unpacked record, so
 * caller should not free anything of it until the record is inserted. Also
 * note that the result is only valid until the next call of the function.
 */
UndoRecData *
PrepareZHeapUndoRecord(UnpackedUndoRecord *uur)
{
	UndoRecData	*rdt_cur = &work_chain[0];
	UndoRecData *rdt_last = rdt_cur;

	/*
	 * Set uur_info for an UnpackedUndoRecord appropriately based on which
	 * other fields are set.
	 */
	/*
	 * A.H. Uncomment this if we can update individual fields w/o
	 * reconstructing the whole chain. For this, the function should have a
	 * boolean argument telling whether a new record is being constructed or
	 * an existing is updated.
	 */
	//Assert(uur->uur_info == 0);

	if (uur->uur_fork != MAIN_FORKNUM)
		uur->uur_info |= UREC_INFO_RELATION_DETAILS;
	if (uur->uur_block != InvalidBlockNumber)
		uur->uur_info |= UREC_INFO_BLOCK;
	if (uur->uur_payload.len || uur->uur_tuple.len)
		uur->uur_info |= UREC_INFO_PAYLOAD;

	/*
	 * Copy the UnpackedUndoRecord into the temporary variables of the types
	 * that will actually be stored in the undo pages.
	 */
	work_hdr.urec_info = uur->uur_info;
	work_hdr.urec_reloid = uur->uur_reloid;
	work_hdr.urec_prevxid = uur->uur_prevxid;
	work_hdr.urec_xid = uur->uur_xid;
	work_hdr.urec_cid = uur->uur_cid;

	/* Add the header to the chain; */
	rdt_cur->data = (char *) &work_hdr;
	rdt_cur->len = SizeOfUndoRecordHeader;

	/* Process the optional fields and add them to the chain too. */
	if (uur->uur_fork != MAIN_FORKNUM)
	{
		work_rd.urec_fork = uur->uur_fork;

		rdt_cur++;
		rdt_cur->data = (char *) &work_rd;
		rdt_cur->len = SizeOfUndoRecordRelationDetails;
		rdt_last->next = rdt_cur;
		rdt_last = rdt_cur;
	}

	if (uur->uur_block != InvalidBlockNumber)
	{
		work_blk.urec_blkprev = uur->uur_blkprev;
		work_blk.urec_block = uur->uur_block;
		work_blk.urec_offset = uur->uur_offset;

		rdt_cur++;
		rdt_cur->data = (char *) &work_blk;
		rdt_cur->len = SizeOfUndoRecordBlock;
		rdt_last->next = rdt_cur;
		rdt_last = rdt_cur;
	}

	if (uur->uur_payload.len || uur->uur_tuple.len)
	{
		work_payload.urec_payload_len = uur->uur_payload.len;
		work_payload.urec_tuple_len = uur->uur_tuple.len;

		rdt_cur++;
		rdt_cur->data = (char *) &work_payload;
		rdt_cur->len = SizeOfUndoRecordPayload;
		rdt_last->next = rdt_cur;
		rdt_last = rdt_cur;

		if (uur->uur_payload.len > 0)
		{
			rdt_cur++;
			rdt_cur->data = (char *) uur->uur_payload.data;
			rdt_cur->len = uur->uur_payload.len;
			rdt_last->next = rdt_cur;
			rdt_last = rdt_cur;
		}

		if (uur->uur_tuple.len > 0)
		{
			rdt_cur++;
			rdt_cur->data = (char *) uur->uur_tuple.data;
			rdt_cur->len = uur->uur_tuple.len;
			rdt_last->next = rdt_cur;
			rdt_last = rdt_cur;
		}
	}

	rdt_last->next = NULL;

	return &work_chain[0];
}

/*
 * UnpackZHeapUndoRecord()
 *
 * Read serialized undo record, pointed to by 'readptr', and convert it to the
 * unpacked form.
 *
 * If 'header_only' is true, skip processing of the payload as well as the
 * tuple.
 *
 * If 'copy' is true, allocate memory for payload and/or tuple, otherwise make
 * them point to inside the input chunk.
 *
 * Note that, even if 'header_only' is false, neither payload nor tuple data
 * is copied, so caller needs to ensure that the data is processed before the
 * next record is read.
 */
void
UnpackZHeapUndoRecord(char *readptr, bool header_only, bool copy,
					  UnpackedUndoRecord *uur)
{
	/* Read the header. */
	memcpy(&work_hdr, readptr, SizeOfUndoRecordHeader);
	readptr += SizeOfUndoRecordHeader;

	uur->uur_info = work_hdr.urec_info;
	uur->uur_reloid = work_hdr.urec_reloid;
	uur->uur_prevxid = work_hdr.urec_prevxid;
	uur->uur_xid = work_hdr.urec_xid;
	uur->uur_cid = work_hdr.urec_cid;

	/* Read and process the optional parts. */
	if ((uur->uur_info & UREC_INFO_RELATION_DETAILS) != 0)
	{
		memcpy(&work_rd, readptr, SizeOfUndoRecordRelationDetails);
		readptr += SizeOfUndoRecordRelationDetails;

		uur->uur_fork = work_rd.urec_fork;
	}

	if ((uur->uur_info & UREC_INFO_BLOCK) != 0)
	{
		memcpy(&work_blk, readptr, SizeOfUndoRecordBlock);
		readptr += SizeOfUndoRecordBlock;

		uur->uur_blkprev = work_blk.urec_blkprev;
		uur->uur_block = work_blk.urec_block;
		uur->uur_offset = work_blk.urec_offset;
	}

	if (header_only)
		return;

	/* Read and process the payload information if needed. */
	if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		memcpy(&work_payload, readptr, SizeOfUndoRecordPayload);
		readptr += SizeOfUndoRecordPayload;

		uur->uur_payload.len = work_payload.urec_payload_len;
		uur->uur_tuple.len = work_payload.urec_tuple_len;

		if (uur->uur_payload.len > 0)
		{
			if (copy)
			{
				uur->uur_payload.data = (char *) palloc(uur->uur_payload.len);
				memcpy(uur->uur_payload.data, readptr, uur->uur_payload.len);
			}
			else
				uur->uur_payload.data = readptr;

			readptr += uur->uur_payload.len;
		}

		if (uur->uur_tuple.len > 0)
		{
			if (copy)
			{
				uur->uur_tuple.data = (char *) palloc(uur->uur_tuple.len);
				memcpy(uur->uur_tuple.data, readptr, uur->uur_tuple.len);
			}
			else
				uur->uur_tuple.data = readptr;
		}
	}

	uur->data_copy = copy;
}

/*
 * Compute size of the Unpacked undo record in memory
 */
Size
UnpackedUndoRecordSize(UnpackedUndoRecord *uur)
{
	Size		size;

	size = sizeof(UnpackedUndoRecord);

	/* Add payload size if record contains payload data. */
	if ((uur->uur_info & UREC_INFO_PAYLOAD) != 0)
	{
		size += uur->uur_payload.len;
		size += uur->uur_tuple.len;
	}

	return size;
}

/*
 * Release the resources allocated by UndoFetchRecord.
 *
 * XXX Rename to UndoRecordFree() ?
 */
void
UndoRecordRelease(UnpackedUndoRecord *urec)
{
	if (urec->data_copy)
	{
		if (urec->uur_payload.data)
			pfree(urec->uur_payload.data);
		if (urec->uur_tuple.data)
			pfree(urec->uur_tuple.data);
	}

	pfree(urec);
}

/*
 * ResetUndoRecord - Helper function for UndoFetchRecord to reset the current
 * record.
 */
void
ResetUndoRecord(UnpackedUndoRecord *urec)
{
	if (urec->data_copy)
	{
		if (urec->uur_payload.data)
			pfree(urec->uur_payload.data);
		if (urec->uur_tuple.data)
			pfree(urec->uur_tuple.data);
	}

	/* Reset the urec before fetching the tuple */
	urec->uur_tuple.data = NULL;
	urec->uur_tuple.len = 0;
	urec->uur_payload.data = NULL;
	urec->uur_payload.len = 0;
}
