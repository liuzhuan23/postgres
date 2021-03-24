/*-------------------------------------------------------------------------
 *
 * zheapamdesc.c
 *	  rmgr descriptor routines for access/zheap/zheapamxlog.c
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/rmgrdesc/zheapamdesc.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/zheapam_xlog.h"
#include "common/zheapam_undo.h"

void
zheap_desc(StringInfo buf, XLogReaderState *record)
{
	char	   *rec = XLogRecGetData(record);
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	info &= XLOG_ZHEAP_OPMASK;
	if (info == XLOG_ZHEAP_CLEAN)
	{
		xl_zheap_clean *xlrec = (xl_zheap_clean *) rec;

		appendStringInfo(buf, "remxid %u", xlrec->latestRemovedXid);
	}
	else if (info == XLOG_ZHEAP_INSERT)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_insert *xlrec = (xl_zheap_insert *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "off %u, blkprev %lu", xlrec->offnum, xlundohdr->blkprev);
	}
	else if (info == XLOG_ZHEAP_MULTI_INSERT)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_multi_insert *xlrec = (xl_zheap_multi_insert *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "%d tuples", xlrec->ntuples);
	}
	else if (info == XLOG_ZHEAP_DELETE)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_delete *xlrec = (xl_zheap_delete *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "off %u, trans_slot %u, hasUndoTuple: %c, blkprev %lu",
						 xlrec->offnum, xlrec->trans_slot_id,
						 (xlrec->flags & XLZ_HAS_DELETE_UNDOTUPLE) ? 'T' : 'F',
						 xlundohdr->blkprev);
	}
	else if (info == XLOG_ZHEAP_UPDATE)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_update *xlrec = (xl_zheap_update *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "oldoff %u, trans_slot %u, hasUndoTuple: %c, newoff: %u, blkprev %lu",
						 xlrec->old_offnum, xlrec->old_trans_slot_id,
						 (xlrec->flags & XLZ_HAS_UPDATE_UNDOTUPLE) ? 'T' : 'F',
						 xlrec->new_offnum,
						 xlundohdr->blkprev);
	}
	else if (info == XLOG_ZHEAP_FREEZE_XACT_SLOT)
	{
		xl_zheap_freeze_xact_slot *xlrec = (xl_zheap_freeze_xact_slot *) rec;

		appendStringInfo(buf, "latest frozen xid %u nfrozen %u",
						 xlrec->lastestFrozenXid, xlrec->nFrozen);
	}
	else if (info == XLOG_ZHEAP_INVALID_XACT_SLOT)
	{
		uint16		nCompletedSlots = *(uint16 *) rec;

		appendStringInfo(buf, "completed_slots %u", nCompletedSlots);
	}
	else if (info == XLOG_ZHEAP_LOCK)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_lock *xlrec = (xl_zheap_lock *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "off %u, xid %u, trans_slot_id %u",
						 xlrec->offnum, xlrec->prev_xid, xlrec->trans_slot_id);
	}
}

void
zheap2_desc(StringInfo buf, XLogReaderState *record)
{
	char	   *rec = XLogRecGetData(record);
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	info &= XLOG_ZHEAP_OPMASK;
	if (info == XLOG_ZHEAP_CONFIRM)
	{
		xl_zheap_confirm *xlrec = (xl_zheap_confirm *) rec;

		appendStringInfo(buf, "off %u: flags %u", xlrec->offnum, xlrec->flags);
	}
	else if (info == XLOG_ZHEAP_UNUSED)
	{
		xl_undo_header *xlundohdr = (xl_undo_header *) rec;
		xl_zheap_unused *xlrec = (xl_zheap_unused *) ((char *) xlundohdr + SizeOfUndoHeader);

		appendStringInfo(buf, "remxid %u, trans_slot_id %u, blkprev %lu",
						 xlrec->latestRemovedXid, xlrec->trans_slot_id,
						 xlundohdr->blkprev);
	}
	else if (info == XLOG_ZHEAP_VISIBLE)
	{
		xl_zheap_visible *xlrec = (xl_zheap_visible *) rec;

		appendStringInfo(buf, "cutoff xid %u flags %d",
						 xlrec->cutoff_xid, xlrec->flags);
	}
}

void
zundo_desc(StringInfo buf, XLogReaderState *record)
{
	char	   *rec = XLogRecGetData(record);
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;

	if (info == XLOG_ZUNDO_PAGE)
	{
		uint8	   *flags = (uint8 *) rec;

		appendStringInfo(buf, "page_contains_tpd_slot: %c ",
						 (*flags & XLU_PAGE_CONTAINS_TPD_SLOT) ? 'T' : 'F');
		appendStringInfo(buf, "is_page_initialized: %c ",
						 (*flags & XLU_INIT_PAGE) ? 'T' : 'F');
		if (*flags & XLU_PAGE_CONTAINS_TPD_SLOT)
		{
			xl_zundo_page *xlrec =
			(xl_zundo_page *) ((char *) flags + sizeof(uint8));

			appendStringInfo(buf, "urec_ptr %lu xid %u trans_slot_id %u",
							 xlrec->urec_ptr,
							 XidFromFullTransactionId(xlrec->fxid),
							 xlrec->trans_slot_id);
		}
	}
	else if (info == XLOG_ZUNDO_RESET_SLOT)
	{
		xl_zundo_reset_slot *xlrec = (xl_zundo_reset_slot *) rec;

		appendStringInfo(buf, "urec_ptr %lu trans_slot_id %u",
						 xlrec->urec_ptr, xlrec->trans_slot_id);
	}
}

const char *
zheap_identify(uint8 info)
{
	const char *id = NULL;

	switch (info & ~XLR_INFO_MASK)
	{
		case XLOG_ZHEAP_CLEAN:
			id = "CLEAN";
			break;
		case XLOG_ZHEAP_INSERT:
			id = "INSERT";
			break;
		case XLOG_ZHEAP_INSERT | XLOG_ZHEAP_INIT_PAGE:
			id = "INSERT+INIT";
			break;
		case XLOG_ZHEAP_DELETE:
			id = "DELETE";
			break;
		case XLOG_ZHEAP_UPDATE:
			id = "UPDATE";
			break;
		case XLOG_ZHEAP_UPDATE | XLOG_ZHEAP_INIT_PAGE:
			id = "UPDATE+INIT";
			break;
		case XLOG_ZHEAP_FREEZE_XACT_SLOT:
			id = "FREEZE_XACT_SLOT";
			break;
		case XLOG_ZHEAP_INVALID_XACT_SLOT:
			id = "INVALID_XACT_SLOT";
			break;
		case XLOG_ZHEAP_LOCK:
			id = "LOCK";
			break;
		case XLOG_ZHEAP_MULTI_INSERT:
			id = "MULTI_INSERT";
			break;
		case XLOG_ZHEAP_MULTI_INSERT | XLOG_ZHEAP_INIT_PAGE:
			id = "MULTI_INSERT+INIT";
			break;
	}

	return id;
}

const char *
zheap2_identify(uint8 info)
{
	const char *id = NULL;

	switch (info & ~XLR_INFO_MASK)
	{
		case XLOG_ZHEAP_CONFIRM:
			id = "CONFIRM";
			break;
		case XLOG_ZHEAP_UNUSED:
			id = "UNUSED";
			break;
		case XLOG_ZHEAP_VISIBLE:
			id = "VISIBLE";
			break;
	}

	return id;
}

const char *
zundo_identify(uint8 info)
{
	const char *id = NULL;

	switch (info & ~XLR_INFO_MASK)
	{
		case XLOG_ZUNDO_PAGE:
			id = "UNDO PAGE";
			break;
		case XLOG_ZUNDO_RESET_SLOT:
			id = "UNDO RESET SLOT";
			break;
	}

	return id;
}

/*
 * Append the uur_blkprev value to the message. Log number is only written if
 * the value points to a log other than the current one.
 */
static void
append_blkprev(StringInfo buf, UndoRecPtr blk_prev, UndoRecPtr blk_cur)
{
	appendStringInfo(buf, " uur_blkprev ");
	if (UndoRecPtrGetLogNo(blk_prev) != UndoRecPtrGetLogNo(blk_cur))
		appendStringInfo(buf, "%06X.", (UndoLogNumber) UndoRecPtrGetLogNo(blk_prev));
	appendStringInfo(buf, "%010zX", UndoRecPtrGetOffset(blk_prev));
}

/* TODO Print some info of the tuple headers where possible. */
void
zheap_undo_desc(StringInfo buf, const WrittenUndoNode *record)
{
	uint8	type;

	Assert(record->n.rmid == RM_ZHEAP_ID);

	type = record->n.type;
	if (type == UNDO_ZHEAP_INSERT)
	{
		UnpackedUndoRecord	uur;

		UnpackZHeapUndoRecord(record->n.data, true, false, &uur);
		appendStringInfo(buf,
						 "INSERT reloid %u, blk %u, off %u, cid %u,",
						 uur.uur_reloid, uur.uur_block, uur.uur_offset,
						 uur.uur_cid);
		append_blkprev(buf, uur.uur_blkprev, record->location);
	}
	else if (type == UNDO_ZHEAP_MULTI_INSERT)
	{
		UnpackedUndoRecord	uur;
		int		nranges;

		UnpackZHeapUndoRecord(record->n.data, false, false, &uur);

		Assert(uur.uur_payload.len > sizeof(int));
		memcpy(&nranges, uur.uur_payload.data, sizeof(int));

		appendStringInfo(buf,
						 "MULTI_INSERT reloid %u, blk %u, cid %u,",
						 uur.uur_reloid, uur.uur_block, uur.uur_cid);
		append_blkprev(buf, uur.uur_blkprev, record->location);
		appendStringInfo(buf, ", nranges %d", nranges);
	}
	else if (type == UNDO_ZHEAP_DELETE)
	{
		UnpackedUndoRecord	uur;

		UnpackZHeapUndoRecord(record->n.data, false, false, &uur);
		appendStringInfo(buf,
						 "DELETE reloid %u, blk %u, off %u, cid %u, prevxid %u,",
						 uur.uur_reloid, uur.uur_block, uur.uur_offset,
						 uur.uur_cid, uur.uur_prevxid);
		append_blkprev(buf, uur.uur_blkprev, record->location);
	}
	else if (type == UNDO_ZHEAP_INPLACE_UPDATE)
	{
		UnpackedUndoRecord	uur;

		UnpackZHeapUndoRecord(record->n.data, false, false, &uur);
		appendStringInfo(buf,
						 "INPLACE_UPDATE reloid %u, blk %u, off %u, cid %u, prevxid %u,",
						 uur.uur_reloid, uur.uur_block, uur.uur_offset,
						 uur.uur_cid, uur.uur_prevxid);
		append_blkprev(buf, uur.uur_blkprev, record->location);
	}
	else if (type == UNDO_ZHEAP_UPDATE)
	{
		UnpackedUndoRecord	uur;

		UnpackZHeapUndoRecord(record->n.data, false, false, &uur);
		appendStringInfo(buf, "UPDATE reloid %u, blk %u, off %u, cid %u, prevxid %u,",
						 uur.uur_reloid, uur.uur_block, uur.uur_offset,
						 uur.uur_cid, uur.uur_prevxid);
		append_blkprev(buf, uur.uur_blkprev, record->location);
	}
	else if (type == UNDO_ZHEAP_XID_LOCK_ONLY ||
			 type == UNDO_ZHEAP_XID_LOCK_FOR_UPDATE ||
			 type == UNDO_ZHEAP_XID_MULTI_LOCK_ONLY)
	{
		UnpackedUndoRecord	uur;
		const	char	*type_str;

		UnpackZHeapUndoRecord(record->n.data, false, false, &uur);
		switch (type)
		{
			case	UNDO_ZHEAP_XID_MULTI_LOCK_ONLY:
				type_str = "MULTI_LOCK_ONLY";
				break;
			case	UNDO_ZHEAP_XID_LOCK_FOR_UPDATE:
				type_str = "LOCK_FOR_UPDATE";
				break;
			case	UNDO_ZHEAP_XID_LOCK_ONLY:
				type_str = "LOCK_ONLY";
				break;

			default:
				Assert(false);
		}

		appendStringInfo(buf, "LOCK type %s, reloid %u, blk %u, off %u, cid %u, prevxid %u,",
						 type_str, uur.uur_reloid, uur.uur_block, uur.uur_offset,
						 uur.uur_cid, uur.uur_prevxid);
		append_blkprev(buf, uur.uur_blkprev, record->location);
	}
	else if (type == UNDO_ZHEAP_ITEMID_UNUSED)
	{
		UnpackedUndoRecord	uur;

		UnpackZHeapUndoRecord(record->n.data, false, false, &uur);
		appendStringInfo(buf, "ITEMID_UNUSED reloid %u, blk %u, off %u, cid %u, prevxid %u,",
						 uur.uur_reloid, uur.uur_block, uur.uur_offset,
						 uur.uur_cid, uur.uur_prevxid);
		append_blkprev(buf, uur.uur_blkprev, record->location);
	}
	else
		Assert(false);
}
