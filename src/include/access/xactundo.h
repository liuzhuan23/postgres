/*-------------------------------------------------------------------------
 *
 * xactundo.h
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/xactundo.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef XACTUNDO_H
#define XACTUNDO_H

#include "access/twophase.h"
#include "access/undodefs.h"
#include "access/xlogdefs.h"
#include "common/zheapam_undo.h"
#include "datatype/timestamp.h"
#include "lib/stringinfo.h"
#include "storage/buf.h"

typedef struct XactUndoContext
{
	UndoPersistenceLevel plevel;
	StringInfoData data;
} XactUndoContext;

extern Size GetUndoDataSize(UndoRecData *rdata);
extern void SerializeUndoData(StringInfo buf, RmgrId rmid,
							  uint8 rec_type, UndoRecData *rdata);
extern void ResetXactUndo(void);
extern bool XactHasUndo(void);
extern UndoRecPtr PrepareXactUndoData(XactUndoContext *ctx, char persistence,
									  Size record_size);
extern void InsertXactUndoData(XactUndoContext *ctx, int first_block_id);
extern void RegisterXactUndoBuffers(XactUndoContext *ctx,
									uint8 first_block_id);
extern void SetXactUndoPageLSNs(XactUndoContext *ctx, XLogRecPtr lsn);
extern void CleanupXactUndoInsertion(XactUndoContext *ctx);

/* undo re-insertion during recovery */
extern UndoRecPtr XactUndoReplay(XLogReaderState *xlog_record, RmgrId rmid,
								 uint8 rec_type, void *rec_data,
								 size_t rec_size);

/* undo execution */
extern void PerformUndoActionsRange(UndoRecPtr begin, UndoRecPtr end,
									char relpersistence, int nestingLevel);
extern void PerformUndoActions(int nestingLevel);
extern void PerformBackgroundUndo(UndoRecPtr begin, UndoRecPtr end,
								  UndoPersistenceLevel plevel);

/* transaction integration */
extern void AtCommit_XactUndo(void);
extern void AtAbort_XactUndo(void);
extern void AtSubCommit_XactUndo(int level);
extern void AtSubAbort_XactUndo(int level, bool cleanup_only);
extern void AtPrepare_XactUndo(GlobalTransaction);
extern void PostPrepare_XactUndo(void);
extern void AtProcExit_XactUndo(void);
extern bool GetCurrentUndoRange(UndoRecPtr * begin, UndoRecPtr * end,
								UndoPersistenceLevel plevel);

#endif
