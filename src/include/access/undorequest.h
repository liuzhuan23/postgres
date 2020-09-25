/*-------------------------------------------------------------------------
 *
 * undorequest.h
 *		Undo request manager.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/undorequest.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef UNDOREQUEST_H
#define UNDOREQUEST_H

#ifndef FRONTEND
#include "access/htup.h"
#include "access/tupdesc.h"
#include "datatype/timestamp.h"
#include "storage/lwlock.h"
#endif

#include "access/transam.h"
#include "access/undodefs.h"

/*
 * FREE means that the UndoRequest object is not in use. It is available
 * to be allocated.
 *
 * ALLOCATED means that the UndoRequest object has been allocated but the
 * contents may not be valid yet (except for status, fxid, and dbid). It is
 * used for transactions that are still in progress.
 *
 * READY means that the UndoRequest object has valid contents but is not
 * eligible to be processed. It is used for prepared transactions, because
 * we don't know whether or not we'll actually need to process the undo
 * until they either commit or are rolled back.
 *
 * WAITING means that the UndoRequest object needs to be processed but is
 * not yet being processed. It is only used for transacions that have
 * aborted (including abort prepared)
 *
 * IN_PROGRESS means that the UndoRequest object is currently being
 * processed. Like WAITING, the transaction must have aborted.
 */
typedef enum UndoRequestStatus
{
	UNDO_REQUEST_FREE,
	UNDO_REQUEST_ALLOCATED,
	UNDO_REQUEST_READY,
	UNDO_REQUEST_WAITING,
	UNDO_REQUEST_IN_PROGRESS
} UndoRequestStatus;

/*
 * An UndoRequestData object stores the information that we must have in order
 * to perform background undo for a transaction. It may be stored in memory or
 * serialized to disk.
 *
 * However, a request should never be serialized to disk if the status is
 * UNDO_REQUEST_FREE or UNDO_REQUEST_ALLOCATED. That's because a FREE request
 * object doesn't need to be saved, and an ALLOCATED request won't valid
 * contents. We don't have all of this information while the transaction is
 * still runnning.
 *
 * If the transaction commits, we need never collect all of these details and
 * can just free the UndoRequest; but if it aborts or is prepared, we need to
 * remember all of these details at that point.
 *
 * If the transaction is aborted by a crash, we need to reconstruct these
 * details after restarting.
 *
 * Note that we don't care about temporary undo, because it can never need
 * to be performed in the background. If the session dies without taking care
 * of permanent or unlogged undo, the associated undo actions still need to
 * be performed at some later point, but the same principle does not apply
 * to temporary undo. All temporary objects disappear with the session that
 * owned them, making the undo irrelevant.
 *
 * fxid should be InvalidTransactionId if and only if the status is set to
 * UNDO_REQUEST_FREE. It identifies the transaction to which this
 * UndoRequestData has been allocated.
 */
typedef struct UndoRequestData
{
	UndoRequestStatus	status;
	FullTransactionId fxid;
	Oid			dbid;
	Size		size;
	UndoRecPtr	start_location_logged;
	UndoRecPtr	end_location_logged;
	UndoRecPtr	start_location_unlogged;
	UndoRecPtr	end_location_unlogged;
} UndoRequestData;

#ifndef FRONTEND
/* Same as number of rows in the structure definition above. */
#define NUM_UNDO_REQUEST_DATA_COLUMNS 8

struct UndoRequestManager;
typedef struct UndoRequestData UndoRequestData;
typedef struct UndoRequestManager UndoRequestManager;

/* GUCs */
extern bool undo_force_foreground;

/* Initialization functions. */
extern Size EstimateUndoRequestManagerSize(unsigned capacity);
extern void InitializeUndoRequestManager(UndoRequestManager *urm,
										 LWLock *lock, unsigned capacity,
										 unsigned soft_limit);

/* Call this before inserting undo records. */
extern UndoRequest *RegisterUndoRequest(UndoRequestManager *urm,
										FullTransactionId fxid,
										Oid dbid);

/* Remember undo size and end locations. */
extern void FinalizeUndoRequest(UndoRequestManager *urm,
								UndoRequest *req,
								Size size,
								UndoRecPtr start_location_logged,
								UndoRecPtr start_location_unlogged,
								UndoRecPtr end_location_logged,
								UndoRecPtr end_location_unlogged,
								bool mark_as_ready);

/* Forget about an UndoRequest we don't need any more. */
extern void UnregisterUndoRequest(UndoRequestManager *urm, UndoRequest *req);

/* Attempt to dispatch UndoRequest for background processing. */
extern bool PerformUndoInBackground(UndoRequestManager *urm, UndoRequest *req,
									bool force);

/* Check how long a worker would need to wait for an UndoRequest. */
extern long UndoRequestWaitTime(UndoRequestManager *urm, TimestampTz when);

/* Get work for background undo process. */
extern UndoRequest *GetNextUndoRequest(UndoRequestManager *urm, Oid dbid,
									   bool minimum_runtime_reached,
									   Oid *out_dbid, FullTransactionId *fxid,
									   UndoRecPtr *start_location_logged,
									   UndoRecPtr *end_location_logged,
									   UndoRecPtr *start_location_unlogged,
									   UndoRecPtr *end_location_unlogged);

/* Reschedule failed undo attempt. */
extern void RescheduleUndoRequest(UndoRequestManager *urm, UndoRequest *req);

/* Save and restore state. */
extern char *SerializeUndoRequestData(UndoRequestManager *urm, Size *nbytes);
extern void RestoreUndoRequestData(UndoRequestManager *urm, Size nbytes,
								   char *data);
extern UndoRequest *FindUndoRequestByFXID(UndoRequestManager *urm,
										  FullTransactionId fxid);

/* Introspection. */
extern unsigned SnapshotActiveUndoRequests(UndoRequestManager *,
										   UndoRequestData **);
extern bool UndoRequestExists(UndoRequestManager *urm, FullTransactionId fxid,
				  bool *is_failed_request);
extern bool UndoRequestIsInProgress(UndoRequest *req);
extern TupleDesc MakeUndoRequestDataTupleDesc(void);
extern HeapTuple MakeUndoRequestDataTuple(TupleDesc, UndoRequestData *,
										  unsigned index);

/* Get oldest registered FXID. */
extern FullTransactionId UndoRequestManagerOldestFXID(UndoRequestManager *urm);

extern void UndoRequestUpdateLastReplayed(UndoRequestManager *urm,
										  UndoRecPtr last_replayed);
#endif	/* FRONTEND */
#endif
