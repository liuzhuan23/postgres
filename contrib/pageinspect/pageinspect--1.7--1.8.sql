/* contrib/pageinspect/pageinspect--1.7--1.8.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pageinspect UPDATE TO '1.8'" to load this file. \quit

--
-- heap_tuple_infomask_flags()
--
CREATE FUNCTION heap_tuple_infomask_flags(
       t_infomask integer,
       t_infomask2 integer,
       raw_flags OUT text[],
       combined_flags OUT text[])
RETURNS record
AS 'MODULE_PATHNAME', 'heap_tuple_infomask_flags'
LANGUAGE C STRICT PARALLEL SAFE;

--
-- get_undo_raw_page()
--
CREATE FUNCTION get_undo_raw_page(int4, int4)
RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT PARALLEL SAFE;

--
-- undo_page_header()
--
CREATE FUNCTION undo_page_header(IN page bytea,
    OUT lsn pg_lsn,
    OUT checksum smallint,
    OUT insertion_point smallint,
    OUT first_record smallint,
    OUT first_chunk smallint,
    OUT continue_chunk text,
    OUT continue_chunk_type smallint)
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT PARALLEL SAFE;
