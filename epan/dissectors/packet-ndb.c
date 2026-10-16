/* packet-ndb.c
 * Routines for the NDB protocol as the nodes of a RonDB cluster speak it:
 * the management protocol, the handshake that turns a socket into a
 * signal link, and the signals on such a link.
 *
 * The names of signals, blocks and fields are iClaustron's
 * (https://github.com/iClaustron/iclaustron); its protocol chapter quotes
 * what this dissector prints.
 *
 * Copyright 2026, Hopsworks and/or its affiliates.
 * Written by Mikael Ronström <mikael@logicalclocks.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * What a connection carries
 * -------------------------
 *
 * Every connection starts with text lines, each ending in a newline:
 *
 *   - to the management server (port 1186 by default): requests and
 *     replies, a command line, "name: value" lines and an empty line;
 *   - to a data node, on a port given out at run time: two short
 *     exchanges, first about encryption ("ndbd TLS disabled" and an
 *     empty line, or "ndbd" and "ndbd passwd"; answered "Cleartext ok"
 *     or "ok"), then the hello ("192 1 2 0": our node, the link type,
 *     the other node, the link number; answered "2 1").
 *
 * After its text, each direction of a signal link carries messages and
 * nothing else; a management connection becomes a signal link the same
 * way after a "transporter connect" request. The dissector reads text
 * lines while the bytes are printable and messages from the first byte
 * that is not.
 *
 * A message is a run of 32-bit words in the sender's byte order:
 *
 *   word 1   byte order (bits 0, 7, 24, 31), fragment state high bit (1),
 *            signal id present (2), compressed (3), checksum present (4),
 *            priority (5-6), total length in words (8-23), fragment state
 *            low bit (25), data length in words (26-30)
 *   word 2   signal number (0-15), its layout version (16-19), trace
 *            (20-25), number of sections (26-27)
 *   word 3   sender block (0-15), receiver block (16-31)
 *   [signal id], data (0-25 words), one length per section, the
 *   sections, [checksum: every other word exclusive-ored]
 *
 * A block field below 0x8000 is a block number in its low 9 bits and an
 * instance above them; from 0x8000 up it names a user thread of an API
 * node. With 64 instances or more the two would overlap; a development
 * cluster has far fewer.
 *
 * Signals sent to the bundle block (0x7FF) carry several parts of the
 * same signal: a header word per part (the block it is for in bits
 * 16-31, its length less three in bits 0-4), then its data.
 *
 * A signal too long for one message travels as a train of fragments,
 * marked first, middle and last, on one link. Each fragment's data ends
 * with the number of each section it carries and the train's fragment
 * id; its sections are pieces of the signal's, appended to the section
 * their number names. The data nodes repeat the signal's data in every
 * fragment and send the highest section first; an API node puts the
 * data in the last fragment only and the sections in order. Either way
 * the last fragment's data is the signal's. The dissector shows each
 * fragment, and at the last one the joined signal, as a data source of
 * its own, with the frames its fragments came in.
 *
 * Scans are decoded as iClaustron's protocol chapter (section 7.2) reads
 * them, which captures are to confirm: SCAN_REQ with its flags and its
 * three sections (the receivers, the columns after five size words, the
 * bounds), SCAN_CONF with an entry per receiver, SCAN_REF, SCAN_MORE_REQ
 * and SCAN_ROW_KEY_REP. A scan's rows are ROW_DATA_REP, whose first word
 * then names a receiver rather than a query.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include <wsutil/pint.h>

void proto_register_ndb(void);
void proto_reg_handoff_ndb(void);

static int proto_ndb;
static dissector_handle_t ndb_handle;

#define NDB_MGM_PORT              1186

/* The handshake's text. */
#define NDB_LINK_LINE             "ndbd"
#define NDB_TRANSPORTER_CONNECT   "transporter connect"
#define NDB_HELLO_MAX_BYTES       23
#define NDB_LINK_TYPE_TCP         1

/* Word 1 */
#define NDB_W1_BYTE_ORDER         0x81000081
#define NDB_W1_FRAG_HIGH          0x00000002
#define NDB_W1_SIGNAL_ID          0x00000004
#define NDB_W1_COMPRESSED         0x00000008
#define NDB_W1_CHECKSUM           0x00000010
#define NDB_W1_PRIO               0x00000060
#define NDB_W1_TOTAL_WORDS        0x00FFFF00
#define NDB_W1_FRAG_LOW           0x02000000
#define NDB_W1_DATA_WORDS         0x7C000000
/* Word 2 */
#define NDB_W2_SIGNAL             0x0000FFFF
#define NDB_W2_VERSION            0x000F0000
#define NDB_W2_TRACE              0x03F00000
#define NDB_W2_SECTIONS           0x0C000000
/* Word 3 */
#define NDB_W3_SENDER             0x0000FFFF
#define NDB_W3_RECEIVER           0xFFFF0000

#define NDB_HEADER_WORDS          3
#define NDB_MAX_DATA_WORDS        25
#define NDB_MAX_SECTIONS          3
#define NDB_MAX_MESSAGE_WORDS     8192

#define NDB_BLOCK_BUNDLE          0x07FF
#define NDB_BLOCK_NODE_WATCH      0x0FA2
#define NDB_BLOCK_CONFIG_SERVICE  0x0FA3
#define NDB_FIRST_USER_THREAD     0x8000
#define NDB_BLOCK_NUMBER_BITS     9
#define NDB_BLOCK_COORDINATOR     0x0F5

/* KEY_OP_REQ's flags for its optional words. */
#define NDB_FLAG_DIST_KEY         (1U << 2)
#define NDB_FLAG_TAKEOVER         (1U << 14)
#define NDB_FLAG_USER_ID          (1U << 29)

/* A signal number whose layout here is not the one we decode. */
#define NDB_SIG_OTHER             0x10000

/* Column headers: the column id above, the value's size in bytes below. */
#define NDB_COL_ID                0xFFFF0000
#define NDB_COL_PARTIAL           0x00008000
#define NDB_COL_SIZE              0x00007FFF
/* Ids that are not columns. */
#define NDB_COL_READ_EVERY        0xFFF0
#define NDB_COL_READ_MASKED       0xFFF3
#define NDB_COL_PARTITION         0xFFFE

/* Scans: SCAN_REQ's distribution key flag, SCAN_CONF's receiver count,
 * the coordinator's pointer for a receiver that is done, and the row
 * count that says a fourth word holds the rows. */
#define NDB_SCAN_DIST_KEY         (1U << 26)
#define NDB_SCAN_CONF_COUNT       0x7FFFFFFF
#define NDB_NULL_RECORD           0xFFFFFF00
#define NDB_RECEIVER_ROWS         0x000003FF
#define NDB_SCAN_SIZE_WORDS       5

/* A data node's state, in HEARTBEAT_CONF: 16 words, the last 8 a bitmap. */
#define NDB_NODE_STATE_WORDS      16
#define NDB_CONNECTED_WORDS       8

/* LIST_OBJECTS_CONF: its own words, and words per object in section 0. */
#define NDB_LIST_OBJECTS_CONF_WORDS 2
#define NDB_OBJECT_WORDS          3

/* Keys for per-packet data: the calls for a frame, and from this key up
 * one per message, by call (bits 18-29) and message (bits 0-17). */
#define NDB_KEY_CALLS             0x7fffffff
#define NDB_KEY_MESSAGES          0x40000000
#define NDB_KEY_CALL_SHIFT        18
#define NDB_KEY_MESSAGE_MASK      0x0003ffff

/* Fragment states. */
#define NDB_FRAGMENT_FIRST        1
#define NDB_FRAGMENT_LAST         3
/* The most words a joined signal is shown with: its length field. */
#define NDB_MAX_JOINED_WORDS      0xffffU

/* Signal numbers, by iClaustron's names. */
#define NDB_SIG_HEARTBEAT_CONF          1
#define NDB_SIG_HEARTBEAT_REF           2
#define NDB_SIG_HEARTBEAT_REQ           3
#define NDB_SIG_COLUMN_DATA_ORD         4
#define NDB_SIG_ROW_DATA_REP            5
#define NDB_SIG_KEY_DATA_ORD            6
#define NDB_SIG_TAKEOVER_CONF           8
#define NDB_SIG_TAKEOVER_REF            9
#define NDB_SIG_KEY_OP_CONF             10
#define NDB_SIG_KEY_OP_REF              11
#define NDB_SIG_KEY_OP_REQ              12
#define NDB_SIG_ROLLBACK_CONF           13
#define NDB_SIG_ROLLBACK_REF            14
#define NDB_SIG_ROLLBACK_REQ            15
#define NDB_SIG_TRANS_ABORTED_REP       16
#define NDB_SIG_COMMIT_CONF             17
#define NDB_SIG_COMMIT_REF              18
#define NDB_SIG_COMMIT_REQ              19
#define NDB_SIG_TABLE_DESC_REF          23
#define NDB_SIG_TABLE_DESC_REQ          24
#define NDB_SIG_NODE_LOST_REP           26
#define NDB_SIG_NODE_LOST_DONE_REP      27
#define NDB_SIG_SCAN_MORE_REQ           28
#define NDB_SIG_SCAN_CONF               29
#define NDB_SIG_SCAN_REF                31
#define NDB_SIG_SCAN_REQ                32
#define NDB_SIG_SCAN_ROW_KEY_REP        33
#define NDB_SIG_COORD_FREE_CONF         34
#define NDB_SIG_COORD_FREE_REF          35
#define NDB_SIG_COORD_FREE_REQ          36
#define NDB_SIG_COORD_ALLOC_CONF        37
#define NDB_SIG_COORD_ALLOC_REF         38
#define NDB_SIG_COORD_ALLOC_REQ         39
#define NDB_SIG_NODE_JOINED_REP         163
#define NDB_SIG_TABLE_DESC_CONF         190
#define NDB_SIG_LIST_OBJECTS_REQ        193
#define NDB_SIG_LIST_OBJECTS_CONF       194
#define NDB_SIG_COMMIT_MARKER_FREE_ORD  469
#define NDB_SIG_UNIQUE_OP_REQ           519
#define NDB_SIG_UNIQUE_OP_CONF          520
#define NDB_SIG_UNIQUE_OP_REF           521
#define NDB_SIG_TABLE_CHANGED_REP       606
#define NDB_SIG_DEADLOCK_FOUND_REP      980
#define NDB_SIG_COLLATION_DESC_REQ      984
#define NDB_SIG_COLLATION_DESC_CONF     985
#define NDB_SIG_COLLATION_DESC_REF      986

static const value_string ndb_signal_vals[] = {
    { NDB_SIG_HEARTBEAT_CONF,         "HEARTBEAT_CONF" },
    { NDB_SIG_HEARTBEAT_REF,          "HEARTBEAT_REF" },
    { NDB_SIG_HEARTBEAT_REQ,          "HEARTBEAT_REQ" },
    { NDB_SIG_COLUMN_DATA_ORD,        "COLUMN_DATA_ORD" },
    { NDB_SIG_ROW_DATA_REP,           "ROW_DATA_REP" },
    { NDB_SIG_KEY_DATA_ORD,           "KEY_DATA_ORD" },
    { NDB_SIG_TAKEOVER_CONF,          "TAKEOVER_CONF" },
    { NDB_SIG_TAKEOVER_REF,           "TAKEOVER_REF" },
    { NDB_SIG_KEY_OP_CONF,            "KEY_OP_CONF" },
    { NDB_SIG_KEY_OP_REF,             "KEY_OP_REF" },
    { NDB_SIG_KEY_OP_REQ,             "KEY_OP_REQ" },
    { NDB_SIG_ROLLBACK_CONF,          "ROLLBACK_CONF" },
    { NDB_SIG_ROLLBACK_REF,           "ROLLBACK_REF" },
    { NDB_SIG_ROLLBACK_REQ,           "ROLLBACK_REQ" },
    { NDB_SIG_TRANS_ABORTED_REP,      "TRANS_ABORTED_REP" },
    { NDB_SIG_COMMIT_CONF,            "COMMIT_CONF" },
    { NDB_SIG_COMMIT_REF,             "COMMIT_REF" },
    { NDB_SIG_COMMIT_REQ,             "COMMIT_REQ" },
    { NDB_SIG_TABLE_DESC_REF,         "TABLE_DESC_REF" },
    { NDB_SIG_TABLE_DESC_REQ,         "TABLE_DESC_REQ" },
    { NDB_SIG_NODE_LOST_REP,          "NODE_LOST_REP" },
    { NDB_SIG_NODE_LOST_DONE_REP,     "NODE_LOST_DONE_REP" },
    { NDB_SIG_SCAN_MORE_REQ,          "SCAN_MORE_REQ" },
    { NDB_SIG_SCAN_CONF,              "SCAN_CONF" },
    { NDB_SIG_SCAN_REF,               "SCAN_REF" },
    { NDB_SIG_SCAN_REQ,               "SCAN_REQ" },
    { NDB_SIG_SCAN_ROW_KEY_REP,       "SCAN_ROW_KEY_REP" },
    { NDB_SIG_COORD_FREE_CONF,        "COORD_FREE_CONF" },
    { NDB_SIG_COORD_FREE_REF,         "COORD_FREE_REF" },
    { NDB_SIG_COORD_FREE_REQ,         "COORD_FREE_REQ" },
    { NDB_SIG_COORD_ALLOC_CONF,       "COORD_ALLOC_CONF" },
    { NDB_SIG_COORD_ALLOC_REF,        "COORD_ALLOC_REF" },
    { NDB_SIG_COORD_ALLOC_REQ,        "COORD_ALLOC_REQ" },
    { NDB_SIG_NODE_JOINED_REP,        "NODE_JOINED_REP" },
    { NDB_SIG_TABLE_DESC_CONF,        "TABLE_DESC_CONF" },
    { NDB_SIG_LIST_OBJECTS_REQ,       "LIST_OBJECTS_REQ" },
    { NDB_SIG_LIST_OBJECTS_CONF,      "LIST_OBJECTS_CONF" },
    { NDB_SIG_COMMIT_MARKER_FREE_ORD, "COMMIT_MARKER_FREE_ORD" },
    { NDB_SIG_UNIQUE_OP_REQ,          "UNIQUE_OP_REQ" },
    { NDB_SIG_UNIQUE_OP_CONF,         "UNIQUE_OP_CONF" },
    { NDB_SIG_UNIQUE_OP_REF,          "UNIQUE_OP_REF" },
    { NDB_SIG_TABLE_CHANGED_REP,      "TABLE_CHANGED_REP" },
    { NDB_SIG_DEADLOCK_FOUND_REP,     "DEADLOCK_FOUND_REP" },
    { NDB_SIG_COLLATION_DESC_REQ,     "COLLATION_DESC_REQ" },
    { NDB_SIG_COLLATION_DESC_CONF,    "COLLATION_DESC_CONF" },
    { NDB_SIG_COLLATION_DESC_REF,     "COLLATION_DESC_REF" },
    { 0, NULL }
};

/* Data node blocks by their number, without the instance. */
static const value_string ndb_link_type_vals[] = {
    { NDB_LINK_TYPE_TCP, "TCP" },
    { 0, NULL }
};

static const value_string ndb_start_level_vals[] = {
    { 0, "nothing" },
    { 1, "process up" },
    { 2, "starting" },
    { 3, "started" },
    { 4, "single user" },
    { 5, "stopping, first phase" },
    { 6, "stopping, second phase" },
    { 7, "stopping, third phase" },
    { 8, "stopping, last phase" },
    { 0, NULL }
};

static const value_string ndb_object_kind_vals[] = {
    { 2, "table" },
    { 3, "unique index" },
    { 6, "ordered index" },
    { 0, NULL }
};

static const value_string ndb_block_vals[] = {
    { 0xF4,  "ARCHIVE" },
    { 0xF5,  "COORDINATOR" },
    { 0xF6,  "DISTRIBUTION" },
    { 0xF7,  "LOCAL_OPS" },
    { 0xF8,  "HASH_INDEX" },
    { 0xF9,  "ROW_STORE" },
    { 0xFA,  "DICTIONARY" },
    { 0xFB,  "START_CONTROL" },
    { 0xFC,  "MEMBERSHIP" },
    { 0xFD,  "FILE_IO" },
    { 0xFE,  "NODE_ADMIN" },
    { 0xFF,  "INDEX_BUILD" },
    { 0x100, "UTILITY" },
    { 0x101, "CHANGE_FEED" },
    { 0x102, "ORDERED_INDEX" },
    { 0x108, "JOIN" },
    { 0x10A, "LINK_ADMIN" },
    { 0x10B, "READ_WORKER" },
    { 0x10C, "READ_WORKER" },
    { 0x10D, "READ_WORKER" },
    { 0x10E, "READ_WORKER" },
    { 0x10F, "READ_WORKER" },
    { 0x110, "READ_WORKER" },
    { 0x111, "READ_WORKER" },
    { 0, NULL }
};

static const value_string ndb_fragment_vals[] = {
    { 0, "whole" },
    { 1, "first fragment" },
    { 2, "middle fragment" },
    { 3, "last fragment" },
    { 0, NULL }
};

static const value_string ndb_operation_vals[] = {
    { 0, "read" },
    { 1, "update" },
    { 2, "insert" },
    { 3, "delete" },
    { 4, "write" },
    { 5, "read exclusive" },
    { 0, NULL }
};

static const value_string ndb_bound_vals[] = {
    { 0, "low, inclusive" },
    { 1, "low, exclusive" },
    { 2, "high, inclusive" },
    { 3, "high, exclusive" },
    { 4, "equal" },
    { 0, NULL }
};

static const value_string ndb_abort_vals[] = {
    { 0, "abort on error" },
    { 2, "ignore error" },
    { 0, NULL }
};

static const value_string ndb_collation_kind_vals[] = {
    { 0, "by collation number" },
    { 1, "by collation name" },
    { 2, "by character set name (its default collation)" },
    { 0, NULL }
};

static const value_string ndb_collation_error_vals[] = {
    { 1, "malformed, or sections that do not fit the kind" },
    { 2, "reply address on another node" },
    { 3, "unknown kind of lookup" },
    { 4, "collation number 0, or 2048 and above" },
    { 5, "bad name" },
    { 6, "no such collation" },
    { 7, "no such character set" },
    { 8, "weights asked for from \"all sent\"" },
    { 9, "busy with another request with weights, send again" },
    { 10, "out of memory to build the answer in" },
    { 0, NULL }
};

static const true_false_string tfs_big_little = {
    "big endian", "little endian"
};

/* Text */
static int hf_ndb_line;
static int hf_ndb_hello_node;
static int hf_ndb_hello_link_type;
static int hf_ndb_hello_far_node;
static int hf_ndb_hello_instance;
/* Header */
static int hf_ndb_word1;
static int hf_ndb_big_endian;
static int hf_ndb_frag_high;
static int hf_ndb_has_signal_id;
static int hf_ndb_compressed;
static int hf_ndb_has_checksum;
static int hf_ndb_prio;
static int hf_ndb_total_words;
static int hf_ndb_frag_low;
static int hf_ndb_data_words;
static int hf_ndb_fragment;
static int hf_ndb_word2;
static int hf_ndb_signal;
static int hf_ndb_signal_version;
static int hf_ndb_trace;
static int hf_ndb_sections;
static int hf_ndb_word3;
static int hf_ndb_sender;
static int hf_ndb_receiver;
static int hf_ndb_signal_id;
static int hf_ndb_word;
static int hf_ndb_section_len;
static int hf_ndb_section;
static int hf_ndb_checksum;
static int hf_ndb_fragment_id;
static int hf_ndb_section_number;
static int hf_ndb_joined_in;
static int hf_ndb_train_fragments;
static int hf_ndb_train_frame;
/* Bundles */
static int hf_ndb_part_header;
static int hf_ndb_part_receiver;
static int hf_ndb_part_len;
/* Signal fields */
static int hf_ndb_coord_ptr;
static int hf_ndb_client_ptr;
static int hf_ndb_client_ptr_word;
static int hf_ndb_commit_ack_owed;
static int hf_ndb_query_ref;
static int hf_ndb_table_id;
static int hf_ndb_column_data_len;
static int hf_ndb_table_version;
static int hf_ndb_flags;
static int hf_ndb_flag_dirty;
static int hf_ndb_flag_no_disk;
static int hf_ndb_flag_commit;
static int hf_ndb_flag_operation;
static int hf_ndb_flag_simple;
static int hf_ndb_flag_execute;
static int hf_ndb_flag_start;
static int hf_ndb_flag_abort;
static int hf_ndb_flag_committed_base;
static int hf_ndb_flag_no_wait;
static int hf_ndb_flag_batch_safe;
static int hf_ndb_flag_batch_unsafe;
static int hf_ndb_trans_id_lo;
static int hf_ndb_trans_id_hi;
static int hf_ndb_trans_id;
static int hf_ndb_error_code;
static int hf_ndb_error_data;
static int hf_ndb_gci_hi;
static int hf_ndb_gci_lo;
static int hf_ndb_gci;
static int hf_ndb_gci_word;
static int hf_ndb_info;
static int hf_ndb_info_ops;
static int hf_ndb_info_commit;
static int hf_ndb_info_marker;
static int hf_ndb_op_query_ref;
static int hf_ndb_op_row_len;
static int hf_ndb_block_ref;
static int hf_ndb_ref_node;
static int hf_ndb_ref_block;
static int hf_ndb_version;
static int hf_ndb_mysql_version;
static int hf_ndb_heartbeat;
static int hf_ndb_min_db_version;
static int hf_ndb_min_api_version;
static int hf_ndb_start_level;
static int hf_ndb_node_group;
static int hf_ndb_dynamic_id;
static int hf_ndb_start_phase;
static int hf_ndb_restart_type;
static int hf_ndb_single_user;
static int hf_ndb_single_user_api;
static int hf_ndb_connected_node;
static int hf_ndb_instance;
static int hf_ndb_release_id;
static int hf_ndb_caller_data;
static int hf_ndb_request_type;
static int hf_ndb_id_or_name_len;
static int hf_ndb_schema_trans;
static int hf_ndb_total_len;
static int hf_ndb_table_kind;
static int hf_ndb_row;
static int hf_ndb_row_len;
static int hf_ndb_error_line;
static int hf_ndb_list_flags;
static int hf_ndb_list_names;
static int hf_ndb_list_dependent;
static int hf_ndb_list_old_table_id;
static int hf_ndb_object_kind;
static int hf_ndb_object_count;
static int hf_ndb_object_flags;
static int hf_ndb_object_store;
static int hf_ndb_object_temporary;
static int hf_ndb_flag_dist_key;
static int hf_ndb_flag_takeover;
static int hf_ndb_flag_user_id;
static int hf_ndb_user_id;
static int hf_ndb_user_id_version;
static int hf_ndb_takeover_info;
static int hf_ndb_takeover_flag;
static int hf_ndb_takeover_row;
static int hf_ndb_takeover_frag;
static int hf_ndb_op_dist_key;
static int hf_ndb_row_for;
static int hf_ndb_scan_flags;
static int hf_ndb_scan_ext;
static int hf_ndb_scan_exclusive;
static int hf_ndb_scan_no_disk;
static int hf_ndb_scan_hold_lock;
static int hf_ndb_scan_committed;
static int hf_ndb_scan_keys;
static int hf_ndb_scan_storage_order;
static int hf_ndb_scan_descending;
static int hf_ndb_scan_range;
static int hf_ndb_scan_batch_rows_bits;
static int hf_ndb_scan_dist_key;
static int hf_ndb_scan_join;
static int hf_ndb_scan_every_conf;
static int hf_ndb_scan_extended_conf;
static int hf_ndb_scan_committed_base;
static int hf_ndb_scan_multi_frag;
static int hf_ndb_scan_spare;
static int hf_ndb_scan_word5;
static int hf_ndb_scan_word5_low;
static int hf_ndb_scan_word5_per_worker;
static int hf_ndb_scan_word5_partition;
static int hf_ndb_scan_word5_interval;
static int hf_ndb_trans_record;
static int hf_ndb_batch_bytes;
static int hf_ndb_batch_rows;
static int hf_ndb_dist_key;
static int hf_ndb_receiver_id;
static int hf_ndb_receiver_coord;
static int hf_ndb_scan_conf_info;
static int hf_ndb_scan_conf_count;
static int hf_ndb_scan_conf_end;
static int hf_ndb_receiver_info;
static int hf_ndb_receiver_len;
static int hf_ndb_receiver_rows;
static int hf_ndb_receiver_rows_word;
static int hf_ndb_receiver_len_word;
static int hf_ndb_receiver_active;
static int hf_ndb_close_owed;
static int hf_ndb_stop;
static int hf_ndb_key_len;
static int hf_ndb_row_key_info;
static int hf_ndb_row_key_scan;
static int hf_ndb_row_key_op;
static int hf_ndb_row_key_frag;
static int hf_ndb_key;
static int hf_ndb_column_size_word;
static int hf_ndb_bound;
static int hf_ndb_bound_type;
static int hf_ndb_bound_range;
static int hf_ndb_bound_len;
static int hf_ndb_object_state;
static int hf_ndb_object_id;
static int hf_ndb_object_name_len;
static int hf_ndb_object_name;
/* Columns */
static int hf_ndb_column_header;
static int hf_ndb_column_id;
static int hf_ndb_column_partial;
static int hf_ndb_column_size;
static int hf_ndb_column_value;
static int hf_ndb_column_bitmap;
static int hf_ndb_packed_values;
static int hf_ndb_coll_kind;
static int hf_ndb_coll_number;
static int hf_ndb_coll_name_len;
static int hf_ndb_coll_default;
static int hf_ndb_coll_binary;
static int hf_ndb_coll_flags;
static int hf_ndb_coll_flag_default;
static int hf_ndb_coll_flag_binary;
static int hf_ndb_coll_flag_unicode;
static int hf_ndb_coll_flag_case;
static int hf_ndb_coll_flag_ascii;
static int hf_ndb_coll_flag_no_pad;
static int hf_ndb_coll_min_bytes;
static int hf_ndb_coll_max_bytes;
static int hf_ndb_coll_sort_growth;
static int hf_ndb_coll_upper_growth;
static int hf_ndb_coll_lower_growth;
static int hf_ndb_coll_pad;
static int hf_ndb_coll_levels;
static int hf_ndb_coll_min_sort;
static int hf_ndb_coll_max_sort;
static int hf_ndb_coll_charset_len;
static int hf_ndb_coll_collation_len;
static int hf_ndb_coll_error;
static int hf_ndb_coll_req_flags;
static int hf_ndb_coll_req_with_weights;
static int hf_ndb_coll_position;
static int hf_ndb_coll_case_word;
static int hf_ndb_coll_names_word;
static int hf_ndb_coll_weight_entries;
static int hf_ndb_coll_weights_len;
static int hf_ndb_coll_contraction_entries;
static int hf_ndb_coll_contractions_len;
static int hf_ndb_coll_next_position;
static int hf_ndb_wr_first;
static int hf_ndb_wr_count;
static int hf_ndb_wr_step;
static int hf_ndb_wr_encoded_len;
static int hf_ndb_wr_weight_len;
static int hf_ndb_wr_encoded;
static int hf_ndb_wr_weight;
static int hf_ndb_ct_points;
static int hf_ndb_ct_previous;
static int hf_ndb_ct_weight_len;
static int hf_ndb_ct_code_point;
static int hf_ndb_ct_weight;

static int ett_ndb;
static int ett_ndb_line;
static int ett_ndb_message;
static int ett_ndb_word1;
static int ett_ndb_word2;
static int ett_ndb_word3;
static int ett_ndb_data;
static int ett_ndb_sections;
static int ett_ndb_part;
static int ett_ndb_part_header;
static int ett_ndb_flags;
static int ett_ndb_info;
static int ett_ndb_op;
static int ett_ndb_ref;
static int ett_ndb_client_ptr;
static int ett_ndb_coll_flags;
static int ett_ndb_coll_req_flags;
static int ett_ndb_coll_case;
static int ett_ndb_coll_names;
static int ett_ndb_weights;
static int ett_ndb_weight_run;
static int ett_ndb_contraction;
static int ett_ndb_node_state;
static int ett_ndb_connected;
static int ett_ndb_row;
static int ett_ndb_column;
static int ett_ndb_column_header;
static int ett_ndb_list_flags;
static int ett_ndb_object;
static int ett_ndb_object_flags;
static int ett_ndb_scan_flags;
static int ett_ndb_scan_word5;
static int ett_ndb_scan_conf_info;
static int ett_ndb_receiver;
static int ett_ndb_receiver_info;
static int ett_ndb_row_key_info;
static int ett_ndb_takeover_info;
static int ett_ndb_bound;
static int ett_ndb_bound_word;

static expert_field ei_ndb_bad_message;
static expert_field ei_ndb_bad_checksum;
static expert_field ei_ndb_fragment;
static expert_field ei_ndb_unjoined;
static expert_field ei_ndb_compressed;
static expert_field ei_ndb_short;

static int * const ndb_word1_fields[] = {
    &hf_ndb_big_endian,
    &hf_ndb_frag_high,
    &hf_ndb_has_signal_id,
    &hf_ndb_compressed,
    &hf_ndb_has_checksum,
    &hf_ndb_prio,
    &hf_ndb_total_words,
    &hf_ndb_frag_low,
    &hf_ndb_data_words,
    NULL
};

static int * const ndb_word2_fields[] = {
    &hf_ndb_signal,
    &hf_ndb_signal_version,
    &hf_ndb_trace,
    &hf_ndb_sections,
    NULL
};

static int * const ndb_word3_fields[] = {
    &hf_ndb_sender,
    &hf_ndb_receiver,
    NULL
};

static int * const ndb_part_header_fields[] = {
    &hf_ndb_part_receiver,
    &hf_ndb_part_len,
    NULL
};

static int * const ndb_flags_fields[] = {
    &hf_ndb_flag_dirty,
    &hf_ndb_flag_no_disk,
    &hf_ndb_flag_dist_key,
    &hf_ndb_flag_commit,
    &hf_ndb_flag_operation,
    &hf_ndb_flag_simple,
    &hf_ndb_flag_execute,
    &hf_ndb_flag_start,
    &hf_ndb_flag_abort,
    &hf_ndb_flag_takeover,
    &hf_ndb_flag_user_id,
    &hf_ndb_flag_committed_base,
    &hf_ndb_flag_no_wait,
    &hf_ndb_flag_batch_safe,
    &hf_ndb_flag_batch_unsafe,
    NULL
};

static int * const ndb_scan_flags_fields[] = {
    &hf_ndb_scan_ext,
    &hf_ndb_scan_exclusive,
    &hf_ndb_scan_no_disk,
    &hf_ndb_scan_hold_lock,
    &hf_ndb_scan_committed,
    &hf_ndb_scan_keys,
    &hf_ndb_scan_storage_order,
    &hf_ndb_scan_descending,
    &hf_ndb_scan_range,
    &hf_ndb_scan_batch_rows_bits,
    &hf_ndb_scan_dist_key,
    &hf_ndb_scan_join,
    &hf_ndb_scan_every_conf,
    &hf_ndb_scan_extended_conf,
    &hf_ndb_scan_committed_base,
    &hf_ndb_scan_multi_frag,
    NULL
};

static int * const ndb_scan_word5_fields[] = {
    &hf_ndb_scan_word5_low,
    &hf_ndb_scan_word5_per_worker,
    &hf_ndb_scan_word5_partition,
    &hf_ndb_scan_word5_interval,
    NULL
};

static int * const ndb_scan_conf_info_fields[] = {
    &hf_ndb_scan_conf_count,
    &hf_ndb_scan_conf_end,
    NULL
};

static int * const ndb_receiver_info_fields[] = {
    &hf_ndb_receiver_len,
    &hf_ndb_receiver_rows,
    NULL
};

static int * const ndb_row_key_info_fields[] = {
    &hf_ndb_row_key_scan,
    &hf_ndb_row_key_op,
    &hf_ndb_row_key_frag,
    NULL
};

static int * const ndb_takeover_info_fields[] = {
    &hf_ndb_takeover_flag,
    &hf_ndb_takeover_row,
    &hf_ndb_takeover_frag,
    NULL
};

static int * const ndb_bound_fields[] = {
    &hf_ndb_bound_type,
    &hf_ndb_bound_range,
    &hf_ndb_bound_len,
    NULL
};

static int * const ndb_info_fields[] = {
    &hf_ndb_info_ops,
    &hf_ndb_info_commit,
    &hf_ndb_info_marker,
    NULL
};

static int * const ndb_ref_fields[] = {
    &hf_ndb_ref_node,
    &hf_ndb_ref_block,
    NULL
};

static int * const ndb_coll_flags_fields[] = {
    &hf_ndb_coll_flag_default,
    &hf_ndb_coll_flag_binary,
    &hf_ndb_coll_flag_unicode,
    &hf_ndb_coll_flag_case,
    &hf_ndb_coll_flag_ascii,
    &hf_ndb_coll_flag_no_pad,
    NULL
};

static int * const ndb_coll_req_flags_fields[] = {
    &hf_ndb_coll_req_with_weights,
    NULL
};

static int * const ndb_coll_case_fields[] = {
    &hf_ndb_coll_upper_growth,
    &hf_ndb_coll_lower_growth,
    NULL
};

static int * const ndb_coll_names_fields[] = {
    &hf_ndb_coll_charset_len,
    &hf_ndb_coll_collation_len,
    NULL
};

static int * const ndb_column_header_fields[] = {
    &hf_ndb_column_id,
    &hf_ndb_column_partial,
    &hf_ndb_column_size,
    NULL
};

static int * const ndb_list_flags_fields[] = {
    &hf_ndb_list_names,
    &hf_ndb_list_dependent,
    &hf_ndb_list_old_table_id,
    NULL
};

static int * const ndb_object_flags_fields[] = {
    &hf_ndb_object_state,
    &hf_ndb_object_temporary,
    &hf_ndb_object_store,
    NULL
};

/* What is known about one TCP connection. */
typedef struct {
    address  client_addr;
    uint32_t client_port;
    /* Has each direction left its text lines? 0 is from the client. */
    bool     binary[2];
    /* Has the client asked for a signal link? */
    bool     linking;
    /* Trains of fragments begun and not yet ended, each way, by sender
     * block and fragment id. */
    wmem_map_t *trains[2];
} ndb_conv_t;

/* A train of fragments, being joined or joined. */
typedef struct {
    /* The bytes of each section so far, by section number. */
    wmem_array_t *pieces[NDB_MAX_SECTIONS];
    /* The frame each fragment came in. */
    wmem_array_t *frames;
    unsigned      fragments;
    /* The highest section number seen, plus one. */
    unsigned      sections;
    /* The frame of the last fragment, once it has come. */
    uint32_t      joined_in;
    /* The joined signal as a whole message, once it can be made. */
    uint8_t      *joined;
    unsigned      joined_words;
    unsigned      encoding;
} ndb_train_t;

/* What a fragment was found to belong to, kept for later passes. */
typedef struct {
    /* NULL when its train began before the capture. */
    ndb_train_t *train;
    bool         last;
} ndb_piece_t;

/* Where a message lies, for what is kept about it between passes. */
typedef struct {
    ndb_conv_t *conv;
    int         dir;
    unsigned    key;
} ndb_msg_ctx_t;

/* What a call for a frame started from, kept for later passes. */
typedef struct {
    bool binary_at_start;
    bool linking_at_start;
} ndb_call_t;

/* ---- Formatting ---- */

static void
ndb_format_block(char *buf, uint32_t value)
{
    const char *name;
    uint32_t number;
    uint32_t instance;

    if (value >= NDB_FIRST_USER_THREAD) {
        snprintf(buf, ITEM_LABEL_LENGTH, "user thread %u (0x%04x)",
                 value - NDB_FIRST_USER_THREAD, value);
        return;
    }
    if (value == NDB_BLOCK_BUNDLE) {
        snprintf(buf, ITEM_LABEL_LENGTH, "BUNDLE (0x%04x)", value);
        return;
    }
    if (value == NDB_BLOCK_NODE_WATCH) {
        snprintf(buf, ITEM_LABEL_LENGTH, "NODE_WATCH (0x%04x)", value);
        return;
    }
    if (value == NDB_BLOCK_CONFIG_SERVICE) {
        snprintf(buf, ITEM_LABEL_LENGTH, "CONFIG_SERVICE (0x%04x)", value);
        return;
    }
    number = value & ((1U << NDB_BLOCK_NUMBER_BITS) - 1);
    instance = value >> NDB_BLOCK_NUMBER_BITS;
    name = try_val_to_str(number, ndb_block_vals);
    if (name == NULL) {
        snprintf(buf, ITEM_LABEL_LENGTH, "block 0x%03x instance %u (0x%04x)",
                 number, instance, value);
    } else if (instance == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s (0x%04x)", name, value);
    } else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s instance %u (0x%04x)", name,
                 instance, value);
    }
}

/* A version as major.minor.build, the way the nodes encode it. */
static void
ndb_format_version(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%u.%u.%u (0x%06x)",
             (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF, value);
}

#define NDB_COLL_CONTRACTIONS  0x110000
#define NDB_COLL_ALL_SENT      0xFFFFFFFF
#define NDB_COLL_NO_STEP       0xFF

/* A position in a collation's weights: a code point or a contraction. */
static void
ndb_format_position(char *buf, uint32_t value)
{
    if (value == NDB_COLL_ALL_SENT)
        snprintf(buf, ITEM_LABEL_LENGTH, "all sent (0x%08x)", value);
    else if (value >= NDB_COLL_CONTRACTIONS)
        snprintf(buf, ITEM_LABEL_LENGTH, "contraction %u",
                 value - NDB_COLL_CONTRACTIONS);
    else
        snprintf(buf, ITEM_LABEL_LENGTH, "code point U+%04X", value);
}

static void
ndb_format_code_point(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "U+%04X", value);
}

static void
ndb_format_step(char *buf, uint32_t value)
{
    if (value == NDB_COLL_NO_STEP)
        snprintf(buf, ITEM_LABEL_LENGTH, "none, all share one weight string");
    else
        snprintf(buf, ITEM_LABEL_LENGTH, "the 16-bit number at byte %u",
                 value);
}

/* A column id, or what an id that is not a column asks for. */
static void
ndb_format_column_id(char *buf, uint32_t value)
{
    switch (value) {
    case NDB_COL_READ_EVERY:
        snprintf(buf, ITEM_LABEL_LENGTH, "read every column (0x%04x)", value);
        break;
    case NDB_COL_READ_MASKED:
        snprintf(buf, ITEM_LABEL_LENGTH, "columns by bitmap (0x%04x)", value);
        break;
    case NDB_COL_PARTITION:
        snprintf(buf, ITEM_LABEL_LENGTH, "partition (0x%04x)", value);
        break;
    default:
        snprintf(buf, ITEM_LABEL_LENGTH, "%u", value);
        break;
    }
}

/* The coordinator's pointer for a scan receiver; null once it is done. */
static void
ndb_format_receiver_ptr(char *buf, uint32_t value)
{
    if (value == NDB_NULL_RECORD)
        snprintf(buf, ITEM_LABEL_LENGTH, "none, the receiver is done "
                 "(0x%08x)", value);
    else
        snprintf(buf, ITEM_LABEL_LENGTH, "0x%08x", value);
}

static void
ndb_format_heartbeat(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%u ms", value * 10);
}

/* ---- Words of signal data ---- */

typedef struct {
    tvbuff_t   *tvb;
    proto_tree *tree;
    unsigned    offset;     /* of the next word */
    unsigned    left;       /* words of data not yet shown */
    unsigned    encoding;
    unsigned    sections;   /* how many the message carries */
} ndb_words_t;

static bool
ndb_take(ndb_words_t *w, unsigned *offset)
{
    if (w->left == 0)
        return false;
    *offset = w->offset;
    w->offset += 4;
    w->left--;
    return true;
}

/* The next word as `hf`; its value, or 0 if there is none. */
static uint32_t
ndb_word(ndb_words_t *w, int hf)
{
    unsigned at;
    uint32_t value = 0;

    if (!ndb_take(w, &at))
        return 0;
    proto_tree_add_item_ret_uint(w->tree, hf, w->tvb, at, 4, w->encoding,
                                 &value);
    return value;
}

/* The next word as a bit field with its parts. */
static uint32_t
ndb_bits(ndb_words_t *w, int hf, int ett, int * const *fields)
{
    unsigned at;

    if (!ndb_take(w, &at))
        return 0;
    proto_tree_add_bitmask(w->tree, w->tvb, at, hf, ett, fields, w->encoding);
    return tvb_get_uint32(w->tvb, at, w->encoding);
}

/* The rest as plain words. */
static void
ndb_rest(ndb_words_t *w)
{
    unsigned at;

    while (ndb_take(w, &at))
        proto_tree_add_item(w->tree, hf_ndb_word, w->tvb, at, 4, w->encoding);
}

/* Two words of transaction id, and the id they make. */
static void
ndb_trans_id(ndb_words_t *w)
{
    unsigned start = w->offset;
    uint32_t lo;
    uint32_t hi;
    proto_item *ti;

    if (w->left < 2) {
        ndb_rest(w);
        return;
    }
    lo = ndb_word(w, hf_ndb_trans_id_lo);
    hi = ndb_word(w, hf_ndb_trans_id_hi);
    ti = proto_tree_add_uint64(w->tree, hf_ndb_trans_id, w->tvb, start, 8,
                               ((uint64_t)hi << 32) | lo);
    proto_item_set_generated(ti);
}

static void
ndb_gci(ndb_words_t *w, uint32_t hi, unsigned hi_offset, bool have_lo)
{
    uint32_t lo = 0;
    proto_item *ti;

    if (have_lo)
        lo = ndb_word(w, hf_ndb_gci_lo);
    ti = proto_tree_add_uint64(w->tree, hf_ndb_gci, w->tvb, hi_offset, 4,
                               ((uint64_t)hi << 32) | lo);
    proto_item_set_generated(ti);
}

/*
 * The client's record with its low bit borrowed, set when a
 * COMMIT_MARKER_FREE_ORD is owed. The record is the word with that bit
 * cleared, not shifted.
 */
static void
ndb_client_ptr_flagged(ndb_words_t *w)
{
    unsigned at;
    uint32_t value;
    proto_item *ti;
    proto_tree *tree;

    if (!ndb_take(w, &at))
        return;
    value = tvb_get_uint32(w->tvb, at, w->encoding);
    ti = proto_tree_add_item(w->tree, hf_ndb_client_ptr_word, w->tvb, at, 4,
                             w->encoding);
    tree = proto_item_add_subtree(ti, ett_ndb_client_ptr);
    ti = proto_tree_add_uint(tree, hf_ndb_client_ptr, w->tvb, at, 4,
                             value & ~1U);
    proto_item_set_generated(ti);
    proto_tree_add_item(tree, hf_ndb_commit_ack_owed, w->tvb, at, 4,
                        w->encoding);
}

/*
 * A data node's state in HEARTBEAT_CONF: start level, node group,
 * dynamic id, then one field read by what the node is doing (its start
 * phase while starting, whether the cluster shuts down while stopping)
 * with the restart type after it, single-user mode and the one API node
 * it allows, and a bitmap of the nodes below 256 it is connected to.
 */
static bool
ndb_node_state(ndb_words_t *w)
{
    ndb_words_t state = *w;
    proto_tree *tree;
    proto_tree *ct;
    proto_item *ci;
    unsigned at;
    unsigned i;
    unsigned bit;
    unsigned count = 0;

    if (w->left < NDB_NODE_STATE_WORDS)
        return false;
    tree = proto_tree_add_subtree(w->tree, w->tvb, w->offset,
                                  4 * NDB_NODE_STATE_WORDS,
                                  ett_ndb_node_state, NULL, "Node state");
    state.tree = tree;
    state.left = NDB_NODE_STATE_WORDS - NDB_CONNECTED_WORDS;
    ndb_word(&state, hf_ndb_start_level);
    ndb_word(&state, hf_ndb_node_group);
    ndb_word(&state, hf_ndb_dynamic_id);
    ndb_word(&state, hf_ndb_start_phase);
    ndb_word(&state, hf_ndb_restart_type);
    ndb_word(&state, hf_ndb_word);
    if (ndb_take(&state, &at))
        proto_tree_add_item(tree, hf_ndb_single_user, w->tvb, at, 4,
                            w->encoding);
    ndb_word(&state, hf_ndb_single_user_api);

    ct = proto_tree_add_subtree(tree, w->tvb, state.offset,
                                4 * NDB_CONNECTED_WORDS, ett_ndb_connected,
                                &ci, "Connected nodes:");
    for (i = 0; i < NDB_CONNECTED_WORDS; i++) {
        uint32_t bits;

        at = state.offset + 4 * i;
        bits = tvb_get_uint32(w->tvb, at, w->encoding);
        for (bit = 0; bit < 32; bit++) {
            if ((bits & (1U << bit)) == 0)
                continue;
            proto_tree_add_uint(ct, hf_ndb_connected_node, w->tvb, at, 4,
                                32 * i + bit);
            proto_item_append_text(ci, "%s %u", count > 0 ? "," : "",
                                   32 * i + bit);
            count++;
        }
    }
    if (count == 0)
        proto_item_append_text(ci, " none");
    w->offset += 4 * NDB_NODE_STATE_WORDS;
    w->left -= NDB_NODE_STATE_WORDS;
    return true;
}

/*
 * Column data: for each column a header, its id above and the value's
 * size in bytes below, then the value in whole words; a read names a
 * column with size 0. Two ids are not columns: "read every column"
 * carries the count of columns in its size and no value, and "columns
 * by bitmap" carries a bitmap of the columns wanted, or in a reply the
 * bitmap of those read, with the packed values after it.
 */
static void
ndb_columns(ndb_words_t *w, bool reply)
{
    while (w->left > 0) {
        unsigned at = w->offset;
        uint32_t header = tvb_get_uint32(w->tvb, at, w->encoding);
        uint32_t id = header >> 16;
        uint32_t size = header & NDB_COL_SIZE;
        unsigned words = (size + 3) / 4;
        proto_tree *ct;
        proto_item *ci;

        if (id == NDB_COL_READ_EVERY)
            words = 0;
        if (words > w->left - 1)
            words = w->left - 1;
        ct = proto_tree_add_subtree(w->tree, w->tvb, at, 4 * (1 + words),
                                    ett_ndb_column, &ci, "Column");
        if (id == NDB_COL_READ_EVERY)
            proto_item_set_text(ci, "Read every column: %u columns", size);
        else if (id == NDB_COL_READ_MASKED)
            proto_item_set_text(ci, "%s: %u bytes of bitmap",
                                reply ? "Columns read" : "Columns by bitmap",
                                size);
        else if (id == NDB_COL_PARTITION)
            proto_item_set_text(ci, "Partition");
        else if (size == 0)
            proto_item_set_text(ci, "Column %u, no value", id);
        else
            proto_item_set_text(ci, "Column %u, %u bytes", id, size);
        proto_tree_add_bitmask(ct, w->tvb, at, hf_ndb_column_header,
                               ett_ndb_column_header,
                               ndb_column_header_fields, w->encoding);
        w->offset += 4;
        w->left--;
        if (words > 0) {
            proto_tree_add_item(ct, id == NDB_COL_READ_MASKED ?
                                    hf_ndb_column_bitmap :
                                    hf_ndb_column_value,
                                w->tvb, w->offset, 4 * words, ENC_NA);
            w->offset += 4 * words;
            w->left -= words;
        }
        if (reply && id == NDB_COL_READ_MASKED && w->left > 0) {
            proto_tree_add_item(ct, hf_ndb_packed_values, w->tvb, w->offset,
                                4 * w->left, ENC_NA);
            proto_item_set_len(ci, 4 * (1 + words + w->left));
            w->offset += 4 * w->left;
            w->left = 0;
        }
    }
}

/* Section 0 of LIST_OBJECTS_CONF: three words for each object. */
static void
ndb_objects(ndb_words_t *w)
{
    unsigned n = 0;

    while (w->left >= NDB_OBJECT_WORDS) {
        ndb_words_t object = *w;
        proto_item *oi;
        uint32_t id;
        uint32_t kind;

        n++;
        object.tree = proto_tree_add_subtree_format(w->tree, w->tvb,
                w->offset, 4 * NDB_OBJECT_WORDS, ett_ndb_object, &oi,
                "Object %u", n);
        object.left = NDB_OBJECT_WORDS;
        ndb_bits(&object, hf_ndb_object_flags, ett_ndb_object_flags,
                 ndb_object_flags_fields);
        id = ndb_word(&object, hf_ndb_object_id);
        kind = ndb_word(&object, hf_ndb_object_kind);
        proto_item_append_text(oi, ": id %u, %s", id,
                val_to_str_const(kind, ndb_object_kind_vals, "other kind"));
        w->offset += 4 * NDB_OBJECT_WORDS;
        w->left -= NDB_OBJECT_WORDS;
    }
    ndb_rest(w);
}

/*
 * Section 1 of LIST_OBJECTS_CONF: for each object its name's length in
 * bytes, counting the NUL, then the name padded to whole words.
 */
static void
ndb_object_names(ndb_words_t *w)
{
    while (w->left > 0) {
        uint32_t size = ndb_word(w, hf_ndb_object_name_len);
        unsigned words = (size + 3) / 4;

        if (words > w->left)
            words = w->left;
        if (words == 0)
            continue;
        proto_tree_add_item(w->tree, hf_ndb_object_name, w->tvb, w->offset,
                            4 * words, ENC_ASCII);
        w->offset += 4 * words;
        w->left -= words;
    }
}

/*
 * The form of SCAN_CONF's `count` entries in the words left: 3 for the
 * short form, where an entry with all ones for rows takes a fourth word;
 * 4 or 5 for the extended form the request asks for with flag bit 29.
 * The confirmation does not say which. Five words an entry can only be
 * the extended form. Four can also be the short form with every entry's
 * rows in a fourth word, which needs all ones in each third word.
 */
static unsigned
ndb_scan_entry_form(const ndb_words_t *w, unsigned count)
{
    unsigned i;

    if (count == 0)
        return 3;
    if (w->left == 5 * count)
        return 5;
    if (w->left != 4 * count)
        return 3;
    for (i = 0; i < count; i++) {
        uint32_t info = tvb_get_uint32(w->tvb, w->offset + 16 * i + 8,
                                       w->encoding);
        if ((info & NDB_RECEIVER_ROWS) != NDB_RECEIVER_ROWS)
            return 4;
    }
    return 3;
}

/*
 * SCAN_CONF's entries, one per receiver reported: its id and the
 * coordinator's pointer for it, then its batch. In the short form the
 * batch is one word, its length in words above bit 10 and its rows
 * below, rows all ones meaning a fourth word holds them. In the
 * extended form the rows and the length are words of their own, and an
 * API of 8.0.20 or later gets a fifth, the join's active mask. At most
 * `count`, as the confirmation's own word says.
 */
static void
ndb_scan_entries(ndb_words_t *w, unsigned count)
{
    unsigned form = ndb_scan_entry_form(w, count);
    unsigned n = 0;

    while (w->left >= form && n < count) {
        unsigned at = w->offset;
        uint32_t third = tvb_get_uint32(w->tvb, at + 8, w->encoding);
        uint32_t rows;
        uint32_t len;
        unsigned words = form;
        ndb_words_t entry = *w;
        proto_item *ei;
        uint32_t id;

        if (form == 3) {
            rows = third & NDB_RECEIVER_ROWS;
            len = third >> 10;
            if (rows == NDB_RECEIVER_ROWS && w->left >= 4) {
                words = 4;
                rows = tvb_get_uint32(w->tvb, at + 12, w->encoding);
            }
        } else {
            rows = third;
            len = tvb_get_uint32(w->tvb, at + 12, w->encoding);
        }
        n++;
        entry.tree = proto_tree_add_subtree_format(w->tree, w->tvb, at,
                4 * words, ett_ndb_receiver, &ei, "Receiver %u", n);
        entry.left = words;
        id = ndb_word(&entry, hf_ndb_receiver_id);
        ndb_word(&entry, hf_ndb_receiver_coord);
        if (form == 3) {
            ndb_bits(&entry, hf_ndb_receiver_info, ett_ndb_receiver_info,
                     ndb_receiver_info_fields);
            if (words == 4)
                ndb_word(&entry, hf_ndb_receiver_rows_word);
        } else {
            ndb_word(&entry, hf_ndb_receiver_rows_word);
            ndb_word(&entry, hf_ndb_receiver_len_word);
            if (form == 5)
                ndb_word(&entry, hf_ndb_receiver_active);
        }
        proto_item_append_text(ei, ": id 0x%08x, %u rows in %u words", id,
                               rows, len);
        w->offset += 4 * words;
        w->left -= words;
    }
    ndb_rest(w);
}

/*
 * SCAN_REQ's column section: five size words, then the columns to read,
 * as many words as the first size says; what follows is shown as words.
 */
static void
ndb_scan_columns(ndb_words_t *w)
{
    uint32_t first = 0;
    unsigned i;
    ndb_words_t list;
    unsigned used;

    for (i = 0; i < NDB_SCAN_SIZE_WORDS && w->left > 0; i++) {
        unsigned at = w->offset;
        proto_item *ti;
        uint32_t value = tvb_get_uint32(w->tvb, at, w->encoding);

        if (i == 0)
            first = value;
        ti = proto_tree_add_item(w->tree, hf_ndb_column_size_word, w->tvb,
                                 at, 4, w->encoding);
        proto_item_append_text(ti, " (size word %u)", i + 1);
        w->offset += 4;
        w->left--;
    }
    list = *w;
    used = first < w->left ? first : w->left;
    list.left = used;
    ndb_columns(&list, false);
    w->offset += 4 * used;
    w->left -= used;
    ndb_rest(w);
}

/*
 * SCAN_REQ's bounds: per bound a word with its type, and in a range's
 * first word also the range's number and length, then a column header
 * (the column's id in the index, the value's bytes) and the value
 * padded to whole words.
 */
static void
ndb_bounds(ndb_words_t *w)
{
    while (w->left > 0) {
        unsigned at = w->offset;
        uint32_t word = tvb_get_uint32(w->tvb, at, w->encoding);
        uint32_t header = 0;
        unsigned words = 0;
        proto_tree *bt;
        proto_item *bi;

        bt = proto_tree_add_subtree(w->tree, w->tvb, at, 4, ett_ndb_bound,
                                    &bi, "Bound");
        proto_tree_add_bitmask(bt, w->tvb, at, hf_ndb_bound,
                               ett_ndb_bound_word, ndb_bound_fields,
                               w->encoding);
        w->offset += 4;
        w->left--;
        if (w->left > 0) {
            header = tvb_get_uint32(w->tvb, w->offset, w->encoding);
            proto_tree_add_bitmask(bt, w->tvb, w->offset,
                                   hf_ndb_column_header,
                                   ett_ndb_column_header,
                                   ndb_column_header_fields, w->encoding);
            w->offset += 4;
            w->left--;
            words = ((header & NDB_COL_SIZE) + 3) / 4;
            if (words > w->left)
                words = w->left;
        }
        if (words > 0) {
            proto_tree_add_item(bt, hf_ndb_column_value, w->tvb, w->offset,
                                4 * words, ENC_NA);
            w->offset += 4 * words;
            w->left -= words;
        }
        proto_item_set_len(bi, (int)(w->offset - at));
        proto_item_set_text(bi, "Bound %s, column %u, %u bytes",
                            val_to_str_const(word & 0xF, ndb_bound_vals,
                                             "of another type"),
                            header >> 16, header & NDB_COL_SIZE);
    }
}

/* Data words, by signal; whatever is not named is shown as words. */
static void
ndb_signal_data(ndb_words_t *w, uint32_t signal)
{
    unsigned i;
    unsigned ops;
    unsigned gci_at;
    uint32_t gci_hi;
    uint32_t flags;
    uint32_t count;
    proto_tree *op_tree;

    switch (signal) {
    case NDB_SIG_HEARTBEAT_REQ:
        ndb_bits(w, hf_ndb_block_ref, ett_ndb_ref, ndb_ref_fields);
        ndb_word(w, hf_ndb_version);
        ndb_word(w, hf_ndb_mysql_version);
        break;
    case NDB_SIG_HEARTBEAT_CONF:
        ndb_bits(w, hf_ndb_block_ref, ett_ndb_ref, ndb_ref_fields);
        ndb_word(w, hf_ndb_version);
        ndb_word(w, hf_ndb_heartbeat);
        ndb_word(w, hf_ndb_mysql_version);
        ndb_word(w, hf_ndb_min_db_version);
        if (ndb_node_state(w))
            ndb_word(w, hf_ndb_min_api_version);
        break;
    case NDB_SIG_HEARTBEAT_REF:
        ndb_bits(w, hf_ndb_block_ref, ett_ndb_ref, ndb_ref_fields);
        ndb_word(w, hf_ndb_version);
        ndb_word(w, hf_ndb_error_code);
        ndb_word(w, hf_ndb_mysql_version);
        break;
    case NDB_SIG_KEY_OP_REQ:
    case NDB_SIG_UNIQUE_OP_REQ:
        ndb_word(w, hf_ndb_coord_ptr);
        ndb_word(w, hf_ndb_query_ref);
        ndb_word(w, hf_ndb_column_data_len);
        ndb_word(w, hf_ndb_table_id);
        flags = ndb_bits(w, hf_ndb_flags, ett_ndb_flags, ndb_flags_fields);
        ndb_word(w, hf_ndb_table_version);
        ndb_trans_id(w);
        /*
         * A long KEY_OP_REQ's optional words, each only when its flag is
         * set and in this order: the user id and its version, a
         * takeover's scan information, the distribution key.
         */
        if (signal == NDB_SIG_KEY_OP_REQ && w->sections > 0) {
            if (flags & NDB_FLAG_USER_ID) {
                ndb_word(w, hf_ndb_user_id);
                ndb_word(w, hf_ndb_user_id_version);
            }
            if (flags & NDB_FLAG_TAKEOVER)
                ndb_bits(w, hf_ndb_takeover_info, ett_ndb_takeover_info,
                         ndb_takeover_info_fields);
            if (flags & NDB_FLAG_DIST_KEY)
                ndb_word(w, hf_ndb_op_dist_key);
        }
        break;
    case NDB_SIG_KEY_OP_CONF:
    case NDB_SIG_UNIQUE_OP_CONF:
        ndb_word(w, hf_ndb_client_ptr);
        gci_at = w->offset;
        gci_hi = ndb_word(w, hf_ndb_gci_hi);
        ops = ndb_bits(w, hf_ndb_info, ett_ndb_info, ndb_info_fields) & 0xFFFF;
        ndb_trans_id(w);
        for (i = 0; i < ops && w->left >= 2; i++) {
            op_tree = proto_tree_add_subtree_format(w->tree, w->tvb, w->offset,
                                                    8, ett_ndb_op, NULL,
                                                    "Operation %u", i + 1);
            {
                ndb_words_t op = *w;
                op.tree = op_tree;
                op.left = 2;
                ndb_word(&op, hf_ndb_op_query_ref);
                ndb_word(&op, hf_ndb_op_row_len);
            }
            w->offset += 8;
            w->left -= 2;
        }
        ndb_gci(w, gci_hi, gci_at, w->left > 0);
        break;
    case NDB_SIG_KEY_OP_REF:
    case NDB_SIG_UNIQUE_OP_REF:
        ndb_word(w, hf_ndb_query_ref);
        ndb_trans_id(w);
        ndb_word(w, hf_ndb_error_code);
        ndb_word(w, hf_ndb_error_data);
        break;
    case NDB_SIG_ROW_DATA_REP:
        ndb_word(w, hf_ndb_row_for);
        ndb_trans_id(w);
        if (w->sections > 0) {
            /* The long form: the row is section 0, this its length. */
            ndb_word(w, hf_ndb_row_len);
        } else if (w->left > 0) {
            ndb_words_t row = *w;
            proto_item *ri = proto_tree_add_item(w->tree, hf_ndb_row, w->tvb,
                                                 w->offset, w->left * 4,
                                                 ENC_NA);
            row.tree = proto_item_add_subtree(ri, ett_ndb_row);
            ndb_columns(&row, true);
            w->offset = row.offset;
            w->left = 0;
        }
        break;
    case NDB_SIG_COMMIT_REQ:
    case NDB_SIG_ROLLBACK_REQ:
        ndb_word(w, hf_ndb_coord_ptr);
        ndb_trans_id(w);
        break;
    case NDB_SIG_SCAN_REQ:
        ndb_word(w, hf_ndb_coord_ptr);
        ndb_word(w, hf_ndb_scan_spare);
        flags = ndb_bits(w, hf_ndb_scan_flags, ett_ndb_scan_flags,
                         ndb_scan_flags_fields);
        ndb_word(w, hf_ndb_table_id);
        ndb_word(w, hf_ndb_table_version);
        ndb_bits(w, hf_ndb_scan_word5, ett_ndb_scan_word5,
                 ndb_scan_word5_fields);
        ndb_trans_id(w);
        ndb_word(w, hf_ndb_trans_record);
        ndb_word(w, hf_ndb_batch_bytes);
        ndb_word(w, hf_ndb_batch_rows);
        if (flags & NDB_SCAN_DIST_KEY)
            ndb_word(w, hf_ndb_dist_key);
        break;
    case NDB_SIG_SCAN_CONF:
        ndb_word(w, hf_ndb_client_ptr);
        count = ndb_bits(w, hf_ndb_scan_conf_info, ett_ndb_scan_conf_info,
                         ndb_scan_conf_info_fields) & NDB_SCAN_CONF_COUNT;
        ndb_trans_id(w);
        if (w->sections == 0)
            ndb_scan_entries(w, count);
        break;
    case NDB_SIG_SCAN_REF:
        ndb_word(w, hf_ndb_client_ptr);
        ndb_trans_id(w);
        ndb_word(w, hf_ndb_error_code);
        ndb_word(w, hf_ndb_close_owed);
        break;
    case NDB_SIG_SCAN_MORE_REQ:
        ndb_word(w, hf_ndb_coord_ptr);
        ndb_word(w, hf_ndb_stop);
        ndb_trans_id(w);
        while (w->left > 0)
            ndb_word(w, hf_ndb_receiver_coord);
        break;
    case NDB_SIG_SCAN_ROW_KEY_REP:
        ndb_word(w, hf_ndb_receiver_id);
        ndb_word(w, hf_ndb_key_len);
        ndb_bits(w, hf_ndb_row_key_info, ett_ndb_row_key_info,
                 ndb_row_key_info_fields);
        ndb_trans_id(w);
        if (w->left > 0) {
            proto_tree_add_item(w->tree, hf_ndb_key, w->tvb, w->offset,
                                4 * w->left, ENC_NA);
            w->offset += 4 * w->left;
            w->left = 0;
        }
        break;
    case NDB_SIG_COMMIT_CONF:
        ndb_client_ptr_flagged(w);
        ndb_trans_id(w);
        gci_at = w->offset;
        gci_hi = ndb_word(w, hf_ndb_gci_hi);
        ndb_gci(w, gci_hi, gci_at, w->left > 0);
        break;
    case NDB_SIG_TAKEOVER_CONF:
        ndb_client_ptr_flagged(w);
        ndb_trans_id(w);
        break;
    case NDB_SIG_COMMIT_REF:
    case NDB_SIG_ROLLBACK_REF:
        ndb_word(w, hf_ndb_client_ptr);
        ndb_trans_id(w);
        ndb_word(w, hf_ndb_error_code);
        break;
    case NDB_SIG_ROLLBACK_CONF:
    case NDB_SIG_TAKEOVER_REF:
        ndb_word(w, hf_ndb_client_ptr);
        ndb_trans_id(w);
        break;
    case NDB_SIG_TRANS_ABORTED_REP:
        ndb_word(w, hf_ndb_client_ptr);
        ndb_trans_id(w);
        ndb_word(w, hf_ndb_error_code);
        ndb_word(w, hf_ndb_error_data);
        break;
    case NDB_SIG_COMMIT_MARKER_FREE_ORD:
        ndb_trans_id(w);
        break;
    case NDB_SIG_COORD_ALLOC_REQ:
        ndb_word(w, hf_ndb_client_ptr);
        ndb_bits(w, hf_ndb_block_ref, ett_ndb_ref, ndb_ref_fields);
        ndb_word(w, hf_ndb_instance);
        ndb_word(w, hf_ndb_release_id);
        break;
    case NDB_SIG_COORD_ALLOC_CONF:
        ndb_word(w, hf_ndb_client_ptr);
        ndb_word(w, hf_ndb_coord_ptr);
        ndb_bits(w, hf_ndb_block_ref, ett_ndb_ref, ndb_ref_fields);
        break;
    case NDB_SIG_COORD_ALLOC_REF:
    case NDB_SIG_COORD_FREE_REF:
        ndb_word(w, hf_ndb_client_ptr);
        ndb_word(w, hf_ndb_error_code);
        break;
    case NDB_SIG_COORD_FREE_REQ:
        ndb_word(w, hf_ndb_coord_ptr);
        ndb_bits(w, hf_ndb_block_ref, ett_ndb_ref, ndb_ref_fields);
        ndb_word(w, hf_ndb_client_ptr);
        ndb_word(w, hf_ndb_release_id);
        break;
    case NDB_SIG_COORD_FREE_CONF:
        ndb_word(w, hf_ndb_client_ptr);
        break;
    case NDB_SIG_TABLE_DESC_REQ:
        ndb_word(w, hf_ndb_caller_data);
        ndb_bits(w, hf_ndb_block_ref, ett_ndb_ref, ndb_ref_fields);
        ndb_word(w, hf_ndb_request_type);
        ndb_word(w, hf_ndb_id_or_name_len);
        ndb_word(w, hf_ndb_schema_trans);
        break;
    case NDB_SIG_TABLE_DESC_CONF:
        ndb_word(w, hf_ndb_caller_data);
        ndb_word(w, hf_ndb_table_id);
        ndb_word(w, hf_ndb_gci_word);
        ndb_word(w, hf_ndb_total_len);
        ndb_word(w, hf_ndb_table_kind);
        ndb_bits(w, hf_ndb_block_ref, ett_ndb_ref, ndb_ref_fields);
        break;
    case NDB_SIG_TABLE_DESC_REF:
        /* The request's words come back, then why and where. */
        ndb_word(w, hf_ndb_caller_data);
        ndb_bits(w, hf_ndb_block_ref, ett_ndb_ref, ndb_ref_fields);
        ndb_word(w, hf_ndb_request_type);
        ndb_word(w, hf_ndb_id_or_name_len);
        if (w->left >= 3) {
            ndb_word(w, hf_ndb_schema_trans);
            ndb_word(w, hf_ndb_error_code);
            ndb_word(w, hf_ndb_error_line);
        } else {
            /* An older node sends five words, the error last. */
            ndb_word(w, hf_ndb_error_code);
        }
        break;
    case NDB_SIG_LIST_OBJECTS_REQ:
        ndb_word(w, hf_ndb_caller_data);
        ndb_bits(w, hf_ndb_block_ref, ett_ndb_ref, ndb_ref_fields);
        ndb_bits(w, hf_ndb_list_flags, ett_ndb_list_flags,
                 ndb_list_flags_fields);
        ndb_word(w, hf_ndb_table_id);
        ndb_word(w, hf_ndb_object_kind);
        break;
    case NDB_SIG_LIST_OBJECTS_CONF:
        ndb_word(w, hf_ndb_caller_data);
        ndb_word(w, hf_ndb_object_count);
        /* The trailer, if any; see ndb_has_trailer(). */
        while (w->left > 1)
            ndb_word(w, hf_ndb_section_number);
        ndb_word(w, hf_ndb_fragment_id);
        break;
    case NDB_SIG_COLLATION_DESC_REQ:
        ndb_bits(w, hf_ndb_block_ref, ett_ndb_ref, ndb_ref_fields);
        ndb_word(w, hf_ndb_caller_data);
        ndb_word(w, hf_ndb_coll_kind);
        ndb_word(w, hf_ndb_coll_number);
        ndb_word(w, hf_ndb_coll_name_len);
        ndb_bits(w, hf_ndb_coll_req_flags, ett_ndb_coll_req_flags,
                 ndb_coll_req_flags_fields);
        ndb_word(w, hf_ndb_coll_position);
        break;
    case NDB_SIG_COLLATION_DESC_CONF:
        ndb_word(w, hf_ndb_caller_data);
        ndb_word(w, hf_ndb_coll_number);
        ndb_word(w, hf_ndb_coll_default);
        ndb_word(w, hf_ndb_coll_binary);
        ndb_bits(w, hf_ndb_coll_flags, ett_ndb_coll_flags,
                 ndb_coll_flags_fields);
        ndb_word(w, hf_ndb_coll_min_bytes);
        ndb_word(w, hf_ndb_coll_max_bytes);
        ndb_word(w, hf_ndb_coll_sort_growth);
        ndb_bits(w, hf_ndb_coll_case_word, ett_ndb_coll_case,
                 ndb_coll_case_fields);
        ndb_word(w, hf_ndb_coll_pad);
        ndb_word(w, hf_ndb_coll_levels);
        ndb_word(w, hf_ndb_coll_min_sort);
        ndb_word(w, hf_ndb_coll_max_sort);
        ndb_bits(w, hf_ndb_coll_names_word, ett_ndb_coll_names,
                 ndb_coll_names_fields);
        ndb_word(w, hf_ndb_coll_weight_entries);
        ndb_word(w, hf_ndb_coll_weights_len);
        ndb_word(w, hf_ndb_coll_contraction_entries);
        ndb_word(w, hf_ndb_coll_contractions_len);
        ndb_word(w, hf_ndb_coll_next_position);
        break;
    case NDB_SIG_COLLATION_DESC_REF:
        ndb_word(w, hf_ndb_caller_data);
        ndb_word(w, hf_ndb_coll_error);
        ndb_word(w, hf_ndb_coll_kind);
        ndb_word(w, hf_ndb_coll_number);
        break;
    default:
        break;
    }
    ndb_rest(w);
}

/* What a signal's sections hold, where we know. */
static const char *
ndb_section_name(uint32_t signal, unsigned part)
{
    switch (signal) {
    case NDB_SIG_KEY_OP_REQ:
    case NDB_SIG_UNIQUE_OP_REQ:
        return part == 0 ? "key" : (part == 1 ? "columns" : NULL);
    case NDB_SIG_ROW_DATA_REP:
        return part == 0 ? "row" : NULL;
    case NDB_SIG_SCAN_REQ:
        return part == 0 ? "receivers" :
               (part == 1 ? "columns" : (part == 2 ? "bounds" : NULL));
    case NDB_SIG_SCAN_CONF:
    case NDB_SIG_SCAN_MORE_REQ:
        return part == 0 ? "receivers" : NULL;
    case NDB_SIG_SCAN_ROW_KEY_REP:
        return part == 0 ? "key" : NULL;
    case NDB_SIG_LIST_OBJECTS_CONF:
        return part == 0 ? "objects" : (part == 1 ? "names" : NULL);
    case NDB_SIG_TABLE_DESC_REQ:
        return part == 0 ? "name" : NULL;
    case NDB_SIG_TABLE_DESC_CONF:
        return part == 0 ? "description" : NULL;
    case NDB_SIG_COLLATION_DESC_REQ:
        return part == 0 ? "name" : NULL;
    case NDB_SIG_COLLATION_DESC_CONF:
        return part == 0 ? "names" : (part == 1 ? "weights" : NULL);
    default:
        return NULL;
    }
}

/* Sections that hold names, shown as text too. */
static bool
ndb_section_is_text(uint32_t signal)
{
    return signal == NDB_SIG_TABLE_DESC_REQ ||
           signal == NDB_SIG_COLLATION_DESC_REQ ||
           signal == NDB_SIG_COLLATION_DESC_CONF;
}

/*
 * Section 1 of a collation description: weight runs, padded to a word,
 * then contractions, padded likewise. Numbers in it are big-endian.
 */
static void
ndb_weights(tvbuff_t *tvb, proto_tree *tree, unsigned at, unsigned len,
            uint32_t runs, uint32_t runs_len, uint32_t contractions,
            uint32_t contractions_len)
{
    unsigned end = at + len;
    unsigned pos = at;
    unsigned runs_end = at + runs_len;
    unsigned contractions_at = at + ((runs_len + 3) & ~3U);
    unsigned contractions_end = contractions_at + contractions_len;
    uint32_t n;

    if (runs_end > end)
        runs_end = end;
    if (contractions_end > end)
        contractions_end = end;
    proto_tree *wt = proto_tree_add_subtree_format(tree, tvb, at, len,
            ett_ndb_weights, NULL, "Weights: %u runs, %u contractions",
            runs, contractions);

    for (n = 0; n < runs && pos + 10 <= runs_end; n++) {
        uint32_t first = tvb_get_uint24(tvb, pos, ENC_BIG_ENDIAN);
        uint32_t count = tvb_get_uint24(tvb, pos + 3, ENC_BIG_ENDIAN);
        unsigned enc_len = tvb_get_uint8(tvb, pos + 7);
        unsigned weight_len = tvb_get_ntohs(tvb, pos + 8);
        unsigned size = 10 + enc_len + weight_len;
        proto_tree *rt;

        if (pos + size > runs_end)
            break;
        if (count > 1)
            rt = proto_tree_add_subtree_format(wt, tvb, pos, size,
                    ett_ndb_weight_run, NULL,
                    "U+%04X to U+%04X, %u code points", first,
                    first + count - 1, count);
        else
            rt = proto_tree_add_subtree_format(wt, tvb, pos, size,
                    ett_ndb_weight_run, NULL, "U+%04X", first);
        proto_tree_add_item(rt, hf_ndb_wr_first, tvb, pos, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(rt, hf_ndb_wr_count, tvb, pos + 3, 3,
                            ENC_BIG_ENDIAN);
        proto_tree_add_item(rt, hf_ndb_wr_step, tvb, pos + 6, 1, ENC_NA);
        proto_tree_add_item(rt, hf_ndb_wr_encoded_len, tvb, pos + 7, 1,
                            ENC_NA);
        proto_tree_add_item(rt, hf_ndb_wr_weight_len, tvb, pos + 8, 2,
                            ENC_BIG_ENDIAN);
        if (enc_len > 0)
            proto_tree_add_item(rt, hf_ndb_wr_encoded, tvb, pos + 10,
                                enc_len, ENC_NA);
        if (weight_len > 0)
            proto_tree_add_item(rt, hf_ndb_wr_weight, tvb,
                                pos + 10 + enc_len, weight_len, ENC_NA);
        pos += size;
    }

    pos = contractions_at;
    for (n = 0; n < contractions && pos + 4 <= contractions_end; n++) {
        unsigned points = tvb_get_uint8(tvb, pos);
        unsigned weight_len = tvb_get_ntohs(tvb, pos + 2);
        unsigned size = 4 + 3 * points + weight_len;
        unsigned k;
        proto_tree *ct;

        if (pos + size > contractions_end)
            break;
        ct = proto_tree_add_subtree_format(wt, tvb, pos, size,
                ett_ndb_contraction, NULL, "Contraction of %u code points",
                points);
        proto_tree_add_item(ct, hf_ndb_ct_points, tvb, pos, 1, ENC_NA);
        proto_tree_add_item(ct, hf_ndb_ct_previous, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item(ct, hf_ndb_ct_weight_len, tvb, pos + 2, 2,
                            ENC_BIG_ENDIAN);
        for (k = 0; k < points; k++)
            proto_tree_add_item(ct, hf_ndb_ct_code_point, tvb,
                                pos + 4 + 3 * k, 3, ENC_BIG_ENDIAN);
        if (weight_len > 0)
            proto_tree_add_item(ct, hf_ndb_ct_weight, tvb,
                                pos + 4 + 3 * points, weight_len, ENC_NA);
        pos += size;
    }
}

/* ---- Messages ---- */

/*
 * Whether a message's data ends with a trailer: the number of each
 * section it carries, then a fragment id. Every fragment has one. So
 * may a LIST_OBJECTS_CONF sent whole: the dictionary sends its two
 * words alone, or with a trailer for the sections it carries, none,
 * one (object data or names) or both. Section numbers 0 and 1 are the
 * object data and the names whichever position they are carried in.
 * A long answer goes in pieces of 240 words with the fragment bits set.
 */
static bool
ndb_has_trailer(uint32_t signal, unsigned fragment, unsigned data_words,
                unsigned sections)
{
    if (data_words < sections + 1)
        return false;
    if (fragment != 0)
        return true;
    return signal == NDB_SIG_LIST_OBJECTS_CONF &&
           data_words == NDB_LIST_OBJECTS_CONF_WORDS + sections + 1;
}

/* One bundle: parts of the same signal, each for its own block. */
static void
ndb_bundle(ndb_words_t *w, uint32_t signal, packet_info *pinfo)
{
    unsigned part = 0;

    while (w->left > 0) {
        unsigned at = w->offset;
        uint32_t header = tvb_get_uint32(w->tvb, at, w->encoding);
        unsigned len = (header & 0x1F) + 3;
        unsigned shown = len < w->left - 1 ? len : w->left - 1;
        proto_tree *part_tree;
        proto_item *part_item;
        ndb_words_t inner;

        part++;
        part_tree = proto_tree_add_subtree_format(w->tree, w->tvb, at,
                (int)(4 * (1 + shown)), ett_ndb_part,
                &part_item, "Part %u", part);
        proto_tree_add_bitmask(part_tree, w->tvb, at, hf_ndb_part_header,
                               ett_ndb_part_header, ndb_part_header_fields,
                               w->encoding);
        w->offset += 4;
        w->left--;
        if (len > w->left) {
            expert_add_info_format(pinfo, part_item, &ei_ndb_short,
                                   "The part says %u words; %u are left",
                                   len, w->left);
            len = w->left;
        }
        inner = *w;
        inner.tree = part_tree;
        inner.left = len;
        ndb_signal_data(&inner, signal);
        w->offset += 4 * len;
        w->left -= len;
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%u parts)", part);
}

/* ---- Trains of fragments ---- */

static void
ndb_put_word(uint8_t *p, uint32_t value, unsigned encoding)
{
    if (encoding == ENC_BIG_ENDIAN)
        phtonu32(p, value);
    else
        phtoleu32(p, value);
}

/*
 * Make the joined signal of a train whose last fragment has come: a
 * whole message, in the sender's byte order, of the last fragment's own
 * data (own words at data_at) and the joined sections. Without a signal
 * id or a checksum. Left undone if it would not fit a length field.
 */
static void
ndb_train_join(tvbuff_t *tvb, ndb_train_t *train, uint32_t w1, uint32_t w2,
               uint32_t w3, unsigned data_at, unsigned own)
{
    unsigned words = NDB_HEADER_WORDS + own + train->sections;
    unsigned i;
    uint8_t *p;

    for (i = 0; i < train->sections; i++)
        words += wmem_array_get_count(train->pieces[i]) / 4;
    if (words > NDB_MAX_JOINED_WORDS)
        return;
    train->joined = (uint8_t *)wmem_alloc(wmem_file_scope(), 4 * words);
    train->joined_words = words;
    p = train->joined;
    ndb_put_word(p, (w1 & (NDB_W1_BYTE_ORDER | NDB_W1_PRIO)) |
                    ((words << 8) & NDB_W1_TOTAL_WORDS) |
                    ((own << 26) & NDB_W1_DATA_WORDS), train->encoding);
    p += 4;
    ndb_put_word(p, (w2 & (NDB_W2_SIGNAL | NDB_W2_VERSION | NDB_W2_TRACE)) |
                    ((train->sections << 26) & NDB_W2_SECTIONS),
                 train->encoding);
    p += 4;
    ndb_put_word(p, w3, train->encoding);
    p += 4;
    tvb_memcpy(tvb, p, data_at, 4 * own);
    p += 4 * own;
    for (i = 0; i < train->sections; i++) {
        ndb_put_word(p, wmem_array_get_count(train->pieces[i]) / 4,
                     train->encoding);
        p += 4;
    }
    for (i = 0; i < train->sections; i++) {
        unsigned bytes = wmem_array_get_count(train->pieces[i]);

        if (bytes > 0)
            memcpy(p, wmem_array_get_raw(train->pieces[i]), bytes);
        p += bytes;
    }
}

/*
 * On the first pass, add a fragment to its train: a first fragment
 * begins one, any other goes on the one its sender block and fragment
 * id name, and the last joins it. The fragment's numbers and id are the
 * last 1 + sections of its data words; any before them are its own.
 */
static ndb_piece_t *
ndb_train_add(tvbuff_t *tvb, packet_info *pinfo, const ndb_msg_ctx_t *ctx,
              unsigned fragment, uint32_t w1, uint32_t w2, uint32_t w3,
              unsigned data_at, unsigned data_words, unsigned sections,
              const unsigned *section_at, const unsigned *section_len,
              unsigned encoding)
{
    ndb_piece_t *piece = wmem_new0(wmem_file_scope(), ndb_piece_t);
    unsigned numbers_at;
    wmem_map_t *map = ctx->conv->trains[ctx->dir];
    ndb_train_t *train;
    uint64_t *key;
    uint32_t frame = pinfo->num;
    unsigned i;

    if (data_words < sections + 1)
        return piece;
    numbers_at = data_at + 4 * (data_words - 1 - sections);
    if (map == NULL) {
        map = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
        ctx->conv->trains[ctx->dir] = map;
    }
    key = wmem_new(wmem_file_scope(), uint64_t);
    *key = ((uint64_t)(w3 & NDB_W3_SENDER) << 32) |
           tvb_get_uint32(tvb, data_at + 4 * (data_words - 1), encoding);
    if (fragment == NDB_FRAGMENT_FIRST) {
        /* A train left unfinished under the same id is dropped. */
        train = wmem_new0(wmem_file_scope(), ndb_train_t);
        for (i = 0; i < NDB_MAX_SECTIONS; i++)
            train->pieces[i] = wmem_array_new(wmem_file_scope(), 1);
        train->frames = wmem_array_new(wmem_file_scope(), sizeof(uint32_t));
        train->encoding = encoding;
        wmem_map_insert(map, key, train);
    } else {
        train = (ndb_train_t *)wmem_map_lookup(map, key);
        if (train == NULL)
            return piece;
    }
    for (i = 0; i < sections; i++) {
        uint32_t number = tvb_get_uint32(tvb, numbers_at + 4 * i, encoding);

        if (number >= NDB_MAX_SECTIONS)
            continue;
        if (section_len[i] > 0)
            wmem_array_append(train->pieces[number],
                              tvb_get_ptr(tvb, section_at[i],
                                          4 * section_len[i]),
                              4 * section_len[i]);
        if (number + 1 > train->sections)
            train->sections = number + 1;
    }
    wmem_array_append_one(train->frames, frame);
    train->fragments++;
    piece->train = train;
    if (fragment == NDB_FRAGMENT_LAST) {
        piece->last = true;
        train->joined_in = frame;
        ndb_train_join(tvb, train, w1, w2, w3, data_at,
                       data_words - 1 - sections);
        wmem_map_remove(map, key);
    }
    return piece;
}

/*
 * The layout a signal number has here. Signal 28 is SCAN_MORE_REQ only
 * on its way to the coordinator; between data nodes the same number has
 * another layout, shown as words.
 */
static uint32_t
ndb_layout(uint32_t signal, uint32_t receiver)
{
    if (signal == NDB_SIG_SCAN_MORE_REQ &&
        (receiver >= NDB_FIRST_USER_THREAD ||
         (receiver & ((1U << NDB_BLOCK_NUMBER_BITS) - 1)) !=
             NDB_BLOCK_COORDINATOR))
        return NDB_SIG_OTHER;
    return signal;
}

static void
ndb_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
            unsigned offset, unsigned words, unsigned encoding,
            const ndb_msg_ctx_t *ctx, const ndb_train_t *joined)
{
    uint32_t w1 = tvb_get_uint32(tvb, offset, encoding);
    uint32_t w2 = tvb_get_uint32(tvb, offset + 4, encoding);
    uint32_t w3 = tvb_get_uint32(tvb, offset + 8, encoding);
    uint32_t gsn = w2 & NDB_W2_SIGNAL;
    uint32_t receiver = (w3 & NDB_W3_RECEIVER) >> 16;
    uint32_t signal = ndb_layout(gsn, receiver);
    unsigned data_words = (w1 & NDB_W1_DATA_WORDS) >> 26;
    unsigned sections = (w2 & NDB_W2_SECTIONS) >> 26;
    unsigned fragment = ((w1 & NDB_W1_FRAG_HIGH) ? 2 : 0) |
                        ((w1 & NDB_W1_FRAG_LOW) ? 1 : 0);
    bool has_id = (w1 & NDB_W1_SIGNAL_ID) != 0;
    bool has_sum = (w1 & NDB_W1_CHECKSUM) != 0;
    const char *name = val_to_str_const(signal, ndb_signal_vals, "signal");
    unsigned at = offset + 12;
    unsigned end = offset + 4 * words;
    unsigned section_len[NDB_MAX_SECTIONS] = { 0 };
    unsigned section_at[NDB_MAX_SECTIONS] = { 0 };
    unsigned data_at = 0;
    unsigned i;
    proto_tree *msg_tree;
    proto_item *msg_item;
    proto_item *ti;

    if (joined != NULL) {
        unsigned n = wmem_array_get_count(joined->frames);
        uint32_t *frames = (uint32_t *)wmem_array_get_raw(joined->frames);
        uint32_t shown = 0;

        col_append_fstr(pinfo->cinfo, COL_INFO, " (joined from %u)",
                        joined->fragments);
        msg_tree = proto_tree_add_subtree_format(tree, tvb, offset,
                4 * words, ett_ndb_message, &msg_item,
                "Joined %s (signal %u), %u words from %u fragments",
                try_val_to_str(signal, ndb_signal_vals) ? name : "signal",
                gsn, words, joined->fragments);
        ti = proto_tree_add_uint(msg_tree, hf_ndb_train_fragments, tvb, 0, 0,
                                 joined->fragments);
        proto_item_set_generated(ti);
        for (i = 0; i < n; i++) {
            if (frames[i] == shown)
                continue;
            shown = frames[i];
            ti = proto_tree_add_uint(msg_tree, hf_ndb_train_frame, tvb, 0, 0,
                                     shown);
            proto_item_set_generated(ti);
        }
    } else {
        if (try_val_to_str(signal, ndb_signal_vals) != NULL)
            col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", name);
        else
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "signal %u",
                                gsn);
        msg_tree = proto_tree_add_subtree_format(tree, tvb, offset,
                4 * words, ett_ndb_message, &msg_item,
                "%s (signal %u), %u words",
                try_val_to_str(signal, ndb_signal_vals) ? name : "Signal",
                gsn, words);
    }
    proto_tree_add_bitmask(msg_tree, tvb, offset, hf_ndb_word1, ett_ndb_word1,
                           ndb_word1_fields, encoding);
    ti = proto_tree_add_uint(msg_tree, hf_ndb_fragment, tvb, offset, 4,
                             fragment);
    proto_item_set_generated(ti);
    proto_tree_add_bitmask(msg_tree, tvb, offset + 4, hf_ndb_word2,
                           ett_ndb_word2, ndb_word2_fields, encoding);
    proto_tree_add_bitmask(msg_tree, tvb, offset + 8, hf_ndb_word3,
                           ett_ndb_word3, ndb_word3_fields, encoding);

    if (w1 & NDB_W1_COMPRESSED) {
        expert_add_info(pinfo, msg_item, &ei_ndb_compressed);
        return;
    }
    if (has_id) {
        if (at + 4 > end)
            goto short_message;
        proto_tree_add_item(msg_tree, hf_ndb_signal_id, tvb, at, 4, encoding);
        at += 4;
    }
    if (at + 4 * (data_words + sections) + (has_sum ? 4 : 0) > end)
        goto short_message;

    data_at = at;
    if (data_words > 0) {
        ndb_words_t w;
        proto_tree *data_tree = proto_tree_add_subtree_format(msg_tree, tvb,
                at, 4 * data_words, ett_ndb_data, NULL, "Data, %u words",
                data_words);
        w.tvb = tvb;
        w.tree = data_tree;
        w.offset = at;
        w.left = data_words;
        w.encoding = encoding;
        w.sections = sections;
        if (fragment != 0) {
            /*
             * The last word is the fragment id; before it, one section
             * number per section carried. Any words before those are
             * the signal's own data.
             */
            unsigned own = 0;
            if (data_words >= 1 + sections)
                own = data_words - 1 - sections;
            w.left = own;
            ndb_signal_data(&w, signal);
            for (i = 0; i < sections && w.offset + 4 <= at + 4 * data_words - 4;
                 i++) {
                proto_tree_add_item(data_tree, hf_ndb_section_number, tvb,
                                    w.offset, 4, encoding);
                w.offset += 4;
            }
            proto_tree_add_item(data_tree, hf_ndb_fragment_id, tvb,
                                at + 4 * (data_words - 1), 4, encoding);
            expert_add_info(pinfo, msg_item, &ei_ndb_fragment);
        } else if (receiver == NDB_BLOCK_BUNDLE) {
            ndb_bundle(&w, signal, pinfo);
        } else {
            ndb_signal_data(&w, signal);
        }
        at += 4 * data_words;
    }

    if (sections > 0) {
        unsigned total = 0;
        bool trailer = ndb_has_trailer(signal, fragment, data_words,
                                       sections);
        proto_tree *sec_tree = proto_tree_add_subtree_format(msg_tree, tvb, at,
                4 * sections, ett_ndb_sections, NULL, "Sections, %u",
                sections);
        for (i = 0; i < sections; i++) {
            section_len[i] = tvb_get_uint32(tvb, at, encoding);
            proto_tree_add_item(sec_tree, hf_ndb_section_len, tvb, at, 4,
                                encoding);
            total += section_len[i];
            at += 4;
        }
        if (total > (end - at) / 4) {
            expert_add_info_format(pinfo, msg_item, &ei_ndb_short,
                    "The sections say %u words; %u are left", total,
                    (end - at) / 4);
            return;
        }
        for (i = 0; i < sections; i++) {
            /* Which of the original's sections this one is. */
            unsigned number = i;
            const char *what;
            ndb_words_t sw;

            if (trailer)
                number = tvb_get_uint32(tvb,
                        data_at + 4 * (data_words - 1 - sections + i),
                        encoding);
            what = ndb_section_name(signal, number);
            section_at[i] = at;
            ti = proto_tree_add_item(sec_tree, hf_ndb_section, tvb, at,
                                     4 * section_len[i], ENC_NA);
            if (what != NULL)
                proto_item_append_text(ti, " (section %u, %s)", number,
                                       what);
            else
                proto_item_append_text(ti, " (section %u)", number);
            if (ndb_section_is_text(signal) && number == 0 &&
                section_len[i] > 0)
                proto_item_append_text(ti, ": %s",
                        tvb_format_text(pinfo->pool, tvb, at,
                                        4 * section_len[i]));
            sw.tvb = tvb;
            sw.tree = NULL;
            sw.offset = at;
            sw.left = section_len[i];
            sw.encoding = encoding;
            sw.sections = 0;
            if (signal == NDB_SIG_LIST_OBJECTS_CONF) {
                /*
                 * A piece is 240 words, so it holds whole objects of
                 * three; a name may run on into the next piece, so the
                 * names are taken apart only in a whole answer.
                 */
                if (number == 0) {
                    sw.tree = proto_item_add_subtree(ti, ett_ndb_object);
                    ndb_objects(&sw);
                } else if (number == 1 && fragment == 0) {
                    sw.tree = proto_item_add_subtree(ti, ett_ndb_object);
                    ndb_object_names(&sw);
                }
            } else if (fragment == 0) {
                if ((signal == NDB_SIG_KEY_OP_REQ ||
                     signal == NDB_SIG_UNIQUE_OP_REQ) && number == 1) {
                    sw.tree = proto_item_add_subtree(ti, ett_ndb_row);
                    ndb_columns(&sw, false);
                } else if (signal == NDB_SIG_ROW_DATA_REP && number == 0) {
                    sw.tree = proto_item_add_subtree(ti, ett_ndb_row);
                    ndb_columns(&sw, true);
                } else if (signal == NDB_SIG_SCAN_REQ && number == 0) {
                    sw.tree = proto_item_add_subtree(ti, ett_ndb_receiver);
                    while (sw.left > 0)
                        ndb_word(&sw, hf_ndb_receiver_id);
                } else if (signal == NDB_SIG_SCAN_REQ && number == 1) {
                    sw.tree = proto_item_add_subtree(ti, ett_ndb_row);
                    ndb_scan_columns(&sw);
                } else if (signal == NDB_SIG_SCAN_REQ && number == 2) {
                    sw.tree = proto_item_add_subtree(ti, ett_ndb_bound);
                    ndb_bounds(&sw);
                } else if (signal == NDB_SIG_SCAN_CONF && number == 0 &&
                           data_words >= 2) {
                    sw.tree = proto_item_add_subtree(ti, ett_ndb_receiver);
                    ndb_scan_entries(&sw,
                            tvb_get_uint32(tvb, data_at + 4, encoding) &
                            NDB_SCAN_CONF_COUNT);
                } else if (signal == NDB_SIG_SCAN_MORE_REQ && number == 0) {
                    sw.tree = proto_item_add_subtree(ti, ett_ndb_receiver);
                    while (sw.left > 0)
                        ndb_word(&sw, hf_ndb_receiver_coord);
                }
            }
            if (signal == NDB_SIG_COLLATION_DESC_CONF && number == 1 &&
                fragment == 0 && data_words >= 19) {
                proto_tree *wt = proto_item_add_subtree(ti, ett_ndb_weights);
                ndb_weights(tvb, wt, at, 4 * section_len[i],
                            tvb_get_uint32(tvb, data_at + 4 * 14, encoding),
                            tvb_get_uint32(tvb, data_at + 4 * 15, encoding),
                            tvb_get_uint32(tvb, data_at + 4 * 16, encoding),
                            tvb_get_uint32(tvb, data_at + 4 * 17, encoding));
            }
            at += 4 * section_len[i];
        }
    }

    if (has_sum) {
        uint32_t sum = 0;
        unsigned pos;
        for (pos = offset; pos < end - 4; pos += 4)
            sum ^= tvb_get_uint32(tvb, pos, encoding);
        ti = proto_tree_add_item(msg_tree, hf_ndb_checksum, tvb, end - 4, 4,
                                 encoding);
        if (tvb_get_uint32(tvb, end - 4, encoding) != sum)
            expert_add_info_format(pinfo, ti, &ei_ndb_bad_checksum,
                                   "Should be 0x%08x", sum);
    }

    if (fragment != 0 && ctx != NULL) {
        ndb_piece_t *piece = (ndb_piece_t *)p_get_proto_data(
                wmem_file_scope(), pinfo, proto_ndb, ctx->key);
        ndb_train_t *train;

        if (piece == NULL && !PINFO_FD_VISITED(pinfo)) {
            piece = ndb_train_add(tvb, pinfo, ctx, fragment, w1, w2, w3,
                                  data_at, data_words, sections, section_at,
                                  section_len, encoding);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_ndb, ctx->key,
                             piece);
        }
        if (piece == NULL)
            return;
        train = piece->train;
        if (train == NULL) {
            expert_add_info(pinfo, msg_item, &ei_ndb_unjoined);
        } else if (!piece->last) {
            if (train->joined_in != 0) {
                ti = proto_tree_add_uint(msg_tree, hf_ndb_joined_in, tvb, 0,
                                         0, train->joined_in);
                proto_item_set_generated(ti);
            }
        } else if (train->joined == NULL) {
            expert_add_info_format(pinfo, msg_item, &ei_ndb_unjoined,
                    "The joined signal would be over %u words",
                    NDB_MAX_JOINED_WORDS);
        } else {
            tvbuff_t *jt = tvb_new_child_real_data(tvb, train->joined,
                    4 * train->joined_words, 4 * train->joined_words);

            add_new_data_source(pinfo, jt, "Joined signal");
            ndb_message(jt, pinfo, tree, 0, train->joined_words,
                        train->encoding, NULL, train);
        }
    }
    return;

short_message:
    expert_add_info_format(pinfo, msg_item, &ei_ndb_short,
                           "The header promises more than the %u words",
                           words);
}

/* ---- Text and the stream ---- */

static bool
ndb_is_text_byte(uint8_t b)
{
    return b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b < 0x7f);
}

/* Whether the bytes from offset up to end are all text. */
static bool
ndb_is_text(tvbuff_t *tvb, unsigned offset, unsigned end)
{
    for (; offset < end; offset++)
        if (!ndb_is_text_byte(tvb_get_uint8(tvb, offset)))
            return false;
    return true;
}

/*
 * Whether a client's line asks for a signal link: the first line of a
 * link to a data node ("ndbd", alone or followed by what the client can
 * do about encryption), or "transporter connect" toward the management
 * server.
 */
static bool
ndb_asks_for_link(tvbuff_t *tvb, unsigned offset, unsigned len)
{
    const unsigned link_len = (unsigned)strlen(NDB_LINK_LINE);
    const unsigned connect_len = (unsigned)strlen(NDB_TRANSPORTER_CONNECT);

    if (len == connect_len &&
        tvb_memeql(tvb, offset, (const uint8_t *)NDB_TRANSPORTER_CONNECT,
                   connect_len) == 0)
        return true;
    if (len < link_len ||
        tvb_memeql(tvb, offset, (const uint8_t *)NDB_LINK_LINE,
                   link_len) != 0)
        return false;
    return len == link_len || tvb_get_uint8(tvb, offset + link_len) == ' ';
}

/*
 * Whether a line of a link's handshake is its hello, the last line
 * each side sends before its messages: decimal numbers and spaces, at
 * most 23 bytes.
 */
static bool
ndb_is_hello(tvbuff_t *tvb, unsigned offset, unsigned len)
{
    bool digit = false;
    unsigned i;

    if (len > NDB_HELLO_MAX_BYTES)
        return false;
    for (i = 0; i < len; i++) {
        uint8_t b = tvb_get_uint8(tvb, offset + i);

        if (g_ascii_isdigit(b))
            digit = true;
        else if (b != ' ')
            return false;
    }
    return digit;
}

/*
 * The numbers of a hello, by position: the sender's node id, the link
 * type, the far node's id and which of the links between the two nodes
 * this is. The client sends two to four of them, the data node's reply
 * the first two.
 */
static void
ndb_hello(tvbuff_t *tvb, proto_item *line_item, unsigned offset,
          unsigned len)
{
    static int * const fields[] = {
        &hf_ndb_hello_node,
        &hf_ndb_hello_link_type,
        &hf_ndb_hello_far_node,
        &hf_ndb_hello_instance
    };
    proto_tree *tree = proto_item_add_subtree(line_item, ett_ndb_line);
    unsigned end = offset + len;
    unsigned n = 0;

    while (offset < end && n < array_length(fields)) {
        unsigned start;
        uint32_t value = 0;

        while (offset < end && tvb_get_uint8(tvb, offset) == ' ')
            offset++;
        if (offset == end)
            break;
        start = offset;
        while (offset < end && g_ascii_isdigit(tvb_get_uint8(tvb, offset))) {
            value = value * 10 + (tvb_get_uint8(tvb, offset) - '0');
            offset++;
        }
        proto_tree_add_uint(tree, *fields[n], tvb, start, offset - start,
                            value);
        n++;
    }
}

/* Which way a frame goes: 0 from the client, 1 from the server. */
static int
ndb_direction(const ndb_conv_t *conv, packet_info *pinfo)
{
    if (pinfo->srcport == conv->client_port &&
        addresses_equal(&pinfo->src, &conv->client_addr))
        return 0;
    return 1;
}

static ndb_conv_t *
ndb_get_conv(packet_info *pinfo)
{
    conversation_t *conversation = find_or_create_conversation(pinfo);
    ndb_conv_t *conv = (ndb_conv_t *)conversation_get_proto_data(conversation,
                                                                proto_ndb);

    if (conv == NULL) {
        conv = wmem_new0(wmem_file_scope(), ndb_conv_t);
        /*
         * The client speaks first. Toward the management port that is
         * always so; elsewhere the first frame seen is taken as the
         * client's, which is right when the capture holds the start.
         */
        if (pinfo->srcport == NDB_MGM_PORT) {
            copy_address_wmem(wmem_file_scope(), &conv->client_addr,
                              &pinfo->dst);
            conv->client_port = pinfo->destport;
        } else {
            copy_address_wmem(wmem_file_scope(), &conv->client_addr,
                              &pinfo->src);
            conv->client_port = pinfo->srcport;
        }
        conversation_add_proto_data(conversation, proto_ndb, conv);
    }
    return conv;
}

/*
 * Where this call starts: remembered from the first pass, per call
 * within the frame, since one frame may be given to us more than once
 * (a reassembled message, then the rest of the segment).
 */
static const ndb_call_t *
ndb_call_start(packet_info *pinfo, const ndb_conv_t *conv, int dir,
               unsigned *index)
{
    unsigned *calls = (unsigned *)p_get_proto_data(pinfo->pool, pinfo,
                                                   proto_ndb, NDB_KEY_CALLS);
    ndb_call_t *call;

    if (calls == NULL) {
        calls = wmem_new0(pinfo->pool, unsigned);
        p_add_proto_data(pinfo->pool, pinfo, proto_ndb, NDB_KEY_CALLS, calls);
    }
    call = (ndb_call_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ndb,
                                          *calls);
    if (call == NULL) {
        call = wmem_new(wmem_file_scope(), ndb_call_t);
        call->binary_at_start = conv->binary[dir];
        call->linking_at_start = conv->linking;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_ndb, *calls, call);
    }
    *index = *calls;
    (*calls)++;
    return call;
}

static int
dissect_ndb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
            void *data _U_)
{
    ndb_conv_t *conv = ndb_get_conv(pinfo);
    int dir = ndb_direction(conv, pinfo);
    unsigned call_index;
    const ndb_call_t *call = ndb_call_start(pinfo, conv, dir, &call_index);
    ndb_msg_ctx_t ctx;
    unsigned message = 0;
    bool binary = call->binary_at_start;
    bool linking = call->linking_at_start;
    unsigned length = tvb_reported_length(tvb);
    unsigned offset = 0;
    proto_tree *ndb_tree;
    proto_item *ndb_item;

    ctx.conv = conv;
    ctx.dir = dir;
    ctx.key = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDB");
    col_clear(pinfo->cinfo, COL_INFO);
    ndb_item = proto_tree_add_item(tree, proto_ndb, tvb, 0, -1, ENC_NA);
    ndb_tree = proto_item_add_subtree(ndb_item, ett_ndb);

    while (offset < length) {
        if (!binary) {
            unsigned nl = length;
            unsigned next;
            unsigned line_len;
            bool whole = tvb_find_uint8_remaining(tvb, offset, '\n', &nl);
            bool hello;
            char *text;
            proto_item *li;

            if (!whole)
                nl = length;
            /*
             * Each side's messages follow its hello. Bytes that are not
             * text before a newline mean the capture missed the hello.
             */
            if (!ndb_is_text(tvb, offset, nl)) {
                binary = true;
                if (!PINFO_FD_VISITED(pinfo))
                    conv->binary[dir] = true;
                continue;
            }
            if (!whole && pinfo->can_desegment) {
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return tvb_captured_length(tvb);
            }
            next = whole ? nl + 1 : length;
            line_len = nl - offset;
            if (line_len > 0 && tvb_get_uint8(tvb, nl - 1) == '\r')
                line_len--;
            if (dir == 0 && ndb_asks_for_link(tvb, offset, line_len)) {
                linking = true;
                if (!PINFO_FD_VISITED(pinfo))
                    conv->linking = true;
            }
            hello = linking && ndb_is_hello(tvb, offset, line_len);
            text = tvb_format_text(pinfo->pool, tvb, offset, line_len);
            li = proto_tree_add_item(ndb_tree, hf_ndb_line, tvb, offset,
                                     next - offset, ENC_ASCII);
            if (hello) {
                proto_item_set_text(li, "%s: %s",
                                    dir == 0 ? "Hello" : "Hello reply",
                                    text);
                ndb_hello(tvb, li, offset, line_len);
                binary = true;
                if (!PINFO_FD_VISITED(pinfo))
                    conv->binary[dir] = true;
            } else {
                proto_item_set_text(li, "%s: %s",
                                    dir == 0 ? "Request" : "Reply",
                                    line_len > 0 ? text : "(empty line)");
            }
            if (line_len > 0)
                col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", text);
            offset = next;
            continue;
        }

        /* A message: at least its first word, then all of it. */
        {
            unsigned left = length - offset;
            uint32_t w1;
            unsigned encoding = ENC_LITTLE_ENDIAN;
            unsigned words;
            proto_item *bad;

            if (left < 4) {
                if (pinfo->can_desegment) {
                    pinfo->desegment_offset = offset;
                    pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                    return tvb_captured_length(tvb);
                }
                break;
            }
            w1 = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
            if ((w1 & NDB_W1_BYTE_ORDER) == NDB_W1_BYTE_ORDER) {
                encoding = ENC_BIG_ENDIAN;
                w1 = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
            }
            words = (w1 & NDB_W1_TOTAL_WORDS) >> 8;
            if (words < NDB_HEADER_WORDS || words > NDB_MAX_MESSAGE_WORDS) {
                bad = proto_tree_add_item(ndb_tree, hf_ndb_word, tvb, offset,
                                          4, encoding);
                expert_add_info_format(pinfo, bad, &ei_ndb_bad_message,
                        "Not a message: a length of %u words", words);
                break;
            }
            if (left < 4 * words) {
                if (pinfo->can_desegment) {
                    pinfo->desegment_offset = offset;
                    pinfo->desegment_len = 4 * words - left;
                    return tvb_captured_length(tvb);
                }
                bad = proto_tree_add_item(ndb_tree, hf_ndb_word, tvb, offset,
                                          4, encoding);
                expert_add_info(pinfo, bad, &ei_ndb_short);
                break;
            }
            ctx.key = NDB_KEY_MESSAGES | (call_index << NDB_KEY_CALL_SHIFT) |
                      (message & NDB_KEY_MESSAGE_MASK);
            message++;
            ndb_message(tvb, pinfo, ndb_tree, offset, words, encoding, &ctx,
                        NULL);
            offset += 4 * words;
        }
    }
    return tvb_captured_length(tvb);
}

/*
 * A signal link is known by its first line: "ndbd" alone (older
 * servers) or followed by what the client can do about encryption.
 */
static bool
dissect_ndb_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 void *data)
{
    conversation_t *conversation;

    if (tvb_captured_length(tvb) < 5)
        return false;
    if (tvb_memeql(tvb, 0, (const uint8_t *)"ndbd\n", 5) != 0 &&
        tvb_memeql(tvb, 0, (const uint8_t *)"ndbd ", 5) != 0)
        return false;
    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, ndb_handle);
    dissect_ndb(tvb, pinfo, tree, data);
    return true;
}

void
proto_register_ndb(void)
{
    static hf_register_info hf[] = {
        { &hf_ndb_line,
          { "Line", "ndb.line", FT_STRING, BASE_NONE, NULL, 0x0,
            "A text line of the management protocol or the handshake",
            HFILL } },
        { &hf_ndb_hello_node,
          { "Node", "ndb.hello.node", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The sender's node id", HFILL } },
        { &hf_ndb_hello_link_type,
          { "Link type", "ndb.hello.link_type", FT_UINT32, BASE_DEC,
            VALS(ndb_link_type_vals), 0x0, NULL, HFILL } },
        { &hf_ndb_hello_far_node,
          { "Far node", "ndb.hello.far_node", FT_UINT32, BASE_DEC, NULL,
            0x0, "The node the sender means to reach", HFILL } },
        { &hf_ndb_hello_instance,
          { "Link instance", "ndb.hello.instance", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Which of the links between the two nodes this is",
            HFILL } },
        { &hf_ndb_word1,
          { "Header word 1", "ndb.word1", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_big_endian,
          { "Byte order", "ndb.big_endian", FT_BOOLEAN, 32,
            TFS(&tfs_big_little), NDB_W1_BYTE_ORDER, NULL, HFILL } },
        { &hf_ndb_frag_high,
          { "Fragment state, high bit", "ndb.frag_high", FT_BOOLEAN, 32,
            NULL, NDB_W1_FRAG_HIGH, NULL, HFILL } },
        { &hf_ndb_has_signal_id,
          { "Signal id present", "ndb.has_signal_id", FT_BOOLEAN, 32,
            NULL, NDB_W1_SIGNAL_ID, NULL, HFILL } },
        { &hf_ndb_compressed,
          { "Compressed", "ndb.compressed", FT_BOOLEAN, 32, NULL,
            NDB_W1_COMPRESSED, NULL, HFILL } },
        { &hf_ndb_has_checksum,
          { "Checksum present", "ndb.has_checksum", FT_BOOLEAN, 32, NULL,
            NDB_W1_CHECKSUM, NULL, HFILL } },
        { &hf_ndb_prio,
          { "Priority", "ndb.prio", FT_UINT32, BASE_DEC, NULL, NDB_W1_PRIO,
            NULL, HFILL } },
        { &hf_ndb_total_words,
          { "Message length (words)", "ndb.total_words", FT_UINT32, BASE_DEC,
            NULL, NDB_W1_TOTAL_WORDS, NULL, HFILL } },
        { &hf_ndb_frag_low,
          { "Fragment state, low bit", "ndb.frag_low", FT_BOOLEAN, 32, NULL,
            NDB_W1_FRAG_LOW, NULL, HFILL } },
        { &hf_ndb_data_words,
          { "Data length (words)", "ndb.data_words", FT_UINT32, BASE_DEC,
            NULL, NDB_W1_DATA_WORDS, NULL, HFILL } },
        { &hf_ndb_fragment,
          { "Fragment", "ndb.fragment", FT_UINT32, BASE_DEC,
            VALS(ndb_fragment_vals), 0x0, NULL, HFILL } },
        { &hf_ndb_word2,
          { "Header word 2", "ndb.word2", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_signal,
          { "Signal", "ndb.signal", FT_UINT32, BASE_DEC,
            VALS(ndb_signal_vals), NDB_W2_SIGNAL, NULL, HFILL } },
        { &hf_ndb_signal_version,
          { "Layout version", "ndb.signal_version", FT_UINT32, BASE_DEC,
            NULL, NDB_W2_VERSION, NULL, HFILL } },
        { &hf_ndb_trace,
          { "Trace", "ndb.trace", FT_UINT32, BASE_DEC, NULL, NDB_W2_TRACE,
            NULL, HFILL } },
        { &hf_ndb_sections,
          { "Sections", "ndb.sections", FT_UINT32, BASE_DEC, NULL,
            NDB_W2_SECTIONS, NULL, HFILL } },
        { &hf_ndb_word3,
          { "Header word 3", "ndb.word3", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_sender,
          { "Sender block", "ndb.sender", FT_UINT32, BASE_CUSTOM,
            CF_FUNC(ndb_format_block), NDB_W3_SENDER, NULL, HFILL } },
        { &hf_ndb_receiver,
          { "Receiver block", "ndb.receiver", FT_UINT32, BASE_CUSTOM,
            CF_FUNC(ndb_format_block), NDB_W3_RECEIVER, NULL, HFILL } },
        { &hf_ndb_signal_id,
          { "Signal id", "ndb.signal_id", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_word,
          { "Word", "ndb.word", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_section_len,
          { "Section length (words)", "ndb.section.len", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_section,
          { "Section", "ndb.section", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_checksum,
          { "Checksum", "ndb.checksum", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_fragment_id,
          { "Fragment id", "ndb.fragment_id", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_joined_in,
          { "Joined in frame", "ndb.joined_in", FT_FRAMENUM, BASE_NONE, NULL,
            0x0, "The frame whose message ends this fragment's train",
            HFILL } },
        { &hf_ndb_train_fragments,
          { "Fragments", "ndb.train.fragments", FT_UINT32, BASE_DEC, NULL,
            0x0, "How many messages the joined signal came in", HFILL } },
        { &hf_ndb_train_frame,
          { "Fragment in frame", "ndb.train.frame", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, "A frame that carried fragments of the joined signal",
            HFILL } },
        { &hf_ndb_section_number,
          { "Section number", "ndb.section_number", FT_UINT32, BASE_DEC, NULL,
            0x0, "Which of the signal's sections this fragment carries",
            HFILL } },
        { &hf_ndb_part_header,
          { "Part header", "ndb.part", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_part_receiver,
          { "Receiver block", "ndb.part.receiver", FT_UINT32, BASE_CUSTOM,
            CF_FUNC(ndb_format_block), 0xFFFF0000, NULL, HFILL } },
        { &hf_ndb_part_len,
          { "Length less three", "ndb.part.len", FT_UINT32, BASE_DEC, NULL,
            0x0000001F, NULL, HFILL } },
        { &hf_ndb_coord_ptr,
          { "Coordinator's record", "ndb.coord_ptr", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_client_ptr,
          { "Client's record", "ndb.client_ptr", FT_UINT32, BASE_HEX, NULL,
            0x0, "The client's name for the coordinator's record", HFILL } },
        { &hf_ndb_client_ptr_word,
          { "Client's record", "ndb.client_ptr_word", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_commit_ack_owed,
          { "Commit marker to free", "ndb.commit_ack_owed", FT_BOOLEAN, 32,
            NULL, 0x00000001,
            "COMMIT_MARKER_FREE_ORD is owed for this transaction", HFILL } },
        { &hf_ndb_query_ref,
          { "Query", "ndb.query_ref", FT_UINT32, BASE_HEX, NULL, 0x0,
            "The client's id for the operation", HFILL } },
        { &hf_ndb_table_id,
          { "Table id", "ndb.table_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_column_data_len,
          { "Column data length", "ndb.column_data_len", FT_UINT32,
            BASE_DEC, NULL, 0x0,
            "Words of column data in the signal; 0 when they are in a section",
            HFILL } },
        { &hf_ndb_table_version,
          { "Table version", "ndb.table_version", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },
        { &hf_ndb_flags,
          { "Flags", "ndb.flags", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_flag_dirty,
          { "Dirty", "ndb.flags.dirty", FT_BOOLEAN, 32, NULL, 1U << 0, NULL,
            HFILL } },
        { &hf_ndb_flag_no_disk,
          { "No disk", "ndb.flags.no_disk", FT_BOOLEAN, 32, NULL, 1U << 1,
            NULL, HFILL } },
        { &hf_ndb_flag_commit,
          { "Commit", "ndb.flags.commit", FT_BOOLEAN, 32, NULL, 1U << 4,
            NULL, HFILL } },
        { &hf_ndb_flag_operation,
          { "Operation", "ndb.flags.operation", FT_UINT32, BASE_DEC,
            VALS(ndb_operation_vals), 7U << 5, NULL, HFILL } },
        { &hf_ndb_flag_simple,
          { "Simple", "ndb.flags.simple", FT_BOOLEAN, 32, NULL, 1U << 8,
            NULL, HFILL } },
        { &hf_ndb_flag_execute,
          { "Execute", "ndb.flags.execute", FT_BOOLEAN, 32, NULL, 1U << 10,
            NULL, HFILL } },
        { &hf_ndb_flag_start,
          { "Start", "ndb.flags.start", FT_BOOLEAN, 32, NULL, 1U << 11,
            NULL, HFILL } },
        { &hf_ndb_flag_abort,
          { "On error", "ndb.flags.abort", FT_UINT32, BASE_DEC,
            VALS(ndb_abort_vals), 3U << 12, NULL, HFILL } },
        { &hf_ndb_flag_committed_base,
          { "Read committed base", "ndb.flags.committed_base", FT_BOOLEAN,
            32, NULL, 1U << 20,
            "A committed read through a unique index; a backup replica may "
            "serve it", HFILL } },
        { &hf_ndb_flag_no_wait,
          { "No wait", "ndb.flags.no_wait", FT_BOOLEAN, 32, NULL, 1U << 21,
            NULL, HFILL } },
        { &hf_ndb_flag_batch_safe,
          { "Batch safe", "ndb.flags.batch_safe", FT_BOOLEAN, 32, NULL,
            1U << 22, NULL, HFILL } },
        { &hf_ndb_flag_batch_unsafe,
          { "Batch unsafe", "ndb.flags.batch_unsafe", FT_BOOLEAN, 32, NULL,
            1U << 23, NULL, HFILL } },
        { &hf_ndb_trans_id_lo,
          { "Transaction id, low word", "ndb.trans_id_lo", FT_UINT32,
            BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_trans_id_hi,
          { "Transaction id, high word", "ndb.trans_id_hi", FT_UINT32,
            BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_trans_id,
          { "Transaction id", "ndb.trans_id", FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_error_code,
          { "Error", "ndb.error", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_error_data,
          { "Error data", "ndb.error_data", FT_UINT32, BASE_HEX_DEC, NULL,
            0x0, NULL, HFILL } },
        { &hf_ndb_gci_hi,
          { "Global checkpoint, high word", "ndb.gci_hi", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_gci_lo,
          { "Global checkpoint, low word", "ndb.gci_lo", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_gci,
          { "Global checkpoint", "ndb.gci", FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_gci_word,
          { "Global checkpoint", "ndb.gci_word", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL } },
        { &hf_ndb_info,
          { "Info", "ndb.info", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_info_ops,
          { "Operations", "ndb.info.ops", FT_UINT32, BASE_DEC, NULL,
            0x0000FFFF, NULL, HFILL } },
        { &hf_ndb_info_commit,
          { "Committed", "ndb.info.commit", FT_BOOLEAN, 32, NULL, 1U << 16,
            NULL, HFILL } },
        { &hf_ndb_info_marker,
          { "Commit marker kept", "ndb.info.marker", FT_BOOLEAN, 32, NULL,
            1U << 17, NULL, HFILL } },
        { &hf_ndb_op_query_ref,
          { "Query", "ndb.op.query_ref", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_op_row_len,
          { "Row data length", "ndb.op.row_len", FT_UINT32, BASE_HEX_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_block_ref,
          { "Block reference", "ndb.ref", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_ref_node,
          { "Node", "ndb.ref.node", FT_UINT32, BASE_DEC, NULL, 0x0000FFFF,
            NULL, HFILL } },
        { &hf_ndb_ref_block,
          { "Block", "ndb.ref.block", FT_UINT32, BASE_CUSTOM,
            CF_FUNC(ndb_format_block), 0xFFFF0000, NULL, HFILL } },
        { &hf_ndb_version,
          { "Version", "ndb.version", FT_UINT32, BASE_CUSTOM,
            CF_FUNC(ndb_format_version), 0x0, NULL, HFILL } },
        { &hf_ndb_mysql_version,
          { "MySQL version", "ndb.mysql_version", FT_UINT32, BASE_CUSTOM,
            CF_FUNC(ndb_format_version), 0x0, NULL, HFILL } },
        { &hf_ndb_heartbeat,
          { "Heartbeat interval", "ndb.heartbeat", FT_UINT32, BASE_CUSTOM,
            CF_FUNC(ndb_format_heartbeat), 0x0,
            "In hundredths of a second", HFILL } },
        { &hf_ndb_min_db_version,
          { "Lowest data node version", "ndb.min_db_version", FT_UINT32,
            BASE_CUSTOM, CF_FUNC(ndb_format_version), 0x0, NULL, HFILL } },
        { &hf_ndb_min_api_version,
          { "Lowest API version", "ndb.min_api_version", FT_UINT32,
            BASE_CUSTOM, CF_FUNC(ndb_format_version), 0x0, NULL, HFILL } },
        { &hf_ndb_start_level,
          { "Start level", "ndb.start_level", FT_UINT32, BASE_DEC,
            VALS(ndb_start_level_vals), 0x0, NULL, HFILL } },
        { &hf_ndb_node_group,
          { "Node group", "ndb.node_group", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_dynamic_id,
          { "Dynamic id", "ndb.dynamic_id", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_start_phase,
          { "Start phase, or shutdown", "ndb.start_phase", FT_UINT32,
            BASE_DEC, NULL, 0x0,
            "The start phase while starting; while stopping, set if the "
            "whole cluster shuts down", HFILL } },
        { &hf_ndb_restart_type,
          { "Restart type", "ndb.restart_type", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL } },
        { &hf_ndb_single_user,
          { "Single user mode", "ndb.single_user", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_single_user_api,
          { "Single user API node", "ndb.single_user_api", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_connected_node,
          { "Connected node", "ndb.connected_node", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_instance,
          { "Instance", "ndb.instance", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_release_id,
          { "Release id", "ndb.release_id", FT_UINT32, BASE_HEX, NULL, 0x0,
            "Picked at random when the record is allocated; only a free "
            "with the same id frees it", HFILL } },
        { &hf_ndb_caller_data,
          { "Caller's data", "ndb.caller_data", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },
        { &hf_ndb_request_type,
          { "Request type", "ndb.request_type", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },
        { &hf_ndb_id_or_name_len,
          { "Table id or name length", "ndb.id_or_name_len", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_schema_trans,
          { "Schema transaction", "ndb.schema_trans", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_total_len,
          { "Total length", "ndb.total_len", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_table_kind,
          { "Table kind", "ndb.table_kind", FT_UINT32, BASE_DEC,
            VALS(ndb_object_kind_vals), 0x0, NULL, HFILL } },
        { &hf_ndb_row,
          { "Row", "ndb.row", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_row_len,
          { "Row length (words)", "ndb.row_len", FT_UINT32, BASE_DEC, NULL,
            0x0, "The length of the row that section 0 carries", HFILL } },
        { &hf_ndb_error_line,
          { "Source line", "ndb.error_line", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Where in the data node's source the request was refused",
            HFILL } },
        { &hf_ndb_list_flags,
          { "Request flags", "ndb.list.flags", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },
        { &hf_ndb_list_names,
          { "With names", "ndb.list.names", FT_BOOLEAN, 32, NULL,
            0x10000000, NULL, HFILL } },
        { &hf_ndb_list_dependent,
          { "Dependents of the table", "ndb.list.dependent", FT_BOOLEAN, 32,
            NULL, 0x40000000, NULL, HFILL } },
        { &hf_ndb_list_old_table_id,
          { "Table id, older form", "ndb.list.old_table_id", FT_UINT32,
            BASE_DEC, NULL, 0x00000FFF, NULL, HFILL } },
        { &hf_ndb_object_kind,
          { "Object kind", "ndb.object.kind", FT_UINT32, BASE_DEC,
            VALS(ndb_object_kind_vals), 0x0, NULL, HFILL } },
        { &hf_ndb_object_count,
          { "Objects in this piece", "ndb.object.count", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_object_flags,
          { "Object flags", "ndb.object.flags", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },
        { &hf_ndb_object_state,
          { "State", "ndb.object.state", FT_UINT32, BASE_DEC, NULL,
            0x0F000000, NULL, HFILL } },
        { &hf_ndb_object_temporary,
          { "Temporary", "ndb.object.temporary", FT_BOOLEAN, 32, NULL,
            0x00800000, NULL, HFILL } },
        { &hf_ndb_object_store,
          { "Store", "ndb.object.store", FT_UINT32, BASE_DEC, NULL,
            0x00700000, NULL, HFILL } },
        { &hf_ndb_object_id,
          { "Object id", "ndb.object.id", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_object_name_len,
          { "Name length", "ndb.object.name_len", FT_UINT32, BASE_DEC, NULL,
            0x0, "Bytes, counting the NUL", HFILL } },
        { &hf_ndb_object_name,
          { "Name", "ndb.object.name", FT_STRINGZPAD, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_column_header,
          { "Column header", "ndb.column", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_column_id,
          { "Column id", "ndb.column.id", FT_UINT32, BASE_CUSTOM,
            CF_FUNC(ndb_format_column_id), NDB_COL_ID, NULL, HFILL } },
        { &hf_ndb_column_partial,
          { "Partial", "ndb.column.partial", FT_BOOLEAN, 32, NULL,
            NDB_COL_PARTIAL, "A part of the value only", HFILL } },
        { &hf_ndb_column_size,
          { "Size (bytes)", "ndb.column.size", FT_UINT32, BASE_DEC, NULL,
            NDB_COL_SIZE, NULL, HFILL } },
        { &hf_ndb_column_value,
          { "Value", "ndb.column.value", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_column_bitmap,
          { "Bitmap", "ndb.column.bitmap", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_packed_values,
          { "Packed values", "ndb.column.packed", FT_BYTES, BASE_NONE, NULL,
            0x0, "The values read, in column order, packed", HFILL } },
        { &hf_ndb_coll_kind,
          { "Lookup", "ndb.collation.kind", FT_UINT32, BASE_DEC,
            VALS(ndb_collation_kind_vals), 0x0, NULL, HFILL } },
        { &hf_ndb_coll_number,
          { "Collation number", "ndb.collation.number", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_name_len,
          { "Name length", "ndb.collation.name_len", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Bytes of the name in section 0", HFILL } },
        { &hf_ndb_coll_default,
          { "Default collation of the set", "ndb.collation.default",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_binary,
          { "Binary collation of the set", "ndb.collation.binary",
            FT_UINT32, BASE_DEC, NULL, 0x0, "0 if the set has none", HFILL } },
        { &hf_ndb_coll_flags,
          { "Flags", "ndb.collation.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_coll_flag_default,
          { "The set's default", "ndb.collation.flags.default", FT_BOOLEAN,
            32, NULL, 0x01, NULL, HFILL } },
        { &hf_ndb_coll_flag_binary,
          { "Binary order", "ndb.collation.flags.binary", FT_BOOLEAN, 32,
            NULL, 0x02, NULL, HFILL } },
        { &hf_ndb_coll_flag_unicode,
          { "Unicode set", "ndb.collation.flags.unicode", FT_BOOLEAN, 32,
            NULL, 0x04, NULL, HFILL } },
        { &hf_ndb_coll_flag_case,
          { "Case sensitive", "ndb.collation.flags.case_sensitive",
            FT_BOOLEAN, 32, NULL, 0x08, NULL, HFILL } },
        { &hf_ndb_coll_flag_ascii,
          { "Pure ASCII set", "ndb.collation.flags.ascii", FT_BOOLEAN, 32,
            NULL, 0x10, NULL, HFILL } },
        { &hf_ndb_coll_flag_no_pad,
          { "No pad", "ndb.collation.flags.no_pad", FT_BOOLEAN, 32, NULL,
            0x20, "Trailing spaces count when comparing", HFILL } },
        { &hf_ndb_coll_min_bytes,
          { "Fewest bytes a character", "ndb.collation.min_bytes",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_max_bytes,
          { "Most bytes a character", "ndb.collation.max_bytes", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_sort_growth,
          { "Sort-key bytes per byte", "ndb.collation.sort_growth",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_upper_growth,
          { "Upper-case bytes per byte", "ndb.collation.upper_growth",
            FT_UINT32, BASE_DEC, NULL, 0x000000FF, NULL, HFILL } },
        { &hf_ndb_coll_lower_growth,
          { "Lower-case bytes per byte", "ndb.collation.lower_growth",
            FT_UINT32, BASE_DEC, NULL, 0x0000FF00, NULL, HFILL } },
        { &hf_ndb_coll_pad,
          { "Pad byte", "ndb.collation.pad", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_coll_levels,
          { "Weight levels compared", "ndb.collation.levels", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_min_sort,
          { "Lowest-sorting code point", "ndb.collation.min_sort", FT_UINT32,
            BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_max_sort,
          { "Highest-sorting code point", "ndb.collation.max_sort",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_charset_len,
          { "Character set name length", "ndb.collation.charset_len",
            FT_UINT32, BASE_DEC, NULL, 0x0000FFFF, NULL, HFILL } },
        { &hf_ndb_coll_collation_len,
          { "Collation name length", "ndb.collation.collation_len",
            FT_UINT32, BASE_DEC, NULL, 0xFFFF0000, NULL, HFILL } },
        { &hf_ndb_coll_req_flags,
          { "Request flags", "ndb.collation.req_flags", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_req_with_weights,
          { "With weights", "ndb.collation.req_flags.with_weights",
            FT_BOOLEAN, 32, NULL, 0x1, NULL, HFILL } },
        { &hf_ndb_coll_position,
          { "Weights from", "ndb.collation.position", FT_UINT32, BASE_CUSTOM,
            CF_FUNC(ndb_format_position), 0x0, NULL, HFILL } },
        { &hf_ndb_coll_case_word,
          { "Case growth", "ndb.collation.case_word", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_names_word,
          { "Name lengths", "ndb.collation.names_word", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_weight_entries,
          { "Weight runs", "ndb.collation.runs", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL } },
        { &hf_ndb_coll_weights_len,
          { "Weight runs, bytes", "ndb.collation.runs_len", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_contraction_entries,
          { "Contractions", "ndb.collation.contractions", FT_UINT32,
            BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_contractions_len,
          { "Contractions, bytes", "ndb.collation.contractions_len",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_next_position,
          { "Next request from", "ndb.collation.next_position", FT_UINT32,
            BASE_CUSTOM, CF_FUNC(ndb_format_position), 0x0, NULL, HFILL } },
        { &hf_ndb_wr_first,
          { "First code point", "ndb.collation.run.first", FT_UINT24,
            BASE_CUSTOM, CF_FUNC(ndb_format_code_point), 0x0, NULL,
            HFILL } },
        { &hf_ndb_wr_count,
          { "Code points", "ndb.collation.run.count", FT_UINT24, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_wr_step,
          { "Steps", "ndb.collation.run.step", FT_UINT8, BASE_CUSTOM,
            CF_FUNC(ndb_format_step), 0x0, NULL, HFILL } },
        { &hf_ndb_wr_encoded_len,
          { "Encoding length", "ndb.collation.run.encoded_len", FT_UINT8,
            BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_wr_weight_len,
          { "Weight string length", "ndb.collation.run.weight_len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_wr_encoded,
          { "First code point in the set", "ndb.collation.run.encoded",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_wr_weight,
          { "Weight string", "ndb.collation.run.weight", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_ct_points,
          { "Code points", "ndb.collation.contraction.points", FT_UINT8,
            BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_ct_previous,
          { "Second weighed by the first",
            "ndb.collation.contraction.previous_context", FT_BOOLEAN, 8, NULL,
            0x01, NULL, HFILL } },
        { &hf_ndb_ct_weight_len,
          { "Weight string length", "ndb.collation.contraction.weight_len",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_ct_code_point,
          { "Code point", "ndb.collation.contraction.code_point", FT_UINT24,
            BASE_CUSTOM, CF_FUNC(ndb_format_code_point), 0x0, NULL,
            HFILL } },
        { &hf_ndb_ct_weight,
          { "Weight string", "ndb.collation.contraction.weight", FT_BYTES,
            BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_coll_error,
          { "Error", "ndb.collation.error", FT_UINT32, BASE_DEC,
            VALS(ndb_collation_error_vals), 0x0, NULL, HFILL } },
        { &hf_ndb_flag_dist_key,
          { "Distribution key given", "ndb.flags.dist_key", FT_BOOLEAN, 32,
            NULL, 1U << 2, NULL, HFILL } },
        { &hf_ndb_flag_takeover,
          { "Scan takeover", "ndb.flags.takeover", FT_BOOLEAN, 32, NULL,
            1U << 14, "Takes over the lock a scan holds on the row", HFILL } },
        { &hf_ndb_flag_user_id,
          { "User id given", "ndb.flags.user_id", FT_BOOLEAN, 32, NULL,
            1U << 29, "For the data nodes' rate limits", HFILL } },
        { &hf_ndb_user_id,
          { "User id", "ndb.user_id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_user_id_version,
          { "User id version", "ndb.user_id_version", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_takeover_info,
          { "Scan information", "ndb.takeover", FT_UINT32, BASE_HEX, NULL,
            0x0, "Which scanned row the takeover names", HFILL } },
        { &hf_ndb_takeover_flag,
          { "Takeover", "ndb.takeover.flag", FT_BOOLEAN, 32, NULL,
            0x00000001, NULL, HFILL } },
        { &hf_ndb_takeover_row,
          { "Row", "ndb.takeover.row", FT_UINT32, BASE_HEX, NULL,
            0x0007FFFE, "The row word of the row's SCAN_ROW_KEY_REP, its low "
            "18 bits", HFILL } },
        { &hf_ndb_takeover_frag,
          { "Fragment", "ndb.takeover.fragment", FT_UINT32, BASE_DEC, NULL,
            0xFFF00000, NULL, HFILL } },
        { &hf_ndb_op_dist_key,
          { "Distribution key", "ndb.dist_key", FT_UINT32, BASE_HEX, NULL,
            0x0, "For a takeover, the row's fragment", HFILL } },
        { &hf_ndb_row_for,
          { "Query or receiver", "ndb.row_for", FT_UINT32, BASE_HEX, NULL,
            0x0, "The client's id for the query the row answers, or for "
            "the scan receiver it is for", HFILL } },
        { &hf_ndb_scan_flags,
          { "Scan flags", "ndb.scan.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_scan_ext,
          { "Extensions", "ndb.scan.flags.ext", FT_UINT32, BASE_HEX, NULL,
            0x000000FF, NULL, HFILL } },
        { &hf_ndb_scan_exclusive,
          { "Exclusive lock", "ndb.scan.flags.exclusive", FT_BOOLEAN, 32,
            NULL, 1U << 8, NULL, HFILL } },
        { &hf_ndb_scan_no_disk,
          { "No disk", "ndb.scan.flags.no_disk", FT_BOOLEAN, 32, NULL,
            1U << 9, NULL, HFILL } },
        { &hf_ndb_scan_hold_lock,
          { "Hold lock", "ndb.scan.flags.hold_lock", FT_BOOLEAN, 32, NULL,
            1U << 10, NULL, HFILL } },
        { &hf_ndb_scan_committed,
          { "Read committed", "ndb.scan.flags.committed", FT_BOOLEAN, 32,
            NULL, 1U << 11, NULL, HFILL } },
        { &hf_ndb_scan_keys,
          { "Return each row's key", "ndb.scan.flags.keys", FT_BOOLEAN, 32,
            NULL, 1U << 12, "For takeover: a SCAN_ROW_KEY_REP per row",
            HFILL } },
        { &hf_ndb_scan_storage_order,
          { "Storage order", "ndb.scan.flags.storage_order", FT_BOOLEAN, 32,
            NULL, 1U << 13, NULL, HFILL } },
        { &hf_ndb_scan_descending,
          { "Descending", "ndb.scan.flags.descending", FT_BOOLEAN, 32, NULL,
            1U << 14, NULL, HFILL } },
        { &hf_ndb_scan_range,
          { "Range scan", "ndb.scan.flags.range", FT_BOOLEAN, 32, NULL,
            1U << 15, NULL, HFILL } },
        { &hf_ndb_scan_batch_rows_bits,
          { "Batch rows", "ndb.scan.flags.batch_rows", FT_UINT32, BASE_DEC,
            NULL, 0x03FF0000, "0: the first batch's word says", HFILL } },
        { &hf_ndb_scan_dist_key,
          { "Distribution key given", "ndb.scan.flags.dist_key",
            FT_BOOLEAN, 32, NULL, 1U << 26, NULL, HFILL } },
        { &hf_ndb_scan_join,
          { "Join", "ndb.scan.flags.join", FT_BOOLEAN, 32, NULL, 1U << 27,
            NULL, HFILL } },
        { &hf_ndb_scan_every_conf,
          { "Pass every confirmation", "ndb.scan.flags.every_conf",
            FT_BOOLEAN, 32, NULL, 1U << 28, NULL, HFILL } },
        { &hf_ndb_scan_extended_conf,
          { "Extended confirmation", "ndb.scan.flags.extended_conf",
            FT_BOOLEAN, 32, NULL, 1U << 29, NULL, HFILL } },
        { &hf_ndb_scan_committed_base,
          { "Read committed base", "ndb.scan.flags.committed_base",
            FT_BOOLEAN, 32, NULL, 1U << 30, NULL, HFILL } },
        { &hf_ndb_scan_multi_frag,
          { "Several fragments per receiver", "ndb.scan.flags.multi_frag",
            FT_BOOLEAN, 32, NULL, 1U << 31, NULL, HFILL } },
        { &hf_ndb_scan_spare,
          { "Spare", "ndb.scan.spare", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_scan_word5,
          { "Word 5", "ndb.scan.word5", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_scan_word5_low,
          { "Low half", "ndb.scan.word5.low", FT_UINT32, BASE_HEX, NULL,
            0x0000FFFF, NULL, HFILL } },
        { &hf_ndb_scan_word5_per_worker,
          { "Fragments per worker", "ndb.scan.word5.per_worker", FT_UINT32,
            BASE_DEC, NULL, 0x00030000, NULL, HFILL } },
        { &hf_ndb_scan_word5_partition,
          { "Partition given", "ndb.scan.word5.partition", FT_BOOLEAN, 32,
            NULL, 1U << 30, NULL, HFILL } },
        { &hf_ndb_scan_word5_interval,
          { "Hash interval", "ndb.scan.word5.interval", FT_BOOLEAN, 32, NULL,
            1U << 31, NULL, HFILL } },
        { &hf_ndb_trans_record,
          { "Transaction's coordinator record", "ndb.scan.trans_record",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "The record of the transaction the scan belongs to", HFILL } },
        { &hf_ndb_batch_bytes,
          { "Batch bytes", "ndb.scan.batch_bytes", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL } },
        { &hf_ndb_batch_rows,
          { "First batch's rows", "ndb.scan.batch_rows", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_dist_key,
          { "Distribution key", "ndb.scan.dist_key", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_receiver_id,
          { "Receiver", "ndb.scan.receiver", FT_UINT32, BASE_HEX, NULL, 0x0,
            "The client's id for one receiver of a scan's rows", HFILL } },
        { &hf_ndb_receiver_coord,
          { "Coordinator's pointer for the receiver", "ndb.scan.receiver_ptr",
            FT_UINT32, BASE_CUSTOM, CF_FUNC(ndb_format_receiver_ptr), 0x0,
            NULL, HFILL } },
        { &hf_ndb_scan_conf_info,
          { "Information", "ndb.scan.conf_info", FT_UINT32, BASE_HEX, NULL,
            0x0, NULL, HFILL } },
        { &hf_ndb_scan_conf_count,
          { "Receivers reported", "ndb.scan.conf_info.count", FT_UINT32,
            BASE_DEC, NULL, NDB_SCAN_CONF_COUNT, NULL, HFILL } },
        { &hf_ndb_scan_conf_end,
          { "End of data", "ndb.scan.conf_info.end", FT_BOOLEAN, 32, NULL,
            1U << 31, NULL, HFILL } },
        { &hf_ndb_receiver_info,
          { "Batch", "ndb.scan.batch", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_receiver_len,
          { "Words", "ndb.scan.batch.words", FT_UINT32, BASE_DEC, NULL,
            0xFFFFFC00, "Row and key words in the batch", HFILL } },
        { &hf_ndb_receiver_rows,
          { "Rows", "ndb.scan.batch.rows", FT_UINT32, BASE_DEC, NULL,
            NDB_RECEIVER_ROWS, "All ones: the next word holds the rows",
            HFILL } },
        { &hf_ndb_receiver_rows_word,
          { "Rows", "ndb.scan.batch.rows_word", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL } },
        { &hf_ndb_receiver_len_word,
          { "Words", "ndb.scan.batch.words_word", FT_UINT32, BASE_DEC, NULL,
            0x0, "Row and key words in the batch", HFILL } },
        { &hf_ndb_receiver_active,
          { "Join's active mask", "ndb.scan.active_mask", FT_UINT32,
            BASE_HEX, NULL, 0x0, "Meaningful for pushed-down joins only",
            HFILL } },
        { &hf_ndb_close_owed,
          { "Close owed", "ndb.scan.close_owed", FT_UINT32, BASE_DEC, NULL,
            0x0, "1: the client is to close the scan", HFILL } },
        { &hf_ndb_stop,
          { "Stop", "ndb.scan.stop", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Non-zero: close the scan", HFILL } },
        { &hf_ndb_key_len,
          { "Key length (words)", "ndb.scan.key_len", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL } },
        { &hf_ndb_row_key_info,
          { "Row", "ndb.scan.row_key", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_row_key_scan,
          { "Scan number", "ndb.scan.row_key.scan", FT_UINT32, BASE_DEC,
            NULL, 0x000000FF, NULL, HFILL } },
        { &hf_ndb_row_key_op,
          { "Operation number", "ndb.scan.row_key.op", FT_UINT32, BASE_DEC,
            NULL, 0x0003FF00, NULL, HFILL } },
        { &hf_ndb_row_key_frag,
          { "Fragment", "ndb.scan.row_key.fragment", FT_UINT32, BASE_DEC,
            NULL, 0xFFF00000, NULL, HFILL } },
        { &hf_ndb_key,
          { "Key", "ndb.scan.key", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
            HFILL } },
        { &hf_ndb_column_size_word,
          { "Size", "ndb.scan.column_size", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_bound,
          { "Bound word", "ndb.scan.bound", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL } },
        { &hf_ndb_bound_type,
          { "Type", "ndb.scan.bound.type", FT_UINT32, BASE_DEC,
            VALS(ndb_bound_vals), 0x0000000F, NULL, HFILL } },
        { &hf_ndb_bound_range,
          { "Range number", "ndb.scan.bound.range", FT_UINT32, BASE_DEC, NULL,
            0x0000FFF0, NULL, HFILL } },
        { &hf_ndb_bound_len,
          { "Range length (words)", "ndb.scan.bound.len", FT_UINT32, BASE_DEC,
            NULL, 0xFFFF0000, NULL, HFILL } },
    };

    static int *ett[] = {
        &ett_ndb,
        &ett_ndb_line,
        &ett_ndb_message,
        &ett_ndb_word1,
        &ett_ndb_word2,
        &ett_ndb_word3,
        &ett_ndb_data,
        &ett_ndb_sections,
        &ett_ndb_part,
        &ett_ndb_part_header,
        &ett_ndb_flags,
        &ett_ndb_info,
        &ett_ndb_op,
        &ett_ndb_ref,
        &ett_ndb_client_ptr,
        &ett_ndb_coll_flags,
        &ett_ndb_coll_req_flags,
        &ett_ndb_coll_case,
        &ett_ndb_coll_names,
        &ett_ndb_weights,
        &ett_ndb_weight_run,
        &ett_ndb_contraction,
        &ett_ndb_node_state,
        &ett_ndb_connected,
        &ett_ndb_row,
        &ett_ndb_column,
        &ett_ndb_column_header,
        &ett_ndb_list_flags,
        &ett_ndb_object,
        &ett_ndb_object_flags,
        &ett_ndb_scan_flags,
        &ett_ndb_scan_word5,
        &ett_ndb_scan_conf_info,
        &ett_ndb_receiver,
        &ett_ndb_receiver_info,
        &ett_ndb_row_key_info,
        &ett_ndb_takeover_info,
        &ett_ndb_bound,
        &ett_ndb_bound_word,
    };

    static ei_register_info ei[] = {
        { &ei_ndb_bad_message,
          { "ndb.bad_message", PI_MALFORMED, PI_ERROR,
            "Not a message", EXPFILL } },
        { &ei_ndb_bad_checksum,
          { "ndb.bad_checksum", PI_CHECKSUM, PI_ERROR,
            "Checksum does not match", EXPFILL } },
        { &ei_ndb_fragment,
          { "ndb.fragment.note", PI_REASSEMBLE, PI_NOTE,
            "One fragment of a longer signal, joined at its last fragment",
            EXPFILL } },
        { &ei_ndb_unjoined,
          { "ndb.fragment.unjoined", PI_REASSEMBLE, PI_WARN,
            "A fragment whose train began before the capture; not joined",
            EXPFILL } },
        { &ei_ndb_compressed,
          { "ndb.compressed.note", PI_UNDECODED, PI_NOTE,
            "Compressed message, not decoded", EXPFILL } },
        { &ei_ndb_short,
          { "ndb.short", PI_MALFORMED, PI_ERROR,
            "Shorter than it says", EXPFILL } },
    };

    expert_module_t *expert_ndb;

    proto_ndb = proto_register_protocol("NDB Protocol", "NDB", "ndb");
    proto_register_field_array(proto_ndb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ndb = expert_register_protocol(proto_ndb);
    expert_register_field_array(expert_ndb, ei, array_length(ei));
    ndb_handle = register_dissector("ndb", dissect_ndb, proto_ndb);
}

void
proto_reg_handoff_ndb(void)
{
    dissector_add_uint_with_preference("tcp.port", NDB_MGM_PORT, ndb_handle);
    heur_dissector_add("tcp", dissect_ndb_heur, "NDB signal links over TCP",
                       "ndb_tcp", proto_ndb, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
