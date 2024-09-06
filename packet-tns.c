/* packet-tns.c
 * Routines for Oracle TNS packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-tcp.h"

#include <epan/prefs.h>

void proto_register_tns(void);

/* Packet Types */
#define TNS_TYPE_CONNECT        1
#define TNS_TYPE_ACCEPT         2
#define TNS_TYPE_ACK            3
#define TNS_TYPE_REFUSE         4
#define TNS_TYPE_REDIRECT       5
#define TNS_TYPE_DATA           6
#define TNS_TYPE_NULL           7
#define TNS_TYPE_ABORT          9
#define TNS_TYPE_RESEND         11
#define TNS_TYPE_MARKER         12
#define TNS_TYPE_ATTENTION      13
#define TNS_TYPE_CONTROL        14
#define TNS_TYPE_MAX            19

/* Data Packet Functions */
#define SQLNET_SET_PROTOCOL     1
#define SQLNET_SET_DATATYPES    2
#define SQLNET_USER_OCI_FUNC    3
#define SQLNET_RETURN_STATUS    4
#define SQLNET_ACCESS_USR_ADDR  5
#define SQLNET_ROW_TRANSF_HDR   6
#define SQLNET_ROW_TRANSF_DATA  7
#define SQLNET_RETURN_OPI_PARAM 8
#define SQLNET_FUNCCOMPLETE     9
#define SQLNET_NERROR_RET_DEF   10
#define SQLNET_IOVEC_4FAST_UPI  11
#define SQLNET_LONG_4FAST_UPI   12
#define SQLNET_INVOKE_USER_CB   13
#define SQLNET_LOB_FILE_DF      14
#define SQLNET_WARNING          15
#define SQLNET_DESCRIBE_INFO    16
#define SQLNET_PIGGYBACK_FUNC   17
#define SQLNET_SIG_4UCS         18
#define SQLNET_FLUSH_BIND_DATA  19
#define SQLNET_SNS              0xdeadbeef
#define SQLNET_XTRN_PROCSERV_R1 32
#define SQLNET_XTRN_PROCSERV_R2 68

/*+--------------------------------------------------
 *  User to Server request function types
 *  SQLNET_TYPE_USERTOSERVER  0x03
 *  look in ttc7\FunCodes.java
 *---------------------------------------------------*/
#define SQLNET_USER_FUNC_OLOGON     1 /* logon to Oracle */
#define SQLNET_USER_FUNC_OPENCURSOR 2 /* Open Cursor */
#define SQLNET_USER_FUNC_PARSE      3 /* Parse */
#define SQLNET_USER_FUNC_EXECUTE    4 /* Execute */
#define SQLNET_USER_FUNC_OFETCH     5 /* fetch a row */

#define SQLNET_USER_FUNC_CLOSECURSOR 8 /* Close Cursor */

#define SQLNET_USER_FUNC_OLOGOFF   9  /* logoff of ORACLE */
#define SQLNET_USER_FUNC_ODSCRIBE  10 /* describe a select list column */
#define SQLNET_USER_FUNC_ODEFIN    11 /* define[] where the column goes */
#define SQLNET_USER_FUNC_OCOMON    12 /* auto[] commit on */
#define SQLNET_USER_FUNC_OCOMOFF   13 /* auto commit off */
#define SQLNET_USER_FUNC_OCOMMIT   14 /* commit */
#define SQLNET_USER_FUNC_OROLLBACK 15 /* rollback */
#define SQLNET_USER_FUNC_OSFE      16 /* set fatal error options */
#define SQLNET_USER_FUNC_ORESUME   17 /* resume current operation */
#define SQLNET_USER_FUNC_OVERSN    18 /* get ORACLE version-date string */
#define SQLNET_USER_FUNC_OTEMP     19 /* until we get rid of OASQL */
#define SQLNET_USER_FUNC_CANCEL    20 /* cancel the current operation */
#define SQLNET_USER_FUNC_OGEM      21 /* get error message */
#define SQLNET_USER_FUNC_OEXIT     22 /* Exit oracle command */
#define SQLNET_USER_FUNC_OSPECIAL  23 /* special function */
#define SQLNET_USER_FUNC_OABORT    24 /* abort */
#define SQLNET_USER_FUNC_ODQRID    25 /* deq by rowid */
#define SQLNET_USER_FUNC_OLNGF6    26 /* fetch a long column value */
#define SQLNET_USER_FUNC_OCAM      27 /* Create Access Module */
#define SQLNET_USER_FUNC_OSAMS     28 /* Save Access Module Statement */
#define SQLNET_USER_FUNC_OSAM      29 /* Save Access Module */
#define SQLNET_USER_FUNC_OPAMS     30 /* Parse Access Module Statement */
#define SQLNET_USER_FUNC_OHOWMANY  31 /* How Many Items? */
#define SQLNET_USER_FUNC_OINIT     32 /* Initialize Oracle */
#define SQLNET_USER_FUNC_OCHANGEU  33 /* change user id */
#define SQLNET_USER_FUNC_OBINDRP   34 /* Bind by reference positional */
#define SQLNET_USER_FUNC_OGETBV    35 /* Get n'th Bind Variable */
#define SQLNET_USER_FUNC_OGETIV    36 /* Get n'th Into Variable */
#define SQLNET_USER_FUNC_OBINDRV   37 /* Bind by reference */
#define SQLNET_USER_FUNC_OBINDRN   38 /* Bind by reference numeric */
#define SQLNET_USER_FUNC_OPARSEX   39 /* Parse And Execute */
#define SQLNET_USER_FUNC_OPARSYN   40 /* Parse for Syntax only */
#define SQLNET_USER_FUNC_OPARSDI   41 /* Parse for Syntax & SQL Dictionary lookup */
#define SQLNET_USER_FUNC_OCONTINUE 42 /* continue serving after eof */
#define SQLNET_USER_FUNC_ODSCRARR  43 /* array describe */
#define SQLNET_USER_FUNC_OLCCINI   44 /* init sys pars command table */
#define SQLNET_USER_FUNC_OLCCFIN   45 /* finalize sys pars command table */
#define SQLNET_USER_FUNC_OLCCPUT   46 /* put sys par in command table */
#define SQLNET_USER_FUNC_OLCCGPI   47 /* get sys pars info from command table */
#define SQLNET_USER_FUNC_OV6STRT   48 /* start Oracle (V6) */
#define SQLNET_USER_FUNC_OV6STOP   49 /* [poll for] shut down Oracle (V6) */
#define SQLNET_USER_FUNC_ORIP      50 /* run independent process (V6) */
#define SQLNET_USER_FUNC_OTRAM     51 /* test RAM (V6) */
#define SQLNET_USER_FUNC_OARCHIVE  52 /* archive op (V6) */
#define SQLNET_USER_FUNC_OMRSTART  53 /* media recovery - start (V6) */
#define SQLNET_USER_FUNC_OMRRECTS  54 /* media recovery - record tablespace to recover (V6) */

#define SQLNET_USER_FUNC_OMRGSLSQ 55 /* media recovery - get starting log seq # (V6) */
#define SQLNET_USER_FUNC_OMRREC   56 /* media recovery - recover using offline log (V6) */
#define SQLNET_USER_FUNC_OMRCAN   57 /* media recovery - cancel media recovery (V6) */
#define SQLNET_USER_FUNC_O2LOGON  58 /* logon to ORACLE (V6) (supercedes OLOGON) */
#define SQLNET_USER_FUNC_OVERSION 59 /* get ORACLE version-date string in new format */
#define SQLNET_USER_FUNC_OINIT2   60 /* new init call (supersedes OINIT) */
#define SQLNET_USER_FUNC_OCLOALL  61 /* reserved for MAC; close all cursors */
#define SQLNET_USER_FUNC_OALL     62 /* bundled execution call */
#define SQLNET_USER_FUNC_OTEX     63 /* reserved for os2/msdos; transaction execute call */
#define SQLNET_USER_FUNC_OSDAUTH  64 /* reserved for os2/msdos; set DBA authorization call */

#define SQLNET_USER_FUNC_OUDLFUN  65 /* for direct loader: functions */
#define SQLNET_USER_FUNC_OUDLBUF  66 /* for direct loader: buffer transfer */
#define SQLNET_USER_FUNC_OK2RPC   67 /* distrib. trans. mgr. RPC */
#define SQLNET_USER_FUNC_ODSCIDX  68 /* describe indexes for distributed query */
#define SQLNET_USER_FUNC_OSESOPN  69 /* session operations */
#define SQLNET_USER_FUNC_OEXECSCN 70 /* execute using synchronized system commit numbers */
#define SQLNET_USER_FUNC_OALL7    71 /* fast upi calls to opial7 */
#define SQLNET_USER_FUNC_OLONGF   72 /* Long fetch version 7 */
#define SQLNET_USER_FUNC_OEXECA   73 /* call opiexe from opiall; no two-task access */
#define SQLNET_USER_FUNC_OSQL7    74 /* New ver 7 parse call to deal with various flavours*/
#define SQLNET_USER_FUNC_OOBS     75 /* Please DO Not REUSE THIS CODE */
#define SQLNET_USER_FUNC_ORPC     76 /* RPC Call from pl/sql */
#define SQLNET_USER_FUNC_OKGL_OLD 77 /* do a KGL operation */
#define SQLNET_USER_FUNC_OEXFEN   78
#define SQLNET_USER_FUNC_OXAOPN   79 /* X/Open XA operation */
#define SQLNET_USER_FUNC_OKGL     80 /* New OKGL call */
#define SQLNET_USER_FUNC_03LOGON  81 /* 2nd Half of Logon */
#define SQLNET_USER_FUNC_03LOGA   82 /* 1st Half of Logon */
#define SQLNET_USER_FUNC_OFNSTM   83 /* Do Streaming Operation */
#define SQLNET_USER_FUNC_OPENSESS 84 /* Open Session */
#define SQLNET_USER_FUNC_O71XAOPN 85 /* X/Open XA operations (71 interface */
#define SQLNET_USER_FUNC_ODEBUG   86 /* debugging operation */
#define SQLNET_USER_FUNC_ODEBUGS  87 /* special debugging operation */
#define SQLNET_USER_FUNC_OXAST    88 /* XA start */
#define SQLNET_USER_FUNC_OXACM    89 /* XA Switch and Commit */
#define SQLNET_USER_FUNC_OXAPR    90 /* XA Switch and Prepare */
#define SQLNET_USER_FUNC_OXDP     91 /* direct copy from db buffers to client addr */

/* in Oracle 7 and lower, this used to be OCONNECT */
#define SQLNET_USER_FUNC_OKOD 92 /* New OKOD call */

/* Oracle 8 changes follow */
#define SQLNET_USER_FUNC_OCBK       93  /* OCBK call (kernel side only) */
#define SQLNET_USER_FUNC_OALL8      94  /* new v8 bundled call */
#define SQLNET_USER_FUNC_OFNSTM2    95  /* OFNSTM without the begintxn */
#define SQLNET_USER_FUNC_OLOBOPS    96  /* LOB and FILE related calls */
#define SQLNET_USER_FUNC_OFILECRT   97  /* FILE create call */
#define SQLNET_USER_FUNC_ODNY       98  /* new describe query call */
#define SQLNET_USER_FUNC_OCONNECT   99  /* code for non blocking attach host */
#define SQLNET_USER_FUNC_OOPENRCS   100 /* Open a recursive cursor */
#define SQLNET_USER_FUNC_OKPRALL    101 /* Bundled KPR execution */
#define SQLNET_USER_FUNC_OPLS       102 /* Bundled PL/SQL execution */
#define SQLNET_USER_FUNC_OTXSE      103 /* transaction start, attach, detach */
#define SQLNET_USER_FUNC_OTXEN      104 /* transaction commit, rollback, recover */
#define SQLNET_USER_FUNC_OCCA       105 /* Cursor Close All */
#define SQLNET_USER_FUNC_OFOI       106 /* Failover info piggyback */
#define SQLNET_USER_FUNC_O80SES     107 /* V8 session switching piggyback */
#define SQLNET_USER_FUNC_ODDF       108 /* Do Dummy Defines */
#define SQLNET_USER_FUNC_OLRMINI    109 /* init sys pars */
#define SQLNET_USER_FUNC_OLRMFIN    110 /* finalize sys pars */
#define SQLNET_USER_FUNC_OLRMPUT    111 /* put sys par in par space */
#define SQLNET_USER_FUNC_OLRMTRM    112 /* terminate sys pars */
#define SQLNET_USER_FUNC_OEXFENA    113 /* execute but don't unmap (used from opiall0) */
#define SQLNET_USER_FUNC_OINIUCB    114 /* OINIT for Untrusted CallBacks */
#define SQLNET_USER_FUNC_AUTH       115 /* Generic authentication call */
#define SQLNET_USER_FUNC_OFGI       116 /* FailOver Get Instance Info */
#define SQLNET_USER_FUNC_OOTCO      117 /* Oracle Transaction service COmmit remote sites */
#define SQLNET_USER_FUNC_GETSESSKEY 118 /* Get the session key */
#define SQLNET_USER_FUNC_ODSY       119 /* V8 Describe Any */
#define SQLNET_USER_FUNC_OCANA      120 /* Cancel All */
#define SQLNET_USER_FUNC_OAQEQ      121 /* AQ EnQueue */
#define SQLNET_USER_FUNC_OAQDQ      122 /* AQ Dequeue */
#define SQLNET_USER_FUNC_OTRANS     123 /* Object transfer */
#define SQLNET_USER_FUNC_ORFS       124 /* RFS call */
#define SQLNET_USER_FUNC_OKPN       125 /* Kernel Programmatic Notification */
#define SQLNET_USER_FUNC_LISTEN     126 /* Listen */
#define SQLNET_USER_FUNC_OTSCRS     127 /* Oracle Transaction service Commit remote sites (V >= 8.1.3) */
#define SQLNET_USER_FUNC_DPP        128 /* Dir Path Prepare */
#define SQLNET_USER_FUNC_DPLS       129 /* Dir Path Load Stream */
#define SQLNET_USER_FUNC_DPMO       130 /* Dir Path Misc. Ops */
#define SQLNET_USER_FUNC_MS         131 /* Memory Stats */
#define SQLNET_USER_FUNC_AQPS       132 /* AQ Properties Status */
#define SQLNET_USER_FUNC_RFALF      134 /* Remote Fetch Archive Log FAL */
#define SQLNET_USER_FUNC_CIDP       135 /* Client ID propagation */
#define SQLNET_USER_FUNC_DRSCNXP    136 /* DR Server CNX Process */
#define SQLNET_USER_FUNC_SPFPP      138 /* SPFILE parameter put */
#define SQLNET_USER_FUNC_KPFCEX     139 /* KPFC exchange */
#define SQLNET_USER_FUNC_OT         140 /* Object Transfer (V8.2) */
#define SQLNET_USER_FUNC_PUSHTS     141 /* Push Transaction */
#define SQLNET_USER_FUNC_POPTS      142 /* Pop Transaction */
#define SQLNET_USER_FUNC_KFNOP      143 /* KFN Operation */
#define SQLNET_USER_FUNC_DPUS       144 /* Dir Path Unload Stream */
#define SQLNET_USER_FUNC_AQBED      145 /* AQ batch enqueue dequeue */
#define SQLNET_USER_FUNC_FTRANS     146 /* File Transfer */
#define SQLNET_USER_FUNC_PING       147 /* Ping */
#define SQLNET_USER_FUNC_TSM        148 /* TSM */
#define SQLNET_USER_FUNC_TSMB       150 /* Begin TSM */
#define SQLNET_USER_FUNC_TSME       151 /* End TSM */
#define SQLNET_USER_FUNC_SETSCHEMA  152 /* Set schema */
#define SQLNET_USER_FUNC_FFSRS      153 /* Fetch from suspended result set */
#define SQLNET_USER_FUNC_KVP        154 /* Key/Value pair */
#define SQLNET_USER_FUNC_XSCSOP     155 /* XS Create session Operation */
#define SQLNET_USER_FUNC_XSSROP     156 /* XS Session Roundtrip Operation */
#define SQLNET_USER_FUNC_XSPBOP     157 /* XS Piggyback Operation */
#define SQLNET_USER_FUNC_KSRPCEXEC  158 /* KSRPC Execution */
#define SQLNET_USER_FUNC_SCCA       159 /* Streams combined capture apply */
#define SQLNET_USER_FUNC_AQRI       160 /* AQ replay information */
#define SQLNET_USER_FUNC_SSCR       161 /* SSCR */
#define SQLNET_USER_FUNC_SESSGET    162 /* Session Get */
#define SQLNET_USER_FUNC_SESSRLS    163 /* Session RLS */
#define SQLNET_USER_FUNC_WLRD       165 /* Workload replay data */
#define SQLNET_USER_FUNC_RSD        166 /* Replay statistic data */
#define SQLNET_USER_FUNC_QCS        167 /* Query Cache Stats */
#define SQLNET_USER_FUNC_QCID       168 /* Query Cache IDs */
#define SQLNET_USER_FUNC_RPCTS      169 /* RPC Test Stream */
#define SQLNET_USER_FUNC_RPLSQLRPC  170 /* Replay PL/SQL RPC */
#define SQLNET_USER_FUNC_XSOUT      171 /* XStream Out */
#define SQLNET_USER_FUNC_GGRPC      172 /* Golden Gate RPC */

// --
#define SQLNET_USER_FUNC_MAX_OFCN   xxx /* last item allocated */

/* Return OPI Parameter's Type */
#define OPI_VERSION2            1
#define OPI_OSESSKEY            2
#define OPI_OAUTH               3

/* desegmentation of TNS over TCP */
static gboolean tns_desegment = TRUE;

static dissector_handle_t tns_handle;

static int proto_tns = -1;
static int hf_tns_request = -1;
static int hf_tns_response = -1;
static int hf_tns_length = -1;
static int hf_tns_packet_checksum = -1;
static int hf_tns_header_checksum = -1;
static int hf_tns_packet_type = -1;
static int hf_tns_reserved_byte = -1;
static int hf_tns_version = -1;
static int hf_tns_compat_version = -1;

static int hf_tns_service_options = -1;
static int hf_tns_sopt_flag_bconn = -1;
static int hf_tns_sopt_flag_pc = -1;
static int hf_tns_sopt_flag_hc = -1;
static int hf_tns_sopt_flag_fd = -1;
static int hf_tns_sopt_flag_hd = -1;
static int hf_tns_sopt_flag_dc1 = -1;
static int hf_tns_sopt_flag_dc2 = -1;
static int hf_tns_sopt_flag_dio = -1;
static int hf_tns_sopt_flag_ap = -1;
static int hf_tns_sopt_flag_ra = -1;
static int hf_tns_sopt_flag_sa = -1;

static int hf_tns_sdu_size = -1;
static int hf_tns_max_tdu_size = -1;

static int hf_tns_nt_proto_characteristics = -1;
static int hf_tns_ntp_flag_hangon = -1;
static int hf_tns_ntp_flag_crel = -1;
static int hf_tns_ntp_flag_tduio = -1;
static int hf_tns_ntp_flag_srun = -1;
static int hf_tns_ntp_flag_dtest = -1;
static int hf_tns_ntp_flag_cbio = -1;
static int hf_tns_ntp_flag_asio = -1;
static int hf_tns_ntp_flag_pio = -1;
static int hf_tns_ntp_flag_grant = -1;
static int hf_tns_ntp_flag_handoff = -1;
static int hf_tns_ntp_flag_sigio = -1;
static int hf_tns_ntp_flag_sigpipe = -1;
static int hf_tns_ntp_flag_sigurg = -1;
static int hf_tns_ntp_flag_urgentio = -1;
static int hf_tns_ntp_flag_fdio = -1;
static int hf_tns_ntp_flag_testop = -1;

static int hf_tns_line_turnaround = -1;
static int hf_tns_value_of_one = -1;
static int hf_tns_connect_data_length = -1;
static int hf_tns_connect_data_offset = -1;
static int hf_tns_connect_data_max = -1;

static int hf_tns_connect_flags0 = -1;
static int hf_tns_connect_flags1 = -1;
static int hf_tns_conn_flag_nareq = -1;
static int hf_tns_conn_flag_nalink = -1;
static int hf_tns_conn_flag_enablena = -1;
static int hf_tns_conn_flag_ichg = -1;
static int hf_tns_conn_flag_wantna = -1;

static int hf_tns_connect_data = -1;
static int hf_tns_trace_cf1 = -1;
static int hf_tns_trace_cf2 = -1;
static int hf_tns_trace_cid = -1;

static int hf_tns_accept_data_length = -1;
static int hf_tns_accept_data_offset = -1;
static int hf_tns_accept_data = -1;

static int hf_tns_refuse_reason_user = -1;
static int hf_tns_refuse_reason_system = -1;
static int hf_tns_refuse_data_length = -1;
static int hf_tns_refuse_data = -1;

static int hf_tns_abort_reason_user = -1;
static int hf_tns_abort_reason_system = -1;
static int hf_tns_abort_data = -1;

static int hf_tns_marker_type = -1;
static int hf_tns_marker_data_byte = -1;
/* static int hf_tns_marker_data = -1; */

static int hf_tns_redirect_data_length = -1;
static int hf_tns_redirect_data = -1;

static int hf_tns_control_cmd = -1;
static int hf_tns_control_data = -1;

static int hf_tns_data_flag = -1;
static int hf_tns_data_flag_send = -1;
static int hf_tns_data_flag_rc = -1;
static int hf_tns_data_flag_c = -1;
static int hf_tns_data_flag_reserved = -1;
static int hf_tns_data_flag_more = -1;
static int hf_tns_data_flag_eof = -1;
static int hf_tns_data_flag_dic = -1;
static int hf_tns_data_flag_rts = -1;
static int hf_tns_data_flag_sntt = -1;

static int hf_tns_data_id = -1;
static int hf_tns_data_length = -1;
static int hf_tns_data_oci_id = -1;
static int hf_tns_data_piggyback_id = -1;
static int hf_tns_data_unused = -1;

static int hf_tns_data_opi_version2_banner_len = -1;
static int hf_tns_data_opi_version2_banner = -1;
static int hf_tns_data_opi_version2_vsnum = -1;

static int hf_tns_data_opi_num_of_params = -1;
static int hf_tns_data_opi_param_length = -1;
static int hf_tns_data_opi_param_name = -1;
static int hf_tns_data_opi_param_value = -1;

static int hf_tns_data_setp_acc_version = -1;
static int hf_tns_data_setp_cli_plat = -1;
static int hf_tns_data_setp_version = -1;
static int hf_tns_data_setp_banner = -1;

static int hf_tns_data_sns_cli_vers = -1;
static int hf_tns_data_sns_srv_vers = -1;
static int hf_tns_data_sns_srvcnt = -1;

/* TTC/TTI START ====================================
 * Layer offset 0x40 and above */
static int hf_tns_data_ttic_pkt_number = -1;
static int hf_tns_data_ttic_pkt_unknown_1 = -1;
static int hf_tns_data_ttic_req_type = -1;
static int hf_tns_data_ttic_pkt_unknown_3 = -1;
static int hf_tns_data_ttic_data_direction = -1;
static int hf_tns_data_ttic_param_count = -1;
static int hf_tns_data_ttic_stmt_sql = -1;
/* I don't know how to register hf... dynamicly */
static int hf_tns_data_ttic_stmt_sql_p01 = -1;
static int hf_tns_data_ttic_stmt_sql_p02 = -1;
static int hf_tns_data_ttic_stmt_sql_p03 = -1;
static int hf_tns_data_ttic_stmt_sql_p04 = -1;
static int hf_tns_data_ttic_stmt_sql_p05 = -1;
static int hf_tns_data_ttic_stmt_sql_p06 = -1;
static int hf_tns_data_ttic_stmt_sql_p07 = -1;
static int hf_tns_data_ttic_stmt_sql_p08 = -1;
static int hf_tns_data_ttic_stmt_sql_p09 = -1;
static int hf_tns_data_ttic_stmt_sql_p10 = -1;
static int hf_tns_data_ttic_stmt_sql_p11 = -1;
static int hf_tns_data_ttic_stmt_sql_p12 = -1;
static int hf_tns_data_ttic_stmt_sql_p13 = -1;
static int hf_tns_data_ttic_stmt_sql_p14 = -1;
static int hf_tns_data_ttic_stmt_sql_p15 = -1;
static int hf_tns_data_ttic_stmt_sql_p16 = -1;
static int hf_tns_data_ttic_stmt_sql_p17 = -1;
static int hf_tns_data_ttic_stmt_sql_p18 = -1;
static int hf_tns_data_ttic_stmt_sql_p19 = -1;
static int hf_tns_data_ttic_stmt_sql_p20 = -1;
/* TTC/TTI END ====================================== */

static gint ett_tns = -1;
static gint ett_tns_connect = -1;
static gint ett_tns_accept = -1;
static gint ett_tns_refuse = -1;
static gint ett_tns_abort = -1;
static gint ett_tns_redirect = -1;
static gint ett_tns_marker = -1;
static gint ett_tns_attention = -1;
static gint ett_tns_control = -1;
static gint ett_tns_data = -1;
static gint ett_tns_data_flag = -1;
static gint ett_tns_acc_versions = -1;
static gint ett_tns_opi_params = -1;
static gint ett_tns_opi_par = -1;
static gint ett_tns_sopt_flag = -1;
static gint ett_tns_ntp_flag = -1;
static gint ett_tns_conn_flag = -1;
static gint ett_sql = -1;
static gint ett_sql_params = -1; /* TTC/TTI */

#define TCP_PORT_TNS			1521 /* Not IANA registered */

static int * const tns_connect_flags[] = {
	&hf_tns_conn_flag_nareq,
	&hf_tns_conn_flag_nalink,
	&hf_tns_conn_flag_enablena,
	&hf_tns_conn_flag_ichg,
	&hf_tns_conn_flag_wantna,
	NULL
};

static int * const tns_service_options[] = {
	&hf_tns_sopt_flag_bconn,
	&hf_tns_sopt_flag_pc,
	&hf_tns_sopt_flag_hc,
	&hf_tns_sopt_flag_fd,
	&hf_tns_sopt_flag_hd,
	&hf_tns_sopt_flag_dc1,
	&hf_tns_sopt_flag_dc2,
	&hf_tns_sopt_flag_dio,
	&hf_tns_sopt_flag_ap,
	&hf_tns_sopt_flag_ra,
	&hf_tns_sopt_flag_sa,
	NULL
};

static const value_string tns_type_vals[] = {
	{TNS_TYPE_CONNECT,   "Connect" },
	{TNS_TYPE_ACCEPT,    "Accept" },
	{TNS_TYPE_ACK,       "Acknowledge" },
	{TNS_TYPE_REFUSE,    "Refuse" },
	{TNS_TYPE_REDIRECT,  "Redirect" },
	{TNS_TYPE_DATA,      "Data" },
	{TNS_TYPE_NULL,      "Null" },
	{TNS_TYPE_ABORT,     "Abort" },
	{TNS_TYPE_RESEND,    "Resend"},
	{TNS_TYPE_MARKER,    "Marker"},
	{TNS_TYPE_ATTENTION, "Attention"},
	{TNS_TYPE_CONTROL,   "Control"},
	{0, NULL}
};

static const value_string tns_data_funcs[] = {
	{SQLNET_SET_PROTOCOL,     "Set Protocol"},
	{SQLNET_SET_DATATYPES,    "Set Datatypes"},
	{SQLNET_USER_OCI_FUNC,    "User OCI Functions"},
	{SQLNET_RETURN_STATUS,    "Return Status"},
	{SQLNET_ACCESS_USR_ADDR,  "Access User Address Space"},
	{SQLNET_ROW_TRANSF_HDR,   "Row Transfer Header"},
	{SQLNET_ROW_TRANSF_DATA,  "Row Transfer Data"},
	{SQLNET_RETURN_OPI_PARAM, "Return OPI Parameter"},
	{SQLNET_FUNCCOMPLETE,     "Function Complete"},
	{SQLNET_NERROR_RET_DEF,   "N Error return definitions follow"},
	{SQLNET_IOVEC_4FAST_UPI,  "Sending I/O Vec only for fast UPI"},
	{SQLNET_LONG_4FAST_UPI,   "Sending long for fast UPI"},
	{SQLNET_INVOKE_USER_CB,   "Invoke user callback"},
	{SQLNET_LOB_FILE_DF,      "LOB/FILE data follows"},
	{SQLNET_WARNING,          "Warning messages - may be a set of them"},
	{SQLNET_DESCRIBE_INFO,    "Describe Information"},
	{SQLNET_PIGGYBACK_FUNC,   "Piggy back function follow"},
	{SQLNET_SIG_4UCS,         "Signals special action for untrusted callout support"},
	{SQLNET_FLUSH_BIND_DATA,  "Flush Out Bind data in DML/w RETURN when error"},
	{SQLNET_XTRN_PROCSERV_R1, "External Procedures and Services Registrations"},
	{SQLNET_XTRN_PROCSERV_R2, "External Procedures and Services Registrations"},
	{SQLNET_SNS,              "Secure Network Services"},
	{0, NULL}
};

static const value_string tns_data_oci_subfuncs[] = {
	{SQLNET_USER_FUNC_OLOGON, "Logon to Oracle"},
	{SQLNET_USER_FUNC_OPENCURSOR, "Open Cursor"},
	{SQLNET_USER_FUNC_PARSE, "Parse a Row"},
	{SQLNET_USER_FUNC_EXECUTE, "Execute a Row"},
	{SQLNET_USER_FUNC_OFETCH, "Fetch a Row"},
	{SQLNET_USER_FUNC_CLOSECURSOR, "Close Cursor"},
	{SQLNET_USER_FUNC_OLOGOFF, "Logoff of Oracle"},
	{SQLNET_USER_FUNC_ODSCRIBE, "Describe a select list column"},
	{SQLNET_USER_FUNC_ODEFIN, "Define where the column goes"},
	{SQLNET_USER_FUNC_OCOMON, "Auto commit on"},
	{SQLNET_USER_FUNC_OCOMOFF, "Auto commit off"},
	{SQLNET_USER_FUNC_OCOMMIT, "Commit"},
	{SQLNET_USER_FUNC_OROLLBACK, "Rollback"},
	{SQLNET_USER_FUNC_OSFE, "Set fatal error options"},
	{SQLNET_USER_FUNC_ORESUME, "Resume current operation"},
	{SQLNET_USER_FUNC_OVERSN, "Get Oracle version-date string"},
	{SQLNET_USER_FUNC_OTEMP, "Until we get rid of OASQL"},
	{SQLNET_USER_FUNC_CANCEL, "Cancel the current operation"},
	{SQLNET_USER_FUNC_OGEM, "Get error message"},
	{SQLNET_USER_FUNC_OEXIT, "Exit Oracle command"},
	{SQLNET_USER_FUNC_OSPECIAL, "Special function"},
	{SQLNET_USER_FUNC_OABORT, "Abort"},
	{SQLNET_USER_FUNC_ODQRID, "Dequeue by RowID"},
	{SQLNET_USER_FUNC_OLNGF6, "Fetch a long column value"},
	{SQLNET_USER_FUNC_OCAM, "Create Access Module"},
	{SQLNET_USER_FUNC_OSAMS, "Save Access Module Statement"},
	{SQLNET_USER_FUNC_OSAM, "Save Access Module"},
	{SQLNET_USER_FUNC_OPAMS, "Parse Access Module Statement"},
	{SQLNET_USER_FUNC_OHOWMANY, "How many items?"},
	{SQLNET_USER_FUNC_OINIT, "Initialize Oracle"},
	{SQLNET_USER_FUNC_OCHANGEU, "Change User ID"},
	{SQLNET_USER_FUNC_OBINDRP, "Bind by reference positional"},
	{SQLNET_USER_FUNC_OGETBV, "Get n'th Bind Variable"},
	{SQLNET_USER_FUNC_OGETIV, "Get n'th Into Variable"},
	{SQLNET_USER_FUNC_OBINDRV, "Bind by reference"},
	{SQLNET_USER_FUNC_OBINDRN, "Bind by reference numeric"},
	{SQLNET_USER_FUNC_OPARSEX, "Parse and Execute"},
	{SQLNET_USER_FUNC_OPARSYN, "Parse for syntax (only)"},
	{SQLNET_USER_FUNC_OPARSDI, "Parse for syntax and SQL Dictionary lookup"},
	{SQLNET_USER_FUNC_OCONTINUE, "Continue serving after EOF"},
	{SQLNET_USER_FUNC_ODSCRARR, "Array describe"},
	{SQLNET_USER_FUNC_OLCCINI, "Init sys pars command table"},
	{SQLNET_USER_FUNC_OLCCFIN, "Finalize sys pars command table"},
	{SQLNET_USER_FUNC_OLCCPUT, "Put sys par in command table"},
	{SQLNET_USER_FUNC_OLCCGPI, "Get sys pars from command table"},
	{SQLNET_USER_FUNC_OV6STRT, "Start Oracle (V6)"},
	{SQLNET_USER_FUNC_OV6STOP, "Shutdown Oracle (V6)"},
	{SQLNET_USER_FUNC_ORIP, "Run Independent Process (V6)"},
	{SQLNET_USER_FUNC_OTRAM, "Test RAM (V6)"},
	{SQLNET_USER_FUNC_OARCHIVE, "Archive operation (V6)"},
	{SQLNET_USER_FUNC_OMRSTART, "Media Recovery - start (V6)"},
	{SQLNET_USER_FUNC_OMRRECTS, "Media Recovery - record tablespace to recover (V6)"},
	{SQLNET_USER_FUNC_OMRGSLSQ, "Media Recovery - get starting log seq # (V6)"},
	{SQLNET_USER_FUNC_OMRREC, "Media Recovery - recover using offline log (V6)"},
	{SQLNET_USER_FUNC_OMRCAN, "Media Recovery - cancel media recovery (V6)"},
	{SQLNET_USER_FUNC_O2LOGON, "Logon to Oracle (V6)"},
	{SQLNET_USER_FUNC_OVERSION, "Get Oracle version-date string in new format"},
	{SQLNET_USER_FUNC_OINIT2, "Initialize Oracle"},
	{SQLNET_USER_FUNC_OCLOALL, "Reserved for MAC; close all cursors"},
	{SQLNET_USER_FUNC_OALL, "Bundled execution call"},
	{SQLNET_USER_FUNC_OTEX, "Reserved for OS2/M$DOS; transaction execute call"},
	{SQLNET_USER_FUNC_OSDAUTH, "Reserved for OS2/M$DOS; set DBA authorization call "},
	{SQLNET_USER_FUNC_OUDLFUN, "For direct loader: functions"},
	{SQLNET_USER_FUNC_OUDLBUF, "For direct loader: buffer transfer"},
	{SQLNET_USER_FUNC_OK2RPC, "Distrib. trans. mgr. RPC"},
	{SQLNET_USER_FUNC_ODSCIDX, "Describe indexes for distributed query"},
	{SQLNET_USER_FUNC_OSESOPN, "Session operations"},
	{SQLNET_USER_FUNC_OEXECSCN, "Execute using synchronized system commit numbers"},
	{SQLNET_USER_FUNC_OALL7, "Fast UPI calls to OPIAL7"},
	{SQLNET_USER_FUNC_OLONGF, "Long Fetch (V7)"},
	{SQLNET_USER_FUNC_OEXECA, "Call OPIEXE from OPIALL: no two-task access"},
	{SQLNET_USER_FUNC_OSQL7, "Parse Call (V7) to deal with various flavours"},
	{SQLNET_USER_FUNC_ORPC, "RPC call from PL/SQL"},
	{SQLNET_USER_FUNC_OKGL_OLD, "Do a KGL operation (OLD)"},
	{SQLNET_USER_FUNC_OEXFEN, "Execute and Fetch"},
	{SQLNET_USER_FUNC_OXAOPN, "X/Open XA operation"},
	{SQLNET_USER_FUNC_OKGL, "Do KGL operation call (NEW)"},
	{SQLNET_USER_FUNC_03LOGON, "2nd Half of Logon"},
	{SQLNET_USER_FUNC_03LOGA, "1st Half of Logon"},
	{SQLNET_USER_FUNC_OFNSTM, "Do Streaming Operation"},
	{SQLNET_USER_FUNC_OPENSESS, "Open Session (71 interface)"},
	{SQLNET_USER_FUNC_O71XAOPN, "X/Open XA operations (71 interface)"},
	{SQLNET_USER_FUNC_ODEBUG, "Debugging operations"},
	{SQLNET_USER_FUNC_ODEBUGS, "Special debugging operations"},
	{SQLNET_USER_FUNC_OXAST, "XA Start"},
	{SQLNET_USER_FUNC_OXACM, "XA Switch and Commit"},
	{SQLNET_USER_FUNC_OXAPR, "Direct copy from db buffers to client address"},
	{SQLNET_USER_FUNC_OXDP, "OKOD Call (In Oracle <= 7 this used to be Connect"},
	/* in Oracle 7 and lower, this used to be OCONNECT */
	{SQLNET_USER_FUNC_OKOD, " New OKOD call"},
	/* Oracle 8 changes follow */
	{SQLNET_USER_FUNC_OCBK, "RPI Callback with ctxdef"},
	{SQLNET_USER_FUNC_OALL8, "Bundled execution call (V7)"},
	{SQLNET_USER_FUNC_OFNSTM2, "Do Streaming Operation without begintxn"},
	{SQLNET_USER_FUNC_OLOBOPS, "LOB and FILE related calls"},
	{SQLNET_USER_FUNC_OFILECRT, "File Create call"},
	{SQLNET_USER_FUNC_ODNY, "Describe query (V8) call"},
	{SQLNET_USER_FUNC_OCONNECT, "Connect (non-blocking attach host)"},
	{SQLNET_USER_FUNC_OOPENRCS, "Open a recursive cursor"},
	{SQLNET_USER_FUNC_OKPRALL, "Bundled KPR Execution"},
	{SQLNET_USER_FUNC_OPLS, "Bundled PL/SQL execution"},
	{SQLNET_USER_FUNC_OTXSE, "Transaction start, attach, detach"},
	{SQLNET_USER_FUNC_OTXEN, "Transaction commit, rollback, recover"},
	{SQLNET_USER_FUNC_OCCA, "Cursor close all"},
	{SQLNET_USER_FUNC_OFOI, "Failover into piggyback"},
	{SQLNET_USER_FUNC_O80SES, "Session switching piggyback (V8)"},
	{SQLNET_USER_FUNC_ODDF, "Do Dummy Defines"},
	{SQLNET_USER_FUNC_OLRMINI, "Init sys pars (V8)"},
	{SQLNET_USER_FUNC_OLRMFIN, "Finalize sys pars (V8)"},
	{SQLNET_USER_FUNC_OLRMPUT, "Put sys par in par space (V8)"},
	{SQLNET_USER_FUNC_OLRMTRM, "Terminate sys pars (V8)"},
	{SQLNET_USER_FUNC_OINIUCB, "Init Untrusted Callbacks"},
	{SQLNET_USER_FUNC_AUTH, "Generic authentication call"},
	{SQLNET_USER_FUNC_OFGI, "FailOver Get Instance call"},
	{SQLNET_USER_FUNC_OOTCO, "Oracle Transaction service Commit remote sites"},
	{SQLNET_USER_FUNC_GETSESSKEY, "Get the session key"},
	{SQLNET_USER_FUNC_ODSY, "Describe any (V8)"},
	{SQLNET_USER_FUNC_OCANA, "Cancel All"},
	{SQLNET_USER_FUNC_OAQEQ, "AQ Enqueue"},
	{SQLNET_USER_FUNC_OAQDQ, "AQ Dequeue"},
	{SQLNET_USER_FUNC_OTRANS, "Object transfer"},
	{SQLNET_USER_FUNC_ORFS, "RFS Call"},
	{SQLNET_USER_FUNC_OKPN, "Kernel programmatic notification"},
	{SQLNET_USER_FUNC_LISTEN, "Listen"},
	{SQLNET_USER_FUNC_OTSCRS, "Oracle Transaction service Commit remote sites (V >= 8.1.3)"},
	{SQLNET_USER_FUNC_DPP, "Dir Path Prepare"},
	{SQLNET_USER_FUNC_DPLS, "Dir Path Load Stream"},
	{SQLNET_USER_FUNC_DPMO, "Dir Path Misc. Ops"},
	{SQLNET_USER_FUNC_MS, "Memory Stats"},
	{SQLNET_USER_FUNC_AQPS, "AQ Properties Status"},
	{SQLNET_USER_FUNC_RFALF, "Remote Fetch Archive Log FAL"},
	{SQLNET_USER_FUNC_CIDP, "Client ID propagation"},
	{SQLNET_USER_FUNC_DRSCNXP, "DR Server CNX Process"},
	{SQLNET_USER_FUNC_SPFPP, "SPFILE parameter put"},
	{SQLNET_USER_FUNC_KPFCEX, "KPFC exchange"},
	{SQLNET_USER_FUNC_OT, "Object Transfer (V8.2)"},
	{SQLNET_USER_FUNC_PUSHTS, "Push Transaction"},
	{SQLNET_USER_FUNC_POPTS, "Pop Transaction"},
	{SQLNET_USER_FUNC_KFNOP, "KFN Operation"},
	{SQLNET_USER_FUNC_DPUS, "Dir Path Unload Stream"},
	{SQLNET_USER_FUNC_AQBED, "AQ batch enqueue dequeue"},
	{SQLNET_USER_FUNC_FTRANS, "File Transfer"},
	{SQLNET_USER_FUNC_PING, "Ping"},
	{SQLNET_USER_FUNC_TSM, "TSM"},
	{SQLNET_USER_FUNC_TSMB, "Begin TSM"},
	{SQLNET_USER_FUNC_TSME, "End TSM"},
	{SQLNET_USER_FUNC_SETSCHEMA, "Set schema"},
	{SQLNET_USER_FUNC_FFSRS, "Fetch from suspended result set"},
	{SQLNET_USER_FUNC_KVP, "Key/Value pair"},
	{SQLNET_USER_FUNC_XSCSOP, "XS Create session Operation"},
	{SQLNET_USER_FUNC_XSSROP, "XS Session Roundtrip Operation"},
	{SQLNET_USER_FUNC_XSPBOP, "XS Piggyback Operation"},
	{SQLNET_USER_FUNC_KSRPCEXEC, "KSRPC Execution"},
	{SQLNET_USER_FUNC_SCCA, "Streams combined capture apply"},
	{SQLNET_USER_FUNC_AQRI, "AQ replay information"},
	{SQLNET_USER_FUNC_SSCR, "SSCR"},
	{SQLNET_USER_FUNC_SESSGET, "Session Get"},
	{SQLNET_USER_FUNC_SESSRLS, "Session RLS"},
	{SQLNET_USER_FUNC_WLRD, "Workload replay data"},
	{SQLNET_USER_FUNC_RSD, "Replay statistic data"},
	{SQLNET_USER_FUNC_QCS, "Query Cache Stats"},
	{SQLNET_USER_FUNC_QCID, "Query Cache IDs"},
	{SQLNET_USER_FUNC_RPCTS, "RPC Test Stream"},
	{SQLNET_USER_FUNC_RPLSQLRPC, "Replay PL/SQL RPC"},
	{SQLNET_USER_FUNC_XSOUT, "XStream Out"},
	{SQLNET_USER_FUNC_GGRPC, "Golden Gate RPC"},
	{0, NULL}
};
static value_string_ext tns_data_oci_subfuncs_ext = VALUE_STRING_EXT_INIT(tns_data_oci_subfuncs);

/* TTC/TTI START ================================================================= */
#define SQLNET_TTCI_REQ_BEGIN_TS 0x01
#define SQLNET_TTCI_REQ_QRYPRIMKEY 0x20
#define SQLNET_TTCI_REQ_SQLSTMT 0x29
#define SQLNET_TTCI_REQ_TYPE_0x40 0x40
#define SQLNET_TTCI_REQ_GET_BLOB 0x50
#define SQLNET_TTCI_REQ_SQLPARAM_1 0x60
#define SQLNET_TTCI_REQ_SQLPARAM_2 0x68
#define SQLNET_TTCI_REQ_READ_BLOB 0x72

static const value_string tns_data_ttci_req_types[] = {
	{SQLNET_TTCI_REQ_BEGIN_TS, "Begin Transaction"},
	{SQLNET_TTCI_REQ_QRYPRIMKEY, "Query with Primary Key (UPI)"},
	{SQLNET_TTCI_REQ_SQLSTMT, "SQL Statement"},
	{SQLNET_TTCI_REQ_TYPE_0x40, "REQ Type 0x40"},
	{SQLNET_TTCI_REQ_GET_BLOB, "GET BLOB/LOB/FILE"},
	{SQLNET_TTCI_REQ_READ_BLOB, "READ BLOB/LOB/FILE"},
	{SQLNET_TTCI_REQ_SQLPARAM_1, "Batch Processing"},
	{SQLNET_TTCI_REQ_SQLPARAM_2, "SQL Parameter Data"},
	{0, NULL}
};

#define SQLNET_TTCI_STMT_GET_DATA 0xff
#define SQLNET_TTCI_STMT_SET_DATA 0x7f
static const value_string tns_data_ttic_data_direction[] = {
	{SQLNET_TTCI_STMT_GET_DATA, "Read Data"},
	{SQLNET_TTCI_STMT_SET_DATA, "Modify Data"},
	{0, NULL}
};


/* TTC/TTI END ==================================================================== */

static const value_string tns_marker_types[] = {
	{0, "Data Marker - 0 Data Bytes"},
	{1, "Data Marker - 1 Data Bytes"},
	{2, "Attention Marker"},
	{0, NULL}
};

static const value_string tns_control_cmds[] = {
	{1, "Oracle Trace Command"},
	{0, NULL}
};

void proto_reg_handoff_tns(void);
static int dissect_tns_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_);

static guint get_data_func_id(tvbuff_t *tvb, int offset)
{
	/* Determine Data Function id */
	guint8 first_byte;

	first_byte =
	    tvb_reported_length_remaining(tvb, offset) > 0 ? tvb_get_guint8(tvb, offset) : 0;

	if ( tvb_bytes_exist(tvb, offset, 4) && first_byte == 0xDE &&
	     tvb_get_guint24(tvb, offset+1, ENC_BIG_ENDIAN) == 0xADBEEF )
	{
		return SQLNET_SNS;
	}
	else
	{
		return (guint)first_byte;
	}
}

static void vsnum_to_vstext_basecustom(gchar *result, guint32 vsnum)
{
	/*
	 * Translate hex value to human readable version value, described at
	 * http://docs.oracle.com/cd/B28359_01/server.111/b28310/dba004.htm
	 */
	snprintf(result, ITEM_LABEL_LENGTH, "%d.%d.%d.%d.%d",
		 vsnum >> 24,
		(vsnum >> 20) & 0xf,
		(vsnum >> 12) & 0xf,
		(vsnum >>  8) & 0xf,
		 vsnum & 0xff);
}

/**
 * SQL statement parameter header
 * Oracle 12 
 *          ..... B8 B8 ..... ..... ..... ..... B8 ..... .....
 * select : 01 01 00 00 00 00 00 00 01 01 00 02 80 00 00 00 00
 * ins/upd: 01 01 01 01 00 00 00 00 01 01 00 02 0c 00 00 00 00
 * difference between select and insert update:
 * select : byte 3 and byte 4 == 0x00 byte 13 => 0x80
 * ins/upd: byte  3 => 0x01 byte 4 => volatile (0x01, 0x09, 0x36 ...) byte 13 => 0x0c 
 */
typedef struct ttci_param_header {
	uint16_t unknown_1;
	uint8_t  direction;		/* get=0 set=1 */
	uint8_t  flags;         /* 0x01, 0x09, 0x36 ?? */
	uint16_t unknown_2;
	uint16_t unknown_3;
	uint16_t unknown_4;
	uint16_t unknown_5;
	uint8_t  type;          /* select=0x80 ins/upd=0x0c */
	uint16_t unknown_6;
	uint8_t unknown_7;
} ttci_stmt_pd_hdr_t;

/**
 * SQL statement parameter descriptor 
 *                         ..... ..... type.
 *  Parameter-Marker.....: 02 03 69 01 00 02
 *                         02 03 69 01 00 01 
 *                         02 03 69 01 00 b4 
 *                         02 03 69 01 00 0c 
 *                         02 03 69 01 01 0b 
 * 	                       02 03 69 01 00 07
 *                         u16.. u16.. u8 u16.. u8 u16.. u16.. u16.. u16..
 *  Parameter-Descr. 0001: 03 00 00 01 28 00 01 10 00 00 02 03 69 01 00 01  
 *  Parameter-Descr. 0002: 03 00 00 01 34 00 01 10 00 00 02 03 69 01 00 02 
 *  Parameter-Descr. 000c: 03 00 00 01 10 00 01 10 00 00 02 03 69 01 00 0c
 *  Parameter-Descr. 00b4:
 *  Parameter-Descr. 010b:
 *  Parameter-Descr.SHORT: 03 00 00 01 16 00 00 00 00 02 03 69 01 00 01
 *  Byte 5 = 16 or 17....: 03 00 00 01 07 00 00 00 00 02 03 69 01 00 01 
 * 
 *  start of vaue list: first byte 
 *  of each value is length byte
 *  Parameter-Descr. 0007: 03 00 00 01 20 00 01 10 00 00 02 03 69 01 00 07
 *  .....................: u16.. u16.. u8 u16.. u8 u16.. u16.. u16.. u16..
 */
typedef struct {
	uint16_t magic_1;   /* 03 00 */
	uint16_t magic_2;   /* 00 01 */
	uint8_t  flags;      /* 28, 34, 10, 20 | Short: 16, 07*/
	struct {
		uint16_t unknown_1;
		uint8_t unknown_2;
		uint16_t unknown_3;
	} param_props;
	struct {
		uint16_t marker_1;
		uint16_t marker_2;
		uint16_t marker_3;
	} param_marker;
} ttci_stmt_pd_itm_t;

/**
 * @brief TTC/TTI packet structure (work in progress!)
 */
typedef struct {
	uint8_t packet_number;
	uint16_t unknown_1;
	uint8_t request_type;
	uint16_t unknown_2;
	uint16_t unknown_3;
	uint8_t stmt_byte1_prfx;
	uint8_t stmt_byte1;
	uint8_t stmt_byte2;
	uint8_t stmt_byte3;
	uint16_t stmt_sign1;
	uint8_t stmt_sign2;
	uint8_t data_direction;
	uint8_t unknown_4;
	uint16_t unknown_5;
	uint8_t stmt_byte4;
	uint8_t stmt_flags;
	uint8_t param_count;
	uint16_t unknown_6;
	uint16_t unknown_7;
	uint8_t stmt_sel_unk1;
	uint8_t stmt_sel_unk2;
} ttci_packet_t;

//#define _DISSECTOR_SQL_DEBUG

/* TCC/TCI Parse SQL parameter block */
static int dissect_tns_data_sql_params(tvbuff_t *tvb, proto_tree *data_tree _U_, int offset, ttci_packet_t* pttci)
{
	int* hf_prop_ref_list[] = {
		&hf_tns_data_ttic_stmt_sql_p01,
		&hf_tns_data_ttic_stmt_sql_p02,
		&hf_tns_data_ttic_stmt_sql_p03,
		&hf_tns_data_ttic_stmt_sql_p04,
		&hf_tns_data_ttic_stmt_sql_p05,
		&hf_tns_data_ttic_stmt_sql_p06,
		&hf_tns_data_ttic_stmt_sql_p07,
		&hf_tns_data_ttic_stmt_sql_p08,
		&hf_tns_data_ttic_stmt_sql_p09,
		&hf_tns_data_ttic_stmt_sql_p10,
		&hf_tns_data_ttic_stmt_sql_p11,
		&hf_tns_data_ttic_stmt_sql_p12,
		&hf_tns_data_ttic_stmt_sql_p13,
		&hf_tns_data_ttic_stmt_sql_p14,
		&hf_tns_data_ttic_stmt_sql_p15,
		&hf_tns_data_ttic_stmt_sql_p16,
		&hf_tns_data_ttic_stmt_sql_p17,
		&hf_tns_data_ttic_stmt_sql_p18,
		&hf_tns_data_ttic_stmt_sql_p19,
		&hf_tns_data_ttic_stmt_sql_p20,
		NULL,
	};

	ttci_stmt_pd_hdr_t* pd_header;
	ttci_stmt_pd_itm_t* pd_list;
	proto_tree* pd_tree;
	proto_item *pi;
	proto_item *ti;
	uint8_t* byte_buffer;
	int buff_offset;
	int bytes_remaining;
	int pd_list_size;
	#ifdef _DISSECTOR_SQL_DEBUG
	int pd_header_size;
	#endif

	/* get remaining bytes of packet buffer */
	bytes_remaining = tvb_reported_length_remaining(tvb, offset);

	/* size of parameter descriptor list plus value list marker entry */
	pd_list_size = sizeof(ttci_stmt_pd_itm_t) * (pttci->param_count + 1);
	
#ifdef _DISSECTOR_SQL_DEBUG
	/* size of static statement parameter header */
	pd_header_size = sizeof(ttci_stmt_pd_hdr_t);

	fprintf(stdout, "%s: TTCI(offset=0x%04x) SQL:PARAMS:START pdhs=%d pdls=%d remaining=%d +++++++\n", 
		__func__, offset, pd_header_size, pd_list_size, bytes_remaining);
#endif

	/* at least header size + one parameter marker */
	if ( bytes_remaining > (int) (sizeof(ttci_stmt_pd_hdr_t) + 6) ) 
	{
		/* allocate packet buffer */
		if ( !(pd_header = malloc(sizeof(ttci_stmt_pd_hdr_t))) )
		{
			fprintf(stderr, "%s: TTC/TTI: Out of memory. Abort!\n", __func__);
			goto exit_done;
		}
		memset(pd_header, 0, sizeof(ttci_stmt_pd_hdr_t));

		/* allocate parameter descriptor list */
		if (!(pd_list = malloc(pd_list_size)))
		{
			fprintf(stderr, "%s: TTC/TTI: Out of memory. Abort!\n", __func__);
			goto exit_cleanup;
		}
		memset(pd_list, 0, pd_list_size);

		/* get SQL parameter header block */
		pd_header = (ttci_stmt_pd_hdr_t*) tvb_memcpy(tvb, pd_header, offset, sizeof(ttci_stmt_pd_hdr_t));

#ifdef _DISSECTOR_SQL_DEBUG

		fprintf(stdout, "%s: TTCI(offset=0x%04x) param_count=%d direction=0x%02x "
						"flags=0x%02x type=0x%02x u1=0x%04x u2=0x%04x u3=0x%04x u4=0x%04x u5=0x%04x\n", 
			__func__, offset, 
			pttci->param_count,
			pd_header->direction,
			pd_header->flags,
			pd_header->type,
			pd_header->unknown_1,
			pd_header->unknown_2,
			pd_header->unknown_3,
			pd_header->unknown_4,
			pd_header->unknown_5);
#endif

		/* set offset of the parameter descriptor block */
		if (pd_header->unknown_5 == 0x8002) {
			/* header is one byte to short. found in sql 
			 * statement with 1 parameter. */
			buff_offset = offset + sizeof(ttci_stmt_pd_hdr_t) - 1;
		} else {
			buff_offset = offset + sizeof(ttci_stmt_pd_hdr_t);
		}

		/* set offset end of parameter descriptor header */
		int bytes = tvb_reported_length_remaining(tvb, buff_offset);
		bool found = false;
		
		/* find first parameter block */
		if ( bytes > 4 ) do 
		{
			pd_list[0].magic_1 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
			pd_list[0].magic_2 = tvb_get_guint16(tvb, buff_offset + 2, ENC_BIG_ENDIAN);
			if (pd_list[0].magic_1 == 0x0300 && pd_list[0].magic_2 == 0x001) 
			{
				found = true;
				break;
			} 

#ifdef _DISSECTOR_SQL_DEBUG
			fprintf(stdout, "%s: TTCI(offset=0x%04x) magic_1=0x%04x magic_2=0x%04x\n", 
				__func__, buff_offset, pd_list[0].magic_1, pd_list[0].magic_2);
#endif			
			bytes -= 1;
			buff_offset += 1;	
		} while (bytes > 0);

		if (!found) {
			fprintf(stderr, "%s: TTC/TTI: Parameter descriptor not found. Abort! bytes_remaining=%d buff_offset=%d\n",
				__func__, bytes_remaining, buff_offset);
			goto exit_clenup_list;
		}

		/* load parameter descriptors */
		for (int j = 0; j < pttci->param_count; j++) 
		{
			pd_list[j].magic_1 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
			buff_offset += 2;

			pd_list[j].magic_2 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
			buff_offset += 2;

			pd_list[j].flags = tvb_get_guint8 (tvb, buff_offset);
			buff_offset += 1;

			/* end of descriptor list reached */
			if (pd_list[j].magic_1 != 0x0300 && pd_list[j].magic_2 != 0x0001)
			{
				fprintf(stderr, "%s: TTC/TTI: Invalid parameter descriptor detected. Abort! offs=0x%04x ma1=0x%04x ma2=0x%04x flags=0x%02x\n",
					__func__, buff_offset, pd_list[j].magic_1, pd_list[j].magic_2, pd_list[j].flags);
				goto exit_clenup_list;
			}
			
			/* number/date/time parameter types: */
			if (pd_list[j].flags == 0x16 || pd_list[j].flags == 0x07)
			{
				pd_list[j].param_props.unknown_1 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
				buff_offset += 2;
				pd_list[j].param_props.unknown_2 = tvb_get_guint8(tvb, buff_offset);
				buff_offset += 1;
				pd_list[j].param_props.unknown_3 = tvb_get_guint8(tvb, buff_offset);
				buff_offset += 1;

				pd_list[j].param_marker.marker_1 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
				buff_offset += 2;
				pd_list[j].param_marker.marker_2 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
				buff_offset += 2;
				pd_list[j].param_marker.marker_3 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
				buff_offset += 2;
			}
			/* parameter type: */
			else {
				pd_list[j].param_props.unknown_1 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
				buff_offset += 2;
				pd_list[j].param_props.unknown_2 = tvb_get_guint8(tvb, buff_offset);
				buff_offset += 1;
				pd_list[j].param_props.unknown_3 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
				buff_offset += 2;

				pd_list[j].param_marker.marker_1 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
				buff_offset += 2;
				pd_list[j].param_marker.marker_2 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
				buff_offset += 2;
				pd_list[j].param_marker.marker_3 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
				buff_offset += 2;

				if (pd_list[j].flags == 0x01 && pd_list[j].magic_2 == 0x0109)
				{
					/* reread marker 3 word */
					pd_list[j].param_marker.marker_3 = tvb_get_guint16(tvb, buff_offset, ENC_BIG_ENDIAN);
					buff_offset += 2;
				}
			}
			
#ifdef _DISSECTOR_SQL_DEBUG
			fprintf(stdout, "%s: TTCI(offset=0x%04x) >> p=%d ma1=0x%04x ma2=0x%04x flags=0x%02x pu1=0x%04x pu2=0x%02x pu3=0x%04x pm1=0x%04x pm2=0x%04x pm3=0x%04x\n", 
				__func__, buff_offset, j + 1,
				pd_list[j].magic_1,
				pd_list[j].magic_2,
				pd_list[j].flags,
				pd_list[j].param_props.unknown_1,
				pd_list[j].param_props.unknown_2,
				pd_list[j].param_props.unknown_3,
				pd_list[j].param_marker.marker_1,
				pd_list[j].param_marker.marker_2,
				pd_list[j].param_marker.marker_3);
#endif
			/* parameter value list marker reached */
			if (pd_list[j].param_marker.marker_2 == 0x6901 && pd_list[j].param_marker.marker_3 == 0x0007)
			{
#ifdef _DISSECTOR_SQL_DEBUG
				fprintf(stdout, "%s: TTCI(offset=0x%04x) buff_offset=0x%04x *** VALUE LIST REACHED ***\n", 
					__func__, offset, buff_offset);
#endif
				break;
			}
		}

		/* set start of prameter value list */
		offset = buff_offset;

		/* get remaining bytes of packet buffer */
		if (!(bytes_remaining = tvb_reported_length_remaining(tvb, offset)))
		{
			goto exit_clenup_list;
		}

#ifdef _DISSECTOR_SQL_DEBUG
		fprintf(stdout, "%s: TTCI(offset=0x%04x) SQL:VALUES:START remaining=%d +++++++\n", 
			__func__, offset, bytes_remaining);
#endif
		int* hf_prop_ref;
		char numbuf[1024];
		pd_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1, ett_sql_params, &ti, "TTC/TTI SQL Parameters");

		for (int i=0, param_idx=0, value_len=0;
			 i < bytes_remaining && param_idx < pttci->param_count && hf_prop_ref_list[param_idx]; 
			 param_idx++, i += value_len)
		{
			if ( tvb_reported_length_remaining(tvb, offset) <= 0 )
			{
				fprintf(stderr, "%s: TTC/TTI: No bytes left, Abort!\n", __func__);
				goto exit_clenup_list;				
			}

			hf_prop_ref = hf_prop_ref_list[param_idx];
			value_len = tvb_get_guint8(tvb, offset);
			offset += 1;

			/* valid value length */
			if ( !value_len )
			{
				fprintf(stderr, "%s: TTC/TTI: Invalid parameter value length detected. Abort!\n", __func__);
				goto exit_clenup_list;				
			}

#ifdef _DISSECTOR_SQL_DEBUG
			fprintf(stdout, "%s: TTCI(offset=0x%04x) param_idx=%d flags=0x%02x pu1=0x%04x pu2=0x%04x pm3=0x%04x value_len=%d\n", 
				__func__, offset, param_idx + 1, 
				pd_list[param_idx].flags, 
				pd_list[param_idx].param_props.unknown_1,
				pd_list[param_idx].param_props.unknown_2, 
				pd_list[param_idx].param_marker.marker_3, 
				value_len);
#endif
			/* string field */
			if (pd_list[param_idx].param_props.unknown_2 & 0x10)
			{
				if (!(byte_buffer = malloc(value_len + 1)))
				{
					fprintf(stderr, "%s: TTC/TTI: Out of memory. Abort!\n", __func__);
					goto exit_clenup_list;				
				}
				memset(byte_buffer, 0, value_len + 1);

				byte_buffer = tvb_memcpy(tvb, byte_buffer, offset, value_len);
				byte_buffer[value_len + 1] = 0;

#ifdef _DISSECTOR_SQL_DEBUG
				fprintf(stderr, "%s: TTCI(offset=0x%04x) STRING VALUE: %s\n", 
					__func__, offset, byte_buffer);
#endif

				/* selection focus value incl. length byte */
				pi = proto_tree_add_item(pd_tree, (*hf_prop_ref), tvb, offset - 1, (gint) strlen(byte_buffer) + 1, ENC_UTF_8);
				proto_item_set_text(pi, "%02d String: %s", param_idx + 1, (const char*) byte_buffer);
				offset += value_len;

				free(byte_buffer);
			}
			/* NUMBER or DATE or TIME or etc. */
			else 
			{
				memset(numbuf, 0, sizeof(numbuf));

				/* flags:
				 * 0x16 => 0001 0110 --> pu1=0x0000 | pu2=0x0000 [VL=1 -> pm3=0x0007 or VL=2 -> pm3=0x0001]
				 * 0x07 => 0000 0111 --> pu1=0x0000 | pu2=0x0000
				 * 0x01 => 0000 0001 --> pu1=0x0b00 | pu2=0x0004 (date/time)
				 */
				#if 0
				bool isLE = false;
				double value = 0.0f;
				switch (value_len)
				{
					/* 8bit */
					case 1:
						value = tvb_get_gint8(tvb, offset);
						break;
					/* 16bit */
					case 2:
						value = (isLE ? tvb_get_letohis(tvb, offset) : tvb_get_ntohis(tvb, offset));
						break;
					/* 24bit */
					case 3:
						value = (isLE ? tvb_get_letohi24(tvb, offset) : tvb_get_ntoh24(tvb, offset));
						break;
					/* 32bit */
					case 4:
						value = (isLE ? tvb_get_letohil(tvb, offset) : tvb_get_ntohil(tvb, offset));
						break;
					/* 40bit */
					case 5:
						value = (isLE ? tvb_get_letohi40(tvb, offset) : tvb_get_ntohi40(tvb, offset));
						break;
					/* 48bit */
					case 6:
						value = (isLE ? tvb_get_letohi48(tvb, offset) : tvb_get_ntohi48(tvb, offset));
						break;
					/* 56bit */
					case 7:
						value = (isLE ? tvb_get_letohi56(tvb, offset) : tvb_get_ntohi56(tvb, offset));
						break;
					/* 64bit */
					case 8:
						value = (isLE ? tvb_get_letohi64(tvb, offset) : tvb_get_ntohi64(tvb, offset));
						break;
					/* others */
					default:
						/* DATE / TIME VALUE */
						if ((pd_list[param_idx].param_props.unknown_1 == 0x0b00) &&
						    (pd_list[param_idx].param_props.unknown_2 & 0x0004)) 
						{
							/* date / time */
							strcpy(numbuf, "<value not translated>");
						} 
						else 
						{
							value = tvb_get_ntohieee_double(tvb, offset);
						}
						break;
				}
				if (strlen(numbuf) == 0) 
				{
					snprintf(numbuf, 127, "%f", value);
				}
				#endif
				
				char *p = &numbuf[0];
				for(int j=0; j < value_len && j < (int)(sizeof(numbuf)/4); j++) {
					sprintf(p, "%02x ", tvb_get_guint8(tvb, offset + j));
					p += 3;
				}

				/* selection focus value incl. length byte */
				pi = proto_tree_add_item(pd_tree, (*hf_prop_ref), tvb, offset - 1, value_len + 1, ENC_UTF_8);
				if ((pd_list[param_idx].param_props.unknown_1 == 0x0b00) &&
					(pd_list[param_idx].param_props.unknown_2 & 0x0004)) 
				{
#ifdef _DISSECTOR_SQL_DEBUG
					fprintf(stderr, "%s: TTCI(offset=0x%04x) DATE/TIME(%d) VALUE: %s\n", 
							__func__, offset, value_len, numbuf);
#endif
					proto_item_set_text(pi, "%02d Date/Time (Hex Bytes): %s", param_idx + 1, (const char*) numbuf);
				}
				else 
				{
#ifdef _DISSECTOR_SQL_DEBUG
					fprintf(stderr, "%s: TTCI(offset=0x%04x) NUMBER(%d) VALUE: %s\n", 
							__func__, offset, value_len, numbuf);
#endif
					proto_item_set_text(pi, "%02d Number (Hex Bytes): %s", param_idx + 1, (const char*) numbuf);
				}
				offset += value_len;
			}
		}
	
exit_clenup_list:
		free(pd_list);

exit_cleanup:
		free(pd_header);
	} 

exit_done:
#ifdef _DISSECTOR_SQL_DEBUG
	fprintf(stdout, "%s: TTCI(offset=0x%04x) SQL:PARAMS:END --------\n", 
		__func__, offset);
#endif

	return offset;
}

/* TCC/TCI Parse SQL statement packet */
static int dissect_tns_data_sql(tvbuff_t *tvb, proto_tree *data_tree, int offset, ttci_packet_t* pttci)
{
	proto_item *pi;
	uint8_t* byte_buffer;
	gint stmt_length = 0;
	int bytes_remaining;
	int tv_disp_offset = -1;
	int hdr_jmp_len;

	if ( tvb_reported_length_remaining(tvb, offset) > 19 )
	{
		pttci->unknown_2 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
		offset += 2;

		pttci->unknown_3 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
		proto_tree_add_item(data_tree, hf_tns_data_ttic_pkt_unknown_3, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

#ifdef _DISSECTOR_SQL_DEBUG
		fprintf(stdout, "%s: TTCI(offset=0x%04x) unknown_2=0x%04x unknown_3=0x%04x (%d)\n",
			__func__, offset, 
			pttci->unknown_2, 
			pttci->unknown_3,
			pttci->unknown_3);
#endif

		/* should be 0x01 or 0x33 or 0x35 */
		pttci->stmt_byte1 = tvb_get_guint8(tvb, offset);
		offset += 1;
		
		/* offset increased one step */
		if (pttci->stmt_byte1 != 0x01) {
			pttci->stmt_byte1_prfx = pttci->stmt_byte1;
			/* should be 0x01 */
			pttci->stmt_byte1 = tvb_get_guint8(tvb, offset);
			offset += 1;
		}

		/* should be 0x01 */
		pttci->stmt_byte2 = tvb_get_guint8(tvb, offset);
		offset += 1;

		/* should be 0x0d */
		pttci->stmt_byte3 = tvb_get_guint8(tvb, offset);
		offset += 1;

#ifdef _DISSECTOR_SQL_DEBUG
		fprintf(stdout, "%s: TTCI(offset=0x%04x) prfx=0x%02x stmt_byte1=0x%02x stmt_byte2=0x%02x stmt_byte3=0x%02x\n", 
			__func__, offset, 
			pttci->stmt_byte1_prfx, 
			pttci->stmt_byte1, 
			pttci->stmt_byte2, 
			pttci->stmt_byte3);
#endif

		/* should be 0x0000 */
		pttci->stmt_sign1 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
		offset += 2;

		/* should be 0x04 */
		pttci->stmt_sign2 = tvb_get_guint8(tvb, offset);
		offset += 1;

#ifdef _DISSECTOR_SQL_DEBUG		
		fprintf(stdout, "%s: TTCI(offset=0x%04x) stmt_sign1=0x%04x stmt_sign2=0x%02x\n",
			__func__, offset, 
			pttci->stmt_sign1, 
			pttci->stmt_sign2);
#endif

		/* SELECT .... statement (get rows from server) */
		if (pttci->stmt_sign1 == 0 && pttci->stmt_sign2 == 0x04) {
			pttci->data_direction = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(data_tree, hf_tns_data_ttic_data_direction, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			pttci->unknown_4 = tvb_get_guint8(tvb, offset);
			offset += 1;
			pttci->unknown_5 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
			offset += 2;
		}
		/* UPDATE / INSERT / DELETE?? .... statement (push data to server)
			* -> offset increases 2 bytes */
		else if (pttci->stmt_sign1 == 0 && pttci->stmt_sign2 == 0) {
			offset += 2;
			pttci->data_direction = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(data_tree, hf_tns_data_ttic_data_direction, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			pttci->unknown_4 = tvb_get_guint8(tvb, offset);
			offset += 1;
			pttci->unknown_5 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
			offset += 2;
		}

#ifdef _DISSECTOR_SQL_DEBUG
		fprintf(stdout, "%s: TTCI(offset=0x%04x) data_direction=0x%02x unknown_4=0x%02x unknown_5=0x%04x\n",
			__func__, offset, 
			pttci->data_direction, 
			pttci->unknown_4, 
			pttci->unknown_5);
#endif

		/* should be 0x01 */
		pttci->stmt_byte4 = tvb_get_guint8(tvb, offset);
		offset += 1;

		/* should be 0x01 == INSERT/UPDATE/DELETE? or 0x0a == SELECT */
		pttci->stmt_flags = tvb_get_guint8(tvb, offset);
		offset += 1;

		/* INSERT/UPDATE/DELETE? parameter count */
		pttci->param_count = tvb_get_guint8(tvb, offset);
		tv_disp_offset = offset;
		offset += 1;

#ifdef _DISSECTOR_SQL_DEBUG
		fprintf(stdout, "%s: TTCI(offset=0x%04x) stmt_byte4=0x%02x stmt_flags=0x%02x param_count=%d\n",
			__func__, offset, pttci->stmt_byte4, pttci->stmt_flags, pttci->param_count);
#endif

		/* here on select statement a block of 0x7fff 0xffff follows */
		pttci->unknown_6 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
		offset += 2;
		pttci->unknown_7 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
		offset += 2;

		/* parameter count SELECT -> display offset + 7 */
		if ( pttci->stmt_flags == 0x0a )
		{
			/* should be 0x01 */
			pttci->stmt_sel_unk1 = tvb_get_guint8(tvb, offset);
			offset += 1;

			/* should be 0x01 */
			pttci->stmt_sel_unk2 = tvb_get_guint8(tvb, offset);
			offset += 1;

			pttci->param_count = tvb_get_guint8(tvb, offset);
			tv_disp_offset = offset;
			offset += 1;
		}

		proto_tree_add_item(data_tree, hf_tns_data_ttic_param_count, tvb, tv_disp_offset, 1, ENC_BIG_ENDIAN);

#ifdef _DISSECTOR_SQL_DEBUG
		fprintf(stdout, "%s: TTCI(offset=0x%04x) unknown_6=0x%04x unknown_7=0x%04x stmt_sel_unk1=0x%02x stmt_sel_unk2=0x%02x\n",
			__func__, offset, 
			pttci->unknown_6, 
			pttci->unknown_7,
			pttci->stmt_sel_unk1,
			pttci->stmt_sel_unk2);
#endif
	}

	switch (pttci->data_direction)
	{
		case 0x7f: 
		{
			hdr_jmp_len = 15;
			break;
		}
		case 0xff: 
		{
			hdr_jmp_len = 18;
			break;
		}
		default:
		{
			fprintf(stderr, "%s: TTC/TTI: Invalid data direction type, abort.\n", __func__);
			return offset;
		}
	}

	/* set start offset of SQL statement */
	offset += hdr_jmp_len;

	/* get remaining bytes of packet buffer */
	bytes_remaining = tvb_reported_length_remaining(tvb, offset);

#ifdef _DISSECTOR_SQL_DEBUG
	fprintf(stdout, "%s: TTCI(offset=0x%04x) SQL:STMT:START remaining=%d +++++++\n", 
		__func__, offset, bytes_remaining);
#endif

	if ( !bytes_remaining ) 
	{
		return offset;
	}

	/* allocate SQL statement buffer */
	if (!(byte_buffer = malloc(bytes_remaining + 1)))
	{
		fprintf(stderr, "%s: TTC/TTI: Out of memory. Abort!\n", __func__);
		return offset;
	}
	memset(byte_buffer, 0, bytes_remaining + 1);

#ifdef _DISSECTOR_SQL_DEBUG
	fprintf(stdout, "%s: TTCI(offset=0x%04x) buffer_size=%d\n",
		__func__, offset, bytes_remaining + 1);
#endif

	/* copy SQL statement from packet stream */
	byte_buffer = (uint8_t*) tvb_memcpy(tvb, byte_buffer, offset, bytes_remaining);
	for (int i = 0; i < bytes_remaining; i++) 
	{
		/* check end of SQL statement */
		if (byte_buffer[i] == 0x01 && byte_buffer[i+1] == 0x01) 
		{
			stmt_length = i;
			byte_buffer[i] = 0; // terminate
			break;
		}
	}
	
	/* SQL statement loaded? */
	if (stmt_length != (gint) strlen((const char*) byte_buffer))
	{
		fprintf(stderr, "%s: TTC/TTI:SQL statement length mismatch. Abort!\n", __func__);
		free(byte_buffer);
		return offset;
	}

#ifdef _DISSECTOR_SQL_DEBUG
	fprintf(stdout, "%s: TTCI(offset=0x%04x) len=%d stmt=%s\n", 
		__func__, offset, stmt_length, byte_buffer);
#endif		

	/* add statement to tree view */	
	pi = proto_tree_add_item(data_tree, hf_tns_data_ttic_stmt_sql, tvb, offset, stmt_length, ENC_UTF_8);
	proto_item_set_text(pi, "%s", (const char*) byte_buffer);

	free(byte_buffer);

#ifdef _DISSECTOR_SQL_DEBUG
	fprintf(stdout, "%s: TTCI(offset=0x%04x) SQL:STMT:END stmt_length=%d +++++++\n", 
		__func__, offset + stmt_length + 1, stmt_length);
#endif

	/* SQL parameter descriptor block follows after SQL statement */
	return dissect_tns_data_sql_params(tvb, data_tree, offset + stmt_length, pttci);
}

static void dissect_tns_data(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tns_tree)
{
	proto_tree *data_tree;
	guint data_func_id;
	gboolean is_request;
	
	ttci_packet_t ttci_packet = {};

	static int * const flags[] = {
		&hf_tns_data_flag_send,
		&hf_tns_data_flag_rc,
		&hf_tns_data_flag_c,
		&hf_tns_data_flag_reserved,
		&hf_tns_data_flag_more,
		&hf_tns_data_flag_eof,
		&hf_tns_data_flag_dic,
		&hf_tns_data_flag_rts,
		&hf_tns_data_flag_sntt,
		NULL
	};

	is_request = pinfo->match_uint == pinfo->destport;
	data_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1, ett_tns_data, NULL, "Data");

	proto_tree_add_bitmask(data_tree, tvb, offset, hf_tns_data_flag, ett_tns_data_flag, flags, ENC_BIG_ENDIAN);
	offset += 2;
	data_func_id = get_data_func_id(tvb, offset);

	/* Do this only if the Data message have a body. Otherwise, there are only Data flags. */
	if ( tvb_reported_length_remaining(tvb, offset) > 0 )
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str_const(data_func_id, tns_data_funcs, "TNS: unknown"));

		if ( (data_func_id != SQLNET_SNS) && (try_val_to_str(data_func_id, tns_data_funcs) != NULL) )
		{
			proto_tree_add_item(data_tree, hf_tns_data_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
		}
	}

	/* Handle data functions that have more than just ID */
	switch (data_func_id)
	{
		case SQLNET_SET_PROTOCOL:
		{
			proto_tree *versions_tree;
			proto_item *ti;
			char sep;
			if ( is_request )
			{
				versions_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1, ett_tns_acc_versions, &ti, "Accepted Versions");
				sep = ':';
				for (;;) {
					/*
					 * Add each accepted version as a
					 * separate item.
					 */
					guint8 vers;

					vers = tvb_get_guint8(tvb, offset);
					if (vers == 0) {
						/*
						 * A version of 0 terminates
						 * the list.
						 */
						break;
					}
					proto_item_append_text(ti, "%c %u", sep, vers);
					sep = ',';
					proto_tree_add_uint(versions_tree, hf_tns_data_setp_acc_version, tvb, offset, 1, vers);
					offset += 1;
				}
				offset += 1; /* skip the 0 terminator */
				proto_item_set_end(ti, tvb, offset);
				proto_tree_add_item(data_tree, hf_tns_data_setp_cli_plat, tvb, offset, -1, ENC_ASCII);

				return; /* skip call_data_dissector */
			}
			else
			{
				gint len;
				versions_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1, ett_tns_acc_versions, &ti, "Versions");
				sep = ':';
				for (;;) {
					/*
					 * Add each version as a separate item.
					 */
					guint8 vers;

					vers = tvb_get_guint8(tvb, offset);
					if (vers == 0) {
						/*
						 * A version of 0 terminates
						 * the list.
						 */
						break;
					}
					proto_item_append_text(ti, "%c %u", sep, vers);
					sep = ',';
					proto_tree_add_uint(versions_tree, hf_tns_data_setp_version, tvb, offset, 1, vers);
					offset += 1;
				}
				offset += 1; /* skip the 0 terminator */
				proto_item_set_end(ti, tvb, offset);
				proto_tree_add_item_ret_length(data_tree, hf_tns_data_setp_banner, tvb, offset, -1, ENC_ASCII|ENC_NA, &len);
				offset += len;
			}
			break;
		}

		case SQLNET_USER_OCI_FUNC:
			if ( tvb_reported_length_remaining(tvb, offset) > 0 )
			{
				proto_tree_add_item(data_tree, hf_tns_data_oci_id, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
			}

			/* TTC/TTI START ===================================================================== */

			if ( tvb_reported_length_remaining(tvb, offset) > 3 )
			{
				ttci_packet.packet_number = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(data_tree, hf_tns_data_ttic_pkt_number, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;

				ttci_packet.unknown_1 = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
				proto_tree_add_item(data_tree, hf_tns_data_ttic_pkt_unknown_1, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;

				ttci_packet.request_type = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(data_tree, hf_tns_data_ttic_req_type, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
#ifdef _DISSECTOR_SQL_DEBUG
				fprintf(stdout, "%s: TTCI(offset=0x%04x) number=%d type=0x%02x u1=0x%04x (%d)\n",
					__func__, offset, 
					ttci_packet.packet_number, 
					ttci_packet.request_type, 
					ttci_packet.unknown_1, 
					ttci_packet.unknown_1);
#endif
			}
			
			switch(ttci_packet.request_type)
			{
				case SQLNET_TTCI_REQ_SQLSTMT: 
				{
#ifdef _DISSECTOR_SQL_DEBUG
					fprintf(stdout, "%s: TTCI(offset=0x%04x) ======================= START ============================\n",
						__func__, offset);
#endif
					offset = dissect_tns_data_sql(tvb, data_tree, offset, &ttci_packet);
					break;
				}
			}

			/* TTC/TTI END ==============================================================================*/
			break;

		case SQLNET_RETURN_OPI_PARAM:
		{
			guint8 skip = 0, opi = 0;

			if ( tvb_bytes_exist(tvb, offset, 11) )
			{
				/*
				 * OPI_VERSION2 response has a following pattern:
				 *
				 *                _ banner      _ vsnum
				 *               /             /
				 *    ..(.?)(Orac[le.+])(.?)(....).+$
				 *     |
				 *     \ banner length (if equal to 0 then next byte indicates the length).
				 *
				 * These differences (to skip 1 or 2 bytes) due to differences in the drivers.
				 */
				                                  /* Orac[le.+] */
				if ( tvb_get_ntohl(tvb, offset+2) == 0x4f726163 )
				{
					opi = OPI_VERSION2;
					skip = 1;
				}

				else if ( tvb_get_ntohl(tvb, offset+3) == 0x4f726163 )
				{
					opi = OPI_VERSION2;
					skip = 2;
				}

				/*
				 * OPI_OSESSKEY response has a following pattern:
				 *
				 *               _ pattern (v1|v2)
				 *              /        _ params
				 *             /        /
				 *    (....)(........)(.+).+$
				 *       ||
				 *        \ if these two bytes are equal to 0x0c00 then first byte is <Param Counts> (v1),
				 *          else next byte indicate it (v2).
				 */
				                                          /*  ....AUTH (v1) */
				else if ( tvb_get_ntoh64(tvb, offset+3) == 0x0000000c41555448 )
				{
					opi = OPI_OSESSKEY;
					skip = 1;
				}
				                                          /*  ..AUTH_V (v2) */
				else if ( tvb_get_ntoh64(tvb, offset+3) == 0x0c0c415554485f53 )
				{
					opi = OPI_OSESSKEY;
					skip = 2;
				}

				/*
				 * OPI_OAUTH response has a following pattern:
				 *
				 *               _ pattern (v1|v2)
				 *              /        _ params
				 *             /        /
				 *    (....)(........)(.+).+$
				 *       ||
				 *        \ if these two bytes are equal to 0x1300 then first byte is <Param Counts> (v1),
				 *          else next byte indicate it (v2).
				 */

				                                          /*  ....AUTH (v1) */
				else if ( tvb_get_ntoh64(tvb, offset+3) == 0x0000001341555448 )
				{
					opi = OPI_OAUTH;
					skip = 1;
				}
			                                                  /*  ..AUTH_V (v2) */
				else if ( tvb_get_ntoh64(tvb, offset+3) == 0x1313415554485f56 )
				{
					opi = OPI_OAUTH;
					skip = 2;
				}
			}

			if ( opi == OPI_VERSION2 )
			{
				proto_tree_add_item(data_tree, hf_tns_data_unused, tvb, offset, skip, ENC_NA);
				offset += skip;

				guint8 len = tvb_get_guint8(tvb, offset);

				proto_tree_add_item(data_tree, hf_tns_data_opi_version2_banner_len, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;

				proto_tree_add_item(data_tree, hf_tns_data_opi_version2_banner, tvb, offset, len, ENC_ASCII);
				offset += len + (skip == 1 ? 1 : 0);

				proto_tree_add_item(data_tree, hf_tns_data_opi_version2_vsnum, tvb, offset, 4, (skip == 1) ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN);
				offset += 4;
			}
			else if ( opi == OPI_OSESSKEY || opi == OPI_OAUTH )
			{
				proto_tree *params_tree;
				proto_item *params_ti;
				guint par, params;

				if ( skip == 1 )
				{
					proto_tree_add_item_ret_uint(data_tree, hf_tns_data_opi_num_of_params, tvb, offset, 1, ENC_NA, &params);
					offset += 1;

					proto_tree_add_item(data_tree, hf_tns_data_unused, tvb, offset, 5, ENC_NA);
					offset += 5;
				}
				else
				{
					proto_tree_add_item(data_tree, hf_tns_data_unused, tvb, offset, 1, ENC_NA);
					offset += 1;

					proto_tree_add_item_ret_uint(data_tree, hf_tns_data_opi_num_of_params, tvb, offset, 1, ENC_NA, &params);
					offset += 1;

					proto_tree_add_item(data_tree, hf_tns_data_unused, tvb, offset, 2, ENC_NA);
					offset += 2;
				}

				params_tree = proto_tree_add_subtree(data_tree, tvb, offset, -1, ett_tns_opi_params, &params_ti, "Parameters");

				for ( par = 1; par <= params; par++ )
				{
					proto_tree *par_tree;
					proto_item *par_ti;
					guint len, offset_prev;

					par_tree = proto_tree_add_subtree(params_tree, tvb, offset, -1, ett_tns_opi_par, &par_ti, "Parameter");
					proto_item_append_text(par_ti, " %u", par);

					/* Name length */
					proto_tree_add_item_ret_uint(par_tree, hf_tns_data_opi_param_length, tvb, offset, 1, ENC_NA, &len);
					offset += 1;

					/* Name */
					if ( !(len == 0 || len == 2) ) /* Not empty (2 - SQLDeveloper specific sign). */
					{
						proto_tree_add_item(par_tree, hf_tns_data_opi_param_name, tvb, offset, len, ENC_ASCII);
						offset += len;
					}

					/* Value can be NULL. So, save offset to calculate unused data. */
					offset_prev = offset;
					offset += skip == 1 ? 4 : 2;

					/* Value length */
					if ( opi == OPI_OSESSKEY )
					{
						len = tvb_get_guint8(tvb, offset);
					}
					else /* OPI_OAUTH */
					{
						len = tvb_get_guint8(tvb, offset_prev) == 0 ? 0 : tvb_get_guint8(tvb, offset);
					}

					/*
					 * Value
					 *   OPI_OSESSKEY: AUTH_VFR_DATA with length 0, 9, 0x39 comes without data.
					 *   OPI_OAUTH: AUTH_VFR_DATA with length 0, 0x39 comes without data.
					 */
					if ( ((opi == OPI_OSESSKEY) && !(len == 0 || len == 9 || len == 0x39))
					  || ((opi == OPI_OAUTH) && !(len == 0 || len == 0x39)) )
					{
						proto_tree_add_item(par_tree, hf_tns_data_unused, tvb, offset_prev, offset - offset_prev, ENC_NA);

						proto_tree_add_item(par_tree, hf_tns_data_opi_param_length, tvb, offset, 1, ENC_NA);
						offset += 1;

						proto_tree_add_item(par_tree, hf_tns_data_opi_param_value, tvb, offset, len, ENC_ASCII);
						offset += len;

						offset_prev = offset; /* Save offset to calculate rest of unused data */
					}
					else
					{
						offset += 1;
					}

					if ( opi == OPI_OSESSKEY )
					{
						/* SQL Developer specifix fix */
						offset += tvb_get_guint8(tvb, offset) == 2 ? 5 : 3;
					}
					else /* OPI_OAUTH */
					{
						offset += len == 0 ? 1 : 3;
					}

					if ( skip == 1 )
					{
						offset += 1 + ((len == 0 || len == 0x39) ? 3 : 4);

						if ( opi == OPI_OAUTH )
						{
							offset += len == 0 ? 2 : 0;
						}
					}

					proto_tree_add_item(par_tree, hf_tns_data_unused, tvb, offset_prev, offset - offset_prev, ENC_NA);
					proto_item_set_end(par_ti, tvb, offset);
				}
				proto_item_set_end(params_ti, tvb, offset);
			}
			break;
		}

		case SQLNET_PIGGYBACK_FUNC:
			proto_tree_add_item(data_tree, hf_tns_data_piggyback_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			break;

		case SQLNET_SNS:
		{
			proto_tree_add_item(data_tree, hf_tns_data_id, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(data_tree, hf_tns_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			if ( is_request )
			{
				proto_tree_add_item(data_tree, hf_tns_data_sns_cli_vers, tvb, offset, 4, ENC_BIG_ENDIAN);
			}
			else
			{
				proto_tree_add_item(data_tree, hf_tns_data_sns_srv_vers, tvb, offset, 4, ENC_BIG_ENDIAN);
			}
			offset += 4;

			proto_tree_add_item(data_tree, hf_tns_data_sns_srvcnt, tvb, offset, 2, ENC_BIG_ENDIAN);

			/* move back, to include data_id into data_dissector */
			offset -= 10;
			break;
		}
	}

	call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, data_tree);
}

static void dissect_tns_connect(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree)
{
	proto_tree *connect_tree;
	guint32 cd_offset, cd_len;
	int tns_offset = offset-8;
	static int * const flags[] = {
		&hf_tns_ntp_flag_hangon,
		&hf_tns_ntp_flag_crel,
		&hf_tns_ntp_flag_tduio,
		&hf_tns_ntp_flag_srun,
		&hf_tns_ntp_flag_dtest,
		&hf_tns_ntp_flag_cbio,
		&hf_tns_ntp_flag_asio,
		&hf_tns_ntp_flag_pio,
		&hf_tns_ntp_flag_grant,
		&hf_tns_ntp_flag_handoff,
		&hf_tns_ntp_flag_sigio,
		&hf_tns_ntp_flag_sigpipe,
		&hf_tns_ntp_flag_sigurg,
		&hf_tns_ntp_flag_urgentio,
		&hf_tns_ntp_flag_fdio,
		&hf_tns_ntp_flag_testop,
		NULL
	};

	connect_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		ett_tns_connect, NULL, "Connect");

	proto_tree_add_item(connect_tree, hf_tns_version, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(connect_tree, hf_tns_compat_version, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(connect_tree, tvb, offset, hf_tns_service_options, ett_tns_sopt_flag, tns_service_options, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(connect_tree, hf_tns_sdu_size, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(connect_tree, hf_tns_max_tdu_size, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(connect_tree, tvb, offset, hf_tns_nt_proto_characteristics, ett_tns_ntp_flag, flags, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(connect_tree, hf_tns_line_turnaround, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(connect_tree, hf_tns_value_of_one, tvb,
			offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item_ret_uint(connect_tree, hf_tns_connect_data_length, tvb,
			offset, 2, ENC_BIG_ENDIAN, &cd_len);
	offset += 2;

	proto_tree_add_item_ret_uint(connect_tree, hf_tns_connect_data_offset, tvb,
			offset, 2, ENC_BIG_ENDIAN, &cd_offset);
	offset += 2;

	proto_tree_add_item(connect_tree, hf_tns_connect_data_max, tvb,
			offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_bitmask(connect_tree, tvb, offset, hf_tns_connect_flags0, ett_tns_conn_flag, tns_connect_flags, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(connect_tree, tvb, offset, hf_tns_connect_flags1, ett_tns_conn_flag, tns_connect_flags, ENC_BIG_ENDIAN);
	offset += 1;

	/*
	 * XXX - sometimes it appears that this stuff isn't present
	 * in the packet.
	 */
	if ((guint32)(offset + 16) <= tns_offset+cd_offset)
	{
		proto_tree_add_item(connect_tree, hf_tns_trace_cf1, tvb,
				offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(connect_tree, hf_tns_trace_cf2, tvb,
				offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item(connect_tree, hf_tns_trace_cid, tvb,
				offset, 8, ENC_BIG_ENDIAN);
		/* offset += 8;*/
	}

	if ( cd_len > 0)
	{
		proto_tree_add_item(connect_tree, hf_tns_connect_data, tvb,
			tns_offset+cd_offset, -1, ENC_ASCII);
	}
}

static void dissect_tns_accept(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree)
{
	proto_tree *accept_tree;
	guint32 accept_offset, accept_len;
	int tns_offset = offset-8;

	accept_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		    ett_tns_accept, NULL, "Accept");

	proto_tree_add_item(accept_tree, hf_tns_version, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_bitmask(accept_tree, tvb, offset, hf_tns_service_options, ett_tns_sopt_flag, tns_service_options, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(accept_tree, hf_tns_sdu_size, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(accept_tree, hf_tns_max_tdu_size, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(accept_tree, hf_tns_value_of_one, tvb,
			offset, 2, ENC_NA);
	offset += 2;

	proto_tree_add_item_ret_uint(accept_tree, hf_tns_accept_data_length, tvb,
			offset, 2, ENC_BIG_ENDIAN, &accept_len);
	offset += 2;

	proto_tree_add_item_ret_uint(accept_tree, hf_tns_accept_data_offset, tvb,
			offset, 2, ENC_BIG_ENDIAN, &accept_offset);
	offset += 2;

	proto_tree_add_bitmask(accept_tree, tvb, offset, hf_tns_connect_flags0, ett_tns_conn_flag, tns_connect_flags, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(accept_tree, tvb, offset, hf_tns_connect_flags1, ett_tns_conn_flag, tns_connect_flags, ENC_BIG_ENDIAN);
	/* offset += 1; */

	if ( accept_len > 0)
	{
		proto_tree_add_item(accept_tree, hf_tns_accept_data, tvb,
			tns_offset+accept_offset, -1, ENC_ASCII);
	}
	return;
}

static void dissect_tns_refuse(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree)
{
	/* TODO
	 * According to some reverse engineers, the refuse packet is also sent when the login fails.
	 * Byte 54 shows if this is due to invalid ID (0x02) or password (0x03).
	 * At now we do not have pcaps with such messages to check this statement.
	 */
	proto_tree *refuse_tree;

	refuse_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		    ett_tns_refuse, NULL, "Refuse");

	proto_tree_add_item(refuse_tree, hf_tns_refuse_reason_user, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(refuse_tree, hf_tns_refuse_reason_system, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(refuse_tree, hf_tns_refuse_data_length, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(refuse_tree, hf_tns_refuse_data, tvb,
			offset, -1, ENC_ASCII);
}

static void dissect_tns_abort(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree)
{
	proto_tree *abort_tree;

	abort_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		    ett_tns_abort, NULL, "Abort");

	proto_tree_add_item(abort_tree, hf_tns_abort_reason_user, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(abort_tree, hf_tns_abort_reason_system, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(abort_tree, hf_tns_abort_data, tvb,
			offset, -1, ENC_ASCII);
}

static void dissect_tns_marker(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree, int is_attention)
{
	proto_tree *marker_tree;

	if ( is_attention )
	{
		marker_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
			    ett_tns_marker, NULL, "Marker");
	}
	else
	{
		marker_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
			    ett_tns_marker, NULL, "Attention");
	}

	proto_tree_add_item(marker_tree, hf_tns_marker_type, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(marker_tree, hf_tns_marker_data_byte, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(marker_tree, hf_tns_marker_data_byte, tvb,
			offset, 1, ENC_BIG_ENDIAN);
	/*offset += 1;*/
}

static void dissect_tns_redirect(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree)
{
	proto_tree *redirect_tree;

	redirect_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		    ett_tns_redirect, NULL, "Redirect");

	proto_tree_add_item(redirect_tree, hf_tns_redirect_data_length, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(redirect_tree, hf_tns_redirect_data, tvb,
			offset, -1, ENC_ASCII);
}

static void dissect_tns_control(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tns_tree)
{
	proto_tree *control_tree;

	control_tree = proto_tree_add_subtree(tns_tree, tvb, offset, -1,
		    ett_tns_control, NULL, "Control");

	proto_tree_add_item(control_tree, hf_tns_control_cmd, tvb,
			offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(control_tree, hf_tns_control_data, tvb,
			offset, -1, ENC_NA);
}

static guint get_tns_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	/*
	 * Get the 16-bit length of the TNS message, including header
	 */
	return tvb_get_ntohs(tvb, offset);
}

static guint get_tns_pdu_len_nochksum(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	/*
	 * Get the 32-bit length of the TNS message, including header
	 */
	return tvb_get_ntohl(tvb, offset);
}

static int dissect_tns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	guint32 length;
	guint16 chksum;
	guint8  type;

	/*
	 * First, do a sanity check to make sure what we have
	 * starts with a TNS PDU.
	 */
	if (tvb_bytes_exist(tvb, 4, 1)) {
		/*
		 * Well, we have the packet type; let's make sure
		 * it's a known type.
		 */
		type = tvb_get_guint8(tvb, 4);
		if (type < TNS_TYPE_CONNECT || type > TNS_TYPE_MAX)
			return 0;	/* it's not a known type */
	}

	/*
	 * In some messages (observed in Oracle12c) packet length has 4 bytes
	 * instead of 2.
	 *
	 * If packet length has 2 bytes, length and checksum equals two unsigned
	 * 16-bit numbers. Packet checksum is generally unused (equal zero),
	 * but 10g client may set 2nd byte to 4.
	 *
	 * Else, Oracle 12c combine these two 16-bit numbers into one 32-bit.
	 * This number represents the packet length. Checksum is omitted.
	 */
	chksum = tvb_get_ntohs(tvb, 2);

	length = (chksum == 0 || chksum == 4) ? 2 : 4;

	tcp_dissect_pdus(tvb, pinfo, tree, tns_desegment, length,
			(length == 2 ? get_tns_pdu_len : get_tns_pdu_len_nochksum),
			dissect_tns_pdu, data);

	return tvb_captured_length(tvb);
}

static int dissect_tns_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree *tns_tree, *ti;
	proto_item *hidden_item;
	int offset = 0;
	guint32 length;
	guint16 chksum;
	guint8  type;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TNS");

	col_set_str(pinfo->cinfo, COL_INFO,
			(pinfo->match_uint == pinfo->destport) ? "Request" : "Response");

	ti = proto_tree_add_item(tree, proto_tns, tvb, 0, -1, ENC_NA);
	tns_tree = proto_item_add_subtree(ti, ett_tns);

	if (pinfo->match_uint == pinfo->destport)
	{
		hidden_item = proto_tree_add_boolean(tns_tree, hf_tns_request,
					tvb, offset, 0, TRUE);
	}
	else
	{
		hidden_item = proto_tree_add_boolean(tns_tree, hf_tns_response,
					tvb, offset, 0, TRUE);
	}
	proto_item_set_hidden(hidden_item);

	chksum = tvb_get_ntohs(tvb, offset+2);
	if (chksum == 0 || chksum == 4)
	{
		proto_tree_add_item_ret_uint(tns_tree, hf_tns_length, tvb, offset,
					2, ENC_BIG_ENDIAN, &length);
		offset += 2;
		proto_tree_add_checksum(tns_tree, tvb, offset, hf_tns_packet_checksum,
					-1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
		offset += 2;
	}
	else
	{
		/* Oracle 12c uses checksum bytes as part of the packet length. */
		proto_tree_add_item_ret_uint(tns_tree, hf_tns_length, tvb, offset,
					4, ENC_BIG_ENDIAN, &length);
		offset += 4;
	}

	type = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tns_tree, hf_tns_packet_type, tvb,
			offset, 1, type);
	offset += 1;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", %s (%u)",
			val_to_str_const(type, tns_type_vals, "Unknown"), type);

	proto_tree_add_item(tns_tree, hf_tns_reserved_byte, tvb,
			offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_checksum(tns_tree, tvb, offset, hf_tns_header_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
	offset += 2;

	switch (type)
	{
		case TNS_TYPE_CONNECT:
			dissect_tns_connect(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_ACCEPT:
			dissect_tns_accept(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_REFUSE:
			dissect_tns_refuse(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_REDIRECT:
			dissect_tns_redirect(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_ABORT:
			dissect_tns_abort(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_MARKER:
			dissect_tns_marker(tvb,offset,pinfo,tns_tree, 0);
			break;
		case TNS_TYPE_ATTENTION:
			dissect_tns_marker(tvb,offset,pinfo,tns_tree, 1);
			break;
		case TNS_TYPE_CONTROL:
			dissect_tns_control(tvb,offset,pinfo,tns_tree);
			break;
		case TNS_TYPE_DATA:
			dissect_tns_data(tvb,offset,pinfo,tns_tree);
			break;
		default:
			call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo,
			    tns_tree);
			break;
	}

	return tvb_captured_length(tvb);
}

void proto_register_tns(void)
{
	static hf_register_info hf[] = {
		{ &hf_tns_response, {
			"Response", "tns.response", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, "TRUE if TNS response", HFILL }},
		{ &hf_tns_request, {
			"Request", "tns.request", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, "TRUE if TNS request", HFILL }},
		{ &hf_tns_length, {
			"Packet Length", "tns.length", FT_UINT32, BASE_DEC,
			NULL, 0x0, "Length of TNS packet", HFILL }},
		{ &hf_tns_packet_checksum, {
			"Packet Checksum", "tns.packet_checksum", FT_UINT16, BASE_HEX,
			NULL, 0x0, "Checksum of Packet Data", HFILL }},
		{ &hf_tns_header_checksum, {
			"Header Checksum", "tns.header_checksum", FT_UINT16, BASE_HEX,
			NULL, 0x0, "Checksum of Header Data", HFILL }},

		{ &hf_tns_version, {
			"Version", "tns.version", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_compat_version, {
			"Version (Compatible)", "tns.compat_version", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_service_options, {
			"Service Options", "tns.service_options", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_sopt_flag_bconn, {
			"Broken Connect Notify", "tns.so_flag.bconn", FT_BOOLEAN, 16,
			NULL, 0x2000, NULL, HFILL }},
		{ &hf_tns_sopt_flag_pc, {
			"Packet Checksum", "tns.so_flag.pc", FT_BOOLEAN, 16,
			NULL, 0x1000, NULL, HFILL }},
		{ &hf_tns_sopt_flag_hc, {
			"Header Checksum", "tns.so_flag.hc", FT_BOOLEAN, 16,
			NULL, 0x0800, NULL, HFILL }},
		{ &hf_tns_sopt_flag_fd, {
			"Full Duplex", "tns.so_flag.fd", FT_BOOLEAN, 16,
			NULL, 0x0400, NULL, HFILL }},
		{ &hf_tns_sopt_flag_hd, {
			"Half Duplex", "tns.so_flag.hd", FT_BOOLEAN, 16,
			NULL, 0x0200, NULL, HFILL }},
		{ &hf_tns_sopt_flag_dc1, {
			"Don't Care", "tns.so_flag.dc1", FT_BOOLEAN, 16,
			NULL, 0x0100, NULL, HFILL }},
		{ &hf_tns_sopt_flag_dc2, {
			"Don't Care", "tns.so_flag.dc2", FT_BOOLEAN, 16,
			NULL, 0x0080, NULL, HFILL }},
		{ &hf_tns_sopt_flag_dio, {
			"Direct IO to Transport", "tns.so_flag.dio", FT_BOOLEAN, 16,
			NULL, 0x0010, NULL, HFILL }},
		{ &hf_tns_sopt_flag_ap, {
			"Attention Processing", "tns.so_flag.ap", FT_BOOLEAN, 16,
			NULL, 0x0008, NULL, HFILL }},
		{ &hf_tns_sopt_flag_ra, {
			"Can Receive Attention", "tns.so_flag.ra", FT_BOOLEAN, 16,
			NULL, 0x0004, NULL, HFILL }},
		{ &hf_tns_sopt_flag_sa, {
			"Can Send Attention", "tns.so_flag.sa", FT_BOOLEAN, 16,
			NULL, 0x0002, NULL, HFILL }},


		{ &hf_tns_sdu_size, {
			"Session Data Unit Size", "tns.sdu_size", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_max_tdu_size, {
			"Maximum Transmission Data Unit Size", "tns.max_tdu_size", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_nt_proto_characteristics, {
			"NT Protocol Characteristics", "tns.nt_proto_characteristics", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_ntp_flag_hangon, {
			"Hangon to listener connect", "tns.ntp_flag.hangon", FT_BOOLEAN, 16,
			NULL, 0x8000, NULL, HFILL }},
		{ &hf_tns_ntp_flag_crel, {
			"Confirmed release", "tns.ntp_flag.crel", FT_BOOLEAN, 16,
			NULL, 0x4000, NULL, HFILL }},
		{ &hf_tns_ntp_flag_tduio, {
			"TDU based IO", "tns.ntp_flag.tduio", FT_BOOLEAN, 16,
			NULL, 0x2000, NULL, HFILL }},
		{ &hf_tns_ntp_flag_srun, {
			"Spawner running", "tns.ntp_flag.srun", FT_BOOLEAN, 16,
			NULL, 0x1000, NULL, HFILL }},
		{ &hf_tns_ntp_flag_dtest, {
			"Data test", "tns.ntp_flag.dtest", FT_BOOLEAN, 16,
			NULL, 0x0800, NULL, HFILL }},
		{ &hf_tns_ntp_flag_cbio, {
			"Callback IO supported", "tns.ntp_flag.cbio", FT_BOOLEAN, 16,
			NULL, 0x0400, NULL, HFILL }},
		{ &hf_tns_ntp_flag_asio, {
			"ASync IO Supported", "tns.ntp_flag.asio", FT_BOOLEAN, 16,
			NULL, 0x0200, NULL, HFILL }},
		{ &hf_tns_ntp_flag_pio, {
			"Packet oriented IO", "tns.ntp_flag.pio", FT_BOOLEAN, 16,
			NULL, 0x0100, NULL, HFILL }},
		{ &hf_tns_ntp_flag_grant, {
			"Can grant connection to another", "tns.ntp_flag.grant", FT_BOOLEAN, 16,
			NULL, 0x0080, NULL, HFILL }},
		{ &hf_tns_ntp_flag_handoff, {
			"Can handoff connection to another", "tns.ntp_flag.handoff", FT_BOOLEAN, 16,
			NULL, 0x0040, NULL, HFILL }},
		{ &hf_tns_ntp_flag_sigio, {
			"Generate SIGIO signal", "tns.ntp_flag.sigio", FT_BOOLEAN, 16,
			NULL, 0x0020, NULL, HFILL }},
		{ &hf_tns_ntp_flag_sigpipe, {
			"Generate SIGPIPE signal", "tns.ntp_flag.sigpipe", FT_BOOLEAN, 16,
			NULL, 0x0010, NULL, HFILL }},
		{ &hf_tns_ntp_flag_sigurg, {
			"Generate SIGURG signal", "tns.ntp_flag.sigurg", FT_BOOLEAN, 16,
			NULL, 0x0008, NULL, HFILL }},
		{ &hf_tns_ntp_flag_urgentio, {
			"Urgent IO supported", "tns.ntp_flag.urgentio", FT_BOOLEAN, 16,
			NULL, 0x0004, NULL, HFILL }},
		{ &hf_tns_ntp_flag_fdio, {
			"Full duplex IO supported", "tns.ntp_flag.dfio", FT_BOOLEAN, 16,
			NULL, 0x0002, NULL, HFILL }},
		{ &hf_tns_ntp_flag_testop, {
			"Test operation", "tns.ntp_flag.testop", FT_BOOLEAN, 16,
			NULL, 0x0001, NULL, HFILL }},

		{ &hf_tns_line_turnaround, {
			"Line Turnaround Value", "tns.line_turnaround", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_value_of_one, {
			"Value of 1 in Hardware", "tns.value_of_one", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_connect_data_length, {
			"Length of Connect Data", "tns.connect_data_length", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_connect_data_offset, {
			"Offset to Connect Data", "tns.connect_data_offset", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_connect_data_max, {
			"Maximum Receivable Connect Data", "tns.connect_data_max", FT_UINT32, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_connect_flags0, {
			"Connect Flags 0", "tns.connect_flags0", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_connect_flags1, {
			"Connect Flags 1", "tns.connect_flags1", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_conn_flag_nareq, {
			"NA services required", "tns.connect_flags.nareq", FT_BOOLEAN, 8,
			NULL, 0x10, NULL, HFILL }},
		{ &hf_tns_conn_flag_nalink, {
			"NA services linked in", "tns.connect_flags.nalink", FT_BOOLEAN, 8,
			NULL, 0x08, NULL, HFILL }},
		{ &hf_tns_conn_flag_enablena, {
			"NA services enabled", "tns.connect_flags.enablena", FT_BOOLEAN, 8,
			NULL, 0x04, NULL, HFILL }},
		{ &hf_tns_conn_flag_ichg, {
			"Interchange is involved", "tns.connect_flags.ichg", FT_BOOLEAN, 8,
			NULL, 0x02, NULL, HFILL }},
		{ &hf_tns_conn_flag_wantna, {
			"NA services wanted", "tns.connect_flags.wantna", FT_BOOLEAN, 8,
			NULL, 0x01, NULL, HFILL }},

		{ &hf_tns_trace_cf1, {
			"Trace Cross Facility Item 1", "tns.trace_cf1", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_trace_cf2, {
			"Trace Cross Facility Item 2", "tns.trace_cf2", FT_UINT32, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_trace_cid, {
			"Trace Unique Connection ID", "tns.trace_cid", FT_UINT64, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_connect_data, {
			"Connect Data", "tns.connect_data", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_accept_data_length, {
			"Accept Data Length", "tns.accept_data_length", FT_UINT16, BASE_DEC,
			NULL, 0x0, "Length of Accept Data", HFILL }},
		{ &hf_tns_accept_data, {
			"Accept Data", "tns.accept_data", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_accept_data_offset, {
			"Offset to Accept Data", "tns.accept_data_offset", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_refuse_reason_user, {
			"Refuse Reason (User)", "tns.refuse_reason_user", FT_UINT8, BASE_HEX,
			NULL, 0x0, "Refuse Reason from Application", HFILL }},
		{ &hf_tns_refuse_reason_system, {
			"Refuse Reason (System)", "tns.refuse_reason_system", FT_UINT8, BASE_HEX,
			NULL, 0x0, "Refuse Reason from System", HFILL }},
		{ &hf_tns_refuse_data_length, {
			"Refuse Data Length", "tns.refuse_data_length", FT_UINT16, BASE_DEC,
			NULL, 0x0, "Length of Refuse Data", HFILL }},
		{ &hf_tns_refuse_data, {
			"Refuse Data", "tns.refuse_data", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_abort_reason_user, {
			"Abort Reason (User)", "tns.abort_reason_user", FT_UINT8, BASE_HEX,
			NULL, 0x0, "Abort Reason from Application", HFILL }},
		{ &hf_tns_abort_reason_system, {
			"Abort Reason (User)", "tns.abort_reason_system", FT_UINT8, BASE_HEX,
			NULL, 0x0, "Abort Reason from System", HFILL }},
		{ &hf_tns_abort_data, {
			"Abort Data", "tns.abort_data", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_marker_type, {
			"Marker Type", "tns.marker.type", FT_UINT8, BASE_HEX,
			VALS(tns_marker_types), 0x0, NULL, HFILL }},
		{ &hf_tns_marker_data_byte, {
			"Marker Data Byte", "tns.marker.databyte", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
#if 0
		{ &hf_tns_marker_data, {
			"Marker Data", "tns.marker.data", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
#endif

		{ &hf_tns_control_cmd, {
			"Control Command", "tns.control.cmd", FT_UINT16, BASE_HEX,
			VALS(tns_control_cmds), 0x0, NULL, HFILL }},
		{ &hf_tns_control_data, {
			"Control Data", "tns.control.data", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_redirect_data_length, {
			"Redirect Data Length", "tns.redirect_data_length", FT_UINT16, BASE_DEC,
			NULL, 0x0, "Length of Redirect Data", HFILL }},
		{ &hf_tns_redirect_data, {
			"Redirect Data", "tns.redirect_data", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_flag, {
			"Data Flag", "tns.data_flag", FT_UINT16, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_flag_send, {
			"Send Token", "tns.data_flag.send", FT_BOOLEAN, 16,
			NULL, 0x1, NULL, HFILL }},
		{ &hf_tns_data_flag_rc, {
			"Request Confirmation", "tns.data_flag.rc", FT_BOOLEAN, 16,
			NULL, 0x2, NULL, HFILL }},
		{ &hf_tns_data_flag_c, {
			"Confirmation", "tns.data_flag.c", FT_BOOLEAN, 16,
			NULL, 0x4, NULL, HFILL }},
		{ &hf_tns_data_flag_reserved, {
			"Reserved", "tns.data_flag.reserved", FT_BOOLEAN, 16,
			NULL, 0x8, NULL, HFILL }},
		{ &hf_tns_data_flag_more, {
			"More Data to Come", "tns.data_flag.more", FT_BOOLEAN, 16,
			NULL, 0x0020, NULL, HFILL }},
		{ &hf_tns_data_flag_eof, {
			"End of File", "tns.data_flag.eof", FT_BOOLEAN, 16,
			NULL, 0x0040, NULL, HFILL }},
		{ &hf_tns_data_flag_dic, {
			"Do Immediate Confirmation", "tns.data_flag.dic", FT_BOOLEAN, 16,
			NULL, 0x0080, NULL, HFILL }},
		{ &hf_tns_data_flag_rts, {
			"Request To Send", "tns.data_flag.rts", FT_BOOLEAN, 16,
			NULL, 0x0100, NULL, HFILL }},
		{ &hf_tns_data_flag_sntt, {
			"Send NT Trailer", "tns.data_flag.sntt", FT_BOOLEAN, 16,
			NULL, 0x0200, NULL, HFILL }},

		{ &hf_tns_data_id, {
			"Data ID", "tns.data_id", FT_UINT32, BASE_HEX,
			VALS(tns_data_funcs), 0x0, NULL, HFILL }},

		{ &hf_tns_data_length, {
			"Data Length", "tns.data_length", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_oci_id, {
			"Call ID", "tns.data_oci.id", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
			&tns_data_oci_subfuncs_ext, 0x00, NULL, HFILL }},
		
/* TTC/TTI: START ================================================================ */

		{ &hf_tns_data_ttic_pkt_number, {
			"TTC/TTI Packet number", "tns.data_ttic_pkt_number", FT_UINT8, BASE_DEC,
			NULL, 0x00, NULL, HFILL }},

		{ &hf_tns_data_ttic_pkt_unknown_1, {
			"TTC/TTI Unknown 1", "tns.data_ttic_pkt_unknown_1", FT_UINT8, BASE_DEC,
			NULL, 0x00, NULL, HFILL }},

		{ &hf_tns_data_ttic_req_type, {
			"TTC/TTI Request type", "tns.data_ttic_req_type", FT_UINT8, BASE_HEX,
			&tns_data_ttci_req_types, 0x00, NULL, HFILL }},

		{ &hf_tns_data_ttic_pkt_unknown_3, {
			"TTC/TTI Unknown 3", "tns.data_ttic_pkt_unknown_3", FT_UINT8, BASE_DEC,
			NULL, 0x00, NULL, HFILL }},

		{ &hf_tns_data_ttic_data_direction, {
			"TTC/TTI Data direction", "tns.data_ttic_data_direction", FT_UINT8, BASE_HEX,
			&tns_data_ttic_data_direction, 0x00, NULL, HFILL }},

		{ &hf_tns_data_ttic_param_count, {
			"TTC/TTI Parameter count", "tns.data_ttic_param_count", FT_UINT8, BASE_DEC,
			NULL, 0x00, NULL, HFILL }},

		{ &hf_tns_data_ttic_stmt_sql, {
			"TTC/TTI SQL statement", "tns.data_ttic_stmt_sql", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},

		{ &hf_tns_data_ttic_stmt_sql_p01, {
			"SQL Parameter 1", "tns.data_ttic_stmt_sql_p01", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p02, {
			"SQL Parameter 2", "tns.data_ttic_stmt_sql_p02", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p03, {
			"SQL Parameter 3", "tns.data_ttic_stmt_sql_p03", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p04, {
			"SQL Parameter 4", "tns.data_ttic_stmt_sql_p04", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p05, {
			"SQL Parameter 5", "tns.data_ttic_stmt_sql_p05", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p06, {
			"SQL Parameter 6", "tns.data_ttic_stmt_sql_p06", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p07, {
			"SQL Parameter 7", "tns.data_ttic_stmt_sql_p07", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p08, {
			"SQL Parameter 8", "tns.data_ttic_stmt_sql_p08", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p09, {
			"SQL Parameter 9", "tns.data_ttic_stmt_sql_p09", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p10, {
			"SQL Parameter 10", "tns.data_ttic_stmt_sql_p10", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p11, {
			"SQL Parameter 11", "tns.data_ttic_stmt_sql_p11", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p12, {
			"SQL Parameter 12", "tns.data_ttic_stmt_sql_p12", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p13, {
			"SQL Parameter 13", "tns.data_ttic_stmt_sql_p13", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p14, {
			"SQL Parameter 14", "tns.data_ttic_stmt_sql_p14", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p15, {
			"SQL Parameter 15", "tns.data_ttic_stmt_sql_p15", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p16, {
			"SQL Parameter 16", "tns.data_ttic_stmt_sql_p16", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p17, {
			"SQL Parameter 17", "tns.data_ttic_stmt_sql_p17", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p18, {
			"SQL Parameter 18", "tns.data_ttic_stmt_sql_p18", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p19, {
			"SQL Parameter 19", "tns.data_ttic_stmt_sql_p19", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},
		{ &hf_tns_data_ttic_stmt_sql_p20, {
			"SQL Parameter 20", "tns.data_ttic_stmt_sql_p20", FT_STRINGZ, BASE_NONE,
			NULL, 0x00, NULL, HFILL }},

/* TTC/TTI: END ========================================================= */

		{ &hf_tns_data_piggyback_id, {
			/* Also Call ID.
			   Piggyback is a message what calls a small subset of functions
			   declared in tns_data_oci_subfuncs. */
			"Call ID", "tns.data_piggyback.id", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
			&tns_data_oci_subfuncs_ext, 0x00, NULL, HFILL }},

		{ &hf_tns_data_unused, {
			"Unused", "tns.data.unused", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_setp_acc_version, {
			"Accepted Version", "tns.data_setp_req.acc_vers", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setp_cli_plat, {
			"Client Platform", "tns.data_setp_req.cli_plat", FT_STRINGZ, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setp_version, {
			"Version", "tns.data_setp_resp.version", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_setp_banner, {
			"Server Banner", "tns.data_setp_resp.banner", FT_STRINGZ, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_sns_cli_vers, {
			"Client Version", "tns.data_sns.cli_vers", FT_UINT32, BASE_CUSTOM,
			CF_FUNC(vsnum_to_vstext_basecustom), 0x0, NULL, HFILL }},
		{ &hf_tns_data_sns_srv_vers, {
			"Server Version", "tns.data_sns.srv_vers", FT_UINT32, BASE_CUSTOM,
			CF_FUNC(vsnum_to_vstext_basecustom), 0x0, NULL, HFILL }},
		{ &hf_tns_data_sns_srvcnt, {
			"Services", "tns.data_sns.srvcnt", FT_UINT16, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_data_opi_version2_banner_len, {
			"Banner Length", "tns.data_opi.vers2.banner_len", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_opi_version2_banner, {
			"Banner", "tns.data_opi.vers2.banner", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_opi_version2_vsnum, {
			"Version", "tns.data_opi.vers2.version", FT_UINT32, BASE_CUSTOM,
			CF_FUNC(vsnum_to_vstext_basecustom), 0x0, NULL, HFILL }},

		{ &hf_tns_data_opi_num_of_params, {
			"Number of parameters", "tns.data_opi.num_of_params", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_opi_param_length, {
			"Length", "tns.data_opi.param_length", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_opi_param_name, {
			"Name", "tns.data_opi.param_name", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_tns_data_opi_param_value, {
			"Value", "tns.data_opi.param_value", FT_STRING, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_reserved_byte, {
			"Reserved Byte", "tns.reserved_byte", FT_BYTES, BASE_NONE,
			NULL, 0x0, NULL, HFILL }},

		{ &hf_tns_packet_type, {
			"Packet Type", "tns.type", FT_UINT8, BASE_DEC,
			VALS(tns_type_vals), 0x0, "Type of TNS packet", HFILL }}

	};

	static gint *ett[] = {
		&ett_tns,
		&ett_tns_connect,
		&ett_tns_accept,
		&ett_tns_refuse,
		&ett_tns_abort,
		&ett_tns_redirect,
		&ett_tns_marker,
		&ett_tns_attention,
		&ett_tns_control,
		&ett_tns_data,
		&ett_tns_data_flag,
		&ett_tns_acc_versions,
		&ett_tns_opi_params,
		&ett_tns_opi_par,
		&ett_tns_sopt_flag,
		&ett_tns_ntp_flag,
		&ett_tns_conn_flag,
		&ett_sql,
		&ett_sql_params
	};
	module_t *tns_module;

	proto_tns = proto_register_protocol("Transparent Network Substrate Protocol", "TNS", "tns");
	proto_register_field_array(proto_tns, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	tns_handle = register_dissector("tns", dissect_tns, proto_tns);

	tns_module = prefs_register_protocol(proto_tns, NULL);
	prefs_register_bool_preference(tns_module, "desegment_tns_messages",
	  "Reassemble TNS messages spanning multiple TCP segments",
	  "Whether the TNS dissector should reassemble messages spanning multiple TCP segments. "
	  "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	  &tns_desegment);
}

void proto_reg_handoff_tns(void)
{
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_TNS, tns_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
