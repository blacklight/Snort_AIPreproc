/****************************************************************************
 * Copyright (C) 2008-2010 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************/
#ifndef RULE_OPTION_TYPES__H
#define RULE_OPTION_TYPES__H

typedef enum _option_type_t
{
    RULE_OPTION_TYPE_LEAF_NODE,
    RULE_OPTION_TYPE_ASN1,
    RULE_OPTION_TYPE_BYTE_TEST,
    RULE_OPTION_TYPE_BYTE_JUMP,
    RULE_OPTION_TYPE_FLOW,
    RULE_OPTION_TYPE_CVS,
    RULE_OPTION_TYPE_DSIZE,
    RULE_OPTION_TYPE_FLOWBIT,
    RULE_OPTION_TYPE_FTPBOUNCE,
    RULE_OPTION_TYPE_ICMP_CODE,
    RULE_OPTION_TYPE_ICMP_ID,
    RULE_OPTION_TYPE_ICMP_SEQ,
    RULE_OPTION_TYPE_ICMP_TYPE,
    RULE_OPTION_TYPE_IP_FRAGBITS,
    RULE_OPTION_TYPE_IP_FRAG_OFFSET,
    RULE_OPTION_TYPE_IP_ID,
    RULE_OPTION_TYPE_IP_OPTION,
    RULE_OPTION_TYPE_IP_PROTO,
    RULE_OPTION_TYPE_IP_SAME,
    RULE_OPTION_TYPE_IP_TOS,
    RULE_OPTION_TYPE_IS_DATA_AT,
    RULE_OPTION_TYPE_FILE_DATA,
    RULE_OPTION_TYPE_CONTENT,
    RULE_OPTION_TYPE_CONTENT_URI,
    RULE_OPTION_TYPE_PCRE,
#ifdef ENABLE_REACT
    RULE_OPTION_TYPE_REACT,
#endif
#ifdef ENABLE_RESPOND
    RULE_OPTION_TYPE_RESPOND,
#endif
    RULE_OPTION_TYPE_RPC_CHECK,
    RULE_OPTION_TYPE_SESSION,
    RULE_OPTION_TYPE_TCP_ACK,
    RULE_OPTION_TYPE_TCP_FLAG,
    RULE_OPTION_TYPE_TCP_SEQ,
    RULE_OPTION_TYPE_TCP_WIN,
    RULE_OPTION_TYPE_TTL,
    RULE_OPTION_TYPE_URILEN
#ifdef DYNAMIC_PLUGIN
    ,
    RULE_OPTION_TYPE_HDR_OPT_CHECK,
    RULE_OPTION_TYPE_PREPROCESSOR,
    RULE_OPTION_TYPE_DYNAMIC
#endif
} option_type_t;

#endif /* RULE_OPTION_TYPES__H */
