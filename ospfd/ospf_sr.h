/*
 * This is an implementation of draft-psenak-ospf-segment-routing-extensions-04.txt
 * Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * 
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_OSPF_SR_H
#define _ZEBRA_OSPF_SR_H

/*
 * Opaque LSA's link state ID for Segment Routing is
 * structured as follows.
 *
 *        24       16        8        0
 * +--------+--------+--------+--------+
 * | 7 or 8 |  MBZ   |........|........|
 * +--------+--------+--------+--------+
 * |<-Type->|<Resv'd>|<-- Instance --->|
 *
 *
 * Type:      IANA has assigned '7' and '8' for Segment Routing.
 * MBZ:       Reserved, must be set to zero.
 * Instance:  User may select an arbitrary 16-bit value.
 *
 */

#define	MAX_LEGAL_SR_INSTANCE_NUM (0xffff)

/*
 *        24       16        8        0
 * +--------+--------+--------+--------+ ---
 * |   LS age        |Options |  10    |  A
 * +--------+--------+--------+--------+  |
 * | 7 or 8 | NodeID |    Instance     |  |
 * +--------+--------+--------+--------+  |
 * |        Advertising router         |  |  Standard (Opaque) LSA header;
 * +--------+--------+--------+--------+  |  I-D also allows lsa type 9, 11
 * |        LS sequence number         |  |  but we currently support only 10
 * +--------+--------+--------+--------+  |
 * |   LS checksum   |     Length      |  V
 * +--------+--------+--------+--------+ ---
 * |      Type       |     Length      |  A
 * +--------+--------+--------+--------+  |  TLV part for TE; Values might be
 * |              Values ...           |  V  structured as a set of sub-TLVs.
 * +--------+--------+--------+--------+ ---
 */

/*
 * Following section defines TLV (tag, length, value) structures,
 * used for Traffic Engineering.
 */
struct sr_tlv_header
{
  u_int16_t	type;			/* SR_TLV_XXX (see below) */
  u_int16_t	length;			/* Value portion only, in octets */
};

#define TLV_HDR_SIZE \
	(sizeof (struct sr_tlv_header))

#define TLV_BODY_SIZE(tlvh) \
	(ROUNDUP (ntohs ((tlvh)->length), sizeof (u_int32_t)))

#define TLV_SIZE(tlvh) \
	(TLV_HDR_SIZE + TLV_BODY_SIZE(tlvh))

#define TLV_HDR_TOP(lsah) \
	(struct sr_tlv_header *)((char *)(lsah) + OSPF_LSA_HEADER_SIZE)

#define TLV_HDR_NEXT(tlvh) \
	(struct sr_tlv_header *)((char *)(tlvh) + TLV_SIZE(tlvh))

/*
 * Following section defines TLV body parts.
 */

/* OSPFv2 Extended Prefix Opaque LSA (Opaque type 7) */

/* Extended Prefix TLV */
#define SR_TLV_EXTENDED_PREFIX          1
struct sr_tlv_extended_prefix
{
  struct sr_tlv_header  header;
  u_char  route_type;
  u_char  prefix_length;
  u_char  address_family; /* currently we only support ipv4 */
  u_char  reserved;
  struct in_addr prefix;
  /* A set of sub-TLVs will follow */
};

/* SR Prefix SID subTLV *//* May appear more than 1 */
#define	SR_SUBTLV_PREFIX_SID            2
struct sr_subtlv_prefix_sid
{
  struct sr_tlv_header  header; /* Value length is 12 octet. */
#define OSPF_SR_NODE_SID        (1 << 8)
#define OSPF_SR_NO_PHP          (1 << 7)
#define OSPF_SR_MAPPING_SERVER  (1 << 6)
  u_char  flags;
  u_char  mt_id;
  u_char  algorithm;
  u_char  reserved;
  u_int16_t range_size;
  u_int16_t reserved2;
  u_int32_t index;
};

/* SID/Label Binding subTLV */
#define	SR_SUBTLV_SID_LABEL_BINDING     3
struct sr_subtlv_sid_label_binding
{
  struct sr_tlv_header  header;
#define OSPF_SR_MIRRORING        (1 << 8)
  u_char    flags;
  u_char    mt_id;
  u_char    weight;
  u_char    reserved;
  u_int16_t range_size;
  u_int16_t reserved2;
  /* A set of sub-TLVs will follow */
};

/* SID/Label subTLV *//* MUST appear in the SID/LABEL Binding subTLV and it
                         MUST only appear once. */
#define	SR_SUBTLV_SID_LABEL         1
struct sr_subtlv_sid_label
{
  struct sr_tlv_header	header;		/* Value length is 3 or 4 octets. */
  u_int32_t     sid;    /* if length is set to 3, then the 20 rightmost bits
                           represent a label. If length is set to 4 then the
                           value represents a 32bit SID */
};

/* ERO Metric subTLV *//* SHOULD appear */
#define SR_SUBTLV_ERO_METRIC        8
struct sr_subtlv_ero_metric
{
  struct sr_tlv_header	header;		/* Value length is  4 octets. */
  u_int32_t metric;
};

#define SR_SUBTLV_IPV4_ERO          4
#define SR_SUBTLV_IPV4_ERO_BACKUP   6
struct sr_subtlv_ipv4_ero
{
  struct sr_tlv_header	header;		/* Value length is  8 octets. */
#define OSPF_SR_LOOSE       (1 << 8)
  u_char flags;
  u_char reserved;
  u_int16_t reserved2;
  struct in_addr    address;
};

#define SR_SUBTLV_UNNUMBERED_IF_ERO 5
#define SR_SUBTLV_UNNUMBERED_IF_ERO_BACKUP 7
struct sr_subtlv_unnumbered_if_ero
{
  struct sr_tlv_header	header;		/* Value length is 12 octets. */
  u_char flags;
  u_char reserved;
  u_int16_t reserved2;
  u_int32_t router_id;
  u_int32_t interface_id;
};

/* OSPFv2 Extended Link Opaque LSA (Opaque type 8) */

#define SR_TLV_EXTENDED_LINK    1
struct sr_tlv_extended_link
{
  struct sr_tlv_header  header;
  u_char    link_type;
  u_char  reserved;
  u_int16_t  reserved2;
  u_int32_t  link_id;
  u_int32_t  link_data;
  /* A set of sub-TLVs will follow */
};

#define SR_SUBTLV_ADJ_SID   2
struct sr_subtlv_adj_sid
{
  struct sr_tlv_header  header;
#define OSPF_SR_BACKUP       (1 << 8)
  u_char flags;
  u_char mt_id;
  u_char weight;
  u_char reserved;
  /* A set of SID/Label sub-TLVs will follow */
};

#define SR_SUBTLV_LAN_ADJ_SID   3
struct sr_subtlv_lan_adj_sid
{
  struct sr_tlv_header  header;
#define OSPF_SR_BACKUP       (1 << 8)
  u_char flags;
  u_char mt_id;
  u_char weight;
  u_char reserved;
  u_int32_t neighbor_id;
  /* A set of SID/Label sub-TLVs will follow */
};


/* Prototypes. */
extern int ospf_sr_init (void);
extern void ospf_sr_term (void);

#endif /* _ZEBRA_OSPF_SR_H */
