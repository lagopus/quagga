/*
 * This is an implementation of draft-katz-yeung-ospf-traffic-06.txt
 * Copyright (C) 2001 KDD R&D Laboratories, Inc.
 * http://www.kddlabs.co.jp/
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

/***** MTYPE definition is not reflected to "memory.h" yet. *****/
#define MTYPE_OSPF_SR_LINKPARAMS	0

#include <zebra.h>

#ifdef HAVE_SR
#ifndef HAVE_OPAQUE_LSA
#error "Wrong configure option"
#endif /* HAVE_OPAQUE_LSA */

#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "thread.h"
#include "hash.h"
#include "sockunion.h"		/* for inet_aton() */

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_vty.h"
#include "ospfd/ospf_sr.h"

/* Following structure are internal use only. */
struct ospf_sr
{
    enum { disabled, enabled } status;
    u_char nodeid;
};


/*
 * Global variable to manage Opaque-LSA/Segment Routing on this node.
 * Note that all parameter values are stored in network byte order.
 */
static struct ospf_sr OspfSR;

/*------------------------------------------------------------------------*
 * Followings are initialize/terminate functions for MPLS-TE handling.
 *------------------------------------------------------------------------*/

static void ospf_sr_register_vty (void);

static void ospf_sr_config_write_router (struct vty *vty);
static void ospf_sr_config_write_if (struct vty *vty, struct interface *ifp);
static void ospf_sr_show_info (struct vty *vty, struct ospf_lsa *lsa);
static int ospf_sr_lsa_originate (void *arg);
static int ospf_sr_new_lsa_hook(struct ospf_lsa *lsa);

void ospf_sr_config_write_router(struct vty *vty){
    zlog_info("config writer router called");
    return;
}

void ospf_sr_config_write_if(struct vty *vty, struct interface *ifp){
    zlog_info("config write if called");
    return;
}

int ospf_sr_new_lsa_hook(struct ospf_lsa *lsa){
    zlog_info("new lsa hook");
    return;
}

static u_int16_t
show_vty_extended_prefix(struct vty *vty, struct sr_tlv_header *tlvh)
{
  struct sr_tlv_extended_prefix *top = (struct sr_tlv_extended_prefix *) tlvh;

  if (vty != NULL)
    vty_out (vty, "  Prefix: %s/%d%s", inet_ntoa (top->prefix), top->prefix_length, VTY_NEWLINE);
  else
    zlog_debug ("    Prefix: %s/%d", inet_ntoa (top->prefix), top->prefix_length);

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_prefix_sid(struct vty *vty, struct sr_tlv_header *tlvh)
{
  struct sr_subtlv_prefix_sid *top = (struct sr_subtlv_prefix_sid *) tlvh;

  if (vty != NULL)
    vty_out (vty, "  SID: %d-%d%s", ntohs(top->index), ntohs(top->index) + ntohs(top->range_size) - 1, VTY_NEWLINE);
  else
    zlog_debug ("    SID: %d-%d", ntohs(top->index), ntohs(top->index) + ntohs(top->range_size) - 1);

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_unknown_tlv (struct vty *vty, struct sr_tlv_header *tlvh)
{
  if (vty != NULL)
    vty_out (vty, "  Unknown TLV: [type(0x%x), length(0x%x)]%s", ntohs (tlvh->type), ntohs (tlvh->length), VTY_NEWLINE);
  else
    zlog_debug ("    Unknown TLV: [type(0x%x), length(0x%x)]", ntohs (tlvh->type), ntohs (tlvh->length));

  return TLV_SIZE (tlvh);
}


void ospf_sr_show_info(struct vty *vty, struct ospf_lsa *lsa){
  struct lsa_header *lsah = (struct lsa_header *) lsa->data;
  struct sr_tlv_header *tlvh;
  u_int16_t sum = 0, total;
  total = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;

  for (tlvh = TLV_HDR_TOP(lsah); sum < total; tlvh = TLV_HDR_NEXT(tlvh))
    {
      switch (ntohs (tlvh->type))
        {
        case SR_TLV_EXTENDED_PREFIX:
          sum += show_vty_extended_prefix(vty, tlvh);
          break;
        case SR_SUBTLV_PREFIX_SID:
          sum += show_vty_prefix_sid(vty, tlvh);
          break;
        default:
          sum += show_vty_unknown_tlv (vty, tlvh);
          break;
        }
    }

    return;
}

int
ospf_sr_init (void)
{
  int rc = 0;

  ospf_sr_register_vty ();

out:
  return rc;
}

void
ospf_sr_term (void)
{
  ospf_delete_opaque_functab (OSPF_OPAQUE_AREA_LSA,
                              OPAQUE_TYPE_EXTENDED_PREFIX_LSA);
  return;
}

/*------------------------------------------------------------------------*
 * Followings are control functions for MPLS-TE parameters management.
 *------------------------------------------------------------------------*/

int
ospf_sr_lsa_originate (void *arg)
{
    zlog_info("lsa originate called");
    return 0;
}

static void
ospf_sr_lsa_body_set (struct stream *s, struct prefix prefix, int sid)
{
  struct sr_tlv_extended_prefix prefix_tlv;
  struct sr_subtlv_prefix_sid sid_tlv;
  memset(&prefix_tlv, 0, sizeof(prefix_tlv));
  memset(&sid_tlv, 0, sizeof(sid_tlv));

  sid_tlv.header.type = htons(SR_SUBTLV_PREFIX_SID);
  sid_tlv.header.length = htons(12);
  sid_tlv.range_size = htons(1);
  sid_tlv.index = htonl(sid);

  prefix_tlv.header.type = htons(SR_TLV_EXTENDED_PREFIX);
  prefix_tlv.header.length = htons(8);
  prefix_tlv.prefix_length = prefix.prefixlen;
  prefix_tlv.prefix = prefix.u.prefix4;

  stream_put(s, &prefix_tlv, sizeof(prefix_tlv));
  stream_put(s, &sid_tlv, sizeof(sid_tlv));


  return;
}

static u_int16_t
get_sr_instance_value (void)
{
  static u_int16_t seqno = 0;

  if (seqno < MAX_LEGAL_SR_INSTANCE_NUM )
    seqno += 1;
  else
    seqno  = 1; /* Avoid zero. */

  return seqno;
}


/* Create new opaque-LSA. */
static struct ospf_lsa *
ospf_sr_lsa_new (struct ospf_area *area, struct prefix prefix, int sid){
    struct stream *s;
    struct lsa_header *lsah;
    struct ospf_lsa *new = NULL;
    u_char options, lsa_type;
    struct in_addr lsa_id;
    u_int32_t tmp;
    u_int16_t length;

    /* Create a stream for LSA. */
    if ((s = stream_new (OSPF_MAX_LSA_SIZE)) == NULL)
    {
        zlog_warn ("ospf_sr_lsa_new: stream_new() ?");
        goto out;
    }
    lsah = (struct lsa_header *) STREAM_DATA (s);

    options  = LSA_OPTIONS_GET (area);
    options |= LSA_OPTIONS_NSSA_GET (area);
    options |= OSPF_OPTION_O; /* Don't forget this :-) */

    lsa_type = OSPF_OPAQUE_AREA_LSA;
    tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_EXTENDED_PREFIX_LSA, get_sr_instance_value());
    lsa_id.s_addr = htonl (tmp);

    if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
        zlog_debug ("LSA[Type%d:%s]: Create an Opaque-LSA/SR instance", lsa_type, inet_ntoa (lsa_id));

    /* Set opaque-LSA header fields. */
    lsa_header_set (s, options, lsa_type, lsa_id, area->ospf->router_id);

    /* Set opaque-LSA body fields. */
    ospf_sr_lsa_body_set (s, prefix, sid);

    /* Set length. */
    length = stream_get_endp (s);
    lsah->length = htons (length);

    /* Now, create an OSPF LSA instance. */
    if ((new = ospf_lsa_new ()) == NULL)
    {
        zlog_warn ("ospf_sr_lsa_new: ospf_lsa_new() ?");
        stream_free (s);
        goto out;
    }
    if ((new->data = ospf_lsa_data_new (length)) == NULL)
    {
        zlog_warn ("ospf_sr_lsa_new: ospf_lsa_data_new() ?");
        ospf_lsa_unlock (&new);
        new = NULL;
        stream_free (s);
        goto out;
    }

    new->area = area;
    SET_FLAG (new->flags, OSPF_LSA_SELF);
    memcpy (new->data, lsah, length);
    stream_free (s);

out:
    return new;
}

/* Utility functions. */
static int
ospf_str2area_id (const char *str, struct in_addr *area_id, int *format)
{
  char *endptr = NULL;
  unsigned long ret;

  /* match "A.B.C.D". */
  if (strchr (str, '.') != NULL)
    {
      ret = inet_aton (str, area_id);
      if (!ret)
        return -1;
      *format = OSPF_AREA_ID_FORMAT_ADDRESS;
    }
  /* match "<0-4294967295>". */
  else
    {
      if (*str == '-')
        return -1;
      errno = 0;
      ret = strtoul (str, &endptr, 10);
      if (*endptr != '\0' || errno || ret > UINT32_MAX)
        return -1;

      area_id->s_addr = htonl (ret);
      *format = OSPF_AREA_ID_FORMAT_DECIMAL;
    }

  return 0;
}

DEFUN (sr,
       sr_cmd,
       "segment-routing <0-255>",
       "Enable the Segment Routing functionality\n")
{
    int nodeid;

    if(OspfSR.status == enabled){
        vty_out(vty, "segment routing is already enabled. nodeid: %d%s", OspfSR.nodeid, VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    if(IS_DEBUG_OSPF_EVENT)
        zlog_debug("SR: OFF -> ON");

    OspfSR.status = enabled;

    nodeid = atoi(argv[0]);
    OspfSR.nodeid = nodeid;

    return CMD_SUCCESS;
}

DEFUN (sr_extended_prefix,
       sr_extended_prefix_cmd,
       "segment prefix A.B.C.D/M sid <0-4294967295>",
       "Register prefix SID for an IP network\n")
{
    struct ospf *o = ospf_lookup();
    struct ospf_lsa *new;
    int ret = OSPF_AREA_ID_FORMAT_ADDRESS, format, sid;
    struct in_addr area_id;
    struct ospf_area *area;
    struct prefix p;
    
    if(OspfSR.status == enabled){
        VTY_GET_OSPF_AREA_ID(area_id, format, "0");
        area = ospf_area_get(o, area_id, ret);

        str2prefix(argv[0], &p);
        apply_mask(&p);
        sid = atoi(argv[1]);
        new = ospf_sr_lsa_new(area, p, sid);
        if(new == NULL){
            zlog_warn("failed to create lsa");
            return CMD_WARNING;
        }

        if(ospf_lsa_install(o, NULL, new) == NULL){
            zlog_warn("failed to install");
            ospf_lsa_unlock(&new);
            return CMD_WARNING;
        }
        ospf_flood_through_area(area, NULL, new);

    //    vty_out(vty, "%s, %s: %s %s", argv[0], argv[1], inet_ntoa(area_id), VTY_NEWLINE);
        return CMD_SUCCESS;
    }else{
        vty_out(vty, "Segment Routing is disabled%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
}

static void
ospf_sr_register_vty (void)
{
  install_element (OSPF_NODE, &sr_cmd);
  install_element (OSPF_NODE, &sr_extended_prefix_cmd);

  return;
}

#endif /* HAVE_SR */
