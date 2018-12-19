#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <time.h>

#include <libgtpnl/gtp.h>
#include <libgtpnl/gtpnl.h>
#include <libmnl/libmnl.h>
#include "bstrlib.h"

#include "log.h"
#include "common_defs.h"
#include "gtp_mod_kernel.h"
#include "common_types.h"
#include "3gpp_24.008.h"
#include "3gpp_29.274.h"
#include "pgw_pcef_emulation.h"
#include "spgw_config.h"
#include "gtpv1u_sgw_defs.h"
#include "dynamic_memory_check.h"

static struct {
  int                 genl_id;
  struct mnl_socket  *nl;
  bool                is_enabled;
} gtp_nl;


#define GTP_DEVNAME "gtp0"

extern char *SPGWU_IP_LIST[];
extern int TOTAL_NUMBER_OF_SPGWU;
extern int SPGWU_GTP_API_SERVER_PORT;
extern int CURRENT_SELECTED_SPGWU_ID;

#define MAX_NUMBER_OF_UE_TUNNEL_INFO_TABLE 65536

struct ue_tunnel_info
{
  uint32_t i_tei;
  uint32_t o_tei;
  int spgwu_id;
};
struct ue_tunnel_info ue_tunnel_info_table[MAX_NUMBER_OF_UE_TUNNEL_INFO_TABLE];

void init_ue_tunnel_info_table(void);
static int add_ue_tunnel(uint32_t i_tei, uint32_t o_tei, int spgwu_id);
static int del_ue_tunnel(uint32_t i_tei, uint32_t o_tei);
static int search_ue_tunnel_entry_id(uint32_t i_tei, uint32_t o_tei);

//------------------------------------------------------------------------------
int gtp_mod_kernel_init(int *fd0, int *fd1u, struct in_addr *ue_net, int mask, int gtp_dev_mtu)
{
#if ! GTP_KERNEL_MODULE_UNAVAILABLE
  // we don't need GTP v0, but interface with kernel requires 2 file descriptors
  *fd0 = socket(AF_INET, SOCK_DGRAM, 0);
  *fd1u = socket(AF_INET, SOCK_DGRAM, 0);
  struct sockaddr_in sockaddr_fd0 = {
      .sin_family = AF_INET,
      .sin_port = htons(3386),
      .sin_addr = {
          .s_addr   = INADDR_ANY,
      },
  };
  struct sockaddr_in sockaddr_fd1 = {
      .sin_family = AF_INET,
      .sin_port = htons(GTPV1U_UDP_PORT),
      .sin_addr = {
          .s_addr   = INADDR_ANY,
      },
  };

  if (bind(*fd0, (struct sockaddr *) &sockaddr_fd0,
      sizeof(sockaddr_fd0)) < 0) {
    OAILOG_ERROR (LOG_GTPV1U,"bind GTPv0 port");
    return RETURNerror;
  }
  if (bind(*fd1u, (struct sockaddr *) &sockaddr_fd1,
      sizeof(sockaddr_fd1)) < 0) {
    OAILOG_ERROR (LOG_GTPV1U,"bind S1U port");
    return RETURNerror;
  }

  if (gtp_dev_create(-1, GTP_DEVNAME, *fd0, *fd1u) < 0) {
    OAILOG_ERROR (LOG_GTPV1U, "Cannot create GTP tunnel device: %s\n", strerror(errno));
    return RETURNerror;
  }
  gtp_nl.is_enabled = true;

  gtp_nl.nl = genl_socket_open();
  if (gtp_nl.nl == NULL) {
    OAILOG_ERROR (LOG_GTPV1U, "Cannot create genetlink socket\n");
    return RETURNerror;
  }
  gtp_nl.genl_id = genl_lookup_family(gtp_nl.nl, "gtp");
  if (gtp_nl.genl_id < 0) {
    OAILOG_ERROR (LOG_GTPV1U, "Cannot lookup GTP genetlink ID\n");
    return RETURNerror;
  }
  OAILOG_NOTICE (LOG_GTPV1U, "Using the GTP kernel mode (genl ID is %d)\n", gtp_nl.genl_id);

  bstring system_cmd = bformat ("ip link set dev %s mtu %u", GTP_DEVNAME, gtp_dev_mtu);
  int ret = system ((const char *)system_cmd->data);
  if (ret) {
    OAILOG_ERROR (LOG_GTPV1U, "ERROR in system command %s: %d at %s:%u\n", bdata(system_cmd), ret, __FILE__, __LINE__);
    bdestroy_wrapper (&system_cmd);
    return RETURNerror;
  }
  bdestroy_wrapper (&system_cmd);

  struct in_addr ue_gw;
  ue_gw.s_addr = ue_net->s_addr | htonl(1);
  system_cmd = bformat ("ip addr add %s/%u dev %s", inet_ntoa(ue_gw), mask, GTP_DEVNAME);
  ret = system ((const char *)system_cmd->data);
  if (ret) {
    OAILOG_ERROR (LOG_GTPV1U, "ERROR in system command %s: %d at %s:%u\n", bdata(system_cmd), ret, __FILE__, __LINE__);
    bdestroy_wrapper (&system_cmd);
    return RETURNerror;
  }
  bdestroy_wrapper (&system_cmd);


  OAILOG_DEBUG (LOG_GTPV1U, "Setting route to reach UE net %s via %s\n", inet_ntoa(*ue_net), GTP_DEVNAME);

  if (gtp_dev_config(GTP_DEVNAME, ue_net, mask) < 0) {
    OAILOG_ERROR (LOG_GTPV1U,         "Cannot add route to reach network\n");
    return RETURNerror;
  }

  OAILOG_NOTICE (LOG_GTPV1U, "GTP kernel configured\n");
#endif
  return RETURNok;
}

//------------------------------------------------------------------------------
void gtp_mod_kernel_stop(void)
{
#if ! GTP_KERNEL_MODULE_UNAVAILABLE
  if (!gtp_nl.is_enabled)
    return;

  gtp_dev_destroy(GTP_DEVNAME);
#endif
}

//------------------------------------------------------------------------------
int gtp_mod_kernel_tunnel_add(struct in_addr ue, struct in_addr enb, uint32_t i_tei, uint32_t o_tei, uint8_t bearer_id)
{
  int ret = RETURNok;
#if ! GTP_KERNEL_MODULE_UNAVAILABLE
  struct gtp_tunnel *t;

  if (!gtp_nl.is_enabled)
    return RETURNok;

  t = gtp_tunnel_alloc();
  if (t == NULL)
    return RETURNerror;


  gtp_tunnel_set_ifidx(t, if_nametoindex(GTP_DEVNAME));
  gtp_tunnel_set_version(t, 1);
  gtp_tunnel_set_ms_ip4(t, &ue);
  gtp_tunnel_set_sgsn_ip4(t, &enb);
  gtp_tunnel_set_i_tei(t, i_tei);
  gtp_tunnel_set_o_tei(t, o_tei);
  gtp_tunnel_set_bearer_id(t, bearer_id);
  ret = gtp_add_tunnel(gtp_nl.genl_id, gtp_nl.nl, t);
  gtp_tunnel_free(t);
#endif
  return ret;
}

//------------------------------------------------------------------------------
int gtp_mod_kernel_tunnel_del(uint32_t i_tei, uint32_t o_tei)
{
  int ret = RETURNok;
#if ! GTP_KERNEL_MODULE_UNAVAILABLE
  struct gtp_tunnel *t;

  if (!gtp_nl.is_enabled)
    return RETURNok;

  t = gtp_tunnel_alloc();
  if (t == NULL)
    return RETURNerror;

  gtp_tunnel_set_ifidx(t, if_nametoindex(GTP_DEVNAME));
  gtp_tunnel_set_version(t, 1);
  // looking at kernel/drivers/net/gtp.c: not needed gtp_tunnel_set_ms_ip4(t, &ue);
  // looking at kernel/drivers/net/gtp.c: not needed gtp_tunnel_set_sgsn_ip4(t, &enb);
  gtp_tunnel_set_i_tei(t, i_tei);
  gtp_tunnel_set_o_tei(t, o_tei);

  ret = gtp_del_tunnel(gtp_nl.genl_id, gtp_nl.nl, t);
  gtp_tunnel_free(t);

#endif
  return ret;
}

//------------------------------------------------------------------------------
bool gtp_mod_kernel_enabled(void)
{
  return gtp_nl.is_enabled;
}

int gtp_mod_kernel_tunnel_add_at_spgwu(struct in_addr ue, struct in_addr enb, uint32_t i_tei, uint32_t o_tei, uint8_t bearer_id)
{  
  OAILOG_DEBUG (LOG_GTPV1U, "[SPGW-C] GTP tunnel add request\n");
  OAILOG_DEBUG (LOG_GTPV1U, "         ue = %lu, %s\n", ue, inet_ntoa(ue));
  OAILOG_DEBUG (LOG_GTPV1U, "         enb = %lu, %s\n", enb, inet_ntoa(enb));
  OAILOG_DEBUG (LOG_GTPV1U, "         i_tei = %zu\n", i_tei);
  OAILOG_DEBUG (LOG_GTPV1U, "         o_tei = %zu\n", o_tei);
  OAILOG_DEBUG (LOG_GTPV1U, "         bearer_id = %u\n", bearer_id);

  //Add entry in UE tunnel info table
  add_ue_tunnel(i_tei, o_tei, CURRENT_SELECTED_SPGWU_ID);

  char buf[BUFFER_SIZE];
  struct sockaddr_in sockaddr_server;
  int fd = socket(AF_INET, SOCK_STREAM, 0);

  bzero((char *)&sockaddr_server, sizeof(sockaddr_server));
  sockaddr_server.sin_family = AF_INET;
  sockaddr_server.sin_port = htons(SPGWU_GTP_API_SERVER_PORT);
  inet_aton(SPGWU_IP_LIST[CURRENT_SELECTED_SPGWU_ID], &sockaddr_server.sin_addr);

  if (connect(fd, (struct sockaddr *)&sockaddr_server, sizeof(sockaddr_server)) < 0)
  {
      OAILOG_ERROR (LOG_GTPV1U, "[SPGW-C] Connect to SPGW-U at %s:%d failed\n", SPGWU_IP_LIST[CURRENT_SELECTED_SPGWU_ID], SPGWU_GTP_API_SERVER_PORT);
      close(fd);
      return RETURNerror;
  }
  OAILOG_DEBUG (LOG_GTPV1U, "[SPGW-C] Connect to SPGW-U at %s:%d\n", SPGWU_IP_LIST[CURRENT_SELECTED_SPGWU_ID], SPGWU_GTP_API_SERVER_PORT);

  char message[BUFFER_SIZE];
  sprintf(message, "add;%lu;%lu;%zu;%zu;%u;", ue, enb, i_tei, o_tei, bearer_id);
  OAILOG_DEBUG (LOG_GTPV1U, "%s\n" ,message);

  size_t n = strlen(message);
  strcpy(buf, message);

  if (send(fd, buf, n, 0) < 0)
  {
      OAILOG_ERROR (LOG_GTPV1U, "[SPGW-C] Send ERROR\n");
      close(fd);
      return RETURNerror;
  }

  if ( (n = recv(fd, buf, BUFFER_SIZE, 0)) < 0)
  {
      OAILOG_ERROR (LOG_GTPV1U, "[SPGW-C] Recv ERROR\n");
      close(fd);
      return RETURNerror;
  }
  buf[n] = '\0';
  OAILOG_DEBUG (LOG_GTPV1U, "[SPGW-C] SPGWU %s response: %s\n", SPGWU_IP_LIST[CURRENT_SELECTED_SPGWU_ID], buf);
  
  close(fd);

  if(atoi(buf)<0)
  {
      OAILOG_ERROR (LOG_GTPV1U, "[SPGW-C] Add GTP tunne at %s failed\n", SPGWU_IP_LIST[CURRENT_SELECTED_SPGWU_ID]);
      return RETURNerror;
  }
  else
  {
      OAILOG_DEBUG (LOG_GTPV1U, "[SPGW-C] Add GTP tunnel at %s successfully\n", SPGWU_IP_LIST[CURRENT_SELECTED_SPGWU_ID]);
      return RETURNok;
  }
}

int gtp_mod_kernel_tunnel_del_at_spgwu(uint32_t i_tei, uint32_t o_tei)
{
  OAILOG_DEBUG (LOG_GTPV1U, "[SPGW-C] GTP tunnel del request\n");
  OAILOG_DEBUG (LOG_GTPV1U, "         i_tei = %zu\n", i_tei);
  OAILOG_DEBUG (LOG_GTPV1U, "         o_tei = %zu\n", o_tei);

  //Delete entry in UE tunnel info table
  int current_ue_tunnel_spgwu_id = del_ue_tunnel(i_tei, o_tei);
  if(current_ue_tunnel_spgwu_id < 0)
  {
    OAILOG_ERROR (LOG_GTPV1U, "[SPGW-C] Delete GTP tunnel failed, UE tunnel is not found in table\n");
    return RETURNerror;
  }
  
  char buf[BUFFER_SIZE];
  struct sockaddr_in sockaddr_server;
  int fd = socket(AF_INET, SOCK_STREAM, 0);

  bzero((char *)&sockaddr_server, sizeof(sockaddr_server));
  sockaddr_server.sin_family = AF_INET;
  sockaddr_server.sin_port = htons(SPGWU_GTP_API_SERVER_PORT);
  inet_aton(SPGWU_IP_LIST[current_ue_tunnel_spgwu_id], &sockaddr_server.sin_addr);

  if (connect(fd, (struct sockaddr *)&sockaddr_server, sizeof(sockaddr_server)) < 0)
  {
      OAILOG_ERROR (LOG_GTPV1U, "[SPGW-C] Connect to SPGW-U at %s:%d failed\n", SPGWU_IP_LIST[current_ue_tunnel_spgwu_id], SPGWU_GTP_API_SERVER_PORT);
      close(fd);
      return RETURNerror;
  }
  OAILOG_DEBUG (LOG_GTPV1U, "[SPGW-C] Connect to SPGW-U at %s:%d\n", SPGWU_IP_LIST[current_ue_tunnel_spgwu_id], SPGWU_GTP_API_SERVER_PORT);

  char message[BUFFER_SIZE];
  sprintf(message, "del;%zu;%zu;", i_tei, o_tei);
  OAILOG_DEBUG (LOG_GTPV1U, "%s\n" ,message);

  size_t n = strlen(message);
  strcpy(buf, message);

  if (send(fd, buf, n, 0) < 0)
  {
      OAILOG_ERROR (LOG_GTPV1U, "[SPGW-C] Send ERROR\n");
      close(fd);
      return RETURNerror;
  }

  if ( (n = recv(fd, buf, BUFFER_SIZE, 0)) < 0)
  {
      OAILOG_ERROR (LOG_GTPV1U, "[SPGW-C] Recv ERROR\n");
      close(fd);
      return RETURNerror;
  }
  buf[n] = '\0';
  OAILOG_DEBUG (LOG_GTPV1U, "[SPGW-C] Server response: %s\n", buf);
  
  close(fd);

  if(atoi(buf)<0)
  {
      OAILOG_ERROR (LOG_GTPV1U, "[SPGW-C] Delete GTP tunnel at %s failed\n", SPGWU_IP_LIST[current_ue_tunnel_spgwu_id]);
      return RETURNerror;
  }
  else
  {
      OAILOG_DEBUG (LOG_GTPV1U, "[SPGW-C] Delete GTP tunnel at %s successfully\n", SPGWU_IP_LIST[current_ue_tunnel_spgwu_id]);
      return RETURNok;
  }
}

void init_ue_tunnel_info_table(void)
{
  for(int i=0 ; i<MAX_NUMBER_OF_UE_TUNNEL_INFO_TABLE ; i++)
  {
    ue_tunnel_info_table[i].spgwu_id = -1;
  }

  OAILOG_DEBUG (LOG_GTPV1U, "[SPGW-C] Initialize UE tunnel information table successfully\n");
}

static int add_ue_tunnel(uint32_t i_tei, uint32_t o_tei, int spgwu_id)
{
  int current_entry_id = -1;
  
  for(int i=0 ; i<MAX_NUMBER_OF_UE_TUNNEL_INFO_TABLE ; i++)
  {
    if(ue_tunnel_info_table[i].spgwu_id == -1)
    {
      current_entry_id = i;
      break;
    }
  }

  if(current_entry_id >= 0)
  {
    ue_tunnel_info_table[current_entry_id].i_tei = i_tei;
    ue_tunnel_info_table[current_entry_id].o_tei = o_tei;
    ue_tunnel_info_table[current_entry_id].spgwu_id = spgwu_id;

    OAILOG_DEBUG (LOG_GTPV1U, "[SPGW-C] Add UE tunnel information at position %d successfully\n", current_entry_id);
    OAILOG_DEBUG (LOG_GTPV1U, "         i_tei = %zu\n", i_tei);
    OAILOG_DEBUG (LOG_GTPV1U, "         o_tei = %zu\n", o_tei);
    OAILOG_DEBUG (LOG_GTPV1U, "         spgwu_id = %d\n", spgwu_id);

    return RETURNok;
  }
  else
  {
    OAILOG_ERROR (LOG_GTPV1U, "[SPGW-C] Add UE tunnel information failed, table is full\n");
    
    return RETURNerror;
  }
}

static int del_ue_tunnel(uint32_t i_tei, uint32_t o_tei)
{
  int current_entry_id = search_ue_tunnel_entry_id(i_tei, o_tei);

  if(current_entry_id >= 0)
  {
    int current_ue_tunnel_spgwu_id = ue_tunnel_info_table[current_entry_id].spgwu_id;
    ue_tunnel_info_table[current_entry_id].spgwu_id = -1;

    OAILOG_DEBUG (LOG_GTPV1U, "[SPGW-C] Delete UE tunnel information at position %d successfully\n", current_ue_tunnel_spgwu_id);
    OAILOG_DEBUG (LOG_GTPV1U, "         i_tei = %zu\n", i_tei);
    OAILOG_DEBUG (LOG_GTPV1U, "         o_tei = %zu\n", o_tei);
    OAILOG_DEBUG (LOG_GTPV1U, "         spgwu_id = %d\n", current_ue_tunnel_spgwu_id);

    return current_ue_tunnel_spgwu_id;
  }
  else
  {
    OAILOG_ERROR (LOG_GTPV1U, "[SPGW-C] Delete UE tunnel information failed, UE tunnel information is not found in the table\n");
    OAILOG_ERROR (LOG_GTPV1U, "         i_tei = %zu\n", i_tei);
    OAILOG_ERROR (LOG_GTPV1U, "         o_tei = %zu\n", o_tei);
    
    return RETURNerror;
  }
}

static int search_ue_tunnel_entry_id(uint32_t i_tei, uint32_t o_tei)
{
  int current_entry_id = -1; 
  
  for(int i=0 ; i<MAX_NUMBER_OF_UE_TUNNEL_INFO_TABLE ; i++)
  {
    if(ue_tunnel_info_table[i].i_tei == i_tei && ue_tunnel_info_table[i].o_tei == o_tei)
    {
      current_entry_id = i;
      break;
    }
  }

  return current_entry_id;
}