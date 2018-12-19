/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under 
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.  
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file sgw_task.c
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/
#define SGW
#define SGW_TASK_C

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>

#include <libxml/xmlwriter.h>
#include <libxml/xpath.h>
#include "bstrlib.h"
#include "queue.h"

#include "dynamic_memory_check.h"
#include "hashtable.h"
#include "obj_hashtable.h"
#include "log.h"
#include "msc.h"
#include "common_defs.h"
#include "intertask_interface.h"
#include "itti_free_defined_msg.h"
#include "sgw_ie_defs.h"
#include "3gpp_23.401.h"
#include "mme_config.h"
#include "sgw_defs.h"
#include "sgw_handlers.h"
#include "sgw.h"
#include "spgw_config.h"
#include "pgw_lite_paa.h"
#include "pgw_pcef_emulation.h"

#define BUFFER_SIZE 1024
#define MAX_NUMBER_OF_SPGWU_IP_LIST 128

spgw_config_t                           spgw_config;
sgw_app_t                               sgw_app;
pgw_app_t                               pgw_app;

extern __pid_t g_pid;

char *SPGWU_IP_LIST[MAX_NUMBER_OF_SPGWU_IP_LIST];
int TOTAL_NUMBER_OF_SPGWU = 0;
char *SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS;
int SPGWC_REGISTRATION_SERVER_PORT = -1;
int SPGWU_GTP_API_SERVER_PORT = -1;

static void sgw_exit(void);
static void *spgwc_registration_server(void);
static int parse_spgwc_config(char** SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, int *SPGWC_REGISTRATION_SERVER_PORT, int *SPGWU_GTP_API_SERVER_PORT);
static void list_spgwu_ip_list(void);
static int search_spgwu_id(char* spgwu_ip);

//------------------------------------------------------------------------------
static void *sgw_intertask_interface (void *args_p)
{
  itti_mark_task_ready (TASK_SPGW_APP);

  while (1) {
    MessageDef                             *received_message_p = NULL;

    itti_receive_msg (TASK_SPGW_APP, &received_message_p);

    switch (ITTI_MSG_ID (received_message_p)) {

    case GTPV1U_CREATE_TUNNEL_RESP:{
        OAILOG_DEBUG (LOG_SPGW_APP, "Received teid for S1-U: %u and status: %s\n", received_message_p->ittiMsg.gtpv1uCreateTunnelResp.S1u_teid, received_message_p->ittiMsg.gtpv1uCreateTunnelResp.status == 0 ? "Success" : "Failure");
        sgw_handle_gtpv1uCreateTunnelResp (&received_message_p->ittiMsg.gtpv1uCreateTunnelResp);
      }
      break;

    case GTPV1U_UPDATE_TUNNEL_RESP:{
        sgw_handle_gtpv1uUpdateTunnelResp (&received_message_p->ittiMsg.gtpv1uUpdateTunnelResp);
      }
      break;

    case MESSAGE_TEST:
      OAILOG_DEBUG (LOG_SPGW_APP, "Received MESSAGE_TEST\n");
      break;

    case S11_CREATE_BEARER_RESPONSE:{
        sgw_handle_create_bearer_response (&received_message_p->ittiMsg.s11_create_bearer_response);
      }
      break;

    case S11_CREATE_SESSION_REQUEST:{
        /*
         * We received a create session request from MME (with GTP abstraction here)
         * * * * procedures might be:
         * * * *      E-UTRAN Initial Attach
         * * * *      UE requests PDN connectivity
         */
        sgw_handle_create_session_request (&received_message_p->ittiMsg.s11_create_session_request);
      }
      break;

    case S11_DELETE_SESSION_REQUEST:{
        sgw_handle_delete_session_request (&received_message_p->ittiMsg.s11_delete_session_request);
      }
      break;

    case S11_MODIFY_BEARER_REQUEST:{
        sgw_handle_modify_bearer_request (&received_message_p->ittiMsg.s11_modify_bearer_request);
      }
      break;

    case S11_RELEASE_ACCESS_BEARERS_REQUEST:{
        sgw_handle_release_access_bearers_request (&received_message_p->ittiMsg.s11_release_access_bearers_request);
      }
      break;

    case SGI_CREATE_ENDPOINT_RESPONSE:{
        sgw_handle_sgi_endpoint_created (&received_message_p->ittiMsg.sgi_create_end_point_response);
      }
      break;

    case SGI_UPDATE_ENDPOINT_RESPONSE:{
        sgw_handle_sgi_endpoint_updated (&received_message_p->ittiMsg.sgi_update_end_point_response);
      }
      break;

    case TERMINATE_MESSAGE:{
        sgw_exit();
        itti_exit_task ();
      }
      break;

    default:{
        OAILOG_DEBUG (LOG_SPGW_APP, "Unkwnon message ID %d:%s\n", ITTI_MSG_ID (received_message_p), ITTI_MSG_NAME (received_message_p));
      }
      break;
    }

    itti_free_msg_content(received_message_p);
    itti_free (ITTI_MSG_ORIGIN_ID (received_message_p), received_message_p);
    received_message_p = NULL;
  }

  return NULL;
}

//------------------------------------------------------------------------------
int sgw_init (spgw_config_t *spgw_config_pP)
{
  OAILOG_DEBUG (LOG_SPGW_APP, "Initializing SPGW-C-APP task interface\n");

  /*
  if ( gtpv1u_init (spgw_config_pP) < 0) {
    OAILOG_ALERT (LOG_SPGW_APP, "Initializing GTPv1-U ERROR\n");
    return RETURNerror;
  }
  */

  pgw_load_pool_ip_addresses ();

  bstring b = bfromcstr("sgw_s11teid2mme_hashtable");
  sgw_app.s11teid2mme_hashtable = hashtable_ts_create (512, NULL, NULL, b);
  btrunc(b, 0);

  if (sgw_app.s11teid2mme_hashtable == NULL) {
    perror ("hashtable_ts_create");
    bdestroy_wrapper (&b);
    OAILOG_ALERT (LOG_SPGW_APP, "Initializing SPGW-C-APP task interface: ERROR\n");
    return RETURNerror;
  }

  /*sgw_app.s1uteid2enb_hashtable = hashtable_ts_create (512, NULL, NULL, "sgw_s1uteid2enb_hashtable");

  if (sgw_app.s1uteid2enb_hashtable == NULL) {
    perror ("hashtable_ts_create");
    OAILOG_ALERT (LOG_SPGW_APP, "Initializing SPGW-APP task interface: ERROR\n");
    return RETURNerror;
  }*/

  bassigncstr(b, "sgw_s11_bearer_context_information_hashtable");
  sgw_app.s11_bearer_context_information_hashtable = hashtable_ts_create (512, NULL,
          (void (*)(void**))sgw_cm_free_s_plus_p_gw_eps_bearer_context_information,b);
  bdestroy_wrapper (&b);

  if (sgw_app.s11_bearer_context_information_hashtable == NULL) {
    perror ("hashtable_ts_create");
    OAILOG_ALERT (LOG_SPGW_APP, "Initializing SPGW-APP task interface: ERROR\n");
    return RETURNerror;
  }

  sgw_app.sgw_if_name_S1u_S12_S4_up    = bstrcpy(spgw_config_pP->sgw_config.ipv4.if_name_S1u_S12_S4_up);
  sgw_app.sgw_ip_address_S1u_S12_S4_up.s_addr = spgw_config_pP->sgw_config.ipv4.S1u_S12_S4_up.s_addr;
  sgw_app.sgw_if_name_S11_S4           = bstrcpy(spgw_config_pP->sgw_config.ipv4.if_name_S11);
  sgw_app.sgw_ip_address_S11_S4.s_addr = spgw_config_pP->sgw_config.ipv4.S11.s_addr;

  sgw_app.sgw_ip_address_S5_S8_up.s_addr      = spgw_config_pP->sgw_config.ipv4.S5_S8_up.s_addr;

  if (RETURNerror == pgw_pcef_emulation_init (&spgw_config_pP->pgw_config)) {
    return RETURNerror;
  }

  if (itti_create_task (TASK_SPGW_APP, &sgw_intertask_interface, NULL) < 0) {
    perror ("pthread_create");
    OAILOG_ALERT (LOG_SPGW_APP, "Initializing SPGW-C-APP task interface: ERROR\n");
    return RETURNerror;
  }

  if (itti_create_task (TASK_SPGWC_REGISTRATION_SERVER, &spgwc_registration_server, NULL) < 0) {
    perror ("pthread_create");
    OAILOG_ALERT (LOG_SPGW_APP, "Initializing checking SPGW-U state: ERROR\n");
    return RETURNerror;
  }

  FILE *fp = NULL;
  bstring  filename = bformat("/tmp/spgw_%d.status", g_pid);
  fp = fopen(bdata(filename), "w+");
  bdestroy_wrapper (&filename);
  fprintf(fp, "STARTED\n");
  fflush(fp);
  fclose(fp);

  OAILOG_DEBUG (LOG_SPGW_APP, "Initializing SPGW-C-APP task interface: DONE\n");
  return RETURNok;
}

//------------------------------------------------------------------------------
static void sgw_exit(void)
{
  if (sgw_app.s11teid2mme_hashtable) {
    hashtable_ts_destroy (sgw_app.s11teid2mme_hashtable);
  }
  /*if (sgw_app.s1uteid2enb_hashtable) {
    hashtable_destroy (sgw_app.s1uteid2enb_hashtable);
  }*/
  if (sgw_app.s11_bearer_context_information_hashtable) {
    hashtable_ts_destroy (sgw_app.s11_bearer_context_information_hashtable);
  }

  //P-GW code
  struct conf_ipv4_list_elm_s   *conf_ipv4_p = NULL;

  while ((conf_ipv4_p = STAILQ_FIRST (&spgw_config.pgw_config.ipv4_pool_list))) {
    STAILQ_REMOVE_HEAD (&spgw_config.pgw_config.ipv4_pool_list, ipv4_entries);
    free_wrapper ((void**)&conf_ipv4_p);
  }
  OAI_FPRINTF_INFO("TASK_SPGW_APP terminated");
}

static void *spgwc_registration_server(void)
{
  itti_mark_task_ready (TASK_SPGWC_REGISTRATION_SERVER);

  printf("[SPGW-C] Starting SPGW-C registration server daemon\n");

  if (parse_spgwc_config(&SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, &SPGWC_REGISTRATION_SERVER_PORT, &SPGWU_GTP_API_SERVER_PORT) < 0)
  {
      OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-C] Parsing spgwc.conf failed\n");
      return;
  }

  //Initialize UE tunnel information table
  init_ue_tunnel_info_table();

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in sockaddr_fd = {
      .sin_family = AF_INET,
      .sin_port = htons(SPGWC_REGISTRATION_SERVER_PORT),
      .sin_addr = {
          .s_addr   = INADDR_ANY,
      },
  };
  inet_aton(SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, &sockaddr_fd.sin_addr);

  if (bind(fd, (struct sockaddr *) &sockaddr_fd, sizeof(sockaddr_fd)) < 0)
  {
    OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-C] Bind SPGW-C registration server on %s:%d fail\n", SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, SPGWC_REGISTRATION_SERVER_PORT);
    return RETURNerror;
  }
  OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-C] Bind SPGW-C registration server on %s:%d success\n", SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, SPGWC_REGISTRATION_SERVER_PORT);

  if (listen(fd, 5)<0)
  {
    OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-C] Listen SPGW-C fail\n");
    return RETURNerror;
  }
  OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-C] SPGW-C registration server is listening for SPGW-U registration request\n");

  while (true)
  {
    struct sockaddr_in sockaddr_client;
    socklen_t len;
    int clientfd;
    
    clientfd = accept (fd, (struct sockaddr *)&sockaddr_client, &len);
    OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-C] A registration request from SPGW-U\n");

    int n = 0;
    char buf[BUFFER_SIZE];
    if ((n = recv (clientfd, buf, BUFFER_SIZE, 0)) < 0)
    {
      OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-C] Recv ERROR\n");
      close(clientfd);
      continue;
    }
    buf[n]='\0';
    OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-C] Request message: %s\n", buf);

    char type_str[4];
    strncpy(type_str, buf, 3);
    type_str[3] = '\0';

    strncpy(buf, buf+3+1, strlen(buf)-3-1);

    if(!strcmp("reg",type_str))
    {
        //Parse SPGW-U IP
        int i=0;
        while(buf[i]!=';')
            i++;

        char *new_spgwu_ip = malloc(sizeof(char)*(i+1));
        strncpy(new_spgwu_ip, buf, i);
        new_spgwu_ip[i] = '\0';

        //Check if this SPGW-U is registered before
        int spgwu_id = search_spgwu_id(new_spgwu_ip);
        if(spgwu_id < 0)
        {
          SPGWU_IP_LIST[TOTAL_NUMBER_OF_SPGWU] = new_spgwu_ip;
          TOTAL_NUMBER_OF_SPGWU++;
        }
        else
        {
          OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-C] SPGW-U %d/%d: %s is registered before\n",spgwu_id+1 ,TOTAL_NUMBER_OF_SPGWU , new_spgwu_ip);
        }

        sprintf(buf, "%s", "ACK");
        if (send (clientfd, buf, strlen(buf), 0) < 0)
        {
          OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-C] Send ERROR\n");
          close(clientfd);
          continue;
        }
        OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-C] Send back response: %s\n", buf);
        close(clientfd);
        OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-C] A new SPGW-U %s is successfully registered\n", new_spgwu_ip);
        list_spgwu_ip_list();
        continue;
    }
    else
    {
        OAILOG_WARNING (LOG_SPGW_APP, "[SPGW-C] Unknown request: %s\n", type_str);
        close(clientfd);
        list_spgwu_ip_list();
        continue;
    }
  }
}

static int parse_spgwc_config(char** SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, int *SPGWC_REGISTRATION_SERVER_PORT, int *SPGWU_GTP_API_SERVER_PORT)
{
    char buf[1000];
    FILE *fp = fopen("/usr/local/etc/oai/spgwc.conf", "r");
    bool found_spgwc_ip = false;
    bool found_spgwc_port = false;
    bool found_spgwu_port = false;

    if(!fp)
    {
        OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-C] Cannot open spgwc.conf\n");
        return RETURNerror;
    }

    while(fgets(buf, 1000, fp))
    {
        if(strstr(buf, "SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS"))
        {
            int str_start=0;
            int str_end;

            while(buf[str_start] != '"')
            {
                str_start++;
            }

            str_end = str_start + 1;
            while(buf[str_end] != ';')
            {
                str_end++;
            }

            char *result = malloc(sizeof(char)*(str_end-str_start-1));
            
            strncpy(result, buf+str_start+1, str_end-str_start-2);
            result[str_end-str_start-2] = '\0';

            *SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS = result;
            found_spgwc_ip = true;
        }
        else if(strstr(buf, "SPGWC_REGISTRATION_SERVER_PORT"))
        {
            int str_start=0;
            int str_end;

            while(buf[str_start] != '=')
            {
                str_start++;
            }

            str_end = str_start + 1;
            while(buf[str_end] != ';')
            {
                str_end++;
            }

            char result[str_end-str_start-1];
            strncpy(result, buf+str_start+1, str_end-str_start-1);
            result[str_end-str_start-1] = '\0';

            *SPGWC_REGISTRATION_SERVER_PORT = atoi(result);
            found_spgwc_port = true;
        }
        else if(strstr(buf, "SPGWU_GTP_API_SERVER_PORT"))
        {
            int str_start=0;
            int str_end;

            while(buf[str_start] != '=')
            {
                str_start++;
            }

            str_end = str_start + 1;
            while(buf[str_end] != ';')
            {
                str_end++;
            }

            char result[str_end-str_start-1];
            strncpy(result, buf+str_start+1, str_end-str_start-1);
            result[str_end-str_start-1] = '\0';

            *SPGWU_GTP_API_SERVER_PORT = atoi(result);
            found_spgwu_port = true;
        }
        else
        {
            OAILOG_WARNING (LOG_SPGW_APP, "[SPGW-C] Unknown config argument\n");
        }
    }
    if(found_spgwc_ip && found_spgwc_port && found_spgwu_port)
    {
        OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-C] Parsing spgwc.conf successfully\n");
        return RETURNok;
    }
    else
    {
        if(!found_spgwc_ip)
            OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-C] Missing SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS\n");
        if(!found_spgwc_port)
            OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-C] Missing SPGWC_REGISTRATION_SERVER_PORT\n");
        if(!found_spgwu_port)
            OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-C] Missing SPGWU_GTP_API_SERVER_PORT\n");
        
        return RETURNerror;
    }
}

static void list_spgwu_ip_list(void)
{
  OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-C] Total %d SPGW-U is ready\n", TOTAL_NUMBER_OF_SPGWU);
  for(int i=0 ; i<TOTAL_NUMBER_OF_SPGWU ; i++)
  {
    OAILOG_DEBUG (LOG_SPGW_APP, "         %d/%d: %s\n", i+1, TOTAL_NUMBER_OF_SPGWU, SPGWU_IP_LIST[i]);
  }
}

static int search_spgwu_id(char* spgwu_ip)
{
  for(int i=0 ; i<TOTAL_NUMBER_OF_SPGWU ; i++)
  {
    if(strstr(SPGWU_IP_LIST[i], spgwu_ip))
      return i;
  }
  return RETURNerror;
}