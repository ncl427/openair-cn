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

#include "gtp_mod_kernel.h"

spgw_config_t                           spgw_config;
sgw_app_t                               sgw_app;
pgw_app_t                               pgw_app;

extern __pid_t g_pid;

static void spgwu_exit(void);
static void parser(char* buf, int *type_ptr, struct in_addr *ue_ptr, struct in_addr *enb_ptr, uint32_t *i_tei_ptr, uint32_t *o_tei_ptr, uint8_t *bearer_id_ptr);
static int parse_spgwu_config(char** SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, int *SPGWC_REGISTRATION_SERVER_PORT, char **SPGWU_GTP_API_SERVER_IPV4_ADDRESS, int *SPGWU_GTP_API_SERVER_PORT);

//------------------------------------------------------------------------------
static void *spgwu_gtp_api_server (void *args_p)
{
    itti_mark_task_ready (TASK_SPGWU_APP);

    OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] Starting SPGW-U tasks\n");

    char* SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS;
    int SPGWC_REGISTRATION_SERVER_PORT;
    char *SPGWU_GTP_API_SERVER_IPV4_ADDRESS;
    int SPGWU_GTP_API_SERVER_PORT;

    if (parse_spgwu_config(&SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, &SPGWC_REGISTRATION_SERVER_PORT, &SPGWU_GTP_API_SERVER_IPV4_ADDRESS, &SPGWU_GTP_API_SERVER_PORT) < 0)
    {
        OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Parsing spgwu.conf failed\n");
        return;
    }

    //Connect to SPGW-C to do registration
    OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] Starting to register at SPGW-C %s:%d\n", SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, SPGWC_REGISTRATION_SERVER_PORT);
    
    while(true)
    {
        char buf[BUFFER_SIZE];
        struct sockaddr_in sockaddr_server;
        int fd = socket(AF_INET, SOCK_STREAM, 0);

        bzero((char *)&sockaddr_server, sizeof(sockaddr_server));
        sockaddr_server.sin_family = AF_INET;
        sockaddr_server.sin_port = htons(SPGWC_REGISTRATION_SERVER_PORT);
        inet_aton(SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, &sockaddr_server.sin_addr);
        
        if (connect(fd, (struct sockaddr *)&sockaddr_server, sizeof(sockaddr_server)) < 0)
        {
            OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Connect to SPGW-C at %s:%d failed, retry in 5 seconds\n", SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, SPGWC_REGISTRATION_SERVER_PORT);
            close(fd);
            sleep(5);
            continue;
        }
        else
        {
            OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] Connect to SPGW-C at %s:%d successfully\n", SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, SPGWC_REGISTRATION_SERVER_PORT);
        }

        char message[BUFFER_SIZE];
        sprintf(message, "reg;%s;", SPGWU_GTP_API_SERVER_IPV4_ADDRESS);

        size_t n = strlen(message);
        strcpy(buf, message);

        if (send(fd, buf, n, 0) < 0)
        {
            OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Send ERROR\n");
            close(fd);
            continue;
        }

        if ( (n = recv(fd, buf, BUFFER_SIZE, 0)) < 0)
        {
            OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Recv ERROR\n");
            close(fd);
            continue;
        }
        buf[n] = '\0';
        OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] SPGW-C response: %s\n", buf);
        
        close(fd);

        if(strstr(buf, "ACK"))
        {
            OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] SPGW-U %s is successfully registered\n", SPGWU_GTP_API_SERVER_IPV4_ADDRESS);
            break;
        }
        else
        {
            OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] SPGW-U %s registered failed\n", SPGWU_GTP_API_SERVER_IPV4_ADDRESS);
            continue;
        }
    }

    //Starting SPGW-U GTP API server
    OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] Starting GTP API server\n");

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sockaddr_fd = {
        .sin_family = AF_INET,
        .sin_port = htons(SPGWU_GTP_API_SERVER_PORT),
        .sin_addr = {
            .s_addr   = INADDR_ANY,
        },
    };
    inet_aton(SPGWU_GTP_API_SERVER_IPV4_ADDRESS, &sockaddr_fd.sin_addr);

    if (bind(fd, (struct sockaddr *) &sockaddr_fd, sizeof(sockaddr_fd)) < 0)
    {
        OAILOG_ERROR (LOG_SPGW_APP,"[SPGW-U] Bind SPGW-U on %s:%d failed\n", SPGWU_GTP_API_SERVER_IPV4_ADDRESS, SPGWU_GTP_API_SERVER_PORT);
        return RETURNerror;
    }
    OAILOG_DEBUG (LOG_SPGW_APP,"[SPGW-U] Bind SPGW-U on %s:%d successfully\n", SPGWU_GTP_API_SERVER_IPV4_ADDRESS, SPGWU_GTP_API_SERVER_PORT);

    if (listen(fd, 5)<0)
    {
        OAILOG_ERROR (LOG_SPGW_APP,"[SPGW-U] Listen SPGW-U failed\n");
        return RETURNerror;
    }
    OAILOG_DEBUG (LOG_SPGW_APP,"[SPGW-U] SPGW-U GTP API server is listening for request\n");

    while (true)
    {
        struct sockaddr_in sockaddr_client;
        socklen_t len;
        int clientfd;

        clientfd = accept (fd, (struct sockaddr *)&sockaddr_client, &len);
        OAILOG_DEBUG (LOG_SPGW_APP,"[SPGW-U] A request from SPGW-C\n");

        int n = 0;
        char buf[BUFFER_SIZE];
        if ((n = recv (clientfd, buf, BUFFER_SIZE, 0)) < 0)
        {
            OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Recv ERROR\n");
            close(clientfd);
            continue;
        }
        buf[n]='\0';
        OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] Request message: %s\n", buf);

        if(strstr(buf, "SYN"))
        {
            sprintf(buf, "%s", "ACK");
            if (send (clientfd, buf, strlen(buf), 0) < 0)
            {
                OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Send ERROR\n");
                close(clientfd);
                continue;
            }
            OAILOG_DEBUG (LOG_SPGW_APP,"[SPGW-U] Send back response: %s\n", buf);
            close(clientfd);
            continue;
        }

        int type = -1;
        struct in_addr ue;
        struct in_addr enb;
        uint32_t i_tei, o_tei;
        uint8_t bearer_id;

        parser(buf, &type, &ue, &enb, &i_tei, &o_tei, &bearer_id);

        OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] type = %d\n", type);
        if(type == 1)
        {
            OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] GTP tunnel add request\n");
            OAILOG_DEBUG (LOG_SPGW_APP, "         ue = %lu, %s\n", ue, inet_ntoa(ue));
            OAILOG_DEBUG (LOG_SPGW_APP, "         enb = %lu, %s\n", enb, inet_ntoa(enb));
            OAILOG_DEBUG (LOG_SPGW_APP, "         i_tei = %zu\n", i_tei);
            OAILOG_DEBUG (LOG_SPGW_APP, "         o_tei = %zu\n", o_tei);
            OAILOG_DEBUG (LOG_SPGW_APP, "         bearer_id = %u\n", bearer_id);

            int rv = gtp_mod_kernel_tunnel_add(ue, enb, i_tei, o_tei, bearer_id);
            sprintf(buf, "%d", rv);

            if (send (clientfd, buf, strlen(buf), 0) < 0)
            {
                OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Send ERROR\n");
                close(clientfd);
                continue;
            }
            OAILOG_DEBUG (LOG_SPGW_APP,"[SPGW-U] Send back response: %s\n", buf);

            if(rv < 0)
                OAILOG_ERROR (LOG_SPGW_APP,"[SPGW-U] Add GTP tunnel failed\n");
            else
                OAILOG_DEBUG (LOG_SPGW_APP,"[SPGW-U] Add GTP tunnel successfully\n");
        }
        else if(type == 0)
        {
            OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] GTP tunnel del request\n");
            OAILOG_DEBUG (LOG_SPGW_APP, "         i_tei = %zu\n", i_tei);
            OAILOG_DEBUG (LOG_SPGW_APP, "         o_tei = %zu\n", o_tei);

            int rv = gtp_mod_kernel_tunnel_del(i_tei, o_tei);
            sprintf(buf, "%d", rv);

            if (send (clientfd, buf, strlen(buf), 0) < 0)
            {
                OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Send ERROR\n");
                close(clientfd);
                continue;
            }
            OAILOG_DEBUG (LOG_SPGW_APP,"[SPGW-U] Send back response: %s\n", buf);

            if(rv < 0)
                OAILOG_ERROR (LOG_SPGW_APP,"[SPGW-U] Delete GTP tunnel failed\n");
            else
                OAILOG_DEBUG (LOG_SPGW_APP,"[SPGW-U] Delete GTP tunnel successfully\n");
        }
        else
        {
                OAILOG_WARNING (LOG_SPGW_APP, "[SPGW-U] Type error");
        }

        close (clientfd);
    }
    return NULL;
}

//------------------------------------------------------------------------------
int spgwu_init (spgw_config_t *spgw_config_pP)
{
  OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] Initializing SPGW-U-APP\n");

  if (itti_create_task (TASK_SPGWU_APP, &spgwu_gtp_api_server, NULL) < 0) {
    perror ("pthread_create");
    OAILOG_ALERT (LOG_SPGW_APP, "[SPGW-U] Initializing SPGW-U-APP: ERROR\n");
    return RETURNerror;
  }

  FILE *fp = NULL;
  bstring  filename = bformat("/tmp/spgw_%d.status", g_pid);
  fp = fopen(bdata(filename), "w+");
  bdestroy_wrapper (&filename);
  fprintf(fp, "STARTED\n");
  fflush(fp);
  fclose(fp);

  OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] Initializing SPGW-U-APP: DONE\n");
  return RETURNok;
}

//------------------------------------------------------------------------------
static void spgwu_exit(void)
{
  itti_exit_task ();
  OAI_FPRINTF_INFO("[SPGW-U] TASK_SPGW-U-APP terminated");
}

static void parser(char* buf, int *type_ptr, struct in_addr *ue_ptr, struct in_addr *enb_ptr, uint32_t *i_tei_ptr, uint32_t *o_tei_ptr, uint8_t *bearer_id_ptr)
{
    int i=0;
    char type_str[4];

    //Parse type, 0:del; 1:add; -1:error
    strncpy(type_str, buf, 3);
    type_str[3] = '\0';

    strncpy(buf, buf+3+1, strlen(buf)-3-1);

    if(!strcmp("add",type_str))
    {
        *type_ptr = 1;

        //Parse ue
        int i=0;
        while(buf[i]!=';')
            i++;
        char ue_str[20];
        strncpy(ue_str, buf, i);
        ue_str[i] = '\0';
        (*ue_ptr).s_addr = strtoul(ue_str, NULL, 0);

        strncpy(buf, buf+i+1, strlen(buf)-i-1);

        //Parse enb
        i=0;
        while(buf[i]!=';')
            i++;
        char enb_str[20];
        strncpy(enb_str, buf, i);
        enb_str[i] = '\0';
        (*enb_ptr).s_addr = strtoul(enb_str, NULL, 0);

        strncpy(buf, buf+i+1, strlen(buf)-i-1);

        //Parse i_tei
        i=0;
        while(buf[i]!=';')
            i++;
        char i_tei_str[20];
        strncpy(i_tei_str, buf, i);
        i_tei_str[i] = '\0';
        *i_tei_ptr = (unsigned int)strtoul(i_tei_str, NULL, 0);

        strncpy(buf, buf+i+1, strlen(buf)-i-1);

        //Parse o_tei
        i=0;
        while(buf[i]!=';')
            i++;
        char o_tei_str[20];
        strncpy(o_tei_str, buf, i);
        o_tei_str[i] = '\0';
        *o_tei_ptr = (unsigned int)strtoul(o_tei_str, NULL, 0);

        strncpy(buf, buf+i+1, strlen(buf)-i-1);

        //Parse bearer_id
        i=0;
        while(buf[i]!=';')
            i++;
        char bearer_id_str[20];
        strncpy(bearer_id_str, buf, i);
        bearer_id_str[i] = '\0';
        *bearer_id_ptr = (uint8_t)atoi(bearer_id_str);
    }
    else if(!strcmp("del",type_str))
    {
        *type_ptr = 0;

        //Parse i_tei
        i=0;
        while(buf[i]!=';')
            i++;
        char i_tei_str[20];
        strncpy(i_tei_str, buf, i);
        i_tei_str[i] = '\0';
        *i_tei_ptr = (unsigned int)strtoul(i_tei_str, NULL, 0);

        strncpy(buf, buf+i+1, strlen(buf)-i-1);

        //Parse o_tei
        i=0;
        while(buf[i]!=';')
            i++;
        char o_tei_str[20];
        strncpy(o_tei_str, buf, i);
        o_tei_str[i] = '\0';
        *o_tei_ptr = (unsigned int)strtoul(o_tei_str, NULL, 0);
    }
    else
    {
        *type_ptr = -1;
    }

    return;
}

static int parse_spgwu_config(char** SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS, int *SPGWC_REGISTRATION_SERVER_PORT, char **SPGWU_GTP_API_SERVER_IPV4_ADDRESS, int *SPGWU_GTP_API_SERVER_PORT)
{
    char buf[1000];
    FILE *fp = fopen("/usr/local/etc/oai/spgwu.conf", "r");
    bool found_spgwc_ip = false;
    bool found_spgwc_port = false;
    bool found_spgwu_ip = false;
    bool found_spgwu_port = false;

    if(!fp)
    {
        OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Cannot open spgwu.conf\n");
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
        else if(strstr(buf, "SPGWU_GTP_API_SERVER_IPV4_ADDRESS"))
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

            *SPGWU_GTP_API_SERVER_IPV4_ADDRESS = result;
            found_spgwu_ip = true;
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
            OAILOG_WARNING (LOG_SPGW_APP, "[SPGW-U] Unknown config argument\n");
        }
    }
    if(found_spgwc_ip && found_spgwc_port && found_spgwu_port)
    {
        OAILOG_DEBUG (LOG_SPGW_APP, "[SPGW-U] Parsing spgwu.conf successfully\n");
        return RETURNok;
    }
    else
    {
        if(!found_spgwc_ip)
            OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Missing SPGWC_REGISTRATION_SERVER_IPV4_ADDRESS\n");
        if(!found_spgwc_port)
            OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Missing SPGWC_REGISTRATION_SERVER_PORT\n");
        if(!found_spgwu_ip)
            OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Missing SPGWU_GTP_API_SERVER_IPV4_ADDRESS\n");
        if(!found_spgwu_port)
            OAILOG_ERROR (LOG_SPGW_APP, "[SPGW-U] Missing SPGWU_GTP_API_SERVER_PORT\n");
        
        return RETURNerror;
    }
}
