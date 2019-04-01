/*
 * RTP relay module
 *
 * Copyright (C) 2019 Julien Chavanton (Flowroute.com)
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef _RTCP_RELAY_MOD_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define PORT "3490"  // the port users will be connecting to
#define BACKLOG 10   // how many pending connections queue will hold

typedef struct rctp_session {
        char *remote_ip[1];
        int socket_fd;
        int remote_port;
        struct sockaddr_in to;
} rtcp_session_t;

typedef struct rctp_sessions {
        int fdmax;     // highest FD in in our master FD set
        fd_set set;    // master file descriptor list
        int count;
        rtcp_session_t session[10000];
} rtcp_sessions_t;


#define SWITCH_RTCP_MAX_BUF_LEN 16384

typedef struct switch_rtcp_hdr_s {
	unsigned version:2;         /* protocol version                  */
	unsigned p:1;               /* padding flag                      */
	unsigned count:5;           /* number of reception report blocks */
	unsigned type:8;            /* packet type                       */
	unsigned length:16;         /* length in 32-bit words - 1        */
} switch_rtcp_hdr_t;

typedef struct {
	switch_rtcp_hdr_t header;
	char body[SWITCH_RTCP_MAX_BUF_LEN];
} rtcp_msg_t;



#endif
#define _RTCP_RELAY_MOD_H_
