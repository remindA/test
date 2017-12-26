
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef  HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <osipparser2/osip_parser.h>
#include <syslog.h>

#include "siproxd.h"
//#include "plugins.h"
#include "log.h"

struct siproxd_config configuration;
/* Global File instance on pw file */
FILE *siproxd_passwordfile;


#ifdef __LITTLE_ENDIAN
#define IPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]
#else
#define IPQUAD(addr) \
((unsigned char *)&addr)[3], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[0]
#endif

int test(char *path);

int gb28181_log_process(sip_ticket_t *ticket){
   osip_message_t *request;
   osip_uri_t *from_url = NULL;
   osip_uri_t *to_url   = NULL;
   osip_uri_t *req_uri = NULL;
   char *to_username =NULL;
   char *to_host = NULL;
   char *from_username =NULL;
   char *from_host = NULL;
   char *call_type = NULL;

printf("######log process begin\n");
   request=ticket->sipmsg;
   req_uri = request->req_uri;

   /* From: 1st preference is From header, then try contact header */
   if (request->from->url) {
      from_url = request->from->url;
   } else {
      from_url = (osip_uri_t *)osip_list_get(&(request->contacts), 0);
   }

   to_url = request->to->url;

   if (to_url) {
      to_username = to_url->username;
      to_host = to_url->host;
   }

   if (from_url) {
      from_username = from_url->username;
      from_host = from_url->host;
   }

   /* INVITE */
   if (MSG_IS_INVITE(request)) {
		call_type="Invite";
   /* BYE / CANCEL */
   } else if (MSG_IS_ACK(request)) {
      call_type="ACK";
   } else if (MSG_IS_BYE(request) || MSG_IS_CANCEL(request)) {
      call_type="Bye";
   }

   if (call_type) {
      syslog(LOG_INFO, "[CONFIG] %s Call: %s@%s -> %s@%s [Req: %s@%s] [IP: %s:%u]",
           call_type,
           from_username ? from_username: "*NULL*",
           from_host     ? from_host    : "*NULL*",
           to_username   ? to_username  : "*NULL*",
           to_host       ? to_host      : "*NULL*",
           (req_uri && req_uri->username) ? req_uri->username : "*NULL*",
           (req_uri && req_uri->host)     ? req_uri->host     : "*NULL*",
           utils_inet_ntoa(ticket->from.sin_addr),ntohs(ticket->from.sin_port)
           );
	  printf("%s Call: %s@%s -> %s@%s [Req: %s@%s] [IP: %s:%u]",
           call_type,
           from_username ? from_username: "*NULL*",
           from_host     ? from_host    : "*NULL*",
           to_username   ? to_username  : "*NULL*",
           to_host       ? to_host      : "*NULL*",
           (req_uri && req_uri->username) ? req_uri->username : "*NULL*",
           (req_uri && req_uri->host)     ? req_uri->host     : "*NULL*",
           utils_inet_ntoa(ticket->from.sin_addr),ntohs(ticket->from.sin_port)
           );
   }
else
{
	printf("This is not call\n");
}
   printf("######log process end\n");

   return STS_SUCCESS;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		/*printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);*/
	}
#if 0
	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);
#endif
	ret = nfq_get_payload(tb, &data);
	//if (ret >= 0)
	//	printf("payload_len=%d ", ret);

	struct iphdr *iph = (struct iphdr *)data;
	struct udphdr *udph = data + iph->ihl*4;
#if 0
	printf("udp header=%d\n", sizeof(struct udphdr));

	int i,loop;
	unsigned char *buf = (unsigned char *)udph;
	printf("\n");
	loop = (ret>16)?16:ret;
	printf("loop=%d\n", loop);
	for (i=0;i<loop;i++)
	{
		printf("0x%02x,", buf[i]);
	}
	printf("\n");
	#endif
	unsigned char buffer[8196] ={0};
	int len = ntohs(udph->len) - sizeof(struct udphdr);
	unsigned char *sip = (unsigned char *)udph + sizeof(struct udphdr);
	memcpy(buffer, sip, len);
	//printf("buffer=%s\n", buffer);
	sip_ticket_t ticket;

	ticket.raw_buffer = buffer;
	ticket.raw_buffer_len = len;

	//printf("raw_buffer_len=%d\n", ticket.raw_buffer_len);


	/*char tmpbuff[8196] = {0};
	memcpy(tmpbuff, buffer,len);
	tmpbuff[len] = 0;
	printf("parse begin,buffer=%s\n", tmpbuff);
	osip_message_t *psip;
	osip_message_init (&psip);
	osip_message_parse (psip, tmpbuff, len);
	printf("parse end\n");*/

	/*
       * integrity checks
       */
      int sts=security_check_raw(buffer, len);
      if (sts != STS_SUCCESS) {
         //DEBUGC(DBCLASS_SIP,"security check (raw) failed");
         //continue; /* there are no resources to free */
          goto prcess_ret;
      }

	  /*
       * Hacks to fix-up some broken headers
       */
      sts=sip_fixup_asterisk(buffer, &len);

      /*
       * init sip_msg
       */
      sts=osip_message_init(&ticket.sipmsg);
	  //printf("sip=0x%08x\n", ticket.sipmsg);
     // ticket.sipmsg->message=NULL;
      if (sts != 0) {
         ERROR("osip_message_init() failed, sts=%i... this is not good", sts);
         goto prcess_ret; /* skip, there are no resources to free */
      }

	  //printf("osip_message_init ok\n");

      /*
       * RFC 3261, Section 16.3 step 1
       * Proxy Behavior - Request Validation - Reasonable Syntax
       * (parse the received message)
       */
      sts=sip_message_parse(ticket.sipmsg, ticket.raw_buffer, ticket.raw_buffer_len);
      if (sts != 0) {
	  	printf("parse error\n");
         ERROR("sip_message_parse() failed, sts=%i... this is not good", sts);
         DUMP_BUFFER(-1, ticket.raw_buffer, ticket.raw_buffer_len);
         goto end_loop; /* skip and free resources */
      }
	  //printf("sip_message_parse ok\n");
#if 0
      /*
       * integrity checks - parsed buffer
       */
      sts=security_check_sip(&ticket);
      if (sts != STS_SUCCESS) {
         ERROR("security_check_sip() failed, sts=%i... this is not good", sts);
         DUMP_BUFFER(-1, ticket.raw_buffer, ticket.raw_buffer_len);
         goto end_loop; /* skip and free resources */
      }

      DEBUGC(DBCLASS_SIP,"received SIP type %s:%s",
             (MSG_IS_REQUEST(ticket.sipmsg))? "REQ" : "RES",
             (MSG_IS_REQUEST(ticket.sipmsg) ?
                ((ticket.sipmsg->sip_method)?
                   ticket.sipmsg->sip_method : "NULL") :
                ((ticket.sipmsg->reason_phrase) ? 
                   ticket.sipmsg->reason_phrase : "NULL")));
#endif

	gb28181_log_process(&ticket);

/*
 * free the SIP message buffers
 */
      end_loop:
      osip_message_free(ticket.sipmsg);

prcess_ret:
	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	//printf("entering callback\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
#if 1
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	/* initialize parser */
	parser_init ();

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  1000, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		//printf("pkt received\n");
		nfq_handle_packet(h, buf, rv);
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
#endif
}


/*
	
# /usr/sbin/iptables -t mangle -A PREROUTING -p udp --dport 5060 -j NFQUEUE --queue-num 1000
# /usr/sbin/iptables -t mangle -A PREROUTING -p udp --sport 5060 -j NFQUEUE --queue-num 1000
 */

 static int
 read_binary (char **msg, int *len, FILE * torture_file)
 {
   *msg = (char *) osip_malloc (100000); /* msg are under 100000 */
 
   *len = fread (*msg, 1, 100000, torture_file);
   return ferror (torture_file) ? -1 : 0;
 }

int
test_message (char *msg, size_t len, int verbose, int clone, int perf)
{
  osip_message_t *sip;
  int err=0;
  char *result;
  
  int j = perf;
  
  if (verbose)
    fprintf (stdout, "Trying %i sequentials calls to osip_message_init(), osip_message_parse() and osip_message_free()\n", j);
  while (j != 0) {
    j--;

	printf("Begin parse,len=%d\n", len);
    osip_message_init (&sip);
    err = osip_message_parse (sip, msg, len);
      if (err != 0) {
	if (verbose)
	  fprintf (stdout, "ERROR: failed while parsing!\n");
        osip_message_free (sip);
        return err;
      }
      osip_message_free (sip);
  }
  
  osip_message_init (&sip);
  err = osip_message_parse (sip, msg, len);
  if (err != 0) {
    if (verbose)
      fprintf (stdout, "ERROR: failed while parsing!\n");
    osip_message_free (sip);
    return err;
  }
  else {
    size_t length;
    
#if 0
    sdp_message_t *sdp;
    osip_body_t *oldbody;
    int pos;
    
    pos = 0;
    while (!osip_list_eol (&sip->bodies, pos)) {
      oldbody = (osip_body_t *) osip_list_get (&sip->bodies, pos);
      pos++;
      sdp_message_init (&sdp);
      err = sdp_message_parse (sdp, oldbody->body);
      sdp_message_free (sdp);
      sdp = NULL;
      if (err != 0) {
	if (verbose)
	  fprintf (stdout, "ERROR: Bad SDP!\n");
	break;
      }
      else if (verbose)
	fprintf (stdout, "SUCCESS: Correct SDP!\n");
    }
#endif
    
    osip_message_force_update (sip);
    err = osip_message_to_str (sip, &result, &length);
    if (err != OSIP_SUCCESS) {
      if (verbose)
	fprintf (stdout, "ERROR: failed while printing message!\n");
      osip_message_free (sip);
      return err;
    }
    else {
      if (verbose)
	fwrite (result, 1, length, stdout);
      if (clone) {
	int j = perf;
	
	if (verbose)
	  fprintf (stdout, "Trying %i sequentials calls to osip_message_clone() and osip_message_free()\n", j);
	while (j != 0) {
	  osip_message_t *copy;
	  
	  j--;
	  err = osip_message_clone (sip, &copy);
	  if (err != OSIP_SUCCESS) {
	    if (verbose)
	      fprintf (stdout, "ERROR: failed while creating copy of message!\n");
	    break;
	  }
	  else {
	    char *tmp;
	    size_t length;
	    
	    osip_message_force_update (copy);
	    err = osip_message_to_str (copy, &tmp, &length);
	    if (err != OSIP_SUCCESS) {
	      if (verbose)
		fprintf (stdout, "ERROR: failed while printing message!\n");
	    }
	    else {
	      if (0 == strcmp (result, tmp)) {
		if (verbose)
		  printf ("The osip_message_clone method works perfectly\n");
	      }
	      else {
		printf ("ERROR: The osip_message_clone method DOES NOT works\n");
		err=-1;
		if (verbose) {
		  printf ("Here is the copy: \n");
		  fwrite (tmp, 1, length, stdout);
		  printf ("\n");
		}
	      }
	      osip_free (tmp);
	    }
	    osip_message_free (copy);
	  }
	}
	if (verbose)
	  fprintf (stdout, "sequentials calls: done\n");
      }
      osip_free (result);
    }
    osip_message_free (sip);
  }

  return err;
}

int test(char *path)
{
	FILE *torture_file;
	char *msg;
	char *ptr;
	int pos;
	int len;

	torture_file = fopen (path, "r");
	if (torture_file == NULL) {
	return -1;
	}
  
  if (read_binary (&msg, &len, torture_file) < 0) {
    //fprintf (stdout, "test %s : ============================ FAILED (cannot read file)\n", argv[1]);
    return -999;
  }
  	test_message(msg, len, 0, 0, 0);

	fclose(torture_file);
  	return 0;
}
