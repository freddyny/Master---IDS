/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/uip.h"
#include "powertrace.h"
#include "net/rpl/rpl.h"
#include "dev/leds.h"
#include "sys/ctimer.h"
#include "/home/user/Documents/IDS_Git/Master---IDS/udp-server.h"

#include "net/netstack.h"
#include "dev/button-sensor.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>


#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

#define UDP_EXAMPLE_ID  190

static struct uip_udp_conn *server_conn;
// int negative_value;
// int positive_value;
int br_curr_negative_values[9];
int br_curr_positive_values[9];
int br_curr_neighbors[9];
int new_data;

int endOfIp;
uip_ipaddr_t trustAddress;
int (*trustValues)[3] = NULL; 
int count;

int p;
int n; 
int k;
int i;




PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&udp_server_process);

/*---------------------------------------------------------------------------*/
static void reactOnTrustValue(int negative_value, int positive_value, int endOfIp)
{
	int i;
	int index; 
	index = -1;
	int currentIp;
	// printf("Receiving trust about %i \n", endOfIp);
	if(trustValues == NULL) {
		// Initiate the trustValue.
		// PRINTF("In Trustvalues == NULL\n");
		count = 0;
		trustValues = (int(*)[3])malloc(200 * 3 * sizeof(int));
		trustValues[count][0] = endOfIp;
		trustValues[count][1] = negative_value;
		trustValues[count][2] = positive_value; 
	} else {
		
		for(i = 0; i < count; i++) {
			currentIp = trustValues[i][0];
			// PRINTF("Forloop: Current IP: %i, Its negative valuations: %i, Its Positive valuations: %i \n", trustValues[i][0], trustValues[i][1], trustValues[i][2]);
			if (currentIp == endOfIp) {
				// The ip-address is already in the trustValues.
				index = i;
				break;
			}		
		} 
		
		if(index<0) {
		// The ip-addr is not in list. reallocate memory and add it.
			// tmp = realloc(trustValues, sizeof(int) * (count + 1) * 3);

			trustValues[count + 1][0] += endOfIp;
			trustValues[count + 1][1] += negative_value;
			trustValues[count + 1][2] += positive_value;
			index = count + 1;
			count ++;
			printf("Updating trust for new IP: %i, Pos: %i, Neg: %i", endOfIp, positive_value, negative_value);
			// PRINTF("Added ip %i to trustValues with pos: %i and neg: %i, Count: %i\n", endOfIp, positive_value, negative_value, count);

		
		} else {
			// PRINTF("ip is in list! \n");
			// Give the correct trust values.
			
			trustValues[index][1] += negative_value;
			trustValues[index][2] += positive_value;
			
			PRINTF("Updated trust received about node %i. pTrust: %i. nTrust: %i\n", trustValues[index][0], trustValues[index][2], trustValues[index][1]);
			n = trustValues[index][1];
			p = trustValues[index][2];
			k = 1;
			
			
			/*
			b = p / (p + n + k);
			d = n / (p + n + k);
			u = k / (p + n + k);
			*/
			if((p < n) && (k + n + p) > 10) {
				PRINTF("\nThe node %i", endOfIp);
				PRINTF(" is malicious! REMOVE IT!!\n\n");
			
			}
		}
	}
}
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  char *appdata;


  if(uip_newdata()) {
    appdata = (char *)uip_appdata;
    appdata[uip_datalen()] = 0;
    
    if(UIP_IP_BUF->srcipaddr.u8[sizeof(UIP_IP_BUF->srcipaddr.u8) - 1]% 2 == 0) {
	  leds_on(LEDS_ALL);
    } else {
	  leds_off(LEDS_ALL);
    }
    
    // PRINTF("DATA recv '%s' from ", appdata);
    // PRINTF("%d",
    //       UIP_IP_BUF->srcipaddr.u8[sizeof(UIP_IP_BUF->srcipaddr.u8) - 1]);
    // PRINTF("\n");
#if SERVER_REPLY
    PRINTF("DATA sending reply\n");
    uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
    uip_udp_packet_send(server_conn, "Reply", sizeof("Reply"));
    uip_create_unspecified(&server_conn->ripaddr);
#endif
  }
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Server IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(state == ADDR_TENTATIVE || state == ADDR_PREFERRED) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
      /* hack to make address "final" */
      if (state == ADDR_TENTATIVE) {
	uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
  uip_ipaddr_t ipaddr;
  struct uip_ds6_addr *root_if;
  static struct etimer periodic;


  PROCESS_BEGIN();

  PROCESS_PAUSE();

  SENSORS_ACTIVATE(button_sensor);

  PRINTF("UDP server started\n");
  
  count = 0;
  trustValues = NULL;
  
#if UIP_CONF_ROUTER
/* The choice of server address determines its 6LoPAN header compression.
 * Obviously the choice made here must also be selected in udp-client.c.
 *
 * For correct Wireshark decoding using a sniffer, add the /64 prefix to the 6LowPAN protocol preferences,
 * e.g. set Context 0 to aaaa::.  At present Wireshark copies Context/128 and then overwrites it.
 * (Setting Context 0 to aaaa::1111:2222:3333:4444 will report a 16 bit compressed address of aaaa::1111:22ff:fe33:xxxx)
 * Note Wireshark's IPCMV6 checksum verification depends on the correct uncompressed addresses.
 */
 
#if 0
/* Mode 1 - 64 bits inline */
   uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
#elif 1
/* Mode 2 - 16 bits inline */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
/* Mode 3 - derived from link local (MAC) address */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
#endif

  uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);
  root_if = uip_ds6_addr_lookup(&ipaddr);
  if(root_if != NULL) {
    rpl_dag_t *dag;
    dag = rpl_set_root(RPL_DEFAULT_INSTANCE,(uip_ip6addr_t *)&ipaddr);
    uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
    rpl_set_prefix(dag, &ipaddr, 64);
    PRINTF("created a new RPL dag\n");
  } else {
    PRINTF("failed to create a new RPL DAG\n");
  }
#endif /* UIP_CONF_ROUTER */
  
  print_local_addresses();

  /* The data sink runs with a 100% duty cycle in order to ensure high 
     packet reception rates. */
  // NETSTACK_MAC.off(1);

  server_conn = udp_new(NULL, UIP_HTONS(UDP_CLIENT_PORT), NULL);
  if(server_conn == NULL) {
    PRINTF("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(server_conn, UIP_HTONS(UDP_SERVER_PORT));

  PRINTF("Created a server connection with remote address ");
  PRINT6ADDR(&server_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n", UIP_HTONS(server_conn->lport),
         UIP_HTONS(server_conn->rport));
  
  powertrace_start(CLOCK_SECOND * 10); 
  etimer_set(&periodic, 0.1);
  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    } else if (ev == sensors_event && data == &button_sensor) {
      PRINTF("Initiaing global repair\n");
      rpl_repair_root(RPL_DEFAULT_INSTANCE);
    }
    if(!(new_data < 0)) {
		// PRINTF("SERVER RECEIVED TRUST!! Received TRUST!!  %i ", endOfIp);
		// PRINT6ADDR(&trustAddress);
		// PRINTF("\n\n");
		// printf("newdata < 0");
		for(i = 0; i < 9 ; i++) {
			if(br_curr_neighbors[i] > 0) {
				printf("IP: %i, pos: %i, neg: %i\n", br_curr_neighbors[i], br_curr_positive_values[i], br_curr_negative_values[i]);
				reactOnTrustValue(br_curr_negative_values[i], br_curr_positive_values[i], br_curr_neighbors[i]);
			}
			br_curr_negative_values[i] = 0;
			br_curr_positive_values[i] = 0;
			br_curr_neighbors[i] = 0;

		}
		// printf("new_data = -1");
		new_data = -1;
		// endOfIp = -1;
		// negative_value = 0;
		// positive_value = 0;
	}
	if(etimer_expired(&periodic)) {
      etimer_reset(&periodic);
	}
  }
  free(trustValues);
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
 
