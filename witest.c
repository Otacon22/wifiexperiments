#include <stdio.h>
#include <signal.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#define VERSION "1.0"

const u_char broadcastaddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
int verbose = 0;
pcap_t *pcap_handle;
u_char *match_mac = NULL;
int power_only = 0;

void exit_signal(int id)
{
    printf("Exit signal\n");
    if (pcap_handle != NULL) {
	pcap_breakloop(pcap_handle);
	pcap_close(pcap_handle);
    }
    exit(0);
}


void bssid_found(const u_char * bssid, int8_t power, char *type)
{
    if (strncmp(bssid, broadcastaddr, 6) != 0){
        if (match_mac != NULL){
            if (match_mac[0] != bssid[0]) return;            
            if (match_mac[1] != bssid[1]) return;
            if (match_mac[2] != bssid[2]) return;
            if (match_mac[3] != bssid[3]) return;
            if (match_mac[4] != bssid[4]) return;
            if (match_mac[5] != bssid[5]) return;
        }
        if (!power_only){
            printf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx Type:%s",
	           bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], type);
            if (power!=-127){
                printf(" Power:%d", power);
	    }
            printf("\n");
        }
        else if (power!=-127)
            printf("%d\n", power);
    }

}


void process_packet(u_char * useless, const struct pcap_pkthdr *header,
		    const u_char * packet)
{
    int8_t power;
    int8_t power_mac1, power_mac2, power_mac3;
    u_int8_t flags;
    u_int8_t hlen, pos1, pos2, pos3, pos4;
    char *type;

    //printf("Packet with length %d received con %hhx:%hhx\n", header->len,packet[18],packet[19]);
    /* First 18 bytes are radiotap header. We don't care about that */
    /* The byte after the radiotap header is the 802.11 type or subtype */
    /* We have the station address on:
       pkg of type 0x08 (beacon s)
       or of type 0x04 (probe request)
       or of type 0x24 (null function)
       or of type 0x05 (probe response)
       or of type 0x28 (QoS)
     */
    if (header->len >= 24) {
        hlen = packet[2]+(packet[3]<<8); //Usually 18 or 13 in some cases
        
        pos1 = hlen + 4;
        pos2 = hlen + 10;
        pos3 = hlen + 16;
        pos4 = hlen + 22;

        if ((packet[4] & 0x20) == 0x20) //Check if power data present in the packet
	    power = packet[14];
        else
            power = -127; //No power data in the packet

        flags = packet[hlen+1] & 0x03; //FromDS+ToDS
        /* ToDS | FromDS |  SourceAddr
           0    | 0      |  2
           0    | 1      |  3
           1    | 0      |  2
           1    | 1      |  4
         */
	switch (packet[hlen]) {

        case 0x00:
            //Association request
            type = "Association request";
            break;

        case 0x10:
            //Association response
            type = "Association response";
            break;

        case 0x20:
            //Reassociation request
            type = "Reassociation request";
            break;

        case 0x30:
            //Reassociation response
            type = "Reassociation response";
            break;

	case 0x40:
            //probe request
            //destination,source,bss
            type = "Probe request";
            break;

	case 0x50: 
            //probe response
            //destination,source,bss
            type = "Probe response";
            break;

        case 0x60:
            //timing advertisement
            type = "Timing advertisement";
            break;

	case 0x80:
            //beacon
            //destination,source,bss 
            type = "Beacon";
            break;
            
        case 0x90:
            // ATIM
            type = "ATIM";
            break;

        case 0xA0: 
            //Disassociation
            type = "Disassociation";
            break;

        case 0xB0:
            //Authentication
            type = "Authentication";
            break;

        case 0xC0:
            //Deauthentication
            type = "Deauthentication";
            break;

        case 0xD0:
            //Action
            type = "Action";
            break;

        case 0xE0:
            //Action No Ack
            type = "Action No Ack";
            break;

        case 0x74:
            //Control Wrapper
            type = "Control Wrapper";
            break;

        case 0x84:
            //Block Ack Request
            type = "Block Ack Request";
            break;

        case 0x94:
            //Block Ack
            type = "Block Ack";
            break;

        case 0xA4:
            //PS Poll
            type = "PS Poll";
            break;

        case 0xB4:
            //RTS
            type = "RTS";
            break;

        case 0xC4:
            //CTS
            type = "Clear to send";
            break;

        case 0xD4:
            //ACK
            //destination
            type = "ACK";
            break;

        case 0xE4:
            //CF-end
            type = "CF-End";
            break;

        case 0xF4:
            //CF-End+CF-Ack
            type = "CF-End+CF-Ack";
            break;

        case 0x08:
            //Data
            type = "Data";
            break;

        case 0x18:
            //Data+CF-Ack
            type = "Data+CF-Ack";
            break;

        case 0x28:
            //Data+CF-Poll
            type = "Data+CF-Poll";
            break;

        case 0x38:
            //Data+CF-Ack+CF-Poll
            type = "Data+CF-AC";
            break;

        case 0x48:
            type = "Null function";
            break;

        case 0x58:
            //CF-ACK
            type = "CF-ACK";
            break;

        case 0x68:
            //CF-Poll
            type = "CF-Poll";
            break;

        case 0x78:
            //CF-Ack+CF-Poll
            type = "CF-Ack+CF-Poll";
            break;

        case 0x88:
            //QoS Data
            type = "QoS";
            break;

        case 0x98:
            //QoS Data+CF-Ack
            type = "QoS Data+CF-Ack";
            break;

        case 0xA8:
            //QoS Data+CF-Poll
            type = "QoS Data+CF-Poll";
            break;

        case 0xB8:
            //QoS Data+CF-Ack+CF-Poll
            type = "QoS Data+CF-Ack+CF-Poll";
            break;

        case 0xC8:
            //QoS Null
            type = "QoS Null"; 
            break;

        case 0xE8:
            //QoS CF-Poll
            type = "QoS CF-Poll";
            break;
        
        case 0xF8:
            //QoS CF-Ack+CF-Poll
            type = "QoS CF-Ack+CF-Poll";
            break;

	default:
            printf(" Unknown packet: %02hhx \n",packet[hlen]);
	    break;

        }
        
        switch(flags){
        
        case 0:
            power_mac1 = -127;
            power_mac2 = power;
            power_mac3 = -127;
            break;

        case 1:
            power_mac1 = -127;
            power_mac2 = power;
            power_mac3 = -127;
            break;

        case 2:
            power_mac1 = -127;
            power_mac2 = -127;
            power_mac3 = power;
            break;

        case 3:
            power_mac1 = -127;
            power_mac2 = -127;
            power_mac3 = -127;
            break;

        }        

        if (header->len >= pos2){
            bssid_found(packet + pos1, power_mac1, type);
            if (header->len >= pos3){
                bssid_found(packet + pos2, power_mac2, type);
                if (header->len >= pos4){
                    bssid_found(packet + pos3, power_mac3, type);
                }
            }
        }
        
    }
}

void dump_pcap_error(pcap_t *pcap_handle) 
{
	fprintf(stderr, "Error: %s\n", pcap_geterr(pcap_handle));

}

void print_menu(){
    printf("WifiTests - Version %s\nUsage: witest [-options]\n\n", VERSION);
    printf("Options:\n");
    printf("\t--help or -h\t\t\t\t: Shows this help\n");
    printf("\t--verbose or -v\t\t\t\t: Verbose mode\n");
    printf("\t--interface [name] or -i [name]\t\t: Required: Sniff on specified wlan interface\n");
    printf("\t--mac-filter [XX:XX:XX...] or -m [XX:XX:XX...]\t: Filter on specified MAC address\n");
    printf("\t--power-only or -p\t: It shows just the received power\n");
}

int main(int argc, char **argv)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    int status = 0;
    int option_index = 0;
    char *interface = NULL;
    unsigned char mmac[6];
    
    static const struct option long_options[] = {
        { "help", no_argument,	NULL, 'h' },
        { "verbose",	no_argument,	NULL, 'v' },
        { "interface",	required_argument,	NULL, 'i' },
        { "mac-filter",	required_argument,	NULL, 'm' },
        { "power-only", no_argument,	NULL, 'p' },
        { 0, 0, 0, 0 }
    };

    signal(SIGINT, exit_signal);	/* Ctrl-C */
    signal(SIGQUIT, exit_signal);	/* Ctrl-\ */
    
    do {
        option_index = getopt_long(argc, argv, "hvi:m:p", long_options, &option_index);
        switch (option_index)
        {
        case 'h':
            print_menu();
            exit(0);
            break;
        
        case 'v':
            verbose++;
            break;
        
        case 'i':
            interface = optarg;
            break;

        case 'm':
            sscanf(optarg, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &mmac[0],
            &mmac[1], &mmac[2], &mmac[3], &mmac[4], &mmac[5]);
            match_mac = mmac;
            break;

        case 'p':
            power_only = 1;
            break;       

        default:
        break;
        }
    } while (option_index != -1);
    if (interface != NULL){
        pcap_handle = pcap_create(interface, error_buffer);
    }
    else {
        printf("Missing interface! Add it using -i [interface]\n");
        exit(1);
    }
    if (pcap_handle == NULL) {
	fprintf(stderr, "Error while creating handle on interface %s\n",
		argv[argc - 1]);
    }

    /*
    Non necessario se si lavora gia' con una interfaccia monitor, inoltre mettendolo
    non funziona su versioni<libpcap1.0
    status = pcap_set_rfmon(pcap_handle, 1);
    if (status != 0) {
	dump_pcap_error(pcap_handle) ;
	//fprintf(stderr, "Error while opening monitor mode\n");
    }*/

    status = pcap_set_promisc(pcap_handle, 0);
    if (status != 0) {
	//fprintf(stderr, "Error while setting no-promisc\n");
	dump_pcap_error(pcap_handle) ;
    }

    status = pcap_set_timeout(pcap_handle, 0);
    if (status != 0) {
	//fprintf(stderr, "Error while setting timeout on pcap\n");
	dump_pcap_error(pcap_handle) ;
    }

    status = pcap_activate(pcap_handle);
    if (status != 0) {
	dump_pcap_error(pcap_handle) ;
	
	/* 
	fprintf(stderr, "Error while activating pcap number %d\n", status);
	errorstring = pcap_geterr(pcap_handle);
	fprintf(stderr, "Error: %s\n", errorstring);
	*/
    }

    pcap_loop(pcap_handle, -1, process_packet, NULL);


    pcap_close(pcap_handle);
    return 0;
}
