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
unsigned char *match_mac = NULL;
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
            if (strncmp(bssid, match_mac, 6) != 0)
                return;
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
    if (header->len > 18) {
	power = packet[14];


	switch (packet[18]) {

	case 0x40:		//destination,source,bss
            if (header->len >= 40) {
                type = "Probe request";
                bssid_found(packet + 22, -127, type);
                bssid_found(packet + 28, power, type);
                bssid_found(packet + 34, -127, type);
            }
            break;
	case 0x50:		//destination,source,bss
            if (header->len >= 40) {
                type = "Probe response";
                bssid_found(packet + 22, -127, type);
                bssid_found(packet + 28, power, type);
                bssid_found(packet + 34, -127, type);
            }
            break;
	case 0x80:		//destination,source,bss 
            if (header->len >= 40) {
                type = "Beacon";
                bssid_found(packet + 22, -127, type);
                bssid_found(packet + 28, power, type);
                bssid_found(packet + 34, -127, type);
            }
            break;
	case 0x48:		//bss,source,destination
            if (header->len >= 40) {
                type = "Null function";
                bssid_found(packet + 22, -127, type);
                bssid_found(packet + 28, power, type);
                bssid_found(packet + 34, -127, type);
            }
            break;
	case 0x88:		//bss,source,destination
	    if (header->len >= 40) {
                type = "QoS";
		bssid_found(packet + 22, -127, type);
		bssid_found(packet + 28, power, type);
		bssid_found(packet + 34, -127, type);
	    }
	    break;

	case 0xd4:		//destination
            if (header->len == 28) {
                type = "ACK!";
                bssid_found(packet + 22, -127, type);
            }
            break;
	case 0xc4:		//destination
	    if (header->len == 28) {
                type = "Clear to send";
		bssid_found(packet + 22, -127, type);
	    }
	    break;

	default:
	    break;

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
