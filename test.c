
#include <stdio.h>
#include <signal.h>
#include <pcap.h>

pcap_t *pcap_handle;


void exit_signal(int id){
    printf("Exit signal\n");
    if (pcap_handle != NULL) {
        pcap_breakloop(pcap_handle);
        pcap_close(pcap_handle);
    }
    exit (0);
}

void process_packet(u_char* useless, const struct pcap_pkthdr* header, const u_char* packet ){
    printf("Pacchetto lungo %d ricevuto\n",header->len); 
}

int main(){
    char error_buffer[100];
    int status = 0;

    signal(SIGINT, exit_signal); /* Ctrl-C */
    signal(SIGQUIT, exit_signal); /* Ctrl-\ */

    pcap_handle = pcap_create("wlan0", error_buffer);
    if (pcap_handle == NULL){
        printf("Error\n");
    }

    status = pcap_set_rfmon(pcap_handle, 1);
    if (status != 0){
        printf("Error while opening monitor mode\n");
    }
    
    status = pcap_set_promisc(pcap_handle, 0);
    if (status != 0){
        printf("Error while setting no-promisc\n");
    }

    status = pcap_set_timeout(pcap_handle, 0);
    if (status != 0){
        printf("Error while setting timeout on pcap\n");
    }

    status = pcap_activate(pcap_handle);
    if (status != 0){
        printf("Error while activating pcap number %d\n", status);
    }

    pcap_loop(pcap_handle, -1, process_packet, NULL);

    
    pcap_close(pcap_handle);
    return 0;
}
