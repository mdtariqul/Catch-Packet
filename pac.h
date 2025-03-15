#include<stdio.h>
#include <stdlib.h>
#include<string.h>
#include<stdint.h>

#ifdef _WIN32
    // For Windows
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    // For Linux (and other Unix-like systems)
    #include <netinet/in.h>
    #include <endian.h>
#endif

#define BUFFER_SIZE 1024
#define NUMBER_OF_PACKET 31
#define LINE_SIZE 512
#define LINE 48

//#define print 1

#ifdef _WIN32
    // Windows doesn't define the byte order macros, so we explicitly define them
    #define __BYTE_ORDER__ __LITTLE_ENDIAN
#endif


#pragma pack(1)
typedef struct {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t ip_type;
}mac_header;
#pragma back()

#pragma pack(1)
#if __BYTE_ORDER__ == __BIG_ENDIAN
    typedef struct {
        uint8_t  version :4;
        uint8_t  IHL     :4;
        uint8_t  TOS;
        uint16_t total_length;
        uint16_t id;
        uint8_t offset;
        uint8_t flag_off ;
        uint8_t  TTL;
        uint8_t  protocol;
        uint16_t checksum;
        uint32_t source_ip;
        uint32_t dest_ip;
    } ip_header;

#elif __BYTE_ORDER__ == __LITTLE_ENDIAN
    typedef struct {
        uint8_t  IHL     :4;
        uint8_t  version :4;
        uint8_t  TOS;
        uint16_t total_length;
        uint16_t id;
        uint8_t offset;
        uint8_t flag_off ;
        uint8_t  TTL;
        uint8_t  protocol;
        uint16_t checksum;
        uint32_t source_ip;
        uint32_t dest_ip;

    } ip_header;
#else
    #error "Unknown byte order"
#endif

#pragma back()


#pragma pack(1)

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint8_t  d[];
} data;
#pragma back()

#pragma pack(1)

typedef struct Node
{
    uint32_t Source_ip;
    uint32_t destination_ip;
    int counter;
    struct Node* next;
} Node;
#pragma back()



char *print_mac(unsigned char *mac)
{
    static char str[20]= {0};
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return str;
}


unsigned char stoi(char *ch)
{
    unsigned char c = (char)strtol(ch, NULL, 16);
    return c;

}


void clear( char *buf, char *buf2)
{
    int count = 0;
    char *token;
    // Read each byte in the line
    token = strtok(buf, " ");
    while (token != NULL)
    {
        //printf("%x ,",stoi(token));
        *(buf2+count) =stoi(token);
        count++;
        token = strtok(NULL, " ");
    }
    buf2[count] = '\0';
    //printf("\n\n%d",strlen(buf2));
}


void create_raw_data(FILE *fp, uint8_t *buf)
{
    int i=0;
    uint8_t buf2[BUFFER_SIZE];
    if(fp == NULL)
    {
        perror("Error opening file");
        return;
    }
    uint8_t line1[LINE_SIZE];

    while(1){
        fgets(line1, sizeof(line1), fp);

        if(strlen(line1)<74){

            memcpy(buf2+(LINE*i), line1+6, LINE);
            i++;
            buf2[LINE*i]='\0';
            fgets(line1, sizeof(line1), fp);
            //printf("*%s\n", buf);
            break;
        }
        else{
            memcpy(buf2+(LINE*i), line1+6, LINE);
            i++;
            buf2[LINE*i]=' ';
            //printf("**%s\n", buf);
        }

    }

    clear(buf2, buf);


}

char *print_ip_from_int(unsigned int ip)
{
    static char str1[25]= {0};

    unsigned char byte1 = (ip >> 24) & 0xFF;
    unsigned char byte2 = (ip >> 16) & 0xFF;
    unsigned char byte3 = (ip >> 8) & 0xFF;
    unsigned char byte4 = ip & 0xFF;


    sprintf(str1,"%u.%u.%u.%u", byte1, byte2, byte3, byte4);
    return str1;
}


void print_ip_header(ip_header *ip_head) {
    printf("|Version                :  %-17d |\n", (ip_head->version));
    printf("|IHL (Header Length)    :  %-17d |\n", (ip_head->IHL));
    printf("|TOS (Type of Service)  :  %-17d |\n", ntohs(ip_head->TOS));
    printf("|Total Length           :  %-17d |\n", ntohs(ip_head->total_length));
    printf("|ID                     :  %-17d |\n", ntohs(ip_head->id));
    printf("|Flags                  :  %-17hhu |\n", (ip_head->offset)>>5 & 0x7 ) ;
    printf("|TTL (Time to Live)     :  %-17d |\n", ip_head->TTL);
    printf("|Protocol               :  %-17d |\n", ip_head->protocol);
    printf("|Checksum               :  %-17d |\n", ntohs(ip_head->checksum));
    printf("|Source IP              :  %-18s|\n", print_ip_from_int(ntohl(ip_head->source_ip)));
    printf("|Destination IP         :  %-18s|\n", print_ip_from_int(ntohl(ip_head->dest_ip)));

}

void print_mac_header(mac_header *mac_head){
    printf("|DMAC                   :  %-18s|\n", print_mac(mac_head->dmac));
    printf("|SMAC                   :  %-18s|\n", print_mac(mac_head->smac));
    printf("|IP TYPE                :  %-18s|\n", (ntohs(mac_head->ip_type) ==0x800) ? "Ipv4":"Not Ipv4");

}

void print_data( data *data_part)
{
    printf("|Source Port            :  %-18hu|\n", ntohs(data_part->sport));
    printf("|Destination Port       :  %-18hu|\n", ntohs(data_part->dport));
}


Node* create_node(uint32_t sip, uint32_t dip)
{
    Node *new=(Node*)malloc(sizeof(Node));
    if(new== NULL)
    {
        perror("Memory not allocated!\n");
        exit(1);
    }
    new->Source_ip=sip;
    new->destination_ip=dip;
    new->counter=1;
    new->next=NULL;
    return new;
}


void free_list(Node* head)
{
    Node* current_node = head;
    Node* next_node;
    while(current_node != NULL)
    {
        next_node=current_node->next;
        free(current_node);
        current_node=next_node;

    }
    printf("Successfully freed Memory.\n");
}


Node *check_packet(Node *head, uint32_t sip, uint32_t dip )
{
    Node *current = head, *previous;

    // Traverse through the linked list.
    while (current != NULL)
    {
        // Compare the packet in the current node with the given 'tem' packet.
        if ( current->Source_ip == sip && current->destination_ip == dip )
        {
            // If found, return the current node pointer.
            return current;
        }
        previous=current;
        current = current->next;
    }

    previous->next=create_node(sip,dip);
    return NULL;
}


void insert_into_list(Node **head, uint32_t sip, uint32_t dip)
{
    if(*head==NULL)
    {
        *head=create_node(sip,dip);
        printf("1st Node added successfully!\n");
        return;
    }
    Node *check=check_packet(*head, sip, dip);
    if(check==NULL)
    {
        printf("Node added successfully!\n");
    }
    else
    {
        check->counter++;
        printf("Packet Already present. Counter incremented.\n");

    }
    return;
}


void traverse_list(Node* head)
{
    Node *tem=head;
    while(tem != NULL)
    {
        char buffer[512]={0};
        sprintf(buffer + strlen(buffer), "---------------------------------------\n");
        sprintf(buffer + strlen(buffer), "|Sourc IP         :  %-17s|\n", print_ip_from_int(ntohl(tem->Source_ip)));
        sprintf(buffer + strlen(buffer), "|Distenation IP   :  %-17s|\n", print_ip_from_int(ntohl(tem->destination_ip)));
        sprintf(buffer + strlen(buffer), "|counter          :  %-17d|\n", tem->counter);
        sprintf(buffer + strlen(buffer), "---------------------------------------\n\n");

        printf("%s", buffer);
        tem=tem->next;
    }
}
