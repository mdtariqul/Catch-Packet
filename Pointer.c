#include"pac.h"

int main()
{
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif


    

    int j= NUMBER_OF_PACKET;
    Node *head=NULL;

    FILE *fp=fopen("packet.txt", "r");
    if(fp== NULL)
    {
        perror("Error opening file");
        return 1;
    }
    j=1;
    while(1)
    {
      
        uint8_t buf[BUFFER_SIZE]={0};
       

        create_raw_data(fp,buf);
        printf("\n\n\nPacket No    :%d\n", j++);
        mac_header *mac_head= (mac_header *)buf;
        print_mac_header(mac_head);
        if((ntohs(mac_head->ip_type) !=0x800) ) ;
    else{
        ip_header *ip_head=(ip_header *) (buf+sizeof(mac_header));
        print_ip_header(ip_head);

        data *data_part=(data *) (buf+sizeof(mac_header)+sizeof(ip_header));
        print_data(data_part);

        insert_into_list(&head,ip_head->source_ip,ip_head->dest_ip );
        }

        //printf("%c\n",buf[0] );

        if (feof(fp)) {
            printf("File reading completed.\n");
            break;
        }
       
    }

    printf("\n\n");

    printf("This is the final Created list:\n");
    traverse_list(head);

    free_list(head);
    fclose(fp);

}

