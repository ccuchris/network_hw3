#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

void callback(unsigned char *argument, const struct pcap_pkthdr *pac_hdr, const unsigned char *packet)
{
    int *id = (int *)argument;
    printf("packet:%d\n", ++(*id));
    printf("----------------------------------------------------\n");
    printf("%s\n", ctime((time_t *)&(pac_hdr->ts.tv_sec))); //轉換時間
    printf("Mac Source Address: ");
    for (int i = 0; i < 6; i++)
    {
        printf("%02x", packet[i]);
        if (i != 5)
            printf(":");
        if (i == 5)
            printf("\n");
    }
    printf("Mac Destination Address: ");
    for (int i = 6; i < 12; i++)
    {
        printf("%02x", packet[i]);
        if (i != 11)
            printf(":");
        if (i == 11)
            printf("\n");
    }
    printf("Ethernet type :");
    printf("%02x%02x\n",packet[12],packet[13]);
    if (packet[12] == 8 && packet[13] == 0) //IP= 0x0800
    {
        printf("This network layer is IP protocol\n");
        printf("Source IP Address :");
        for (int i = 26; i < 30; i++)
        {
            printf("%d", packet[i]);
            if (i != 29)
                printf(".");
            if (i == 29)
                printf("\n");
        }
        printf("Destination IP Address is ");
        for (int i = 30; i < 34; i++)
        {
            printf("%d", packet[i]);
            if (i != 33)
                printf(".");
            if (i == 33)
                printf("\n");
        }
        if(packet[23]==6) printf("This is TCP\n");
        if(packet[23]==17) printf("This is UDP\n");
        if(packet[23]==6 || packet[23]==17){
            printf("Source port :%d\n",packet[34]*256+packet[35]);
            printf("Destination port :%d\n",packet[36]*256+packet[37]);
        }
    }
    printf("\n\n");
}
int main(int argc, char **argv)
{
    if (argc > 1)
    {
        char filename[1000];
        char error[PCAP_ERRBUF_SIZE] = {0}; // 出錯資訊
        char *dev = pcap_lookupdev(error);  // 網路裝置查詢,獲取網路介面
        if (NULL == dev)
        {
            printf("%s\n", error);
            exit(-1);
        }
        else
        {
            printf("device success:%s\n", dev);
        }
        pcap_t *pcap_handler = pcap_open_live(dev, 65536, 1, 0, error);	//開啟一個用於捕獲資料的網路介面
        if (NULL == pcap_handler)
        {
            printf("%s\n", error);
            exit(-1);
        }
        else
        {
            strcpy(filename, argv[1]);
            pcap_handler = pcap_open_offline(filename, error);
            if (NULL == pcap_handler)
            {
                printf("error to open file:%s\n", filename);
                exit(1);
            }
            else
                printf("Open file:%s\n", filename);
        }
        int id = 0;
        if (pcap_loop(pcap_handler, -1, callback, (u_char *)&id) < 0)	//抓取資料包
        {
            perror("pcap_loop");
        }
    }
}
