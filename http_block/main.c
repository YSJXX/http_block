#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>         // exit
#include <netinet/ip.h>     //ip
#include <netinet/tcp.h>    //tcp
#include <regex.h>          //regex
#include <string.h>

#define FIND 100
static FILE *jfp;




int jfopen(u_char *data_buf)
{

    u_char j_read_buff[200];
    int jmemcmp=0;
    int cmp=0;
    if(jfp != NULL)
    {
        char *pStr=NULL;
        while(!feof(jfp))
        {
            pStr = fgets((char *)j_read_buff,sizeof(j_read_buff),jfp);
            //printf("TEST:: %s \n", pStr);
            jmemcmp = memcmp(pStr,data_buf,strlen((char*)pStr));
            if(!jmemcmp)
                printf("TEST True \n");
                cmp = FIND;
                break;
        }
        free(pStr);
    }
    if(cmp == FIND) return FIND;
    else return 0;
}


int jcheck(const u_char * packet)
{
    struct ip * ip_header = (struct ip *)packet;
    struct tcphdr * tcp_header = (struct tcphdr *) (packet + (ip_header->ip_len<<2) );
    u_char * http = (u_char *)tcp_header + (tcp_header->th_off<<2); // next data 32

    regex_t state;
        //char *string ="Host: sungjun.yoon";
        const char *pattern= "Host: ([A-Za-z\\.0-9]+)";
        int rc;
        size_t nmatch =2;
        regmatch_t pmatch[1];
        char jbuffer[100];
        printf("\n");
        if((rc = regcomp(&state,pattern,REG_EXTENDED)) != 0){
            printf("regcomp error!! '%s' \n",jbuffer);
            exit(EXIT_FAILURE);     // 종료를 위한 정리(버퍼삭제, 열린파일 종료)
        }
        rc = regexec(&state,(char *)http,nmatch,pmatch,0);
        regfree(&state);

        u_char data_buf[200];   //찾은 문자열 저장
        int jcheck=0;
        if(rc !=0){
                printf("Failed to match '%s' with '%s', returning %d. \n",http,pattern,rc);
        }
        else {
            sprintf((char *)data_buf,"%s",&http[pmatch[1].rm_so]);
            printf("데이터 이동 확인: %s \n",data_buf);
            jcheck = jfopen(data_buf);
        }
}


int main(int argc, char* argv[]) {

  jfp = fopen("DB.txt","r");
  //char* dev = argv[1];
  char* dev ="en0";
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (1) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    jcheck(packet);

  }

  pcap_close(handle);
  return 0;
}
