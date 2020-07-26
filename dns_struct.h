#include <string.h>

typedef struct _question {

    char*          dns_name;
    unsigned short type;
    unsigned short clas;

} question;

typedef struct _answer_authority_additonal {

    char*          dns_name;
    unsigned short type;
    unsigned short clas;
    unsigned int   ttl;
    unsigned short addr_len;
    char*          addr;

} answer, authority, additional;

typedef struct _additional_edns {

} additional_edns;

typedef struct _dns_packet {

    /*
        dns_packet:
            Represents the structure of a DNS Packet
    */

    unsigned short id;
    unsigned short ctrl;
    unsigned short ques_count;
    unsigned short ans_cnt;
    unsigned short auth_cnt;
    unsigned short addt_cnt;

    question*   p_que;
    answer*     p_ans;
    authority*  p_auth;
    additional* p_addt;

} dns_packet;
