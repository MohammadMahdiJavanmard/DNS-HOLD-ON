#ifndef GLOBALS_CONSTANTS_DEFINITIONS
#define GLOBALS_CONSTANTS_DEFINITIONS

// the ip of the dns server
char dns_server[100];

#define BUFFER_SIZE 65536
#define PORT_NUMBER 53

#define T_A 1 //Ipv4 address
#define T_MX 15
#define T_CNAME 5
#define T_PTR 12
#define T_NS 2
#define T_SOA 6

//DNS header structure
struct DNS_H {
    unsigned short id_number;

    unsigned char recursion_desired :1;
    unsigned char truncated_message :1;
    unsigned char authoritive_answer :1;
    unsigned char opcode :4;
    unsigned char query_response_flag :1;

    unsigned char response_code :4;
    unsigned char checking_disabled :1;
    unsigned char authenticated_data :1;
    unsigned char z :1;
    unsigned char recursion_available :1;

    unsigned short question_count;
    unsigned short answer_count;
    unsigned short authority_entries_count;
    unsigned short resource_count;
};

//Query Structure Fields
struct QUERY
{
    unsigned short query_type;
    unsigned short query_class;
};

//Resource Record Structure Fields
#pragma pack(push, 1)
struct RESPONSE_DATA {
    unsigned short response_type;
    unsigned short response_class;
    unsigned int ttl;
    unsigned short data_length;
};
#pragma pack(pop)

//Resource Record Contents Pointer
struct RESOURCE_RECORD {
    unsigned char *resource_name;
    struct RESPONSE_DATA *response_data;
    unsigned char *resource_data;
};

//Structure of a Query
typedef struct {
    unsigned char *name;
    struct QUERY *ques;
} QUERY_STRUCT;

#endif
