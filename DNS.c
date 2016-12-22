#include<sys/socket.h>
#include<stdio.h>
#include <time.h>
#include <netdb.h>
#include<string.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<unistd.h>
#include<arpa/inet.h>
#include <arpa/inet.h>
#include <fcntl.h>

// this file contains all the global variables, constants and structs and definitions
#include "globalsConstantsDefines.h"

// This function makes the dns query header
// This function is used in the function resolve_hostname
void create_dns_header(struct DNS_H *dns_header) {

	dns_header->recursion_desired = 1;
	dns_header->authoritive_answer = 0;
	dns_header->id_number = (unsigned short) htons(getpid());
	dns_header->recursion_available = 0;
	dns_header->query_response_flag = 0;
	dns_header->opcode = 0;
	dns_header->truncated_message = 0;
	dns_header->z = 0;
	dns_header->authenticated_data = 0;
	dns_header->checking_disabled = 0;
	dns_header->response_code = 0;
	dns_header->answer_count = 0;
	dns_header->authority_entries_count = 0;
	dns_header->resource_count = 0;
	dns_header->question_count = htons(1);

}

// This (helper) function is used to read the name of the website from the buffer, modify it and return it
// This function is used in the function read_answers_from_buffer, etc.
u_char* read_n(unsigned char* reader, unsigned char* buffer_read, int* count) {
    unsigned char *website_name;
    unsigned int p=0,
    			  jump_steps=0,
				  off_set;
    int i , j;

    *count = 1;
    website_name = (unsigned char*)malloc(256);

    website_name[0]='\0';

    while(*reader!=0) {
        if(*reader>=192) {
        	off_set = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer_read + off_set - 1;
            jump_steps = 1;
        }
        else {
        	website_name[p++]=*reader;
        }

        reader = reader + 1;

        if(jump_steps == 0) {
            *count = *count + 1;
        }
    }

    website_name[p]='\0';
    if(jump_steps == 1) {
        *count = *count + 1;
    }

    for(i=0; i < (int)strlen((const char*) website_name); i++) {
        p = website_name[i];
        for(j=0; j < (int)p; j++) {
        	website_name[i] = website_name[i+1];
            i = i+1;
        }
        website_name[i]='.';
    }

    website_name[i-1]='\0';
    return website_name;
}

// This function reads/extracts the answers (the IPs) from the buffer
// This function is used in the function resolve_hostname.
void read_answers_from_buffer(unsigned char **reader, unsigned char buffer[],
		struct RESOURCE_RECORD *answers, struct DNS_H *dns_header) {

	int offset;
	offset=0;

	int j;
	int i = 0;

	while (i < ntohs(dns_header->answer_count)) {
		answers[i].resource_name = read_n(*reader, buffer, &offset);
		(*reader) = (*reader) + offset;

		answers[i].response_data = (struct RESPONSE_DATA*)(*reader);
		(*reader) = (*reader) + sizeof(struct RESPONSE_DATA);

		if(ntohs(answers[i].response_data->response_type) == 1) {
			answers[i].resource_data = (unsigned char*) malloc(ntohs(answers[i].response_data->data_length));

			for(j=0 ; j < ntohs(answers[i].response_data->data_length) ; j++) {
				answers[i].resource_data[j]=(*reader)[j];
			}

			answers[i].resource_data[ntohs(answers[i].response_data->data_length)] = '\0';

			*reader = *reader + ntohs(answers[i].response_data->data_length);
		}

		else {
			answers[i].resource_data = read_n(*reader,buffer,&offset);
			*reader = *reader + offset;
		}
		i++;
	}
}

// This function reads/extracts the authorities from the buffer
// This function is used in the function resolve_hostname.
void read_authorities_from_buffer(unsigned char **reader, unsigned char buffer[],
		struct RESOURCE_RECORD *authorities, struct DNS_H *dns_header) {

	int offset;
	offset=0;

	int i = 0;
	while (i < ntohs(dns_header->authority_entries_count)) {
		authorities[i].resource_name=read_n(*reader,buffer,&offset);

		(*reader) += offset;

		authorities[i].response_data=(struct RESPONSE_DATA*)(*reader);
		(*reader) += sizeof(struct RESPONSE_DATA);

		authorities[i].resource_data=read_n(*reader,buffer,&offset);
		(*reader) += offset;

		i++;
	}
}

// This function reads the additional information from the buffer
// This function is used in the function resolve_hostname.
void read_additionals_from_buffer(unsigned char **reader, unsigned char buffer[],
		struct RESOURCE_RECORD *addititionals, struct DNS_H *dns_header) {

	int offset = 0;
	int i = 0;

	for(i = 0;i < ntohs(dns_header->resource_count); i++) {
		addititionals[i].resource_name=read_n(*reader,buffer,&offset);
		(*reader) += offset;

		addititionals[i].response_data=(struct RESPONSE_DATA*)(*reader);
		(*reader) +=sizeof(struct RESPONSE_DATA);

		if(ntohs(addititionals[i].response_data->response_type)==1) {
			addititionals[i].resource_data = (unsigned char*)malloc(ntohs(addititionals[i].response_data->data_length));
			int j;
			for(j = 0; j<ntohs(addititionals[i].response_data->data_length); j++)
				addititionals[i].resource_data[j]= (*reader[j]);

			addititionals[i].resource_data[ntohs(addititionals[i].response_data->data_length)]='\0';
			(*reader) += ntohs(addititionals[i].response_data->data_length);
		}
		else {
			addititionals[i].resource_data=read_n(*reader,buffer,&offset);
			(*reader) += offset;
		}
	}
}

// This function changes the name of the website to the dns-required format name
// This function is used in the function resolve_hostname
void change_to_dns_f(unsigned char* dns_name,unsigned char* host_name) {
    int lock = 0 , i;
    strcat((char*)host_name,".");

    for(i = 0 ; i < strlen((char*)host_name) ; i++) {
        if(host_name[i] == '.') {
            *dns_name ++= i - lock;
            for(;lock < i; lock++) {
                *dns_name++=host_name[lock];
            }

            lock++;
        }
    }

    *dns_name++='\0';
}

// This function make a DNS query, puts it in the UDP packet and sends it to the designated dns server.
// Then, based on the number of packets, it receives, it determines whether the attack happens or not
void resolve_hostname(unsigned char *host , int query_type, int timeout)
{
    printf("Resolving %s" , host);

    int s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);

    struct sockaddr_in destination;

    destination.sin_family = AF_INET;
    destination.sin_port = htons(PORT_NUMBER);
    destination.sin_addr.s_addr = inet_addr(dns_server);

    //Setting the structure of DNS query
    unsigned char buffer[BUFFER_SIZE];

    struct DNS_H *dns_header = NULL;

    dns_header = (struct DNS_H *)&buffer;
    create_dns_header(dns_header);

    unsigned char *query_name;
    query_name =(unsigned char*)&buffer[sizeof(struct DNS_H)];


    change_to_dns_f(query_name, host);

    struct QUERY *query_info = NULL;
    query_info =(struct QUERY*)&buffer[sizeof(struct DNS_H) + (strlen((const char*)query_name) + 1)];

    //DEFAULT type of the query is considered as TYPE A
    query_info->query_type = htons( query_type );

    query_info->query_class = htons(1);

    printf("\nSENDING THE REQUIRED PACKET WHICH CONTAINS THE DNS QUERY!!");
    if(sendto(s,(char*)buffer,sizeof(struct DNS_H) +
    		(strlen((const char*)query_name)+1) + sizeof(struct QUERY),
			0,(struct sockaddr*)&destination,sizeof(destination)) < 0) {
        perror("SENDING THE UDP PACKET FAILED :(");
    }
    printf("\nUDP PACKET SENT SUCCESSFULLY :)");

    //Receive the answer
    int i;
    i = sizeof destination;
    printf("\nRECEIVING THE UDP PACKET(S), WHICH CONTAIN(S) DNS REPLY INFO:\n");

    int counter = 0;

    // Setting the timer for the socket to wait for the packet to be received in a limited time
    struct timeval tv;
    tv.tv_sec = timeout; // Defalut value is 15 seconds
    tv.tv_usec = 0;

    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
        perror("ERROR CONFIGURING THE SOCKET TO HAVE THE TIMER");
    }

    int l;
    unsigned char *reader;
    for (l = 1; l <= 2; l++) {
    	int n = recvfrom (s, (char*) buffer , BUFFER_SIZE , 0 , (struct sockaddr*)&destination , (socklen_t*)&i );
		if (n  > 0) {
			printf("-----------------------------------------------------------------------------------");
			counter = counter + 1;
			printf("\nRECEIVING RESPONSE PACKET NUMBER (%d)", counter);
			dns_header = (struct DNS_H*) buffer;

				//advancing to the DNS header (and the query fields)
				reader = &buffer[sizeof(struct DNS_H) + (strlen((const char*)query_name)+1) + sizeof(struct QUERY)];

				printf("\nTHE RESPONSE CONTAINS THE FOLLOWING INFORMATION:");
				printf("\n IT CONTAINS %d QUESTIONS.",ntohs(dns_header->question_count));
				printf("\n IT CONTAINS %d ANSWERS.",ntohs(dns_header->answer_count));
				printf("\n IT CONTAINS %d AUTHORATIVE SERVERS.",ntohs(dns_header->authority_entries_count));
				printf("\n %d ADDITIONAL RECORDS: \n",ntohs(dns_header->resource_count));

				//Start processing the required answers
				struct RESOURCE_RECORD answers[20];

				// reading the answers from the buffer
				read_answers_from_buffer(&reader, buffer, answers, dns_header);

				// read authorities from the buffer
				struct RESOURCE_RECORD authorities[20];
				read_authorities_from_buffer(&reader, buffer, authorities, dns_header);

				//read additional
				struct RESOURCE_RECORD addititionals[20];
				read_additionals_from_buffer(&reader, buffer, addititionals, dns_header);

				struct sockaddr_in a;
				printf("\nIN THIS RESOPNSE, WE HAVE %d  ANSWER RECORDS:\n" , ntohs(dns_header->answer_count) );
				for(i=0 ; i < ntohs(dns_header->answer_count) ; i++)
				{
					printf("NAME: %s ", answers[i].resource_name);

					if( ntohs(answers[i].response_data->response_type) == T_A) { //IPv4 address
						long *p;
						p = (long*)answers[i].resource_data;
						a.sin_addr.s_addr = (*p); //working without ntohl
						printf("HAS IPv4 ADDRESS: %s",inet_ntoa(a.sin_addr));
					}

					if(ntohs(answers[i].response_data->response_type)==5) {
						//Canonical name for an alias
						printf("HAS ALIAS NAME: %s",answers[i].resource_data);
					}
					printf("\n");
				}


				printf("\nIN THIS RESOPNSE, WE HAVE %d AUTHORITIVE RECORDS:\n" , ntohs(dns_header->authority_entries_count) );
				for( i = 0 ; i < ntohs(dns_header->authority_entries_count) ; i++) {

					printf("NAME: %s ",authorities[i].resource_name);
					if(ntohs(authorities[i].response_data->response_type)==2) {
						printf("HAS NAME-SERVER: %s",authorities[i].resource_data);
					}
					printf("\n");
				}


				printf("\nIN THIS RESPONSE, WE HAVE %d ADDITIONAL RECORDS:\n" , ntohs(dns_header->resource_count) );
				for(i = 0; i < ntohs(dns_header->resource_count) ; i++) {
					printf("NAME: %s ",addititionals[i].resource_name);
					if(ntohs(addititionals[i].response_data->response_type)==1) {

						a.sin_addr.s_addr = (long)addititionals[i].resource_data; //(*p);
						printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
					}
					printf("\n");
				}
		}
    }

	if (counter == 1)
		printf("\nTIME-OUT HAPPENED!");

	if (counter == 0) {
		printf("\nWE RECEIVE NO DNS-QUERY RESPONSE. IS DNS-SERVER UP/RUNNING?");
	}

	else if (counter == 1) {
		printf("\nWE RECEIVE ONLY ONE DNS-QUERY RESPONSE. HENCE, WE DIDN'T HAVE ANY DSN-ATTACK.\n");
	}

	else if (counter > 1) {
		printf("\nWE RECEIVE MORE THAN ONE DNS-QUERY RESPONSES. HENCE, DNS ATTACK HAPPENED.\n");
	}

	close(s);
    return;
}

// Compiling: gcc ./DNS.c -o meantest
// Execution: ./meantest 130.245.145.7 falun.com
int main( int argc , char *argv[]) {
    strcpy(dns_server, argv[1]); // argv[1] which is [server IP] (e.g., 130.245.145.7)
    printf("DNS_Server is %s\n", dns_server);
    printf("HostName is %s\n\n", argv[2]); // argv[2] is the host name (e.g., falun.com)

    // default value for the time-out is 15
    resolve_hostname(argv[2], T_A, (argc > 3 ? atoi(argv[3]) : 15));

    return 0;
}
