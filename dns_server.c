#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dns_constants.h"
#include "logging.h"

int serverfd;
int optval = 1;
int port = 53;
int bytesRecv;
char request[BUFSIZE];
char response[BUFSIZE];
char *hostaddrp;
struct sockaddr_in serveraddr;
struct sockaddr_in clientaddr;
struct hostent *hostp;
socklen_t clientlen = sizeof(struct sockaddr_in);

typedef struct _node {
    char*    name_ptr;
    int      offset;
    uint16_t type;
    uint16_t clas;
} *map;

void insert(map *m, int *map_size, char* name_ptr, int offset, uint16_t type, uint16_t clas) {
    // Allocate/Reallocate new data
    if (!(*m)) *m = (map) malloc(sizeof(struct _node));
    else       *m = (map) realloc(*m, ((*map_size)+1)* sizeof(struct _node));
    // Set value
    (*m)[(*map_size)].name_ptr = name_ptr;
    (*m)[(*map_size)].offset   = offset;
    (*m)[(*map_size)].type     = type;
    (*m)[(*map_size)].clas     = clas;
    // Increase size
    (*map_size)++;
}

void erase(map *m, int *map_size) {
    free((*m));
    (*m) = 0;
    (*map_size) = 0;
}

int construct_response(int *response_len) {

    // Print packet in hex form
    //logging(request, "packet-hex");

    int beg = 12;
    int end = 12;

    // Create a struct to remember where name in DNS is, for compression
    map m = NULL;
    int map_size = 0;

    // Zeroing memory
    memset(response, 0, BUFSIZE);

    // Copy ID from request to response
    response[0] = request[0];
    response[1] = request[1];

    // Setting flags of response
    response[2] |= RESPONSE | RD | RA;
    response[3] = 0;

    // Copy no questions in the request
    uint16_t question_count = 0;
    uint16_t answer_count = 0;
    response[4] = request[4];
    response[5] = request[5];
    question_count = ntohs(*(uint16_t*)(request + 4));

    // Copy question field from request to response & record data
    // the requester wants & perform lookup
    uint16_t type;
    uint16_t clas;
    while (question_count--) {

        // Copy the address from request to response
        do {
            response[end] = request[end];
            end++;
        } while (request[end] && end < BUFSIZE);
        response[end] = request[end]; end++;

        // Getting the type
        response[end]   = request[end];
        response[end+1] = request[end+1];
        type = ntohs(*(uint16_t*)(request + end));

        // Getting the class
        response[end+2] = request[end+2];
        response[end+3] = request[end+3];
        clas = ntohs(*(uint16_t*)(request + end + 2));

        // Insert to map to lookup later...
        insert(&m, &map_size,
            request + beg, beg, type, clas
        );

        end += 4;
        beg = end;

    }

    // Lookup data in file, return answer...
    for (int i = 0; i < map_size; ++i) {
        // Open file for searching data & log
        FILE *infofile = fopen(LOOKUP_FILENAME, "r");

        // Read line by line
        char line[256]; memset(line, 0, 256);
        while (fgets(line, 256, infofile))  {

            // First token will be the address...
            char *addr_str = strtok(line, " ");
            char *_tmp_    = addr_str;
            char *addr_dns = m[i].name_ptr;
            int   match    = 1;
            while (*addr_str && *addr_dns) {
                addr_dns++;
                if (*addr_str != '.' && *addr_str != *addr_dns) {
                    match = 0;
                    break;
                }
                addr_str++;
            }
            if (!match) {
                log_n_print("[i] Address not match! \"%s\", but in database we have \"%s\"... Try another address...\n", m[i].name_ptr, _tmp_);
                continue;
            }


            // Second token will be the type...
            char *type = strtok(NULL, " ");
            if (
                (m[i].type == A     && strcmp(type, "A"    ) != 0) ||
                (m[i].type == AAAA  && strcmp(type, "AAAA" ) != 0) ||
                (m[i].type != A     && m[i].type != AAAA         )
            ) {
                log_n_print("[i] Type mismatch! Have %s, but got %04x!\n", type, m[i].type);
                continue;
            }


            // Write compressed name to response
            response[end]   = ((m[i].offset >> 8) | 0b11000000) & 0xff;
            response[end+1] = ((m[i].offset     )             ) & 0xff;

            // Write type to response
            response[end+2] = (m[i].type >> 8) & 0xff;
            response[end+3] = (m[i].type     ) & 0xff;

            // Write class to reponse
            response[end+4] = (m[i].clas >> 8) & 0xff;
            response[end+5] = (m[i].clas     ) & 0xff;

            // Write time to live to response
            response[end+6] = (TTL >> 24) & 0xff;
            response[end+7] = (TTL >> 16) & 0xff;
            response[end+8] = (TTL >> 8 ) & 0xff;
            response[end+9] = (TTL      ) & 0xff;

            end += 12;

            // Third token will be the real address...
            char *ip_string = strtok(NULL, " ");
            char *ip_component;
            uint16_t ip_num;

            if (m[i].type == A) {
                response[end-1] = 0x04;
                ip_component     = strtok(ip_string, ".");
                while (ip_component) {
                    sscanf(ip_component, "%hd", &ip_num);
                    response[end++] = ip_num & 0xff;
                    ip_component    = strtok(NULL, ".");
                }
            } else if (m[i].type == AAAA) {
                response[end-1] = 0x10;
                ip_component     = strtok(ip_string, ":");
                while (ip_component) {
                    sscanf(ip_component, "%hx", &ip_num);
                    response[end++] = (ip_num >> 8) & 0xff;
                    response[end++] = (ip_num     ) & 0xff;
                    ip_component    = strtok(NULL, ":");
                }
            }


            // Add to counting of answer
            memset(line, 0, 256);
            logging("[!] Found address! Write to response...\n", "");
            answer_count++;
        }

        // Closing file
        fclose(infofile);
    }

    // Write number of answer to response
    response[6] = (answer_count >> 8) & 0xff;
    response[7] = (answer_count     ) & 0xff;

    // Write number of bytes used to a buffer & return
    *response_len = end;
    return (answer_count != 0);

}

void setup_server() {

    // Create socket
    serverfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (serverfd < 0) {
        printf("[!] Cannot create socket!\n");
        exit(1);
    }

    // OS typically makes us wait for about 20s
    // after we kill a socket to be re-binded,
    // set this option so that we could re-bind
    // right away.
    setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR,
        &optval, sizeof(int));

    // Create address struct
    memset(&serveraddr, 0, sizeof(struct sockaddr_in));
    serveraddr.sin_family      = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port        = htons(port);

    // Bind address to socket
    if (bind(serverfd, (struct sockaddr*) &serveraddr,
        sizeof(struct sockaddr_in)) < 0) {
            printf("[!] Error on binding!\n");
            exit(1);
        }

}

void run_server() {
    while (1) {

        // Receiving data from socket...
        memset(request, 0, BUFSIZE);
        bytesRecv = recvfrom(serverfd, request, BUFSIZE, 0,
            (struct sockaddr*)&clientaddr, &clientlen
        );
        if (bytesRecv < 0) {
            printf("[!] Error receiving...\n");
            continue;
        }

        // Display the address...
        hostaddrp = inet_ntoa(clientaddr.sin_addr);
        if (!hostaddrp) printf("[!] Error on inet_ntoa()...\n");
        else            printf("[!] Receiving request from [ %s ]!\n", hostaddrp);


        // Construct the DNS response to user...
        int response_len = 0;
        if (construct_response(&response_len)) {
            // If succeed, send to user
            sendto(serverfd, response, response_len, MSG_CONFIRM, (struct sockaddr*) &clientaddr, clientlen);
        }
    }
}

int main() {
    setup_server();
    run_server();
}
