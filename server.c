#include <cjson/cJSON.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <dirent.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "createHash.h"
#include <stdbool.h>

#define BUFFER_SIZE 4096
#define MAX_CHUNK 512000
#define MAXPEERS 5

struct FileInfo {
    char filename[100];
    char fullFileHash[65]; // SHA-256 hash is 64 hex digits + null terminator
    char clientIP[MAXPEERS][INET_ADDRSTRLEN];
    int clientPort[MAXPEERS];
    int numberOfPeers;
    int numberOfChunks;
    struct FileInfo *next; // Pointer for linked list
};

/**********************************************************************/
/* this function creates a UDP socket with address reuse, binds the   */
/* socket to the input port, joins the input multicast group,         */
/* actively listens for UDP packets with JSON data, deserializes the  */
/* JSON data, then prints the formatted recevied JSON data.           */
/**********************************************************************/

void makeSocket(int *sd, char *argv[], struct sockaddr_in *server_addr, char *ipAddr, int portNumber, struct FileInfo **head){
    struct sockaddr_in from_addr; // from address
    socklen_t fromLength = sizeof(from_addr);
    int reuse = 1;
    int rc = 0;
    struct ip_mreq mreq; // multicast structure
    struct FileInfo *curr = NULL; // FileInfo struct for iterating
    struct FileInfo *currPrint = NULL; // FileInfo struct for iterating for printing
    struct FileInfo *node = NULL; // FileInfo struct for new hash nodes
    bool dup = false; // duplicate check

    memset(server_addr, 0, sizeof(*server_addr)); // empty the buffer
  
    *sd = socket(AF_INET, SOCK_DGRAM, 0); // create a UDP socket with SOCK_DGRAM
    if (*sd < 0){ // check for socket errors
        perror("socket creation error\n");
        exit(1);
    }

    // allow the same port to be used for multiple sockets
    rc = setsockopt(*sd, SOL_SOCKET, SO_REUSEPORT, (char *)&reuse, sizeof(reuse));
    if (rc < 0){ // check for reuse errors
        perror("setsockopt error");
        exit(1);
    }
    rc = setsockopt(*sd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));
    if (rc < 0){ // check for reuse errors
        perror("setsockopt error");
        exit(1);
    }

    server_addr->sin_family = AF_INET;
    server_addr->sin_port = htons(portNumber); // convert portNumber to network order 16 bit
    server_addr->sin_addr.s_addr = htonl(INADDR_ANY);

    rc = bind(*sd, (struct sockaddr *)server_addr, sizeof(*server_addr)); // bind the socket to the multicast address and port
    if (rc < 0){ // check for bind errors
        perror ("bind error");
        exit(1);
    }

    memset(&mreq, 0, sizeof(mreq)); // empty the buffer
    mreq.imr_multiaddr.s_addr = inet_addr(ipAddr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    // join multicast group
    if (setsockopt(*sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0){
        perror("setsockopt (IP_ADD_MEMBERSHIP)");
        close(*sd);
        exit (-1);
    }

    while (1){
        char buf[BUFFER_SIZE * 10];
        ssize_t bytes = recvfrom(*sd, buf, sizeof(buf) - 1, 0, (struct sockaddr *) &from_addr, &fromLength);
        const char* error;
        
        // skip if receive fails
        if (bytes < 0){
            perror("error receiving message");
            continue;
        }
        buf[bytes] = '\0'; // make space for null terminator 
        // printf("Received data: %s\n", buf);

        cJSON* json = cJSON_Parse(buf); // deserialize the JSON string into cJSON object
        if (json == NULL){ // check for parsing errors
            error = cJSON_GetErrorPtr();
            if (error != NULL){
                printf("JSON parsing error at %s\n", error);
            } 
            continue;
        } 

        // extract the files array
        cJSON *files = cJSON_GetObjectItemCaseSensitive(json, "files");
        cJSON *arr = NULL;
        if(cJSON_IsArray(files)){
            arr = files;
        }
        else if(cJSON_IsArray(json)){
            arr = json;
        }

        // extract the client IP and port number
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from_addr.sin_addr, clientIP, INET_ADDRSTRLEN);
        int clientPortNumber = ntohs(from_addr.sin_port); // check for duplicate port numbers

        // handles multiple file arrays
        if(arr != NULL){
            cJSON *jsonFile = NULL;
            cJSON_ArrayForEach(jsonFile, arr){
                // extract each field from the cJSON object
                cJSON *filename = cJSON_GetObjectItemCaseSensitive(jsonFile, "filename");
                cJSON *fileSize = cJSON_GetObjectItemCaseSensitive(jsonFile, "fileSize");
                cJSON *numberOfChunks = cJSON_GetObjectItemCaseSensitive(jsonFile, "numberOfChunks");
                cJSON *chunk_hashes = cJSON_GetObjectItemCaseSensitive(jsonFile, "chunk_hashes");
                cJSON *fullFileHash = cJSON_GetObjectItemCaseSensitive(jsonFile, "fullFileHash");

                if (!cJSON_IsString(filename) || !cJSON_IsNumber(fileSize) || !cJSON_IsNumber(numberOfChunks) || !cJSON_IsArray(chunk_hashes) || !cJSON_IsString(fullFileHash)){
                    continue;
                }

                dup = false;
                curr = *head;
                while(curr != NULL){
                    if (strcmp(curr->fullFileHash, fullFileHash->valuestring) == 0){
                        for(int i = 0; i < curr->numberOfPeers; i++){
                            if(strcmp(curr->clientIP[i], clientIP) == 0 && curr->clientPort[i] == clientPortNumber){
                                dup = true; // set duplicate to true if the ip and port number combo aren't unique
                                break;
                            }
                        }
                        // create a new entry if the file registration is unique
                        if(!dup && curr->numberOfPeers < MAXPEERS){
                            strcpy(curr->clientIP[curr->numberOfPeers], clientIP);
                            curr->clientPort[curr->numberOfPeers] = clientPortNumber;
                            curr->numberOfPeers++;
                        }
                        break;
                    }
                    curr = curr->next; // iterate to the next node
                }

                // create a new FileInfo node for new hashes
                if(curr == NULL){
                    node = malloc(sizeof(struct FileInfo));
                    if(!node){
                        perror ("FileInfo memory allocation error");
                        exit(1);
                    }
                    strcpy(node->filename, filename->valuestring);
                    strcpy(node->fullFileHash, fullFileHash->valuestring);
                    node->numberOfChunks = numberOfChunks->valueint;
                    strcpy(node->clientIP[0], clientIP);
                    node->clientPort[0] = clientPortNumber;
                    node->numberOfPeers = 1;
                    node->next = *head;
                    *head = node;
                }
            }
        }
        // handles single json objects
        else{
            // extract each field from the cJSON object
            cJSON *filename = cJSON_GetObjectItemCaseSensitive(json, "filename");
            cJSON *fileSize = cJSON_GetObjectItemCaseSensitive(json, "fileSize");
            cJSON *numberOfChunks = cJSON_GetObjectItemCaseSensitive(json, "numberOfChunks");
            cJSON *chunk_hashes = cJSON_GetObjectItemCaseSensitive(json, "chunk_hashes");
            cJSON *fullFileHash = cJSON_GetObjectItemCaseSensitive(json, "fullFileHash");

            if (!cJSON_IsString(filename) || !cJSON_IsNumber(fileSize) || !cJSON_IsNumber(numberOfChunks) || !cJSON_IsArray(chunk_hashes) || !cJSON_IsString(fullFileHash)){
                printf("error in JSON file received\n"); // check for data type errors
                cJSON_Delete(json);
                continue;
            }

            dup = false;
            curr = *head;
            while(curr != NULL){
                if (strcmp(curr->fullFileHash, fullFileHash->valuestring) == 0){
                    for(int i = 0; i < curr->numberOfPeers; i++){
                        if(strcmp(curr->clientIP[i], clientIP) == 0 && curr->clientPort[i] == clientPortNumber){
                            dup = true; // set duplicate to true if the ip and port number combo aren't unique
                            break;
                        }
                    }
                    // create a new entry if the file registration is unique
                    if(!dup && curr->numberOfPeers < MAXPEERS){
                        strcpy(curr->clientIP[curr->numberOfPeers], clientIP);
                        curr->clientPort[curr->numberOfPeers] = clientPortNumber;
                        curr->numberOfPeers++;
                    }
                    break;
                }
                curr = curr->next; // iterate to the next node
            }

            // create a new FileInfo node for new hashes
            if(curr == NULL){
                node = malloc(sizeof(struct FileInfo));
                if(!node){
                    perror ("FileInfo memory allocation error");
                    exit(1);
                }
                strcpy(node->filename, filename->valuestring);
                strcpy(node->fullFileHash, fullFileHash->valuestring);
                node->numberOfChunks = numberOfChunks->valueint;
                strcpy(node->clientIP[0], clientIP);
                node->clientPort[0] = clientPortNumber;
                node->numberOfPeers = 1;
                node->next = *head;
                *head = node;
            }
        }

        // print the stored file information
        printf("\033[H\033[J");
        printf("Stored File Information:\n");
        currPrint = *head;
        while(currPrint != NULL){
            printf("Filename: %s\n", currPrint->filename);
            printf("        Full Hash: %s\n", currPrint->fullFileHash);
            printf("        Number of Chunks: %d\n", currPrint->numberOfChunks);
            for(int i = 0; i < currPrint->numberOfPeers; i++){
                printf("        Client IP: %s, Client Port: %d\n", currPrint->clientIP[i], currPrint->clientPort[i]);
            }
            currPrint = currPrint->next;
        }

        // convert the raw JSON into a formatted output
        // printf("Received JSON data (Formatted):\n");
        // char *jsonPrint = cJSON_Print(json);
        // printf("%s\n", jsonPrint);
        // free(jsonPrint);
        printf("\n");
        cJSON_Delete(json); // free the memory of the cJSON object
    }
}

/**********************************************************************/
/* the main function accepts the ip address and port number, then     */
/* with makeSocket() binds the UDP port, joins the multicast group    */
/* with the input ip address (224.0.0.1), receives the serialized     */
/* JSON lines, deserializes the lines, then prints the key-value JSON */
/* pairs                                                              */
/**********************************************************************/

int main(int argc, char *argv[]){
    int sd = 0; // socket descriptor 
    int portNumber = 0; 
    char *ipAddr = NULL;
    struct sockaddr_in server_addr; // addresses structure
    struct FileInfo *head = NULL;

    // check for two parameters 
    if (argc < 3){
    printf ("Usage is: server <ipaddr> <portNumber>\n");
    exit(1);
    }
    ipAddr = argv[1];
    portNumber = atoi(argv[2]);

    // create the server socket 
    makeSocket(&sd, argv, &server_addr, ipAddr, portNumber, &head);
    
    return 0;
}
