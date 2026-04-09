#include <cjson/cJSON.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <dirent.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "createHash.h"

#define BUFFER_SIZE 4096
#define MAX_CHUNK 512000

/******************************************************************/
/* this function actually does the sending of the data            */
/******************************************************************/
int sendStuff(char *buffer, int sd, struct sockaddr_in server_address){

  int rc = 0;
  rc = sendto(sd, buffer, strlen(buffer), 0,
	      (struct sockaddr *) &server_address, sizeof(server_address));

  return rc; 
}

/******************************************************************/
/* this function will create a socket and fill in the address of  */
/*  the server                                                    */
/******************************************************************/
void makeSocket(int *sd, char *argv[], struct sockaddr_in *server_address){
  int i; // loop variable
  struct sockaddr_in inaddr; // use this as a temp value for checking validity
  int portNumber; // get this from command line
  char serverIP[50]; // overkill on size
  
  /* this code checks to see if the ip address is a valid ip address */
  /* meaning it is in dotted notation and has valid numbers          */
  if (!inet_pton(AF_INET, argv[1], &inaddr)){
    printf ("error, bad ip address\n");
    exit (1); /* just leave if is incorrect */
  }
  
  /* first create a socket */
  *sd = socket(AF_INET, SOCK_DGRAM, 0); /* create a socket */
  int reuse =1;
  setsockopt(*sd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));


  /* always check for errors */
  if (*sd == -1){ /* means some kind of error occured */
    perror ("socket");
    exit(1); /* just leave if wrong number entered */
  }

 /* check that the port number is a number..... */

  for (i=0;i<strlen(argv[2]); i++){
    if (!isdigit(argv[2][i]))
      {
	printf ("The Portnumber isn't a number!\n");
	exit(1);
      }
  }

  portNumber = strtol(argv[2], NULL, 10); /* many ways to do this */
  /* exit if a bad port number is entered */
  if ((portNumber > 65535) || (portNumber < 0)){
    printf ("you entered an invalid socket number\n");
    exit (1);
  }
  /* now fill in the address data structure we use to sendto the server */  
  strcpy(serverIP, argv[1]); /* copy the ip address */

  server_address->sin_family = AF_INET; /* use AF_INET addresses */
  server_address->sin_port = htons(portNumber); /* convert port number */
  server_address->sin_addr.s_addr = inet_addr(serverIP); /* convert IP addr */

}

/******************************************************************/
/* this function breaks the parameter file into 512KB chunks,     */
/* hashes each chunk with SHA256, adds the chunks to CHUNKS, and  */
/* creates a cJSON object for each file with its chunk data       */
/******************************************************************/
cJSON *chunkFile(char *fileName, char *filePath, char *chunks){
    FILE *fptr = NULL;
    unsigned char *buf = NULL;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned char hex[(2*EVP_MAX_MD_SIZE) + 1];
    unsigned char fullFileHash[(2*EVP_MAX_MD_SIZE) + 1];
    unsigned int hashLength = 0;
    int bytes = 0;
    char chunkPath[BUFFER_SIZE];
    char temp[BUFFER_SIZE];
    cJSON *jsonFile = cJSON_CreateObject();
    cJSON *chunkArr = cJSON_CreateArray();
    int numChunks = 0;
    int i = 0;

    cJSON_AddStringToObject(jsonFile, "filename", fileName);

    /* open the file for reading in binary mode */
    fptr = fopen(filePath, "rb");
    if (fptr == NULL){
      perror ("fopen");
      exit (1);
    }

    buf = malloc(MAX_CHUNK);
    if (buf == NULL){
        fclose(fptr);
        return NULL;
    }

    /* move to the end of the file and rewind */
    fseek(fptr, 0, SEEK_END);
    int fileSize = ftell(fptr);
    rewind(fptr); 

    /* create the SHA256 hash */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    while ((i = fread(temp, 1, sizeof(temp), fptr)) > 0){
        EVP_DigestUpdate(mdctx, temp, i);
    }
    EVP_DigestFinal_ex(mdctx, hash, &hashLength);
    EVP_MD_CTX_free(mdctx);

    /* convert the hash butes to hexadecimal string */
    for (int i = 0; i < hashLength; i++){
            sprintf((char *)hex + (i*2), "%02x", hash[i]);
        }
        hex[hashLength*2] = '\0';
        strcpy((char *)fullFileHash, (char *)hex);
        cJSON_AddNumberToObject(jsonFile, "fileSize", fileSize);
        rewind(fptr);
    
    /* read the file in 512KB chunks then add each chunk to CHUNKS directory and chunk hash to cJSON array */
    while ((bytes = fread(buf, 1, MAX_CHUNK, fptr)) > 0){
        if (!sha256(buf, bytes, hash, &hashLength)){
            perror("SHA256 chunk error\n");
            break;
        }

        /* convert chunk hash bytes to hexadecimal string */
        for (int i = 0; i < hashLength; i++){
            sprintf((char *)hex + (i*2), "%02x", hash[i]);
        }
        hex[hashLength*2] = '\0';
        snprintf(chunkPath, sizeof(chunkPath), "%s/%s", chunks, hex);

        /* write each chunk to CHUNKS */
        FILE *chunkFPtr = fopen(chunkPath, "wb");
        if (chunkFPtr == NULL){
            perror ("fopen");
            exit (1);
        }
        else{
            fwrite(buf, 1, bytes, chunkFPtr);
            fclose(chunkFPtr);
        }
        cJSON *str = cJSON_CreateString((char*)hex);
        cJSON_AddItemToArray(chunkArr, str);
        numChunks++;
    }

    /* add chunk data cJSON data */
    cJSON_AddNumberToObject(jsonFile, "numberOfChunks", numChunks);
    cJSON_AddItemToObject(jsonFile, "chunk_hashes", chunkArr);
    cJSON_AddStringToObject(jsonFile, "fullFileHash", (char *)fullFileHash);
    free(buf);
    fclose(fptr);
    
    return jsonFile;
}

/******************************************************************/
/* the main function accepts the ip address, port number, and the */
/* directory as command line arguments, creates the CHUNKS        */
/* directory or overwrites it, uses chunkFile() to create chunks  */
/* for each file, then prints the JSON data                       */
/******************************************************************/
int main(int argc, char *argv[]){
    int sd;
    int rc;
    struct sockaddr_in server_address; 
    char *directory = NULL;
    char chunksDir[BUFFER_SIZE];
    char filePath[BUFFER_SIZE];
    struct stat statBuf = {0};
    struct dirent *dentry;

    /* check to see if the right number of parameters was entered */
    if (argc < 4){
        printf ("usage is client <ipaddr> <portnumber> <directory>\n");
        exit(1); /* just leave if wrong number entered */
    }
    directory = argv[3];

    /* call the function to make the socket and fill in server address */
    makeSocket(&sd, argv, &server_address);

    /* create CHUNKS path */
    snprintf(chunksDir, sizeof(chunksDir), "%s/CHUNKS", directory);

    /* open FILES directory and check to see if it exists */
    DIR *d = opendir(directory);
    if (d == NULL){
        perror("opendir error");
        exit (1);
    }

    /* create CHUNKS directory if it doesn't exist */
    if (stat(chunksDir, &statBuf) == -1){
        if (mkdir(chunksDir, 0755) != 0){
            perror("error creating CHUNKS directory");
            exit (1);
        }
    }

    /* iterate over each directory file, chunk the contents, and send JSON objects to the server */
    while((dentry = readdir(d)) != NULL){
        if (strcmp(dentry->d_name, ".") == 0 || strcmp(dentry->d_name, "..") == 0 || strcmp(dentry->d_name, "CHUNKS") == 0){
            continue;
        }

        snprintf(filePath, sizeof(filePath), "%s/%s", directory, dentry->d_name);

        cJSON *obj = chunkFile(dentry->d_name, filePath, chunksDir);
        char *pkt = cJSON_PrintUnformatted(obj); /* serialize the JSON object unformatted */
        printf("the string i am sending is %s\n", pkt);
        printf("length to send is %lu\n", strlen(pkt));
        rc = sendStuff(pkt, sd, server_address); /* send the JSON packet to the server */
        printf ("I think i sent %d bytes \n", rc);
        printf("%s\n", cJSON_Print(obj));
        free(pkt);
        cJSON_Delete(obj);
        
    }
    closedir(d);
    return 0;
}
