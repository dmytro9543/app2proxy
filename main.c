#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <sys/statvfs.h>
#include <stdbool.h>
#include <sys/inotify.h>
#include <regex.h>

#include "mongoose.h"

#define BNG_EXPORT_PID_FILE "/var/run/app2proxy.pid"

#define DUMP_REALLOC_SIZE 1024
#define MAX_OUTPUT_LENGTH 1024
#define MAX_PROXY_LEN 256
#define MAX_RESPONSE_LEN 1024
#define CURL_TIMEOUT 2
#define MAX_IP_LENGTH 16  // "xxx.xxx.xxx.xxx" + null terminator

int main_pid = 0;
int no_fork = 0;
char *pid_file = BNG_EXPORT_PID_FILE;

enum {
  None,
  PPPoE,
  IPoE,
  RADIUS
};

typedef void (*sighandler_t) (int);

char* test_proxy(const char* proxy, const char* tipo);
char* test_all_proxies(const char* proxy);
bool is_ipv4(const char* ip);
bool is_ipv6(const char* ip);
void handle_test_proxies(struct mg_connection *c, struct mg_http_message *hm);

static void sig_usr_un(int signo)
{
  if (signo == SIGCHLD || signo == SIGPIPE) {
    return;
  }

  printf("bng_prometheus_export: Signal %d received.\n", signo);
    
  if (!main_pid || (main_pid == getpid())) {
    if (pid_file) unlink(pid_file);
    printf("bng_prometheus_export: Finished.\n");
    exit(0);
  }

  return;
}

int set_sighandler(sighandler_t sig_usr)
{
  if (signal(SIGINT, sig_usr) == SIG_ERR ) {
    printf("No SIGINT signal handler can be installed.\n");
    return -1;
  }
    
  if (signal(SIGPIPE, sig_usr) == SIG_ERR ) {
    printf("No SIGPIPE signal handler can be installed.\n");
    return -1;
  }

  if (signal(SIGCHLD , sig_usr)  == SIG_ERR ) {
    printf("No SIGCHLD signal handler can be installed.\n");
    return -1;
  }

  if (signal(SIGTERM , sig_usr)  == SIG_ERR ) {
    printf("No SIGTERM signal handler can be installed.\n");
    return -1;
  }

  if (signal(SIGHUP , sig_usr)  == SIG_ERR ) {
    printf("No SIGHUP signal handler can be installed.\n");
    return -1;
  }

  return 0;
}

static void run_command(char *command) {
  // Open a pipe to run the command
  FILE *fp = popen(command, "r");
  if (fp == NULL) {
      perror("Error opening pipe");
      return;
  }

  // Read the output from the command
  char buffer[128];
  while (fgets(buffer, sizeof(buffer), fp) != NULL) {
      printf("%s", buffer); // Print each line of output
  }

  // Close the pipe
  if (pclose(fp) == -1) {
      perror("Error closing pipe");
      return;
  }

  printf("%s\nScript executed successfully.\n", command);

}

static char* convert_to_valid_json(const char* input) {
    // Allocate memory for JSON output
    char* json_output = (char*)malloc(MAX_OUTPUT_LENGTH);
    if (!json_output) return NULL;
    
    // Start JSON object
    strcpy(json_output, "{\"data\":\"");
    
    // Pointer to track position in output
    char* out_ptr = json_output + strlen(json_output);
    
    // Process each character in input
    for (; *input && (out_ptr - json_output) < MAX_OUTPUT_LENGTH - 2; input++) {
        switch (*input) {
            case '"':  // Escape double quotes
                *out_ptr++ = '\\';
                *out_ptr++ = '"';
                break;
            case '\\': // Escape backslashes
                *out_ptr++ = '\\';
                *out_ptr++ = '\\';
                break;
            case '\n': // Escape newlines
                *out_ptr++ = '\\';
                *out_ptr++ = 'n';
                break;
            case '\r': // Escape carriage returns
                *out_ptr++ = '\\';
                *out_ptr++ = 'r';
                break;
            case '\t': // Escape tabs
                *out_ptr++ = '\\';
                *out_ptr++ = 't';
                break;
/*            case '.':  // Add leading zero to decimal numbers
                if (isdigit(*(input-1)) {
                    *out_ptr++ = '.';
                } else {
                    *out_ptr++ = '0';
                    *out_ptr++ = '.';
                }
                break;*/
            default:
                *out_ptr++ = *input;
                break;
        }
    }
    
    // Close JSON object
    *out_ptr++ = '"';
    *out_ptr++ = '}';
    *out_ptr = '\0';
    
    return json_output;
}

char* test_proxy(const char* proxy, const char* tipo) {
    char command[512];
    char *output = malloc(MAX_RESPONSE_LEN);
    if (!output) return NULL;
    
    output[0] = '\0';
    
    // Parse proxy components (host:port:user:pass)
    char *proxy_copy = strdup(proxy);
    char *host = strtok(proxy_copy, ":");
    char *port = strtok(NULL, ":");
    char *user = strtok(NULL, ":");
    char *pass = strtok(NULL, ":");
    
    if (!host || !port || !user || !pass) {
        free(proxy_copy);
        free(output);
        return NULL;
    }
    
    // Build curl command based on proxy type
    if (strcmp(tipo, "http-ipv6") == 0) {
        snprintf(command, sizeof(command), 
                 "curl -x http://%s:%s@%s:%s http://ifconfig.co --max-time %d 2>/dev/null",
                 user, pass, host, port, CURL_TIMEOUT);
    } else if (strcmp(tipo, "socks5-ipv6") == 0 || strcmp(tipo, "socks5-ipv4") == 0) {
        snprintf(command, sizeof(command), 
                 "curl -x socks5h://%s:%s@%s:%s http://ifconfig.co --max-time %d 2>/dev/null",
                 user, pass, host, port, CURL_TIMEOUT);
    } else {
        free(proxy_copy);
        free(output);
        return NULL;
    }
    
    // Execute command
    FILE *fp = popen(command, "r");
    if (fp) {
        if (fgets(output, MAX_RESPONSE_LEN, fp) != NULL) {
            // Remove trailing newline
            output[strcspn(output, "\n")] = 0;
        }
        pclose(fp);
    }
    
    free(proxy_copy);
    
    // Check if the response is valid (not empty and not authentication error)
    if (strlen(output) == 0 || strstr(output, "407 Proxy Authentication Required") != NULL) {
        free(output);
        return NULL;
    }
    
    return output;
}

// Test all proxy types for the "any" case
char* test_all_proxies(const char* proxy) {
    const char* types[] = {"http-ipv6", "socks5-ipv4", "socks5-ipv6"};
    char *result = NULL;
    
    for (int i = 0; i < 3; i++) {
        char *ip_result = test_proxy(proxy, types[i]);
        if (ip_result) {
            // Determine protocol based on IP type and test type
            const char *protocol;
            if (strcmp(types[i], "http-ipv6") == 0) {
                protocol = "http-ipv6";
            } else if (is_ipv4(ip_result)) {
                protocol = "socks5-ipv4";
            } else if (is_ipv6(ip_result)) {
                protocol = "socks5-ipv6";
            } else {
                protocol = "unknown";
            }
            
            // Format result string
            result = malloc(strlen(ip_result) + strlen(protocol) + 4);
            if (result) {
                sprintf(result, "%s (%s)", ip_result, protocol);
            }
            
            free(ip_result);
            break;
        }
    }
    
    return result;
}

// Check if string is IPv4 address
bool is_ipv4(const char* ip) {
    regex_t regex;
    int ret;
    
    ret = regcomp(&regex, "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$", REG_EXTENDED);
    if (ret) return false;
    
    ret = regexec(&regex, ip, 0, NULL, 0);
    regfree(&regex);
    
    return ret == 0;
}

// Check if string is IPv6 address (simple check)
bool is_ipv6(const char* ip) {
    return strchr(ip, ':') != NULL;
}

// Handle the /test-proxies endpoint
void handle_test_proxies(struct mg_connection *c, struct mg_http_message *hm) {
    // Parse JSON body manually (simple approach)
    char *body = strndup(hm->body.ptr, hm->body.len);
    char *proxies_start = strstr(body, "\"proxies\":");
    char *type_start = strstr(body, "\"type\":");
    
    if (!proxies_start || !type_start) {
        mg_http_reply(c, 400, "", "{\"error\":\"Invalid input\"}");
        free(body);
        return;
    }
    
    // Extract type
    char *type_value = strtok(type_start + 7, "\",}");
    char type[20];
    if (type_value) {
        strncpy(type, type_value, sizeof(type) - 1);
        type[sizeof(type) - 1] = '\0';
    } else {
        mg_http_reply(c, 400, "", "{\"error\":\"Invalid type\"}");
        free(body);
        return;
    }
    
    // Check if type is valid
    if (strcmp(type, "http-ipv6") != 0 && 
        strcmp(type, "socks5-ipv6") != 0 && 
        strcmp(type, "socks5-ipv4") != 0 && 
        strcmp(type, "any") != 0) {
        mg_http_reply(c, 400, "", "{\"error\":\"Invalid proxy type\"}");
        free(body);
        return;
    }
    
    // Extract proxies array
    char *response = malloc(4096);
    if (!response) {
        mg_http_reply(c, 500, "", "{\"error\":\"Memory allocation failed\"}");
        free(body);
        return;
    }
    
    strcpy(response, "{");
    
    char *proxy_start = strstr(proxies_start, "[");
    if (proxy_start) {
        char *token = strtok(proxy_start + 1, "\",]");
        while (token) {
            if (strlen(token) > 3) { // Minimum valid proxy length
                char *result;
                
                if (strcmp(type, "any") == 0) {
                    result = test_all_proxies(token);
                } else {
                    char *ip_result = test_proxy(token, type);
                    if (ip_result) {
                        // Determine protocol based on IP type
                        const char *protocol;
                        if (strcmp(type, "http-ipv6") == 0) {
                            protocol = "http-ipv6";
                        } else if (is_ipv4(ip_result)) {
                            protocol = "socks5-ipv4";
                        } else if (is_ipv6(ip_result)) {
                            protocol = "socks5-ipv6";
                        } else {
                            protocol = "unknown";
                        }
                        
                        result = malloc(strlen(ip_result) + strlen(protocol) + 4);
                        if (result) {
                            sprintf(result, "%s (%s)", ip_result, protocol);
                        }
                        free(ip_result);
                    } else {
                        result = NULL;
                    }
                }
                
                // Add to response
                if (strlen(response) > 1) strcat(response, ",");
                strcat(response, "\"");
                strcat(response, token);
                strcat(response, "\":");
                
                if (result) {
                    strcat(response, "\"");
                    strcat(response, result);
                    strcat(response, "\"");
                    free(result);
                } else {
                    strcat(response, "\"offline\"");
                }
            }
            
            token = strtok(NULL, "\",]");
        }
    }
    
    strcat(response, "}");
    
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", response);
    
    free(response);
    free(body);
}

static void get_traffic(char **dump_out, char *sid)
{
  unsigned int                            i = 0;
  unsigned int                            num_elements = 0;
  unsigned int                            proto_index = 0;

  if(!dump_out) return;

  // Initialize dump_out to an empty string
  *dump_out = malloc(DUMP_REALLOC_SIZE);
  if (*dump_out == NULL) return; // Check for malloc failure
  (*dump_out)[0] = '\0'; // Start with an empty string

  size_t total_length = 0, dump_out_size = DUMP_REALLOC_SIZE;

  char command[256];
  snprintf(command, sizeof(command), "bng-cmd show traffic sid=%s", sid);
  // Open a pipe to run the command
  FILE *fp = popen(command, "r");
  if (fp == NULL) {
      perror("Error opening pipe");
      return;
  }

  // Read the output from the command
  char buffer[128], *ptr;
  int category = None;
  
  while (fgets(buffer, sizeof(buffer), fp) != NULL) {
    if(strlen(buffer)) {
      // Append the new item to dump_out
      strcat(*dump_out, buffer);
      break;
    }
  }

  // Close the pipe
  if (pclose(fp) == -1) {
      perror("Error closing pipe");
      return;
  }

}

static void get_ping(char **dump_out, char *clientip, int count)
{
  unsigned int                            i = 0;
  unsigned int                            num_elements = 0;
  unsigned int                            proto_index = 0;

  if(!dump_out) return;

  // Initialize dump_out to an empty string
  *dump_out = malloc(DUMP_REALLOC_SIZE);
  if (*dump_out == NULL) return; // Check for malloc failure
  (*dump_out)[0] = '\0'; // Start with an empty string

  size_t total_length = 0, dump_out_size = DUMP_REALLOC_SIZE;

  char command[256];
  snprintf(command, sizeof(command), "vppctl ping %s source WanEthernet1/0/0 repeat %d", clientip, count);
  // Open a pipe to run the command
  FILE *fp = popen(command, "r");
  if (fp == NULL) {
      perror("Error opening pipe");
      return;
  }

  // Read the output from the command
  char buffer[128], *ptr;
  int category = None;
  
  while (fgets(buffer, sizeof(buffer), fp) != NULL) {
    if(strlen(buffer)) {
      // Append the new item to dump_out
      strcat(*dump_out, buffer);
    }
  }

  // Close the pipe
  if (pclose(fp) == -1) {
      perror("Error closing pipe");
      return;
  }

}

static void printMg(struct mg_str *mgstr) {
  for(int i=0; i<mgstr->len; i++)
    printf("%c", mgstr->buf[i]);
  printf("\n--------------\n");
}

// HTTP server event handler function
static void api_ev_handler(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    printf("method: "); printMg(&hm->method);
    printf("uir: "); printMg(&hm->uri);
    printf("query: "); printMg(&hm->query);
    printf("proto: "); printMg(&hm->proto);
    printf("headers.name: "); printMg(&hm->headers[0].name);
    printf("headers.value: "); printMg(&hm->headers[0].value);
    printf("body: "); printMg(&hm->body);
    printf("head: "); printMg(&hm->head);
    printf("message: "); printMg(&hm->message);

    if ( mg_match(hm->method, mg_str("GET"), NULL) ) {
      if( mg_match(hm->uri, mg_str("/traffic"), NULL) ) {
        char sid[128];
        if(hm->query.len && !strncmp(hm->query.buf, "sid=", 4)) {
          int sid_len = hm->query.len - 4;
          strncpy(sid, hm->query.buf + 4, sid_len);
          sid[ sid_len ] = '\0';
          
          char *reply = NULL;
          get_traffic(&reply, sid);

          // Create buffers for the JSON output
          char json[100] = "{";
          char temp[20];

          // Find 'tx' value
          char *tx_start = strstr(reply, "tx:");
          if (tx_start) {
              tx_start += 3; // Move past "tx:"
              char *tx_end = strchr(tx_start, ',');
              if (!tx_end) tx_end = strchr(tx_start, '}');
              if (tx_end) {
                  int tx_len = tx_end - tx_start;
                  strncat(json, "\"tx\":", 5);
                  strncat(json, tx_start, tx_len);
              }
          }

          // Find 'rx' value
          char *rx_start = strstr(reply, "rx:");
          if (rx_start) {
              rx_start += 3; // Move past "rx:"
              char *rx_end = strchr(rx_start, '}');
              if (rx_end) {
                  int rx_len = rx_end - rx_start;
                  if (strlen(json) > 1) strcat(json, ",");
                  strcat(json, "\"rx\":");
                  strncat(json, rx_start, rx_len);
              }
          }

          strcat(json, "}");

          mg_http_reply(c, 200, "", "%s\n", json);
          if(reply)
            free(reply);
        }
        else {
          mg_http_reply(c, 500, "", "{\"%m\":\"%m\"}\n", MG_ESC("error"), MG_ESC("Syntax Error")); 
        }
      }
      else if( mg_match(hm->uri, mg_str("/ping"), NULL) ) {
        char query[256], clientip[MAX_IP_LENGTH];
        int count;
        if(hm->query.len) {
          int qlen = hm->query.len;
          strncpy(query, hm->query.buf, qlen);
          query[ qlen ] = '\0';
          
          char *reply = NULL, *json_output = NULL;
          parse_query(query, clientip, &count);
          if(strlen(clientip)) {
              if(count > 10) count = 10;
              get_ping(&reply, clientip, count);
              json_output = convert_to_valid_json(reply);
              mg_http_reply(c, 200, "", "%s\n", json_output);
              free(json_output);
              if(reply)
                free(reply);
          } else {
            mg_http_reply(c, 500, "", "{\"%m\":\"%m\"}\n", MG_ESC("error"), MG_ESC("Missed IP")); 
          }
        } else {
          mg_http_reply(c, 500, "", "{\"%m\":\"%m\"}\n", MG_ESC("error"), MG_ESC("Syntax Error")); 
        }
      }
      else {
        goto send_errmsg;
      }
      return;
    }
    else if ( mg_match(hm->method, mg_str("POST"), NULL) ) {
      if (mg_match(hm->uri, mg_str("/test-proxies"), NULL)) {
        handle_test_proxies(c, hm);
        return;
      }
      else if( mg_match(hm->uri, mg_str("/delvlan"), NULL) ) {
        char vlans[128];
        if(!strncmp(hm->body.buf, "vlans=", 6)) {
          int len = hm->body.len - 6;
          strncpy(vlans, hm->body.buf + 6, len);
          vlans[ len ] = '\0';

          del_vlan(vlans);

          mg_http_reply(c, 200, "", "{\"result\":\"%m\"}\n", MG_ESC("success")); 
        } else {
          mg_http_reply(c, 500, "", "{\"%m\":\"%m\"}\n", MG_ESC("error"), MG_ESC("Syntax Error")); 
        }
      }
      else {
        goto send_errmsg;
      }
      return;
    }
send_errmsg:
    mg_http_reply(c, 500, "", "{\"%m\":\"%m\"}\n", MG_ESC("error"), MG_ESC("Unsupported URI")); 
  }
  
}

void* api_thread_function(void* arg)
{
    struct mg_mgr mgr;  // Declare event manager
    mg_mgr_init(&mgr);  // Initialise event manager
    mg_http_listen(&mgr, "http://0.0.0.0:80", api_ev_handler, NULL);  // Setup listener
    for (;;) {          // Run an infinite event loop
        mg_mgr_poll(&mgr, 1000);
    }

    return NULL;
}

int main(int argc, char* argv[])
{
  int sockfd, portno;
  struct hostent* server;
  struct sockaddr_in serv_addr;
  char buffer[256];
  DIR *dir;
  char path[256];
  int pid;
	FILE *pid_stream;
  int firstrun = 1;
  pthread_t thread_id, cpu_thread, mem_thread;

  if(argc < 1) {
    fprintf(stderr, "Usage: %s\n", argv[0]);
    return 1;
  }

  if(argc == 2 && !strcmp(argv[1], "nofork")) {
      // nothing to do
  } else {
    if ((pid=fork())<0){
      printf("Cannot fork: %s.\n", strerror(errno));
      return -1;
    }else if (pid!=0){
      /* parent process => exit*/
      return 0;
    }
  }

  main_pid = getpid();

  if(set_sighandler(sig_usr_un))
  	return -1;

  /*int rc = pthread_create(&thread_id, NULL, api_thread_function, NULL);
  if (rc != 0) {
      fprintf(stderr, "Error creating thread: %d\n", rc);
      return EXIT_FAILURE;
  }*/

  /*rc = pthread_create(&mem_thread, NULL, mem_usage_thread, NULL);
  if (rc != 0) {
      fprintf(stderr, "Error creating thread: %d\n", rc);
      return EXIT_FAILURE;
  }*/
 
 
  struct mg_mgr mgr;  // Declare event manager
  mg_mgr_init(&mgr);  // Initialise event manager
  mg_http_listen(&mgr, "http://0.0.0.0:8080", api_ev_handler, NULL);  // Setup listener
  for (;;) {          // Run an infinite event loop
    mg_mgr_poll(&mgr, 1000);
  }

  printf("Main thread: Waiting for new thread to finish...\n");

  // Wait for the thread to complete
  /*rc = pthread_join(thread_id, NULL);
  if (rc != 0) {
      fprintf(stderr, "Error joining thread: %d\n", rc);
  }
  
  rc = pthread_join(cpu_thread, NULL);
  if (rc != 0) {
      fprintf(stderr, "Error joining thread: %d\n", rc);
  }*/
  
  /*rc = pthread_join(mem_thread, NULL);
  if (rc != 0) {
      fprintf(stderr, "Error joining thread: %d\n", rc);
  }*/

  return 0;
}

