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
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <json-c/json.h>

#include "mongoose.h"

#define BNG_EXPORT_PID_FILE "/var/run/app2proxy.pid"

#define DUMP_REALLOC_SIZE 1024
#define MAX_OUTPUT_LENGTH 1024
#define MAX_PROXY_LEN 256
#define MAX_RESPONSE_LEN 1024
#define CURL_TIMEOUT 2
#define DEFAULT_COUNT 3
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
void generate_ipv6_addresses(int count, const char* interface);
static void handle_generate_ipv6(struct mg_connection *c, struct mg_http_message *hm);

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

static void parse_query(const char* query, char* ip, int* count) 
{
    // Initialize defaults
    *count = DEFAULT_COUNT;
    ip[0] = '\0';
    
    // Temporary variables
    char* token;
    char* rest = (char*)query;
    
    // Use strtok_r to safely tokenize the query string
    while ((token = strtok_r(rest, "&", &rest))) {
        if (strncmp(token, "ip=", 3) == 0) {
            // Found IP parameter
            strncpy(ip, token + 3, MAX_IP_LENGTH - 1);
            ip[MAX_IP_LENGTH - 1] = '\0';  // Ensure null-termination
            
            // Remove any trailing parameters from IP (in case of malformed input)
            char* param_end = strchr(ip, '&');
            if (param_end) *param_end = '\0';
        }
        else if (strncmp(token, "count=", 6) == 0) {
            // Found count parameter
            *count = atoi(token + 6);
            if (*count <= 0) *count = DEFAULT_COUNT;  // Validate count
        }
    }
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
    // Parse JSON body
    char *body_str = malloc(hm->body.len + 1);
    if (!body_str) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Memory allocation failed\"}");
        return;
    }
    
    memcpy(body_str, hm->body.buf, hm->body.len);
    body_str[hm->body.len] = '\0';
    
    // Parse JSON using json-c
    json_object *root = json_tokener_parse(body_str);
    free(body_str);
    
    if (!root) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Invalid JSON\"}");
        return;
    }
    
    // Extract type
    json_object *type_obj;
    if (!json_object_object_get_ex(root, "type", &type_obj) || 
        !json_object_is_type(type_obj, json_type_string)) {
        json_object_put(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Invalid or missing type\"}");
        return;
    }
    
    const char *type = json_object_get_string(type_obj);
    
    // Check if type is valid
    if (strcmp(type, "http-ipv6") != 0 && 
        strcmp(type, "socks5-ipv6") != 0 && 
        strcmp(type, "socks5-ipv4") != 0 && 
        strcmp(type, "any") != 0) {
        json_object_put(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Invalid proxy type\"}");
        return;
    }
    
    // Extract proxies array
    json_object *proxies_obj;
    if (!json_object_object_get_ex(root, "proxies", &proxies_obj) || 
        !json_object_is_type(proxies_obj, json_type_array)) {
        json_object_put(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Invalid or missing proxies array\"}");
        return;
    }
    
    // Create response object
    json_object *response_obj = json_object_new_object();
    
    // Process each proxy
    int array_len = json_object_array_length(proxies_obj);
    for (int i = 0; i < array_len; i++) {
        json_object *proxy_item = json_object_array_get_idx(proxies_obj, i);
        
        if (!json_object_is_type(proxy_item, json_type_string)) {
            continue; // Skip non-string items
        }
        
        const char *proxy = json_object_get_string(proxy_item);
        if (strlen(proxy) < 4) { // Minimum valid proxy length
            json_object_object_add(response_obj, proxy, json_object_new_string("invalid"));
            continue;
        }
        
        char *result = NULL;
        
        if (strcmp(type, "any") == 0) {
            result = test_all_proxies(proxy);
        } else {
            char *ip_result = test_proxy(proxy, type);
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
            }
        }
        
        if (result) {
            json_object_object_add(response_obj, proxy, json_object_new_string(result));
            free(result);
        } else {
            json_object_object_add(response_obj, proxy, json_object_new_string("offline"));
        }
    }
    
    // Generate response string
    const char *response_str = json_object_to_json_string(response_obj);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", response_str);
    
    // Cleanup
    json_object_put(response_obj);
    json_object_put(root);
}

void generate_ipv6_suffix(char *suffix) {
    const char *hex_chars = "0123456789abcdef";
    char segment[5];
    
    suffix[0] = '\0';
    
    for (int i = 0; i < 4; i++) {
        snprintf(segment, sizeof(segment), "%c%c%c%c",
                hex_chars[rand() % 16],
                hex_chars[rand() % 16],
                hex_chars[rand() % 16],
                hex_chars[rand() % 16]);
        
        if (i > 0) {
            strcat(suffix, ":");
        }
        strcat(suffix, segment);
    }
}

void generate_ipv6_addresses(int count, const char *interface) {
    FILE *fp;
    char command[256];
    char ip6_prefix[64] = "";
    char suffix[64];
    
    // Seed random number generator
    srand(time(NULL));
    
    // Determine IPv6 prefix
    // Method 1: Check local IPv6 addresses starting with 2 or 3
    snprintf(command, sizeof(command), "ip -6 addr 2>/dev/null | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | cut -f1-4 -d':' | head -1");
    
    fp = popen(command, "r");
    if (fp != NULL) {
        if (fgets(ip6_prefix, sizeof(ip6_prefix), fp) != NULL) {
            ip6_prefix[strcspn(ip6_prefix, "\n")] = '\0';
        }
        pclose(fp);
    }
    
    // Method 2: If no local IPv6 found, try to get public IPv6
    if (strlen(ip6_prefix) == 0) {
        fp = popen("curl -6 -s icanhazip.com 2>/dev/null | cut -f1-4 -d':'", "r");
        if (fp != NULL) {
            if (fgets(ip6_prefix, sizeof(ip6_prefix), fp) != NULL) {
                ip6_prefix[strcspn(ip6_prefix, "\n")] = '\0';
            }
            pclose(fp);
        }
    }
    
    // Fallback if both methods fail
    if (strlen(ip6_prefix) == 0) {
        strcpy(ip6_prefix, "2001:db8"); // Default fallback prefix
    }
    
    // Generate the ipnew.sh file
    fp = fopen("/root/ipnew.sh", "w");
    if (fp == NULL) {
        perror("Failed to create ipnew.sh");
        return;
    }
    
    fprintf(fp, "#!/bin/bash\n");
    
    for (int i = 0; i < count; i++) {
        generate_ipv6_suffix(suffix);
        fprintf(fp, "ip -6 addr add %s:%s/64 dev %s\n", ip6_prefix, suffix, interface);
    }
    
    fclose(fp);
    
    // Make the script executable
    chmod("ipnew.sh", 0755);
    
    printf("Generated %d IPv6 addresses for interface %s\n", count, interface);
    printf("Script saved as ipnew.sh\n");
}

// HTTP handler for the IPv6 generation endpoint
static void handle_generate_ipv6(struct mg_connection *c, struct mg_http_message *hm) {
    struct json_tokener *tokener = NULL;
    struct json_object *parsed_json = NULL;
    
    int count = 10;
    char interface[IFNAMSIZ] = "eth0";
    
    // Initialize JSON parser
    tokener = json_tokener_new();
    if (tokener == NULL) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                      "{\"status\":\"error\", \"message\":\"Failed to initialize JSON parser\"}\n");
        return;
    }
    
    // Parse JSON body
    parsed_json = json_tokener_parse_ex(tokener, hm->body.buf, hm->body.len);
    
    if (parsed_json == NULL) {
        json_tokener_free(tokener);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"status\":\"error\", \"message\":\"Invalid JSON format\"}\n");
        return;
    }
    
    // Extract values
    struct json_object *count_obj, *interface_obj;
    if (json_object_object_get_ex(parsed_json, "quantidade", &count_obj)) {
        if (json_object_is_type(count_obj, json_type_int)) {
            count = json_object_get_int(count_obj);
            if (count < 1) count = 1;
            if (count > 10000) count = 10000;
        }
    }
    
    if (json_object_object_get_ex(parsed_json, "network", &interface_obj)) {
        if (json_object_is_type(interface_obj, json_type_string)) {
            const char *interface_str = json_object_get_string(interface_obj);
            strncpy(interface, interface_str, IFNAMSIZ - 1);
            interface[IFNAMSIZ - 1] = '\0';
        }
    }
    
    // Clean up
    json_object_put(parsed_json);
    json_tokener_free(tokener);
    
    // Generate addresses
    generate_ipv6_addresses(count, interface);
    
    // Return response
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                  "{\"status\":\"success\", \"message\":\"Generated %d IPv6 addresses for interface %s\"}\n", 
                  count, interface);
}

static int ping_ipv6_with_result(const char *ipv6_address, char **error_message) {
    char command[256];
    snprintf(command, sizeof(command), "ping6 -c 1 -W 1 %s 2>&1", ipv6_address);
    
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        *error_message = strdup("Failed to execute ping command");
        return -1;
    }
    
    // Read the output
    char buffer[128];
    char *output = NULL;
    size_t output_size = 0;
    
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        size_t buffer_len = strlen(buffer);
        char *new_output = realloc(output, output_size + buffer_len + 1);
        if (!new_output) {
            free(output);
            pclose(fp);
            *error_message = strdup("Memory allocation failed");
            return -1;
        }
        output = new_output;
        memcpy(output + output_size, buffer, buffer_len);
        output_size += buffer_len;
        output[output_size] = '\0';
    }
    
    int status = pclose(fp);
    
    if (status != 0) {
        // Command failed, set error message
        if (output) {
            *error_message = output;
        } else {
            *error_message = strdup("Unknown error");
        }
        return status;
    } else {
        free(output);
        *error_message = NULL;
        return 0;
    }
}

// HTTP handler for IPv6 ping test
static void handle_ipv6_ping_test(struct mg_connection *c, struct mg_http_message *hm) {
    // Parse JSON body using json-c
    char *body_str = malloc(hm->body.len + 1);
    if (!body_str) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Memory allocation failed\"}");
        return;
    }
    
    memcpy(body_str, hm->body.buf, hm->body.len);
    body_str[hm->body.len] = '\0';
    
    json_object *root = json_tokener_parse(body_str);
    free(body_str);
    
    if (!root) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Invalid JSON\"}");
        return;
    }
    
    // Extract IPv6 addresses array
    json_object *ipv6_addresses_obj;
    if (!json_object_object_get_ex(root, "ipv6_addresses", &ipv6_addresses_obj) || 
        !json_object_is_type(ipv6_addresses_obj, json_type_array)) {
        json_object_put(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Invalid or missing ipv6_addresses array\"}");
        return;
    }
    
    // Check if array is empty
    if (json_object_array_length(ipv6_addresses_obj) == 0) {
        json_object_put(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"No IPv6 addresses provided\"}");
        return;
    }
    
    // Create response array
    json_object *response_array = json_object_new_array();
    
    // Process each IPv6 address
    int array_len = json_object_array_length(ipv6_addresses_obj);
    for (int i = 0; i < array_len; i++) {
        json_object *ipv6_item = json_object_array_get_idx(ipv6_addresses_obj, i);
        
        if (!json_object_is_type(ipv6_item, json_type_string)) {
            continue; // Skip non-string items
        }
        
        const char *ipv6_address = json_object_get_string(ipv6_item);
        
        // Create result object for this IP
        json_object *result_obj = json_object_new_object();
        json_object_object_add(result_obj, "ipv6", json_object_new_string(ipv6_address));
        
        // Ping the IPv6 address
        char *error_message = NULL;
        int status = ping_ipv6_with_result(ipv6_address, &error_message);
        
        if (status == 0) {
            json_object_object_add(result_obj, "status", json_object_new_string("OK"));
        } else {
            json_object_object_add(result_obj, "status", json_object_new_string("OFF"));
            if (error_message) {
                json_object_object_add(result_obj, "error", json_object_new_string(error_message));
                free(error_message);
            }
        }
        
        // Add to response array
        json_object_array_add(response_array, result_obj);
    }
    
    // Generate response string
    const char *response_str = json_object_to_json_string(response_array);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", response_str);
    
    // Cleanup
    json_object_put(response_array);
    json_object_put(root);
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

// Helper function to ping an IPv4 address and return the result
static int ping_ipv4_with_result(const char *ipv4_address, char **error_message) {
    char command[256];
    snprintf(command, sizeof(command), "ping -c 1 -W 1 %s 2>&1", ipv4_address);
    
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        *error_message = strdup("Failed to execute ping command");
        return -1;
    }
    
    // Read the output
    char buffer[128];
    char *output = NULL;
    size_t output_size = 0;
    
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        size_t buffer_len = strlen(buffer);
        char *new_output = realloc(output, output_size + buffer_len + 1);
        if (!new_output) {
            free(output);
            pclose(fp);
            *error_message = strdup("Memory allocation failed");
            return -1;
        }
        output = new_output;
        memcpy(output + output_size, buffer, buffer_len);
        output_size += buffer_len;
        output[output_size] = '\0';
    }
    
    int status = pclose(fp);
    
    if (status != 0) {
        // Command failed, set error message
        if (output) {
            *error_message = output;
        } else {
            *error_message = strdup("Unknown error");
        }
        return status;
    } else {
        free(output);
        *error_message = NULL;
        return 0;
    }
}

// Simple IPv4 validation function
static bool is_valid_ipv4(const char *ip) {
    int segments = 0;
    int digits = 0;
    int value = 0;
    
    for (int i = 0; ip[i] != '\0'; i++) {
        if (ip[i] == '.') {
            if (digits == 0 || value > 255) return false;
            segments++;
            digits = 0;
            value = 0;
        } else if (ip[i] >= '0' && ip[i] <= '9') {
            if (digits > 0 && value == 0) return false; // Leading zero
            value = value * 10 + (ip[i] - '0');
            digits++;
            if (digits > 3 || value > 255) return false;
        } else {
            return false; // Invalid character
        }
    }
    
    return (segments == 3 && digits > 0 && value <= 255);
}

// HTTP handler for IPv4 ping test
static void handle_ipv4_ping_test(struct mg_connection *c, struct mg_http_message *hm) {
    // Parse JSON body using json-c
    char *body_str = malloc(hm->body.len + 1);
    if (!body_str) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Memory allocation failed\"}");
        return;
    }
    
    memcpy(body_str, hm->body.buf, hm->body.len);
    body_str[hm->body.len] = '\0';
    
    json_object *root = json_tokener_parse(body_str);
    free(body_str);
    
    if (!root) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Invalid JSON\"}");
        return;
    }
    
    // Extract IPv4 addresses array
    json_object *ipv4_addresses_obj;
    if (!json_object_object_get_ex(root, "ipv4_addresses", &ipv4_addresses_obj) || 
        !json_object_is_type(ipv4_addresses_obj, json_type_array)) {
        json_object_put(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Invalid or missing ipv4_addresses array\"}");
        return;
    }
    
    // Check if array is empty
    if (json_object_array_length(ipv4_addresses_obj) == 0) {
        json_object_put(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"No IPv4 addresses provided\"}");
        return;
    }
    
    // Create response array
    json_object *response_array = json_object_new_array();
    
    // Process each IPv4 address
    int array_len = json_object_array_length(ipv4_addresses_obj);
    for (int i = 0; i < array_len; i++) {
        json_object *ipv4_item = json_object_array_get_idx(ipv4_addresses_obj, i);
        
        if (!json_object_is_type(ipv4_item, json_type_string)) {
            continue; // Skip non-string items
        }
        
        const char *ipv4_address = json_object_get_string(ipv4_item);
        
        // Create result object for this IP
        json_object *result_obj = json_object_new_object();
        json_object_object_add(result_obj, "ipv4", json_object_new_string(ipv4_address));
        
        // Validate IPv4 format before pinging
        if (!is_valid_ipv4(ipv4_address)) {
            json_object_object_add(result_obj, "status", json_object_new_string("INVALID"));
            json_object_object_add(result_obj, "error", json_object_new_string("Invalid IPv4 format"));
        } else {
            // Ping the IPv4 address
            char *error_message = NULL;
            int status = ping_ipv4_with_result(ipv4_address, &error_message);
            
            if (status == 0) {
                json_object_object_add(result_obj, "status", json_object_new_string("OK"));
            } else {
                json_object_object_add(result_obj, "status", json_object_new_string("OFF"));
                if (error_message) {
                    json_object_object_add(result_obj, "error", json_object_new_string(error_message));
                    free(error_message);
                }
            }
        }
        
        // Add to response array
        json_object_array_add(response_array, result_obj);
    }
    
    // Generate response string
    const char *response_str = json_object_to_json_string(response_array);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", response_str);
    
    // Cleanup
    json_object_put(response_array);
    json_object_put(root);
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
      else if (mg_match(hm->uri, mg_str("/generate-ipv6"), NULL)) {
        handle_generate_ipv6(c, hm);
        return;
      }
      else if (mg_match(hm->uri, mg_str("/ipv6-ping-test"), NULL)) {
        handle_ipv6_ping_test(c, hm);
        return;
      }
      if (mg_match(hm->uri, mg_str("/ipv4-ping-test"), NULL)) {
          handle_ipv4_ping_test(c, hm);
          return;
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
  mg_http_listen(&mgr, "http://0.0.0.0:8001", api_ev_handler, NULL);  // Setup listener
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

