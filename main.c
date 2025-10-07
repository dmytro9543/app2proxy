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
#define MAX_CONFIG_SIZE 655360  // Maximum config file size

#define CONFIG_PATH "/etc/3proxy/3proxy.cfg"

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
static void handle_generate_ipv6(struct mg_connection *c, struct mg_http_message *hm);
static void handle_delete_proxies(struct mg_connection *c, struct mg_http_message *hm);

static void sig_usr_un(int signo)
{
  if (signo == SIGCHLD || signo == SIGPIPE) {
    return;
  }

  printf("app2proxy: Signal %d received.\n", signo);
    
  if (!main_pid || (main_pid == getpid())) {
    if (pid_file) unlink(pid_file);
    printf("app2proxy: Finished.\n");
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

void generate_ipv6_addresses(int count, const char *interface, char **ipv6list) {
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
        char ipv6addr[132];
        snprintf(ipv6addr, sizeof(ipv6addr), "%s:%s", ip6_prefix, suffix);
        ipv6list[i] = strdup(ipv6addr);
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

    char *ipv6list[10000];
    
    // Generate addresses
    generate_ipv6_addresses(count, interface, ipv6list);

    // Create JSON response
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_string("success"));
    
    // Create message using snprintf
    char message[256];
    snprintf(message, sizeof(message), "Generated %d IPv6 addresses for interface %s", count, interface);
    json_object_object_add(response, "message", json_object_new_string(message));
    
    // Add IPv6 addresses array
    struct json_object *ip_array = json_object_new_array();
    for (int i = 0; i < count; i++) {
        json_object_array_add(ip_array, json_object_new_string(ipv6list[i]));
    }
    json_object_object_add(response, "addresses", ip_array);
    
    // Send response
    const char *json_str = json_object_to_json_string(response);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s\n", json_str);
    
    // Cleanup
    json_object_put(response);
    for (int i = 0; i < count; i++) {
        free(ipv6list[i]);
    }
    
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

// Debug function to check current IPv6 status
static void debug_ipv6_status(const char* ipv6_address) {
    printf("\n=== IPv6 DEBUG INFO for %s ===\n", ipv6_address);
    
    // Check if IP exists
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip -6 addr show | grep -A 5 -B 5 '%s'", ipv6_address);
    printf("Current IP status:\n");
    system(cmd);
    
    // Check routes
    printf("\nRoute information:\n");
    snprintf(cmd, sizeof(cmd), "ip -6 route get %s 2>/dev/null", ipv6_address);
    system(cmd);
    
    printf("=== END DEBUG INFO ===\n\n");
}

// Function to remove IPv6 address from network interface - SIMPLIFIED AND ROBUST VERSION
static int remove_ipv6_address(const char* ipv6_address) {
    printf("Removing IPv6 address: %s\n", ipv6_address);
    
    // Method 1: First try to find and remove the exact address as shown in system
    char check_cmd[512];
    char remove_cmd[512];
    int result = -1;
    
    // Get the exact IP address with prefix from system
    snprintf(check_cmd, sizeof(check_cmd),
             "ip -6 addr show | grep -o '[0-9a-f:]*/[0-9]*' | grep '%s' | head -1",
             ipv6_address);
    
    FILE *fp = popen(check_cmd, "r");
    char exact_ip[128] = "";
    if (fp != NULL) {
        if (fgets(exact_ip, sizeof(exact_ip), fp) != NULL) {
            // Remove newline
            exact_ip[strcspn(exact_ip, "\n")] = '\0';
            printf("Found exact IP in system: %s\n", exact_ip);
            
            // Remove the exact IP
            snprintf(remove_cmd, sizeof(remove_cmd), "ip -6 addr del %s 2>/dev/null", exact_ip);
            printf("Executing: %s\n", remove_cmd);
            result = system(remove_cmd);
            
            if (result == 0) {
                printf("Successfully removed exact IP: %s\n", exact_ip);
                pclose(fp);
                return result;
            }
        }
        pclose(fp);
    }
    
    // Method 2: Try to find interface and remove
    char interface[64] = "";
    snprintf(check_cmd, sizeof(check_cmd),
             "ip -6 addr show | grep -B 10000 '%s' | grep '^[0-9]' | tail -1 | cut -d: -f2 | sed 's/ //'",
             ipv6_address);
    
    fp = popen(check_cmd, "r");
    if (fp != NULL) {
        if (fgets(interface, sizeof(interface), fp) != NULL) {
            interface[strcspn(interface, "\n")] = '\0';
            printf("Detected interface: %s\n", interface);
            
            if (strlen(interface) > 0) {
                // Try different prefix lengths
                const int prefixes[] = {56, 64, 128, 0};
                for (int i = 0; prefixes[i] != 0; i++) {
                    snprintf(remove_cmd, sizeof(remove_cmd), 
                             "ip -6 addr del %s dev %s 2>/dev/null", 
                             exact_ip, interface);
                    printf("Trying: %s\n", remove_cmd);
                    result = system(remove_cmd);
                    
                    if (result == 0) {
                        printf("Successfully removed with prefix %s from %s\n", exact_ip, interface);
                        pclose(fp);
                        return result;
                    }
                }
            }
        }
        pclose(fp);
    }
    
    printf("Warning: Could not remove IPv6 address %s\n", ipv6_address);
    printf("The address might already be removed or not exist in the expected format.\n");
    
    // Final check to see if it still exists
    snprintf(check_cmd, sizeof(check_cmd),
             "ip -6 addr show | grep -q '%s'", ipv6_address);
    result = system(check_cmd);
    
    if (result != 0) {
        printf("Verified: IPv6 address %s is not present in system\n", ipv6_address);
        return 0; // Consider success if it doesn't exist
    } else {
        printf("IPv6 address %s still exists. Manual removal may be needed.\n", ipv6_address);
        return -1;
    }
}

// SIMPLIFIED IPv6 address extraction - more robust
static char* extract_ipv6_address(const char* block) {
    printf("Searching for IPv6 in configuration block...\n");
    
    // Look for IPv6 pattern in the entire block
    const char *ptr = block;
    
    while (*ptr) {
        // Look for sequence that resembles IPv6 (contains multiple colons)
        if ((*ptr == '2' || *ptr == 'f' || *ptr == 'e') && strchr(ptr, ':') != NULL) {
            const char *start = ptr;
            const char *end = ptr;
            int colon_count = 0;
            int valid_length = 0;
            
            // Parse potential IPv6 address
            while (*end && 
                   ((*end >= '0' && *end <= '9') ||
                    (*end >= 'a' && *end <= 'f') ||
                    (*end >= 'A' && *end <= 'F') ||
                    *end == ':')) {
                if (*end == ':') colon_count++;
                end++;
                valid_length++;
            }
            
            // Valid IPv6 should have multiple colons and reasonable length
            if (colon_count >= 2 && valid_length >= 15 && valid_length <= 39) {
                // Extract the IP
                char *ipv6_addr = malloc(valid_length + 1);
                if (ipv6_addr) {
                    strncpy(ipv6_addr, start, valid_length);
                    ipv6_addr[valid_length] = '\0';
                    
                    // Validate it looks like a real IPv6 (not part of a word)
                    if (strstr(ipv6_addr, "2804:") == ipv6_addr) { // Match your prefix
                        printf("SUCCESS: Found IPv6 address: %s\n", ipv6_addr);
                        return ipv6_addr;
                    }
                    free(ipv6_addr);
                }
            }
        }
        ptr++;
    }
    
    // Alternative: look for -e parameter specifically
    char *e_param = strstr(block, "-e");
    if (e_param) {
        e_param += 2; // Skip "-e"
        // Skip whitespace
        while (*e_param == ' ' || *e_param == '\t') e_param++;
        
        // Extract potential IPv6
        const char *ip_start = e_param;
        const char *ip_end = e_param;
        
        while (*ip_end && 
               ((*ip_end >= '0' && *ip_end <= '9') ||
                (*ip_end >= 'a' && *ip_end <= 'f') ||
                (*ip_end >= 'A' && *ip_end <= 'F') ||
                *ip_end == ':')) {
            ip_end++;
        }
        
        int ip_len = ip_end - ip_start;
        if (ip_len > 0 && strchr(ip_start, ':') != NULL) {
            char *ipv6_addr = malloc(ip_len + 1);
            if (ipv6_addr) {
                strncpy(ipv6_addr, ip_start, ip_len);
                ipv6_addr[ip_len] = '\0';
                printf("SUCCESS: Found IPv6 via -e parameter: %s\n", ipv6_addr);
                return ipv6_addr;
            }
        }
    }
    
    printf("No IPv6 address found in block\n");
    return NULL;
}

// Function to restart 3proxy service
static int restart_3proxy_service() {
    int result = system("service 3proxy restart");
    if (result == 0) {
        printf("3proxy service restarted successfully\n");
    } else {
        printf("Failed to restart 3proxy service\n");
    }
    return result;
}

// Function to delete proxies from 3proxy configuration - FIXED VERSION
static int delete_proxies_from_config(const char** usernames, int count, char** deleted_users, int* deleted_count, char** removed_ipv6_addresses, int* ipv6_count) {
    printf("Starting delete_proxies_from_config\n");
    
    // Read the config file
    FILE *file = fopen(CONFIG_PATH, "r");
    if (!file) {
        printf("Failed to open config file\n");
        return -1;
    }
    
    // Create temporary file for new config
    FILE *temp_file = fopen("/etc/3proxy/3proxy.cfg.tmp", "w");
    if (!temp_file) {
        fclose(file);
        printf("Failed to create temp file\n");
        return -1;
    }
    
    *ipv6_count = 0;
    char line[40960];
    int in_proxy_block = 0;
    int skip_block = 0;
    char current_user[128] = "";
    char block_buffer[81920] = ""; // Increased buffer size
    size_t block_pos = 0;
    int found_auth_in_block = 0;
    
    // Read file line by line
    while (fgets(line, sizeof(line), file)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Check for proxy block header (comment lines starting with ####)
        if (strstr(line, "####") != NULL && !in_proxy_block) {
            // This might be the start of a proxy block
            in_proxy_block = 1;
            skip_block = 0;
            current_user[0] = '\0';
            block_buffer[0] = '\0';
            block_pos = 0;
            found_auth_in_block = 0;
            
            // Add this line to block buffer
            size_t len = strlen(line);
            if (block_pos + len + 2 < sizeof(block_buffer)) {
                memcpy(block_buffer + block_pos, line, len);
                block_pos += len;
                block_buffer[block_pos++] = '\n';
            }
            continue;
        }
        
        // Check if we're starting a proxy block with auth strong
        if (strstr(line, "auth strong") != NULL) {
            // If we're already in a block (from a comment header), just mark that we found auth
            if (in_proxy_block) {
                found_auth_in_block = 1;
            } else {
                // Start new block
                in_proxy_block = 1;
                skip_block = 0;
                current_user[0] = '\0';
                block_buffer[0] = '\0';
                block_pos = 0;
                found_auth_in_block = 1;
            }
            
            // Add this line to block buffer
            size_t len = strlen(line);
            if (block_pos + len + 2 < sizeof(block_buffer)) {
                memcpy(block_buffer + block_pos, line, len);
                block_pos += len;
                block_buffer[block_pos++] = '\n';
            }
        }
        // Check for allow line in proxy block
        else if (in_proxy_block && strstr(line, "allow") != NULL) {
            // Extract username
            char *allow_pos = strstr(line, "allow");
            if (allow_pos) {
                char *user_start = allow_pos + 5;
                while (*user_start == ' ' || *user_start == '\t') user_start++;
                
                char *user_end = user_start;
                while (*user_end && *user_end != ' ' && *user_end != '\t' && *user_end != '\n' && *user_end != '\r') {
                    user_end++;
                }
                
                size_t user_len = user_end - user_start;
                if (user_len < sizeof(current_user) - 1) {
                    strncpy(current_user, user_start, user_len);
                    current_user[user_len] = '\0';
                    
                    // Check if this user should be deleted
                    for (int i = 0; i < count; i++) {
                        if (strcmp(current_user, usernames[i]) == 0) {
                            skip_block = 1;
                            printf("Marking block for user %s to be deleted\n", current_user);
                            break;
                        }
                    }
                }
            }
            
            // Add line to block buffer
            size_t len = strlen(line);
            if (block_pos + len + 2 < sizeof(block_buffer)) {
                memcpy(block_buffer + block_pos, line, len);
                block_pos += len;
                block_buffer[block_pos++] = '\n';
            }
        }
        // Check for flush line (end of proxy block)
        else if (in_proxy_block && strstr(line, "flush") != NULL) {
            // Add flush line to block
            size_t len = strlen(line);
            if (block_pos + len + 2 < sizeof(block_buffer)) {
                memcpy(block_buffer + block_pos, line, len);
                block_pos += len;
                block_buffer[block_pos++] = '\n';
            }
            
            // NOW extract IPv6 address from the COMPLETE block
            if (skip_block) {
                printf("Complete block for user %s:\n%s\n", current_user, block_buffer);
                char *ipv6_addr = extract_ipv6_address(block_buffer);
                if (ipv6_addr && *ipv6_count < 10) {
                    removed_ipv6_addresses[*ipv6_count] = ipv6_addr;
                    (*ipv6_count)++;
                    printf("Found IPv6 address to remove: %s\n", ipv6_addr);
                } else if (ipv6_addr) {
                    free(ipv6_addr);
                }
            }
            
            // Write block if not skipped
            if (!skip_block) {
                fwrite(block_buffer, 1, block_pos, temp_file);
            } else {
                printf("Skipping block for user %s\n", current_user);
            }
            
            in_proxy_block = 0;
            skip_block = 0;
            current_user[0] = '\0';
            block_buffer[0] = '\0';
            block_pos = 0;
            found_auth_in_block = 0;
        }
        // Handle users line (special case)
        else if (strstr(line, "users") != NULL && !in_proxy_block) {
            // Process users line to remove deleted users
            char new_users_line[81920] = "";
            char *users_pos = strstr(line, "users");
            
            if (users_pos) {
                strcpy(new_users_line, "users");
                char *users_list = users_pos + 5;
                
                // Skip whitespace
                while (*users_list == ' ' || *users_list == '\t') users_list++;
                
                // Parse each user entry
                char *current = users_list;
                int first_user = 1;
                int users_removed = 0;
                
                while (*current) {
                    char *user_end = current;
                    while (*user_end && *user_end != ' ' && *user_end != '\t') user_end++;
                    
                    if (user_end > current) {
                        char user_entry[256];
                        size_t entry_len = user_end - current;
                        strncpy(user_entry, current, entry_len);
                        user_entry[entry_len] = '\0';
                        
                        // Extract username
                        char username[128];
                        strncpy(username, user_entry, sizeof(username) - 1);
                        username[sizeof(username) - 1] = '\0';
                        
                        char *colon_pos = strchr(username, ':');
                        if (colon_pos) *colon_pos = '\0';
                        
                        // Check if user should be kept
                        int keep_user = 1;
                        for (int i = 0; i < count; i++) {
                            if (strcmp(username, usernames[i]) == 0) {
                                keep_user = 0;
                                users_removed++;
                                deleted_users[(*deleted_count)++] = usernames[i];
                                printf("Removing user from users line: %s\n", username);
                                break;
                            }
                        }
                        
                        if (keep_user) {
                            //if (!first_user) strcat(new_users_line, " ");
                            strcat(new_users_line, " ");
                            strcat(new_users_line, user_entry);
                            first_user = 0;
                        }
                    }
                    
                    current = user_end;
                    while (*current == ' ' || *current == '\t') current++;
                }
                
                printf("Processed users line: %d users removed\n", users_removed);
                fprintf(temp_file, "%s\n", new_users_line);
            } else {
                fprintf(temp_file, "%s\n", line);
            }
        }
        // Regular line (not in proxy block)
        else if (!in_proxy_block) {
            fprintf(temp_file, "%s\n", line);
        }
        // Line inside proxy block (including comment headers, auth, proxy/socks commands, etc.)
        else if (in_proxy_block) {
            // Add line to block buffer
            size_t len = strlen(line);
            if (block_pos + len + 2 < sizeof(block_buffer)) {
                memcpy(block_buffer + block_pos, line, len);
                block_pos += len;
                block_buffer[block_pos++] = '\n';
            }
        }
    }
    
    // Handle any remaining block at end of file
    if (in_proxy_block && !skip_block && block_pos > 0) {
        fwrite(block_buffer, 1, block_pos, temp_file);
    } else if (in_proxy_block && skip_block) {
        printf("Skipping remaining block for user %s\n", current_user);
        // Extract IPv6 from remaining block
        char *ipv6_addr = extract_ipv6_address(block_buffer);
        if (ipv6_addr && *ipv6_count < 10) {
            removed_ipv6_addresses[*ipv6_count] = ipv6_addr;
            (*ipv6_count)++;
            printf("Found IPv6 address to remove: %s\n", ipv6_addr);
        } else if (ipv6_addr) {
            free(ipv6_addr);
        }
    }
    
    fclose(file);
    fclose(temp_file);
    
    // Replace original file with temp file
    if (rename("/etc/3proxy/3proxy.cfg.tmp", CONFIG_PATH) != 0) {
        printf("Failed to replace config file\n");
        remove("/etc/3proxy/3proxy.cfg.tmp");
        return -1;
    }
    
    printf("Successfully updated config file. Removed %d IPv6 addresses.\n", *ipv6_count);
    return 0;
}
// HTTP handler for deleting proxies
static void handle_delete_proxies(struct mg_connection *c, struct mg_http_message *hm) {
    printf("=== Starting delete_proxies handler ===\n");
    
    // Validate input size first
    if (hm->body.len > 1024 || hm->body.len == 0) {
        printf("Request too large or empty: %zu bytes\n", hm->body.len);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Invalid request size\"}");
        return;
    }
    
    // Parse JSON body
    char *body_str = malloc(hm->body.len + 1);
    if (!body_str) {
        printf("Memory allocation failed for body\n");
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Memory allocation failed\"}");
        return;
    }
    
    memcpy(body_str, hm->body.buf, hm->body.len);
    body_str[hm->body.len] = '\0';
    printf("Received JSON: %s\n", body_str);
    
    json_object *root = json_tokener_parse(body_str);
    free(body_str);
    
    if (!root) {
        printf("Invalid JSON received\n");
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Invalid JSON\"}");
        return;
    }
    
    // Extract usernames array
    if (!json_object_is_type(root, json_type_array)) {
        printf("Expected array but got different type\n");
        json_object_put(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Expected JSON array of usernames\"}");
        return;
    }
    
    int array_len = json_object_array_length(root);
    printf("Number of users to delete: %d\n", array_len);
    
    if (array_len == 0) {
        printf("Empty array received\n");
        json_object_put(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"No usernames provided\"}");
        return;
    }
    
    // Extract usernames
    const char **usernames = malloc(array_len * sizeof(char*));
    memset(usernames, 0, array_len * sizeof(char*));
    if (!usernames) {
        printf("Memory allocation failed for usernames array\n");
        json_object_put(root);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Memory allocation failed\"}");
        return;
    }

    const char **deleted_usernames = malloc(array_len * sizeof(char*));
    memset(deleted_usernames, 0, array_len * sizeof(char*));
    if (!usernames) {
        printf("Memory allocation failed for deleted_usernames array\n");
        json_object_put(root);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Memory allocation failed\"}");
        return;
    }

    for (int i = 0; i < array_len; i++) {
        json_object *user_item = json_object_array_get_idx(root, i);
        if (json_object_is_type(user_item, json_type_string)) {
            usernames[i] = json_object_get_string(user_item);
            printf("User to delete[%d]: %s\n", i, usernames[i]);
        } else {
            usernames[i] = "";
            printf("Warning: non-string item at index %d\n", i);
        }
    }

    int deleted_count = 0;
    
    // Delete proxies from configuration
    char *removed_ipv6_addresses[10000] = {NULL};
    int ipv6_count = 0;
    
    printf("Calling delete_proxies_from_config...\n");
    int delete_result = delete_proxies_from_config(usernames, array_len, deleted_usernames, &deleted_count, removed_ipv6_addresses, &ipv6_count);
    printf("delete_proxies_from_config returned: %d, deleted_count: %d\n", delete_result, deleted_count);
    
    if (delete_result == 0) {
        printf("Config update successful, restarting service...\n");
        
        // Restart 3proxy service
        int restart_result = restart_3proxy_service();
        printf("Service restart result: %d\n", restart_result);
        
        // In handle_delete_proxies function, before removing IPv6:
        printf("Removing %d IPv6 addresses\n", ipv6_count);
        for (int i = 0; i < ipv6_count; i++) {
            if (removed_ipv6_addresses[i]) {
                printf("Removing IPv6: %s\n", removed_ipv6_addresses[i]);
                
                // Debug first
                debug_ipv6_status(removed_ipv6_addresses[i]);
                
                remove_ipv6_address(removed_ipv6_addresses[i]);
            }
        }
        
        // Create success response
        json_object *response_obj = json_object_new_object();
        json_object_object_add(response_obj, "status", json_object_new_string("success"));
        json_object_object_add(response_obj, "message", json_object_new_string("Proxies deleted successfully"));
        
        json_object *deleted_users = json_object_new_array();
        for (int i = 0; i < deleted_count; i++) {
            json_object_array_add(deleted_users, json_object_new_string(deleted_usernames[i]));
        }
        json_object_object_add(response_obj, "deleted_users", deleted_users);

        json_object *notfound_users = json_object_new_array();
        for (int i = 0; i < array_len; i++) {
            if (usernames[i] == NULL) continue;  // Skip if username is NULL
            
            int found = 0;
            
            // Check if this username exists in deleted_usernames
            for (int j = 0; j < deleted_count; j++) {
                if (deleted_usernames[j] != NULL && 
                    strcmp(usernames[i], deleted_usernames[j]) == 0) {
                    found = 1;
                    break;
                }
            }
            
            // If not found in deleted_usernames, add to notfound array
            if (!found) {
                json_object *username_obj = json_object_new_string(usernames[i]);
                if (username_obj) {
                    json_object_array_add(notfound_users, username_obj);
                }
            }
        }
        json_object_object_add(response_obj, "not_found", notfound_users);


        if (ipv6_count > 0) {
            json_object *removed_ips = json_object_new_array();
            for (int i = 0; i < ipv6_count; i++) {
                if (removed_ipv6_addresses[i]) {
                    printf(" ## %s\n", removed_ipv6_addresses[i]);
                    json_object_array_add(removed_ips, json_object_new_string(removed_ipv6_addresses[i]));
                    free(removed_ipv6_addresses[i]);
                }
            }
            json_object_object_add(response_obj, "removed_ipv6_addresses", removed_ips);
       }
        
        const char *response_str = json_object_to_json_string(response_obj);
        mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", response_str);
        
        json_object_put(response_obj);
        printf("Delete operation completed successfully\n");
    } else {
        printf("Config update failed\n");
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Failed to delete proxies from configuration\"}");
    }
    
    free(usernames);
    json_object_put(root);
    printf("=== Delete proxies handler finished ===\n");
}

// Function to add IPv6 address to interface
static int add_ipv6_to_interface(const char *ipv6_address, const char *interface) {
    char command[256];
    snprintf(command, sizeof(command), "ip -6 addr add %s dev %s 2>/dev/null", ipv6_address, interface);
    
    int result = system(command);
    printf("IPv6 add result: %s, %d\n", command, result);
    return (result == 0);
}

// Function to read existing 3proxy configuration
static char* read_3proxy_config() {
    printf("Config path: %s\n", CONFIG_PATH);
    
    FILE *file = fopen(CONFIG_PATH, "r");
    if (!file) {
        printf("Failed to open config file: %s\n", strerror(errno));
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *content = malloc(length + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }
    
    fread(content, 1, length, file);
    content[length] = '\0';
    fclose(file);
    
    return content;
}

// Function to write 3proxy configuration
static int write_3proxy_config(const char *content) {
    printf("Writing 3proxy config...\n");
    char backup_cmd[256];
    snprintf(backup_cmd, sizeof(backup_cmd), "cp %s %s.backup", CONFIG_PATH, CONFIG_PATH);
    system(backup_cmd);
    
    FILE *file = fopen(CONFIG_PATH, "w");
    if (!file) {
        printf("Failed to open config file for writing: %s\n", strerror(errno));
        return 0;
    }
    
    fprintf(file, "%s", content);
    fclose(file);
    
    return 1;
}

char* remove_ipv6_prefix(const char* ipv6_input) {
    if (ipv6_input == NULL) {
        return NULL;
    }
    
    // Find the last occurrence of '/'
    char* slash_pos = strrchr(ipv6_input, '/');
    
    if (slash_pos == NULL) {
        // No prefix found, return a copy of the original string
        return strdup(ipv6_input);
    }
    
    // Calculate the length of the IP address part
    size_t ip_length = slash_pos - ipv6_input;
    
    // Allocate memory for the result
    char* result = malloc(ip_length + 1);
    if (result == NULL) {
        return NULL;
    }
    
    // Copy the IP address part
    strncpy(result, ipv6_input, ip_length);
    result[ip_length] = '\0';
    
    return result;
}


// Function to generate proxy configuration block
static char* generate_proxy_config(const char *proxy_type, const char *host, int port, 
                                  const char *username, const char *password, 
                                  const char *external_ip, const char *parent_info) {
    printf("Generating proxy config...");
    
    char *config = malloc(1024);
    if (!config) return NULL;
    
    config[0] = '\0';

    char* external_ip_removed_prefix = remove_ipv6_prefix(external_ip);
    
    // Common authentication and access control
    strcat(config, "auth strong\n");
    
    char allow_line[256];
    snprintf(allow_line, sizeof(allow_line), "allow %s\n", username);
    strcat(config, allow_line);
    
    // Generate specific proxy configuration based on type
    if (strcmp(proxy_type, "socks-ipv6") == 0) {
        char proxy_line[256];
        snprintf(proxy_line, sizeof(proxy_line), "socks -64 -p%d -i%s -e%s\n", 
                port, host, external_ip_removed_prefix);
        strcat(config, proxy_line);
        printf("Generated SOCKS5 IPv6 config");
    }
    else if (strcmp(proxy_type, "proxy-ipv6") == 0) {
        char proxy_line[256];
        snprintf(proxy_line, sizeof(proxy_line), "proxy -64 -p%d -i%s -e%s\n", 
                port, host, external_ip_removed_prefix);
        strcat(config, proxy_line);
        printf("Generated HTTP IPv6 config");
    }
    else if (strcmp(proxy_type, "proxy-ipv4") == 0) {
        char proxy_line[256];
        snprintf(proxy_line, sizeof(proxy_line), "proxy -p%d -i%s -e%s\n", 
                port, host, external_ip_removed_prefix);
        strcat(config, proxy_line);
        printf("Generated HTTP IPv4 config");
    }
    else if (strcmp(proxy_type, "socks-ipv4") == 0) {
        char proxy_line[256];
        snprintf(proxy_line, sizeof(proxy_line), "socks -p%d -i%s -e%s\n", 
                port, host, external_ip_removed_prefix);
        strcat(config, proxy_line);
	printf("Generated SOCKS5 IPv4 config");
    }
    else if (strcmp(proxy_type, "parent") == 0 && parent_info) {
        // Parse parent info: "parent_ip parent_port parent_user parent_pass"
        char parent_ip[64], parent_user[64], parent_pass[64];
        int parent_port;
        
        if (sscanf(parent_info, "%63s %d %63s %63s", parent_ip, &parent_port, parent_user, parent_pass) == 4) {
            char parent_line[256];
            snprintf(parent_line, sizeof(parent_line), "parent 1000 socks5 %s %d %s %s\n", 
                    parent_ip, parent_port, parent_user, parent_pass);
            strcat(config, parent_line);
            
            char socks_line[256];
            snprintf(socks_line, sizeof(socks_line), "socks -p%d\n", port);
            strcat(config, socks_line);
        }
	printf("Generated Parent config");
    }
    
    strcat(config, "flush\n\n");
    printf("Generated config:\n%s\n", config);

    free(external_ip_removed_prefix);
    
    return config;
}

// Function to add user to 3proxy users line
static char* update_users_line(const char *current_config, const char *username, const char *password) {
    printf("Updating users line...");
    
    char *users_start = strstr(current_config, "users ");
    if (!users_start) {
        printf("Users line not found in config!\n");
        return NULL;
    }
    
    char *users_end = strchr(users_start, '\n');
    if (!users_end) {
        printf("Users line not properly terminated!\n");
        return NULL;
    }
    
    // Calculate lengths
    size_t users_line_len = users_end - users_start;
    size_t new_user_len = strlen(username) + strlen(password) + 5; // " :CL:" + username + password
    
    // Create new users line
    char *new_users_line = malloc(users_line_len + new_user_len + 2);
    if (!new_users_line) return NULL;
    
    // Copy existing users line without the newline
    strncpy(new_users_line, users_start, users_line_len);
    new_users_line[users_line_len] = '\0';
    
    // Check if user already exists
    char user_search[99999];
    snprintf(user_search, sizeof(user_search), " %s:", username);
    if (strstr(new_users_line, user_search) == NULL) {
        // Add new user
        strcat(new_users_line, " ");
        strcat(new_users_line, username);
        strcat(new_users_line, ":CL:");
        strcat(new_users_line, password);
        printf("Added user: %s\n", username);
    } else {
        printf("User %s already exists\n", username);
        free(new_users_line);
        return NULL;
    }
    
    strcat(new_users_line, "\n");
    
    // Replace the users line in the config
    char *new_config = malloc(strlen(current_config) + new_user_len + 2);
    if (!new_config) {
        free(new_users_line);
        return NULL;
    }
    
    // Copy part before users line
    strncpy(new_config, current_config, users_start - current_config);
    new_config[users_start - current_config] = '\0';
    
    // Add new users line
    strcat(new_config, new_users_line);
    
    // Copy part after users line
    strcat(new_config, users_end + 1);
    
    free(new_users_line);
    return new_config;
}

// Ultra-simple function to delete proxy block by username
static int delete_proxy_by_username_simple(const char *username) {
    printf("Deleting proxy for user: %s\n", username);
    
    // Read entire config file
    char *config = read_3proxy_config();
    if (!config) {
        printf("Failed to read config file\n");
        return -1;
    }
    
    char *new_config = malloc(strlen(config) + 1);
    if (!new_config) {
        free(config);
        return -1;
    }
    
    new_config[0] = '\0';
    
    char *current = config;
    int deleted = 0;
    
    while (*current) {
        // Look for proxy blocks
        if (strncmp(current, "auth strong", 11) == 0) {
            char *block_start = current;
            
            // Find the end of this block (next auth strong or end of file)
            char *block_end = strstr(current + 11, "auth strong");
            if (!block_end) {
                block_end = config + strlen(config);
            }
            
            // Check if this block contains our target username
            char block_segment[block_end - block_start + 1];
            strncpy(block_segment, block_start, block_end - block_start);
            block_segment[block_end - block_start] = '\0';
            
            // Look for "allow username" in this block
            char allow_pattern[99999];
            snprintf(allow_pattern, sizeof(allow_pattern), "allow %s", username);
            
            if (strstr(block_segment, allow_pattern) != NULL) {
                // Skip this block - don't copy it to new config
                printf("Skipping block for user %s\n", username);
                current = block_end;
                deleted = 1;
                continue;
            }
        }
        
        // Handle users line
        if (strncmp(current, "users", 5) == 0) {
            char *line_end = strchr(current, '\n');
            if (!line_end) line_end = config + strlen(config);
            
            char users_line[line_end - current + 1];
            strncpy(users_line, current, line_end - current);
            users_line[line_end - current] = '\0';
            
            if (strstr(users_line, username) != NULL) {
                // Rebuild users line without the target user
                printf("Rebuilding users line without %s\n", username);
                
                char new_users_line[99999] = "users";
                char *token;
                char *rest = users_line + 5; // Skip "users"
                
                // Skip initial whitespace
                while (*rest == ' ' || *rest == '\t') rest++;
                
                char *token_rest = rest;
                while ((token = strtok_r(token_rest, " \t", &token_rest))) {
                    char user_part[99999];
                    strncpy(user_part, token, sizeof(user_part) - 1);
                    user_part[sizeof(user_part) - 1] = '\0';
                    
                    char *colon_pos = strchr(user_part, ':');
                    if (colon_pos) *colon_pos = '\0';
                    
                    if (strcmp(user_part, username) != 0) {
                        strcat(new_users_line, " ");
                        strcat(new_users_line, token);
                    }
                }
                
                strcat(new_users_line, "\n");
                strcat(new_config, new_users_line);
                current = line_end + 1;
                continue;
            }
        }
        
        // Copy character by character
        strncat(new_config, current, 1);
        current++;
    }
    
    // Write new config
    FILE *file = fopen(CONFIG_PATH, "w");
    if (file) {
        fwrite(new_config, 1, strlen(new_config), file);
        fclose(file);
        printf("Successfully updated config file\n");
    } else {
        printf("Failed to write config file\n");
        free(config);
        free(new_config);
        return -1;
    }
    
    free(config);
    free(new_config);
    
    if (deleted) {
        printf("Successfully deleted proxy for user %s\n", username);
        return 0;
    } else {
        printf("No proxy found for user %s\n", username);
        return -1;
    }
}

// HTTP handler for regenerate-proxy endpoint - UPDATED VERSION
static void handle_regenerate_proxy(struct mg_connection *c, struct mg_http_message *hm) {
    printf("Handling regenerate-proxy request with broken proxy detection\n");
    
    // Parse JSON body using json-c
    char *body_str = malloc(hm->body.len + 1);
    if (!body_str) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Memory allocation failed\"}");
        return;
    }
    
    memcpy(body_str, hm->body.buf, hm->body.len);
    body_str[hm->body.len] = '\0';
    
    printf("Received JSON: %s\n", body_str);
    
    json_object *root = json_tokener_parse(body_str);
    free(body_str);
    
    if (!root) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Invalid JSON\"}");
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
    
    // Extract type array
    json_object *type_obj;
    if (!json_object_object_get_ex(root, "Type", &type_obj) || 
        !json_object_is_type(type_obj, json_type_array) ||
        json_object_array_length(type_obj) == 0) {
        json_object_put(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Invalid or missing Type array\"}");
        return;
    }
    
    // Extract interface
    json_object *interface_obj;
    const char *interface = "eth0"; // default
    if (json_object_object_get_ex(root, "interface", &interface_obj) && 
        json_object_is_type(interface_obj, json_type_string)) {
        interface = json_object_get_string(interface_obj);
    }
    
    printf("Interface: %s\n", interface);
    
    // Read existing configuration
    char *current_config = read_3proxy_config();
    if (!current_config) {
        json_object_put(root);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                      "{\"error\":\"Failed to read current configuration\"}");
        return;
    }
    
    printf("Current config exists, length: %ld\n", strlen(current_config));
    
    // Process each proxy
    int proxies_len = json_object_array_length(proxies_obj);
    const char *proxy_type = json_object_get_string(json_object_array_get_idx(type_obj, 0));
    
    printf("Processing %d proxies of type: %s\n", proxies_len, proxy_type);
    
    char *new_config = strdup(current_config);
    free(current_config);
    
    int success_count = 0;
    int broken_fixed_count = 0;
    int already_configured_count = 0;
    
    // Arrays for detailed response
    json_object *regenerated_users = json_object_new_array();
    json_object *broken_fixed_users = json_object_new_array();
    json_object *already_configured_users = json_object_new_array();
    json_object *failed_users = json_object_new_array();
    
    for (int i = 0; i < proxies_len; i++) {
        json_object *proxy_item = json_object_array_get_idx(proxies_obj, i);
        
        if (!json_object_is_type(proxy_item, json_type_string)) {
            json_object_array_add(failed_users, json_object_new_string("invalid_format"));
            continue;
        }
        
        const char *proxy_str = json_object_get_string(proxy_item);
        printf("Processing proxy: %s\n", proxy_str);
        
        // Parse proxy string: "host:port:username:password external_ip [parent_info]"
        char host[64], username[64], password[64], external_ip[64], parent_info[256];
        int port;
        
        parent_info[0] = '\0';
        external_ip[0] = '\0';
        
        int parse_success = 0;
        
        if (strcmp(proxy_type, "parent") == 0) {
            // Format: "host:port:username:password parent_ip parent_port parent_user parent_pass"
            if (sscanf(proxy_str, "%63[^:]:%d:%63[^:]:%63s %63s %63s", 
                      host, &port, username, password, external_ip, parent_info) >= 5) {
                parse_success = 1;
                printf("Parsed: host=%s, port=%d, user=%s, pass=***, ip=%s, parent_info=%s\n", 
                   host, port, username, external_ip, parent_info);
                // Reconstruct parent info
                char *space_pos = strchr(proxy_str, ' ');
                if (space_pos) {
                    strncpy(parent_info, space_pos + 1, sizeof(parent_info) - 1);
                    parent_info[sizeof(parent_info) - 1] = '\0';
                }
            }
        } else {
            // Format: "host:port:username:password external_ip"
            if (sscanf(proxy_str, "%63[^:]:%d:%63[^:]:%63s %63s", 
                      host, &port, username, password, external_ip) == 5) {
                parse_success = 1;
                printf("Parsed: host=%s, port=%d, user=%s, pass=***, ip=%s\n", 
                   host, port, username, external_ip);
            }
        }
        
        if (!parse_success) {
            printf("Failed to parse proxy string: %s\n", proxy_str);
            json_object_array_add(failed_users, json_object_new_string(proxy_str));
            continue;
        }
        
        // Check if proxy exists but is broken
        int proxy_exists = 0;
        char allow_pattern[256];
        snprintf(allow_pattern, sizeof(allow_pattern), "allow %s", username);
        if (strstr(new_config, allow_pattern) != NULL) {
            proxy_exists = 1;
            printf("Proxy for user %s exists but is broken - deleting and regenerating\n", username);
            
            // Delete the broken proxy
            if (delete_proxy_by_username_simple(username) == 0) {
                printf("Successfully deleted broken proxy for user %s\n", username);
                broken_fixed_count++;
                json_object_array_add(broken_fixed_users, json_object_new_string(username));
                
                // Reload the config after deletion
                free(new_config);
                new_config = read_3proxy_config();
                if (!new_config) {
                    printf("Failed to reload config after deletion\n");
                    json_object_array_add(failed_users, json_object_new_string(username));
                    continue;
                }
            } else {
                printf("Failed to delete broken proxy for user %s\n", username);
                json_object_array_add(failed_users, json_object_new_string(username));
                continue;
            }
        }
        
        // For IPv6 proxies, add the IPv6 address to the interface
        if (strstr(proxy_type, "ipv6") != NULL && external_ip[0] != '\0') {
            printf("Adding IPv6 address to interface...\n");
            if (!add_ipv6_to_interface(external_ip, interface)) {
                printf("Warning: Failed to add IPv6 address %s to interface %s\n", 
                       external_ip, interface);
                // Continue anyway - the IP might already be there
            }
        }
        
        // Update users line
        char *updated_config = update_users_line(new_config, username, password);
        if (updated_config) {
            free(new_config);
            new_config = updated_config;
            printf("Users line updated successfully for user %s\n", username);
        } else {
            printf("User %s already exists in users line\n", username);
        }
        
        // Generate proxy configuration
        char *proxy_config = generate_proxy_config(proxy_type, host, port, username, 
                                                  password, external_ip, parent_info);
        if (proxy_config) {
            // Append to configuration
            char *combined_config = malloc(strlen(new_config) + strlen(proxy_config) + 1);
            if (combined_config) {
                strcpy(combined_config, new_config);
                strcat(combined_config, proxy_config);
                free(new_config);
                new_config = combined_config;
                success_count++;
                
                if (!proxy_exists) {
                    json_object_array_add(regenerated_users, json_object_new_string(username));
                }
                
                printf("Successfully added proxy configuration for user %s\n", username);
            } else {
                printf("Failed to combine config for user %s\n", username);
                json_object_array_add(failed_users, json_object_new_string(username));
            }
            free(proxy_config);
        } else {
            printf("Failed to generate proxy config for user %s\n", username);
            json_object_array_add(failed_users, json_object_new_string(username));
        }
    }
    
    // Write new configuration
    if (success_count > 0 && write_3proxy_config(new_config)) {
        
        int restart_result = restart_3proxy_service();
        printf("Service restart result: %d\n", restart_result);
        
        // Create detailed response
        json_object *response_obj = json_object_new_object();
        json_object_object_add(response_obj, "status", json_object_new_string("success"));
        
        char message[512];
        if (broken_fixed_count > 0) {
            snprintf(message, sizeof(message), 
                    "Processed %d proxies: %ld regenerated, %d failed", 
                    proxies_len, success_count, 
                    json_object_array_length(failed_users));
        } else {
            snprintf(message, sizeof(message), 
                    "Processed %d proxies: %ld regenerated, %d failed", 
                    proxies_len, success_count, 
                    json_object_array_length(failed_users));
        }
        
        json_object_object_add(response_obj, "message", json_object_new_string(message));
        json_object_object_add(response_obj, "type", json_object_new_string(proxy_type));
        
        // Add detailed arrays
        //json_object_object_add(response_obj, "already_configured", already_configured_users);
        json_object_object_add(response_obj, "regenerated", regenerated_users);
        if (broken_fixed_count > 0) {
            json_object_object_add(response_obj, "broken_fixed", broken_fixed_users);
        } else {
            json_object_put(broken_fixed_users);
        }
        json_object_object_add(response_obj, "failed", failed_users);
        
        const char *response_str = json_object_to_json_string(response_obj);
        mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", response_str);
        
        json_object_put(response_obj);
        
    } else {
        // Clean up JSON objects on failure
        json_object_put(already_configured_users);
        json_object_put(regenerated_users);
        json_object_put(broken_fixed_users);
        json_object_put(failed_users);
        
        if (success_count == 0) {
            mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                          "{\"error\":\"Failed to update configuration - no proxies were added\"}");
        } else {
            mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                          "{\"error\":\"Failed to write configuration file\"}");
        }
    }

    free(new_config);
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
      else if (mg_match(hm->uri, mg_str("/delete-proxies"), NULL)) {
        handle_delete_proxies(c, hm);
        return;
      }
      else if (mg_match(hm->uri, mg_str("/regenerate-proxy"), NULL)) {
          handle_regenerate_proxy(c, hm);
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

