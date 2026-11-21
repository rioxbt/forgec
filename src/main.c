/* SPDX-License-Identifier: MIT */
/* forgec: a single-process, lock-free, epoll git forge.
   Binds an ephemeral port, tells the make.fun env its port, serves the four
   surfaces, and polls /done until the env says the trial is over. */
#include "http.h"
#include "forge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>

/* ---------------------------------------------------------------- tiny HTTP client */

/* Parse http://host:port from a URL; returns 0 on success. */
static int parse_url(const char *url, char *host, size_t hsz, int *port) {
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    else if (strncmp(p, "https://", 8) == 0) p += 8;
    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    if (colon && (!slash || colon < slash)) {
        size_t hl = (size_t)(colon - p);
        if (hl >= hsz) hl = hsz - 1;
        memcpy(host, p, hl); host[hl] = '\0';
        *port = atoi(colon + 1);
    } else {
        size_t hl = slash ? (size_t)(slash - p) : strlen(p);
        if (hl >= hsz) hl = hsz - 1;
        memcpy(host, p, hl); host[hl] = '\0';
        *port = 80;
    }
    return 0;
}

/* Resolve a host to an IPv4 address string without NSS: dotted IPv4 passes through,
   a bare name is looked up in /etc/hosts, and only then does getaddrinfo run. */
static int resolve_host(const char *host, char *out, size_t osz) {
    /* dotted IPv4? */
    int dots = 0;
    for (const char *p = host; *p; p++) if (*p == '.') dots++;
    if (dots == 3) { snprintf(out, osz, "%s", host); return 0; }
    FILE *f = fopen("/etc/hosts", "r");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof line, f)) {
            char *hash = strchr(line, '#'); if (hash) *hash = '\0';
            char *save = NULL;
            char *ip = strtok_r(line, " \t\r\n", &save);
            if (!ip) continue;
            char *nm;
            while ((nm = strtok_r(NULL, " \t\r\n", &save))) {
                if (strcmp(nm, host) == 0) { snprintf(out, osz, "%s", ip); fclose(f); return 0; }
            }
        }
        fclose(f);
    }
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
        struct sockaddr_in *in = (struct sockaddr_in *)res->ai_addr;
        snprintf(out, osz, "%s", inet_ntoa(in->sin_addr));
        freeaddrinfo(res);
        return 0;
    }
    if (res) freeaddrinfo(res);
    return -1;
}

/* One request/response exchange; returns malloc'd body (NUL-terminated) or NULL. */
static char *env_request(const char *env_url, const char *method, const char *path,
                         const char *body, size_t body_len, int *out_status) {
    char host[256]; int port = 8080;
    parse_url(env_url, host, sizeof host, &port);
    char ip[64];
    if (resolve_host(host, ip, sizeof ip) < 0) return NULL;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { close(fd); return NULL; }

    Buf req; buf_init(&req);
    buf_addf(&req, "%s %s HTTP/1.1\r\nHost: %s:%d\r\n", method, path, host, port);
    if (body && body_len) {
        buf_addf(&req, "Content-Type: application/json\r\nContent-Length: %zu\r\n", body_len);
    }
    buf_adds(&req, "Connection: close\r\n\r\n");
    if (body && body_len) buf_add(&req, body, body_len);
    size_t off = 0;
    while (off < req.len) {
        ssize_t n = send(fd, req.p + off, req.len - off, MSG_NOSIGNAL);
        if (n <= 0) { close(fd); buf_free(&req); return NULL; }
        off += (size_t)n;
    }
    buf_free(&req);

    Buf resp; buf_init(&resp);
    char tmp[4096]; ssize_t n;
    while ((n = recv(fd, tmp, sizeof tmp, 0)) > 0) buf_add(&resp, tmp, (size_t)n);
    close(fd);

    if (out_status) {
        int st = 0;
        if (resp.len > 9) st = atoi(resp.p + 9);
        *out_status = st;
    }
    /* body starts after the header block */
    char *bd = NULL;
    if (resp.p) {
        char *sep = strstr(resp.p, "\r\n\r\n");
        char *start = sep ? sep + 4 : resp.p;
        size_t blen = resp.len - (size_t)(start - resp.p);
        bd = (char *)malloc(blen + 1);
        memcpy(bd, start, blen); bd[blen] = '\0';
    }
    buf_free(&resp);
    return bd;
}

/* ---------------------------------------------------------------- lifecycle */

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }
int g_done_fd = -1;

int main(int argc, char **argv) {
    int port = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) port = atoi(argv[++i]);
    }

    const char *env_url = getenv("MAKEFUN_ENV_URL");
    const char *tok = getenv("MAKEFUN_SHOP_TOKEN");
    g_token = tok ? tok : "";
    const char *lg = getenv("MAKEFUN_LOGIN");
    if (lg && lg[0]) g_login = lg;

    obj_init();
    store_init();

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 1; }
    if (listen(fd, 512) < 0) { perror("listen"); return 1; }
    socklen_t alen = sizeof addr;
    if (getsockname(fd, (struct sockaddr *)&addr, &alen) < 0) { perror("getsockname"); return 1; }
    int bound_port = ntohs(addr.sin_port);
    fprintf(stderr, "[entry] listening on port %d\n", bound_port);

    if (env_url && env_url[0]) {
        char body[64];
        snprintf(body, sizeof body, "{\"port\":%d}", bound_port);
        int status = 0;
        char *resp = env_request(env_url, "POST", "/register", body, strlen(body), &status);
        fprintf(stderr, "[entry] register -> %d\n", status);
        free(resp);
    }

    /* fork a done-poller: on {"done":true} it writes a byte to the pipe. */
    int pipefd[2];
    if (env_url && env_url[0] && pipe(pipefd) == 0) {
        pid_t pid = fork();
        if (pid == 0) {
            close(pipefd[0]);
            for (;;) {
                int status = 0;
                char *resp = env_request(env_url, "GET", "/done", NULL, 0, &status);
                if (resp && strstr(resp, "\"done\":true")) { free(resp); break; }
                free(resp);
                struct timespec ts = {0, 250000000};
                nanosleep(&ts, NULL);
            }
            ssize_t w = write(pipefd[1], "x", 1);
            (void)w;
            _exit(0);
        }
        /* parent watches the pipe in the epoll loop via a small thread-free trick:
           we simply register it as a listener socket? epoll needs an fd; we add it as
           a second source. Reuse http_run by passing it? Instead: poll periodically. */
        close(pipefd[1]);
        fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
        g_done_fd = pipefd[0];
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);
    http_run(fd);
    return 0;
}
