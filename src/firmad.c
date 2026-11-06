#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <jansson.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define SERVER_PORT 5050
#define MAX_LINE (1024U * 1024U)
#define KEY_ID "demo-local"
#define PRIVATE_PEM "keys/private.pem"
#define PUBLIC_PEM "keys/public.pem"

static volatile sig_atomic_t running = 1;
static int listen_fd = -1;
static EVP_PKEY *private_key = NULL;
static EVP_PKEY *public_key = NULL;

static void stop_server(int signal_number) {
    (void)signal_number;
    running = 0;
    if (listen_fd >= 0) close(listen_fd); /* close() es async-signal-safe */
    listen_fd = -1;
}

static int key_permissions_ok(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) return 0;
    if (st.st_uid != geteuid() || (st.st_mode & 0077) != 0) return 0;
    return 1;
}

static int load_keys(void) {
    if (!key_permissions_ok(PRIVATE_PEM)) {
        fprintf(stderr, "ERROR: la clave privada debe ser archivo regular, del usuario actual y modo 600 (o mas restrictivo).\n");
        return 0;
    }
    FILE *f = fopen(PRIVATE_PEM, "rb");
    if (!f) return 0;
    private_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!private_key || EVP_PKEY_base_id(private_key) != EVP_PKEY_ED25519) return 0;

    f = fopen(PUBLIC_PEM, "rb");
    if (!f) return 0;
    public_key = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!public_key || EVP_PKEY_base_id(public_key) != EVP_PKEY_ED25519) return 0;
    return EVP_PKEY_eq(private_key, public_key) == 1;
}

static void put_string(json_t *o, const char *k, const char *v) {
    json_object_set_new(o, k, json_string(v));
}

static json_t *error_json(const char *id, const char *code, const char *message) {
    json_t *o = json_object();
    if (id) put_string(o, "request_id", id);
    put_string(o, "status", "ERROR");
    put_string(o, "code", code);
    put_string(o, "message", message);
    return o;
}

static json_t *ok_json(const char *id) {
    json_t *o = json_object();
    if (id) put_string(o, "request_id", id);
    put_string(o, "status", "OK");
    return o;
}

/* Base64 estricto: rechaza caracteres extranos, padding invalido y cadenas no canonicas. */
static int base64_decode(const char *text, unsigned char **out, size_t *out_len) {
    if (!text) return 0;
    size_t n = strlen(text);
    if (n > MAX_LINE || (n % 4) != 0) return 0;
    size_t pad = 0;
    if (n && text[n - 1] == '=') pad++;
    if (n > 1 && text[n - 2] == '=') pad++;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)text[i];
        int valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (!valid && !(c == '=' && i >= n - pad)) return 0;
    }
    if (n == 0) {
        *out = malloc(1);
        *out_len = 0;
        return *out != NULL;
    }
    unsigned char *buf = malloc((n / 4) * 3 + 1);
    if (!buf) return 0;
    int len = EVP_DecodeBlock(buf, (const unsigned char *)text, (int)n);
    if (len < 0) { free(buf); return 0; }
    *out_len = (size_t)len - pad;
    /* Exige que la codificacion de los mismos bytes coincida con la entrada. */
    unsigned char *roundtrip = malloc(n + 1);
    if (!roundtrip) { free(buf); return 0; }
    int enc = EVP_EncodeBlock(roundtrip, buf, (int)*out_len);
    int canonical = enc == (int)n && memcmp(roundtrip, text, n) == 0;
    free(roundtrip);
    if (!canonical) { free(buf); return 0; }
    *out = buf;
    return 1;
}

static char *base64_encode(const unsigned char *data, size_t len) {
    if (len > (size_t)INT32_MAX) return NULL;
    size_t size = ((len + 2) / 3) * 4;
    char *encoded = malloc(size + 1);
    if (!encoded) return NULL;
    EVP_EncodeBlock((unsigned char *)encoded, data, (int)len);
    return encoded;
}

static json_t *handle_request(const char *line, size_t len) {
    json_t *req = json_loadb(line, len, 0, NULL);
    if (!req) return error_json(NULL, "BAD_REQUEST", "JSON invalido");

    const char *id = json_string_value(json_object_get(req, "request_id"));
    const char *op = json_string_value(json_object_get(req, "op"));
    const char *key_id = json_string_value(json_object_get(req, "key_id"));
    const char *data_b64 = json_string_value(json_object_get(req, "data_b64"));
    json_t *res = NULL;
    unsigned char *data = NULL, *signature = NULL;
    size_t data_len = 0, signature_len = 0;
    char *signature_b64 = NULL;
    EVP_MD_CTX *ctx = NULL;

    if (!id || !op || !key_id || !data_b64 || strlen(id) > 64 || strlen(id) == 0) {
        res = error_json(id, "BAD_REQUEST", "Faltan campos o sus tipos son invalidos");
        goto done;
    }
    if (strcmp(op, "SIGN") && strcmp(op, "VERIFY")) {
        res = error_json(id, "BAD_REQUEST", "Operacion no admitida");
        goto done;
    }
    if (strcmp(key_id, KEY_ID) != 0) {
        res = error_json(id, "KEY_NOT_FOUND", "No existe el identificador de clave");
        goto done;
    }
    if (!base64_decode(data_b64, &data, &data_len)) {
        res = error_json(id, "BAD_REQUEST", "Base64 del documento invalido");
        goto done;
    }
    ctx = EVP_MD_CTX_new();
    if (!ctx) { res = error_json(id, "INTERNAL", "No se pudo iniciar la operacion"); goto done; }

    if (!strcmp(op, "SIGN")) {
        if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, private_key) != 1 ||
            EVP_DigestSign(ctx, NULL, &signature_len, data, data_len) != 1 ||
            signature_len != 64) {
            res = error_json(id, "INTERNAL", "Error al preparar la firma"); goto done;
        }
        signature = malloc(signature_len);
        if (!signature || EVP_DigestSign(ctx, signature, &signature_len, data, data_len) != 1) {
            res = error_json(id, "INTERNAL", "Error al firmar"); goto done;
        }
        signature_b64 = base64_encode(signature, signature_len);
        if (!signature_b64) { res = error_json(id, "INTERNAL", "Error al codificar firma"); goto done; }
        res = ok_json(id);
        put_string(res, "alg", "Ed25519");
        put_string(res, "key_id", KEY_ID);
        put_string(res, "signature_b64", signature_b64);
    } else {
        const char *sig_b64 = json_string_value(json_object_get(req, "signature_b64"));
        if (!base64_decode(sig_b64, &signature, &signature_len) || signature_len != 64) {
            res = error_json(id, "BAD_REQUEST", "Formato de firma Base64 invalido"); goto done;
        }
        if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, public_key) != 1) {
            res = error_json(id, "INTERNAL", "No se pudo verificar"); goto done;
        }
        int valid = EVP_DigestVerify(ctx, signature, signature_len, data, data_len);
        if (valid < 0) { res = error_json(id, "INTERNAL", "Error criptografico"); goto done; }
        res = ok_json(id);
        json_object_set_new(res, "valid", json_boolean(valid == 1));
    }

done:
    EVP_MD_CTX_free(ctx);
    free(signature_b64);
    free(signature);
    free(data);
    if (!res) res = error_json(id, "INTERNAL", "Error inesperado");
    json_decref(req);
    return res;
}

static int write_all(int fd, const char *buffer, size_t size) {
    while (size > 0) {
        ssize_t n = send(fd, buffer, size, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return 0;
        buffer += n;
        size -= (size_t)n;
    }
    return 1;
}

static void reply(int fd, json_t *res) {
    if (!res) return;
    char *line = json_dumps(res, 0);
    if (line) {
        write_all(fd, line, strlen(line));
        write_all(fd, "\n", 1);
        free(line);
    }
    json_decref(res);
}

static void serve_client(int fd) {
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char *buf = malloc(MAX_LINE + 1);
    if (!buf) { reply(fd, error_json(NULL, "INTERNAL", "Memoria insuficiente")); return; }
    size_t used = 0;
    int found = 0;
    while (used <= MAX_LINE) {
        ssize_t n = recv(fd, buf + used, MAX_LINE + 1 - used, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            reply(fd, error_json(NULL, errno == EAGAIN || errno == EWOULDBLOCK ? "TIMEOUT" : "INTERNAL", "Lectura no completada"));
            goto done;
        }
        if (n == 0) break;
        char *end = memchr(buf + used, '\n', (size_t)n);
        if (end) { used = (size_t)(end - buf); found = 1; break; }
        used += (size_t)n;
    }
    if (!found) {
        reply(fd, error_json(NULL, used > MAX_LINE ? "TOO_LARGE" : "BAD_REQUEST", "Se requiere una linea JSON terminada en salto de linea"));
        goto done;
    }
    if (used > MAX_LINE) {
        reply(fd, error_json(NULL, "TOO_LARGE", "Tamano excedido")); goto done;
    }
    reply(fd, handle_request(buf, used));
done:
    free(buf);
}

int main(void) {
    struct rlimit core = {.rlim_cur = 0, .rlim_max = 0};
    setrlimit(RLIMIT_CORE, &core);
    struct sigaction sa = {0};
    sa.sa_handler = stop_server;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (!load_keys()) { fprintf(stderr, "No se pudieron cargar las claves de laboratorio. Revise keys/ y permisos.\n"); goto error; }
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); goto error; }
    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(SERVER_PORT)};
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) < 0) { perror("bind"); goto error; }
    if (listen(listen_fd, 8) < 0) { perror("listen"); goto error; }

    printf("firmad - Servicio de Firma Electronica Interna (prototipo academico)\n");
    printf("Escuchando en 127.0.0.1:%d | Ed25519 | clave: %s\n", SERVER_PORT, KEY_ID);
    printf("Modo secuencial: un cliente por vez. Ctrl+C para detener.\n");
    fflush(stdout);

    while (running) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR || !running || errno == EBADF) continue;
            perror("accept"); continue;
        }
        serve_client(fd);
        close(fd);
    }
    printf("Servidor detenido.\n");
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    return 0;
error:
    if (listen_fd >= 0) close(listen_fd);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    return 1;
}
