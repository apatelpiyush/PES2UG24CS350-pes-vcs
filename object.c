// object.c — Content-addressable object store

#include "pes.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

static const char *object_type_string(ObjectType type) {
    switch (type) {
    case OBJ_BLOB:   return "blob";
    case OBJ_TREE:   return "tree";
    case OBJ_COMMIT: return "commit";
    default:         return NULL;
    }
}

static int parse_type_string(const char *s, ObjectType *out) {
    if (strcmp(s, "blob") == 0)   { *out = OBJ_BLOB;   return 0; }
    if (strcmp(s, "tree") == 0)   { *out = OBJ_TREE;   return 0; }
    if (strcmp(s, "commit") == 0) { *out = OBJ_COMMIT; return 0; }
    return -1;
}

// ─── object_write / object_read ─────────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str = object_type_string(type);
    if (!type_str || !id_out) return -1;

    char header[128];
    int hn = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (hn < 0 || (size_t)hn >= sizeof(header)) return -1;
    size_t header_len = (size_t)hn + 1;

    size_t total = header_len + len;
    unsigned char *buf = malloc(total);
    if (!buf) return -1;

    memcpy(buf, header, header_len);
    memcpy(buf + header_len, data, len);

    compute_hash(buf, total, id_out);

    if (object_exists(id_out)) {
        free(buf);
        return 0;
    }

    
