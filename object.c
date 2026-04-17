Complete `object.c` file:

```c
// object.c — Content-addressable object store

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '�';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE)
        return -1;

    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1)
            return -1;
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

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    char type_str[16];

    switch (type) {
        case OBJ_BLOB:
            strcpy(type_str, "blob");
            break;
        case OBJ_TREE:
            strcpy(type_str, "tree");
            break;
        case OBJ_COMMIT:
            strcpy(type_str, "commit");
            break;
        default:
            return -1;
    }

    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;

    size_t full_len = header_len + len;
    unsigned char *full_data = malloc(full_len);
    if (!full_data)
        return -1;

    memcpy(full_data, header, header_len);
    memcpy(full_data + header_len, data, len);

    compute_hash(full_data, full_len, id_out);

    if (object_exists(id_out)) {
        free(full_data);
        return 0;
    }

    mkdir(PES_DIR, 0755);
    mkdir(OBJECTS_DIR, 0755);

    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755);

    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));

    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/tmpXXXXXX", shard_dir);

    int fd = mkstemp(temp_path);
    if (fd < 0) {
        free(full_data);
        return -1;
    }

    ssize_t written = write(fd, full_data, full_len);
    if (written != (ssize_t)full_len) {
        close(fd);
        unlink(temp_path);
        free(full_data);
        return -1;
    }

    if (fsync(fd) < 0) {
        close(fd);
        unlink(temp_path);
        free(full_data);
        return -1;
    }

    close(fd);

    if (rename(temp_path, final_path) < 0) {
        unlink(temp_path);
        free(full_data);
        return -1;
    }

    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    free(full_data);
    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));

    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    if (file_size <= 0) {
        fclose(fp);
        return -1;
    }

    unsigned char *buffer = malloc(file_size);
    if (!buffer) {
        fclose(fp);
        return -1;
    }

    if (fread(buffer, 1, file_size, fp) != (size_t)file_size) {
        fclose(fp);
        free(buffer);
        return -1;
    }

    fclose(fp);

    ObjectID verify;
    compute_hash(buffer, file_size, &verify);

    if (memcmp(verify.hash, id->hash, HASH_SIZE) != 0) {
        free(buffer);
        return -1;
    }

    unsigned char *null_pos = memchr(buffer, '�', file_size);
    if (!null_pos) {
        free(buffer);
        return -1;
    }

    size_t header_len = null_pos - buffer;

    char header[64];
    if (header_len >= sizeof(header)) {
        free(buffer);
        return -1;
    }

    memcpy(header, buffer, header_len);
    header[header_len] = '�';

    char type_str[16];
    size_t data_len;

    if (sscanf(header, "%15s %zu", type_str, &data_len) != 2) {
        free(buffer);
        return -1;
    }

    if (strcmp(type_str, "blob") == 0)
        *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0)
        *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0)
        *type_out = OBJ_COMMIT;
    else {
        free(buffer);
        return -1;
    }

    unsigned char *data_start = null_pos + 1;

    if ((size_t)(buffer + file_size - data_start) != data_len) {
        free(buffer);
        return -1;
    }

    *data_out = malloc(data_len);
    if (!*data_out) {
        free(buffer);
        return -1;
    }

    memcpy(*data_out, data_start, data_len);
    *len_out = data_len;

    free(buffer);
    return 0;
}
```
