#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define RING_MAX_HANDLES 64

typedef struct {
    size_t capacity;
    size_t write_pos;
} ring_header_t;

typedef struct {
    int used;
    int fd;
    size_t map_len;
    uint8_t *map;
    ring_header_t *header;
    uint8_t *data;
    pthread_mutex_t lock;
} ring_handle_t;

static ring_handle_t g_handles[RING_MAX_HANDLES];
static pthread_mutex_t g_handles_lock = PTHREAD_MUTEX_INITIALIZER;

static int build_ring_path(const char *name, char *out, size_t out_len) {
    if (name == NULL || out == NULL || out_len == 0) {
        return EINVAL;
    }

    const char *prefix = "/dev/shm/";
    const char *clean_name = name;
    if (name[0] == '/') {
        clean_name = name + 1;
    }

    int n = snprintf(out, out_len, "%s%s", prefix, clean_name);
    if (n < 0 || (size_t)n >= out_len) {
        return ENAMETOOLONG;
    }
    return 0;
}

int ring_open(const char *name, size_t size, int *out_handle) {
    if (name == NULL || out_handle == NULL || size == 0) {
        return EINVAL;
    }

    char path[PATH_MAX];
    int err = build_ring_path(name, path, sizeof(path));
    if (err != 0) {
        return err;
    }

    const size_t map_len = sizeof(ring_header_t) + size;
    int fd = open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        return errno;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        err = errno;
        close(fd);
        return err;
    }

    if ((size_t)st.st_size != map_len) {
        if (ftruncate(fd, (off_t)map_len) != 0) {
            err = errno;
            close(fd);
            return err;
        }
    }

    uint8_t *map = (uint8_t *)mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        err = errno;
        close(fd);
        return err;
    }

    ring_header_t *header = (ring_header_t *)map;
    uint8_t *data = map + sizeof(ring_header_t);

    if ((size_t)st.st_size != map_len || header->capacity != size || header->write_pos >= size) {
        header->capacity = size;
        header->write_pos = 0;
        memset(data, 0, size);
        (void)msync(map, map_len, MS_SYNC);
    }

    pthread_mutex_lock(&g_handles_lock);
    int slot = -1;
    for (int i = 0; i < RING_MAX_HANDLES; i++) {
        if (!g_handles[i].used) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&g_handles_lock);
        munmap(map, map_len);
        close(fd);
        return EMFILE;
    }

    g_handles[slot].used = 1;
    g_handles[slot].fd = fd;
    g_handles[slot].map_len = map_len;
    g_handles[slot].map = map;
    g_handles[slot].header = header;
    g_handles[slot].data = data;
    pthread_mutex_init(&g_handles[slot].lock, NULL);

    *out_handle = slot;
    pthread_mutex_unlock(&g_handles_lock);
    return 0;
}

int ring_write(int handle, const void *buf, size_t len) {
    if (buf == NULL || len == 0) {
        return EINVAL;
    }
    if (handle < 0 || handle >= RING_MAX_HANDLES) {
        return EBADF;
    }

    ring_handle_t *h = &g_handles[handle];
    if (!h->used || h->header == NULL || h->data == NULL) {
        return EBADF;
    }

    pthread_mutex_lock(&h->lock);

    const size_t cap = h->header->capacity;
    if (cap == 0) {
        pthread_mutex_unlock(&h->lock);
        return EINVAL;
    }

    const uint8_t *src = (const uint8_t *)buf;
    size_t to_write = len;

    if (to_write > cap) {
        src += (to_write - cap);
        to_write = cap;
    }

    size_t pos = h->header->write_pos % cap;
    size_t first = cap - pos;
    if (first > to_write) {
        first = to_write;
    }

    memcpy(h->data + pos, src, first);
    if (to_write > first) {
        memcpy(h->data, src + first, to_write - first);
    }

    h->header->write_pos = (pos + to_write) % cap;
    (void)msync(h->map, h->map_len, MS_ASYNC);

    pthread_mutex_unlock(&h->lock);
    return 0;
}

void ring_close(int handle) {
    if (handle < 0 || handle >= RING_MAX_HANDLES) {
        return;
    }

    pthread_mutex_lock(&g_handles_lock);
    ring_handle_t *h = &g_handles[handle];
    if (!h->used) {
        pthread_mutex_unlock(&g_handles_lock);
        return;
    }

    pthread_mutex_lock(&h->lock);
    h->used = 0;
    if (h->map != NULL && h->map_len > 0) {
        munmap(h->map, h->map_len);
    }
    if (h->fd >= 0) {
        close(h->fd);
    }
    pthread_mutex_unlock(&h->lock);
    pthread_mutex_destroy(&h->lock);

    h->fd = -1;
    h->map_len = 0;
    h->map = NULL;
    h->header = NULL;
    h->data = NULL;

    pthread_mutex_unlock(&g_handles_lock);
}
