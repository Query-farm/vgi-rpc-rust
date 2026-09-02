#ifndef VGI_IROH_H
#define VGI_IROH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VGI_IROH_ABI_VERSION 1u
#define VGI_IROH_ERROR_MESSAGE_CAPACITY 512u

typedef struct vgi_iroh_endpoint vgi_iroh_endpoint;
typedef struct vgi_iroh_stream vgi_iroh_stream;
typedef struct vgi_iroh_http_response vgi_iroh_http_response;

typedef enum vgi_iroh_result {
    VGI_IROH_OK = 0,
    VGI_IROH_ERROR = 1
} vgi_iroh_result;

typedef enum vgi_iroh_error_stage {
    VGI_IROH_STAGE_PARSE = 1,
    VGI_IROH_STAGE_BIND = 2,
    VGI_IROH_STAGE_RESOLVE = 3,
    VGI_IROH_STAGE_CONNECT = 4,
    VGI_IROH_STAGE_ALPN = 5,
    VGI_IROH_STAGE_OPEN_STREAM = 6,
    VGI_IROH_STAGE_WRITE = 7,
    VGI_IROH_STAGE_READ = 8,
    VGI_IROH_STAGE_CANCEL = 9,
    VGI_IROH_STAGE_SHUTDOWN = 10,
    VGI_IROH_STAGE_INTERNAL = 11
} vgi_iroh_error_stage;

typedef enum vgi_iroh_error_category {
    VGI_IROH_CATEGORY_INVALID_INPUT = 1,
    VGI_IROH_CATEGORY_UNSUPPORTED = 2,
    VGI_IROH_CATEGORY_UNAVAILABLE = 3,
    VGI_IROH_CATEGORY_TIMEOUT = 4,
    VGI_IROH_CATEGORY_PROTOCOL = 5,
    VGI_IROH_CATEGORY_CONNECTION_RESET = 6,
    VGI_IROH_CATEGORY_CANCELLED = 7,
    VGI_IROH_CATEGORY_INTERNAL = 8
} vgi_iroh_error_category;

typedef enum vgi_iroh_dispatch_certainty {
    VGI_IROH_DISPATCH_NOT_SENT = 0,
    VGI_IROH_DISPATCH_UNKNOWN = 1,
    VGI_IROH_DISPATCH_SENT = 2
} vgi_iroh_dispatch_certainty;

/* Source-compatible aliases for the pre-v1 review vocabulary. */
#define VGI_IROH_STAGE_CONFIG VGI_IROH_STAGE_PARSE
#define VGI_IROH_STAGE_ENDPOINT VGI_IROH_STAGE_BIND
#define VGI_IROH_STAGE_WRITE_REQUEST VGI_IROH_STAGE_WRITE
#define VGI_IROH_STAGE_READ_RESPONSE VGI_IROH_STAGE_READ
#define VGI_IROH_STAGE_FINISH VGI_IROH_STAGE_WRITE
#define VGI_IROH_CATEGORY_INVALID_ARGUMENT VGI_IROH_CATEGORY_INVALID_INPUT
#define VGI_IROH_CATEGORY_IO VGI_IROH_CATEGORY_CONNECTION_RESET
#define VGI_IROH_DISPATCH_NOT_APPLICABLE VGI_IROH_DISPATCH_NOT_SENT
#define VGI_IROH_DISPATCH_NOT_DISPATCHED VGI_IROH_DISPATCH_NOT_SENT
#define VGI_IROH_DISPATCH_POSSIBLY_DISPATCHED VGI_IROH_DISPATCH_UNKNOWN
#define VGI_IROH_DISPATCH_DISPATCHED VGI_IROH_DISPATCH_SENT

typedef struct vgi_iroh_error {
    uint32_t stage;
    uint32_t category;
    uint32_t dispatch_certainty;
    char message[VGI_IROH_ERROR_MESSAGE_CAPACITY];
} vgi_iroh_error;

typedef enum vgi_iroh_relay_mode {
    VGI_IROH_RELAY_DEFAULT = 0,
    VGI_IROH_RELAY_DISABLED = 1,
    VGI_IROH_RELAY_CUSTOM = 2
} vgi_iroh_relay_mode;

/* String pointers are borrowed only for the duration of the call. */
typedef struct vgi_iroh_endpoint_config {
    uint32_t abi_version;
    const char *secret_key;
    uint32_t relay_mode;
    const char *const *relay_urls;
    size_t relay_url_count;
    uint64_t connect_timeout_ms;
    uint64_t io_timeout_ms;
} vgi_iroh_endpoint_config;

/* Optional address hints make direct-only and private-network dialing deterministic. */
typedef struct vgi_iroh_remote {
    const char *endpoint_id;
    const char *relay_url;
    const char *const *direct_addresses;
    size_t direct_address_count;
} vgi_iroh_remote;

typedef struct vgi_iroh_header {
    const uint8_t *name;
    size_t name_len;
    const uint8_t *value;
    size_t value_len;
} vgi_iroh_header;

typedef struct vgi_iroh_http_request {
    const char *method;
    const char *path;
    const vgi_iroh_header *headers;
    size_t header_count;
    const uint8_t *body;
    size_t body_len;
} vgi_iroh_http_request;

/* All functions are panic-contained. A non-OK result initializes error.
 * String/header copy calls accept a NULL buffer with zero capacity to query
 * the required length without producing an error. */
uint32_t vgi_iroh_abi_version(void);
vgi_iroh_result vgi_iroh_endpoint_create(const vgi_iroh_endpoint_config *config,
                                         vgi_iroh_endpoint **out,
                                         vgi_iroh_error *error);
void vgi_iroh_endpoint_cancel(vgi_iroh_endpoint *endpoint);
void vgi_iroh_endpoint_free(vgi_iroh_endpoint *endpoint);
vgi_iroh_result vgi_iroh_endpoint_id(const vgi_iroh_endpoint *endpoint,
                                     char *buffer, size_t capacity,
                                     size_t *required,
                                     vgi_iroh_error *error);

vgi_iroh_result vgi_iroh_stream_open(vgi_iroh_endpoint *endpoint,
                                     const vgi_iroh_remote *remote,
                                     vgi_iroh_stream **out,
                                     vgi_iroh_error *error);
/* Open timeout is nonfatal to the shared endpoint and reports OK+timed_out=1. */
vgi_iroh_result vgi_iroh_stream_open_timeout(vgi_iroh_endpoint *endpoint,
                                             const vgi_iroh_remote *remote,
                                             uint64_t timeout_ms,
                                             vgi_iroh_stream **out, uint8_t *timed_out,
                                             vgi_iroh_error *error);
vgi_iroh_result vgi_iroh_stream_remote_id(const vgi_iroh_stream *stream,
                                          char *buffer, size_t capacity,
                                          size_t *required,
                                          vgi_iroh_error *error);
vgi_iroh_result vgi_iroh_stream_read(vgi_iroh_stream *stream,
                                     uint8_t *buffer, size_t capacity,
                                     size_t *read,
                                     vgi_iroh_error *error);
/* A polling timeout is reported as OK with timed_out=1 and does not poison the stream. */
vgi_iroh_result vgi_iroh_stream_read_timeout(vgi_iroh_stream *stream,
                                             uint8_t *buffer, size_t capacity,
                                             uint64_t timeout_ms,
                                             size_t *read, uint8_t *timed_out,
                                             vgi_iroh_error *error);
vgi_iroh_result vgi_iroh_stream_write(vgi_iroh_stream *stream,
                                      const uint8_t *buffer, size_t length,
                                      vgi_iroh_error *error);
/* A write timeout is an error and poisons this logical stream: bytes may have been sent. */
vgi_iroh_result vgi_iroh_stream_write_timeout(vgi_iroh_stream *stream,
                                              const uint8_t *buffer, size_t length,
                                              uint64_t timeout_ms,
                                              vgi_iroh_error *error);
vgi_iroh_result vgi_iroh_stream_finish(vgi_iroh_stream *stream,
                                       vgi_iroh_error *error);
void vgi_iroh_stream_cancel(vgi_iroh_stream *stream);
void vgi_iroh_stream_free(vgi_iroh_stream *stream);

vgi_iroh_result vgi_iroh_http_request_start(vgi_iroh_endpoint *endpoint,
                                            const vgi_iroh_remote *remote,
                                            const vgi_iroh_http_request *request,
                                            vgi_iroh_http_response **out,
                                            vgi_iroh_error *error);
/* Timeout waiting for response headers is an error with unknown dispatch certainty. */
vgi_iroh_result vgi_iroh_http_request_start_timeout(vgi_iroh_endpoint *endpoint,
                                                    const vgi_iroh_remote *remote,
                                                    const vgi_iroh_http_request *request,
                                                    uint64_t timeout_ms,
                                                    vgi_iroh_http_response **out,
                                                    vgi_iroh_error *error);
uint16_t vgi_iroh_http_response_status(const vgi_iroh_http_response *response);
vgi_iroh_result vgi_iroh_http_response_remote_id(const vgi_iroh_http_response *response,
                                                 char *buffer, size_t capacity,
                                                 size_t *required,
                                                 vgi_iroh_error *error);
size_t vgi_iroh_http_response_header_count(const vgi_iroh_http_response *response);
vgi_iroh_result vgi_iroh_http_response_header(const vgi_iroh_http_response *response,
                                              size_t index,
                                              uint8_t *name, size_t name_capacity, size_t *name_required,
                                              uint8_t *value, size_t value_capacity, size_t *value_required,
                                              vgi_iroh_error *error);
vgi_iroh_result vgi_iroh_http_response_read(vgi_iroh_http_response *response,
                                            uint8_t *buffer, size_t capacity,
                                            size_t *read,
                                            vgi_iroh_error *error);
/* A polling timeout is reported as OK with timed_out=1 and does not poison the response. */
vgi_iroh_result vgi_iroh_http_response_read_timeout(vgi_iroh_http_response *response,
                                                    uint8_t *buffer, size_t capacity,
                                                    uint64_t timeout_ms,
                                                    size_t *read, uint8_t *timed_out,
                                                    vgi_iroh_error *error);
void vgi_iroh_http_response_cancel(vgi_iroh_http_response *response);
void vgi_iroh_http_response_free(vgi_iroh_http_response *response);

#ifdef __cplusplus
}
#endif
#endif
