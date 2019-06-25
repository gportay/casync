/* SPDX-License-Identifier: LGPL-2.1+ */

#include <curl/curl.h>
#include <getopt.h>
#include <stddef.h>
#include <unistd.h>

#include "caprotocol.h"
#include "caremote.h"
#include "cautil.h"
#include "realloc-buffer.h"
#include "parse-util.h"
#include "util.h"
#include "list.h"

static volatile sig_atomic_t quit = false;

static int arg_log_level = -1;
static bool arg_verbose = false;
static curl_off_t arg_rate_limit_bps = 0;

static enum {
        ARG_PROTOCOL_HTTP,
        ARG_PROTOCOL_FTP,
        ARG_PROTOCOL_HTTPS,
        ARG_PROTOCOL_SFTP,
        _ARG_PROTOCOL_INVALID = -1,
} arg_protocol = _ARG_PROTOCOL_INVALID;

typedef enum ProcessUntil {
        PROCESS_UNTIL_WRITTEN,
        PROCESS_UNTIL_CAN_PUT_CHUNK,
        PROCESS_UNTIL_CAN_PUT_INDEX,
        PROCESS_UNTIL_CAN_PUT_ARCHIVE,
        PROCESS_UNTIL_HAVE_REQUEST,
        PROCESS_UNTIL_FINISHED,
} ProcessUntil;

typedef struct CaChunk {
        CaChunkID id;
        CURL *curl;
        ReallocBuffer buffer;
        LIST_FIELDS(struct CaChunk, list);
} CaChunk;

static CaChunk *ca_chunk_new(void);
static CaChunk *ca_chunk_free(CaChunk *c);
static int ca_chunk_acquire_file(CaChunk *c, CURLM *curlm, const char *url, CaChunkID *id);
static int ca_chunk_acquire_file_process(CaChunk *c, CURLM *curlm); /* TODO: find a better name */

typedef struct CaProcess {
        CaRemote *remote;
        CURLM *curlm;
        int still_running;
        LIST_HEAD(CaChunk, chunks);
} CaProcess;

static CaProcess *ca_process_new(CaRemote *rr);
static CaProcess *ca_process_free(CaProcess *p);

static CURLcode robust_curl_easy_perform(CURL *curl) {
        uint64_t sleep_base_usec = 100 * 1000;
        unsigned trial = 1;
        unsigned limit = 10;
        CURLcode c;

        assert(curl);

        while (trial < limit) {

                c = curl_easy_perform(curl);

                switch (c) {

                case CURLE_COULDNT_CONNECT: {
                        uint64_t sleep_usec;

                        /* Although this is not considered as a transient error by curl,
                         * this error can happen momentarily while casync is retrieving
                         * all the chunks from a remote. In this case we want to give
                         * a break to the server and retry later.
                         */

                        sleep_usec = sleep_base_usec * trial;
                        log_info("Could not connect, retrying in %" PRIu64 " ms", sleep_usec / 1000);
                        usleep(sleep_usec);
                        trial++;
                        break;
                }

                default:
                        return c;
                        break;
                }
        }

        return c;
}

static int ca_process_remote(CaProcess *p, ProcessUntil until) {
        CaRemote *rr;
        int r;

        assert(p);
        rr = p->remote;

        for (;;) {

                switch (until) {

                case PROCESS_UNTIL_CAN_PUT_CHUNK:

                        r = ca_remote_can_put_chunk(rr);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether we can add a chunk to the buffer: %m");
                        if (r > 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_CAN_PUT_INDEX:

                        r = ca_remote_can_put_index(rr);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether we can add an index fragment to the buffer: %m");
                        if (r > 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_CAN_PUT_ARCHIVE:

                        r = ca_remote_can_put_archive(rr);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether we can add an archive fragment to the buffer: %m");
                        if (r > 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_HAVE_REQUEST:

                        r = ca_remote_has_pending_requests(rr);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether there are pending requests.");
                        if (r > 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_WRITTEN:
                        r = ca_remote_has_unwritten(rr);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether there's more data to write.");
                        if (r == 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_FINISHED:
                        break;

                default:
                        assert(false);
                }

                r = ca_remote_step(rr);
                if (r == -EPIPE || r == CA_REMOTE_FINISHED) {

                        if (until == PROCESS_UNTIL_FINISHED)
                                return 0;

                        return -EPIPE;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to process remoting engine: %m");

                if (r != CA_REMOTE_POLL)
                        continue;

                if (p->curlm) {
                        do {
                                struct curl_waitfd pollfd[2];
                                CURLMsg *msg;
                                CaChunk *c;
                                int n, msgs_left;

                                if (curl_multi_perform(p->curlm, &p->still_running) != CURLM_OK)
                                        return log_error_errno(EIO, "Failed to call curl_multi_perform");

                                if (p->still_running)
                                        log_debug("Still acquiring %d chunk(s)...", p->still_running);
                                else
                                        log_debug("Waiting for I/O...");

                                r = ca_remote_get_io_fds(rr, &pollfd[0].fd, &pollfd[1].fd);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to get IO fds");

                                r = ca_remote_get_io_events(rr, &pollfd[0].events, &pollfd[1].events);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to get IO events");

                                if (curl_multi_wait(p->curlm, pollfd, 2, 1000, &n) != CURLM_OK)
                                        return log_error_errno(EIO, "Failed to call curl_multi_wait");

                                while ((msg = curl_multi_info_read(p->curlm, &msgs_left))) {
                                        log_debug("%d messages left...", n);
                                        if (msg->msg != CURLMSG_DONE)
                                                continue;

                                        LIST_FOREACH(list, c, p->chunks) {
                                                if (msg->easy_handle == c->curl)
                                                        break;
                                        }

                                        if (!c)
                                                continue;

                                        r = ca_chunk_acquire_file_process(c, p->curlm);
                                        if (r < 0)
                                                return r;

                                        if (r == 0) {
                                                r = ca_process_remote(p, PROCESS_UNTIL_CAN_PUT_CHUNK);
                                                if (r == -EPIPE)
                                                        return r;

                                                r = ca_remote_put_missing(rr, &c->id);
                                                if (r < 0)
                                                        return log_error_errno(r, "Failed to write missing message: %m");

                                                r = ca_process_remote(p, PROCESS_UNTIL_WRITTEN);
                                                if (r == -EPIPE)
                                                        return 0;
                                                if (r < 0)
                                                        return r;
                                        } else {
                                                r = ca_process_remote(p, PROCESS_UNTIL_CAN_PUT_CHUNK);
                                                if (r == -EPIPE)
                                                        return r;

                                                r = ca_remote_put_chunk(rr, &c->id, CA_CHUNK_COMPRESSED, realloc_buffer_data(&c->buffer), realloc_buffer_size(&c->buffer));
                                                if (r < 0)
                                                        return log_error_errno(r, "Failed to write chunk: %m");

                                                r = ca_process_remote(p, PROCESS_UNTIL_WRITTEN);
                                                if (r == -EPIPE)
                                                        return 0;
                                                if (r < 0)
                                                        return r;
                                        }

                                        LIST_REMOVE(list, p->chunks, c);
                                        ca_chunk_free(c);
                                }

                                log_debug("%d event(s)...", n);
                                if (n > 0)
                                        break;
                        } while (p->still_running);

                        continue;
                }

                r = ca_remote_poll(rr, UINT64_MAX, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to poll remoting engine: %m");
        }
}

static size_t write_index(const void *buffer, size_t size, size_t nmemb, void *userdata) {
        CaProcess *p = userdata;
        CaRemote *rr = p->remote;
        size_t product;
        int r;

        product = size * nmemb;

        r = ca_process_remote(p, PROCESS_UNTIL_CAN_PUT_INDEX);
        if (r < 0)
                return 0;

        r = ca_remote_put_index(rr, buffer, product);
        if (r < 0) {
                log_error("Failed to put index: %m");
                return 0;
        }

        r = ca_process_remote(p, PROCESS_UNTIL_WRITTEN);
        if (r < 0)
                return r;

        return product;
}

static int write_index_eof(CaProcess *p) {
        int r;
        CaRemote *rr;

        assert(p);
        assert(p->remote);

        rr = p->remote;

        r = ca_process_remote(p, PROCESS_UNTIL_CAN_PUT_INDEX);
        if (r < 0)
                return r;

        r = ca_remote_put_index_eof(rr);
        if (r < 0)
                return log_error_errno(r, "Failed to put index EOF: %m");

        r = ca_process_remote(p, PROCESS_UNTIL_WRITTEN);
        if (r < 0)
                return r;

        return 0;
}

static size_t write_archive(const void *buffer, size_t size, size_t nmemb, void *userdata) {
        CaProcess *p = userdata;
        CaRemote *rr = p->remote;
        size_t product;
        int r;

        product = size * nmemb;

        r = ca_process_remote(p, PROCESS_UNTIL_CAN_PUT_ARCHIVE);
        if (r < 0)
                return 0;

        r = ca_remote_put_archive(rr, buffer, product);
        if (r < 0) {
                log_error("Failed to put archive: %m");
                return 0;
        }

        r = ca_process_remote(p, PROCESS_UNTIL_WRITTEN);
        if (r < 0)
                return r;

        return product;
}

static int write_archive_eof(CaProcess *p) {
        int r;
        CaRemote *rr;

        assert(p);
        assert(p->remote);

        rr = p->remote;

        r = ca_process_remote(p, PROCESS_UNTIL_CAN_PUT_ARCHIVE);
        if (r < 0)
                return r;

        r = ca_remote_put_archive_eof(rr);
        if (r < 0)
                return log_error_errno(r, "Failed to put archive EOF: %m");

        r = ca_process_remote(p, PROCESS_UNTIL_WRITTEN);
        if (r < 0)
                return r;

        return 0;
}

static size_t write_chunk(const void *buffer, size_t size, size_t nmemb, void *userdata) {
        ReallocBuffer *chunk_buffer = userdata;
        size_t product, z;

        product = size * nmemb;

        z = realloc_buffer_size(chunk_buffer) + product;
        if (z < realloc_buffer_size(chunk_buffer)) {
                log_error("Overflow");
                return 0;
        }

        if (z > (CA_PROTOCOL_SIZE_MAX - offsetof(CaProtocolChunk, data))) {
                log_error("Chunk too large");
                return 0;
        }

        if (!realloc_buffer_append(chunk_buffer, buffer, product)) {
                log_oom();
                return 0;
        }

        return product;
}

static char *chunk_url(const char *store_url, const CaChunkID *id) {
        char ids[CA_CHUNK_ID_FORMAT_MAX], *buffer;
        const char *suffix;
        size_t n;

        /* Chop off URL arguments and multiple trailing dashes, then append the chunk ID and ".cacnk" */

        suffix = ca_compressed_chunk_suffix();

        n = strcspn(store_url, "?;");
        while (n > 0 && store_url[n-1] == '/')
                n--;

        buffer = new(char, n + 1 + 4 + 1 + CA_CHUNK_ID_FORMAT_MAX-1 + strlen(suffix) + 1);
        if (!buffer)
                return NULL;

        ca_chunk_id_format(id, ids);

        strcpy(mempcpy(mempcpy(mempcpy(mempcpy(mempcpy(buffer, store_url, n), "/", 1), ids, 4), "/", 1), ids, CA_CHUNK_ID_FORMAT_MAX-1), suffix);

        return buffer;
}

static int acquire_file(const char *url,
                        size_t (*callback)(const void *p, size_t size, size_t nmemb, void *userdata),
                        void *userdata) {

        long protocol_status;
        CURL *curl;
        int r = 1;

        assert(url);
        assert(callback);

        curl = curl_easy_init();
        if (!curl) {
                r = log_oom();
                goto finish;
        }

        if (curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK) {
                log_error("Failed to turn on location following.");
                r = -EIO;
                goto finish;
        }

        if (curl_easy_setopt(curl, CURLOPT_PROTOCOLS, arg_protocol == ARG_PROTOCOL_FTP ? CURLPROTO_FTP :
                                                      arg_protocol == ARG_PROTOCOL_SFTP? CURLPROTO_SFTP: CURLPROTO_HTTP|CURLPROTO_HTTPS) != CURLE_OK) {
                log_error("Failed to limit protocols to HTTP/HTTPS/FTP/SFTP.");
                r = -EIO;
                goto finish;
        }

        if (IN_SET(arg_protocol, ARG_PROTOCOL_HTTP, ARG_PROTOCOL_HTTPS)) {
                if (curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0) != CURLE_OK)
                        log_error("Failed to set HTTP version to 2.0, ignoring.");
                if (curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L) != CURLE_OK)
                        log_error("Failed to turn on pipelining or multiplexing, ignoring.");
        }

        if (arg_protocol == ARG_PROTOCOL_SFTP) {
                /* activate the ssh agent. For this to work you need
                   to have ssh-agent running (type set | grep SSH_AGENT to check) */
                if (curl_easy_setopt(curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_AGENT) != CURLE_OK)
                        log_error("Failed to turn on ssh agent support, ignoring.");
        }

        if (curl_easy_setopt(curl, CURLOPT_VERBOSE, arg_log_level > 4)) {
                log_error("Failed to set CURL verbosity.");
                r = -EIO;
                goto finish;
        }

        if (arg_rate_limit_bps > 0) {
                if (curl_easy_setopt(curl, CURLOPT_MAX_SEND_SPEED_LARGE, arg_rate_limit_bps) != CURLE_OK) {
                        log_error("Failed to set CURL send speed limit.");
                        r = -EIO;
                        goto finish;
                }

                if (curl_easy_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE, arg_rate_limit_bps) != CURLE_OK) {
                        log_error("Failed to set CURL receive speed limit.");
                        r = -EIO;
                        goto finish;
                }
        }

        if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK) {
                log_error("Failed to set CURL URL to: %s", url);
                r = -EIO;
                goto finish;
        }

        if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback) != CURLE_OK) {
                log_error("Failed to set CURL callback function.");
                r = -EIO;
                goto finish;
        }

        if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, userdata) != CURLE_OK) {
                log_error("Failed to set CURL private data.");
                r = -EIO;
                goto finish;
        }

        log_debug("Acquiring %s...", url);

        if (robust_curl_easy_perform(curl) != CURLE_OK) {
                log_error("Failed to acquire %s", url);
                r = -EIO;
                goto finish;
        }

        if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &protocol_status) != CURLE_OK) {
                log_error("Failed to query response code");
                r = -EIO;
                goto finish;
        }

        if (IN_SET(arg_protocol, ARG_PROTOCOL_HTTP, ARG_PROTOCOL_HTTPS) && protocol_status != 200) {
                if (arg_verbose)
                        log_error("HTTP server failure %li while requesting %s.", protocol_status, url);

                r = 0;
        } else if (arg_protocol == ARG_PROTOCOL_FTP && (protocol_status < 200 || protocol_status > 299)) {
                if (arg_verbose)
                        log_error("FTP server failure %li while requesting %s.", protocol_status, url);

                r = 0;
        } else if (arg_protocol == ARG_PROTOCOL_SFTP && (protocol_status != 0)) {
                if (arg_verbose)
                        log_error("SFTP server failure %li while requesting %s.", protocol_status, url);

                r = 0;
        }

finish:
        if (curl)
                curl_easy_cleanup(curl);

        return r;
}

static CaChunk *ca_chunk_new(void) {
        CaChunk *c;

        c = new0(CaChunk, 1);
        if (!c)
                return NULL;

        LIST_INIT(list, c);

        return c;
}

static CaChunk *ca_chunk_free(CaChunk *c) {
        if (!c)
                return NULL;

        if (c->curl)
                curl_easy_cleanup(c->curl);

        realloc_buffer_free(&c->buffer);

        return mfree(c);
}

static const char *ca_chunk_get_url(CaChunk *c) {
        char *url;

        if (!c)
                return NULL;

        if (curl_easy_getinfo(c->curl, CURLINFO_EFFECTIVE_URL, &url))
                return NULL;

        return url;
}

static int ca_chunk_acquire_file(CaChunk *c, CURLM *curlm, const char *url, CaChunkID *id) {
        CURL *curl;
        int r = 0;

        if (!c)
                return -EINVAL;
        if (!url)
                return -EINVAL;
        if (c->curl)
                return -EBUSY;

        curl = curl_easy_init();
        if (!curl)
                return log_oom();

        if (curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK) {
                log_error("Failed to turn on location following.");
                r = -EIO;
                goto finish;
        }

        if (curl_easy_setopt(curl, CURLOPT_PROTOCOLS, arg_protocol == ARG_PROTOCOL_FTP ? CURLPROTO_FTP :
                                                      arg_protocol == ARG_PROTOCOL_SFTP? CURLPROTO_SFTP: CURLPROTO_HTTP|CURLPROTO_HTTPS) != CURLE_OK) {
                log_error("Failed to limit protocols to HTTP/HTTPS/FTP/SFTP.");
                r = -EIO;
                goto finish;
        }

        if (arg_protocol == ARG_PROTOCOL_SFTP) {
                /* activate the ssh agent. For this to work you need
                   to have ssh-agent running (type set | grep SSH_AGENT to check) */
                if (curl_easy_setopt(curl, CURLOPT_SSH_AUTH_TYPES, CURLSSH_AUTH_AGENT) != CURLE_OK)
                        log_error("Failed to turn on ssh agent support, ignoring.");
        }

        if (curl_easy_setopt(curl, CURLOPT_VERBOSE, arg_log_level > 4)) {
                log_error("Failed to set CURL verbosity.");
                r = -EIO;
                goto finish;
        }

        if (arg_rate_limit_bps > 0) {
                if (curl_easy_setopt(curl, CURLOPT_MAX_SEND_SPEED_LARGE, arg_rate_limit_bps) != CURLE_OK) {
                        log_error("Failed to set CURL send speed limit.");
                        r = -EIO;
                        goto finish;
                }

                if (curl_easy_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE, arg_rate_limit_bps) != CURLE_OK) {
                        log_error("Failed to set CURL receive speed limit.");
                        r = -EIO;
                        goto finish;
                }
        }

        if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK) {
                log_error("Failed to set CURL URL to: %s", url);
                r = -EIO;
                goto finish;
        }

        if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_chunk) != CURLE_OK) {
                log_error("Failed to set CURL callback function.");
                r = -EIO;
                goto finish;
        }

        if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &c->buffer) != CURLE_OK) {
                log_error("Failed to set CURL private data.");
                r = -EIO;
                goto finish;
        }

        memcpy(&c->id, id, sizeof(*id)); /* TODO: remove memcpy */
        log_debug("Acquiring %s...", url);

        if (curlm) {
                c->curl = curl;

                if (curl_multi_add_handle(curlm, curl) != CURLM_OK) {
                        log_error("Failed to call curl_multi_add_handle for %s", url);
                        r = -EIO;
                        goto finish;
                }

                return 1;
        }

        if (robust_curl_easy_perform(curl) != CURLE_OK) {
                log_error("Failed to acquire %s", url);
                r = -EIO;
                goto finish;
        }

        r = ca_chunk_acquire_file_process(c, curlm);

finish:
        curl_easy_cleanup(curl);

        return r;
}

static int ca_chunk_acquire_file_process(CaChunk *c, CURLM *curlm) {
        long protocol_status;
        CURL *curl;
        int r = 0;

        if (!c)
                return -EINVAL;

        assert(c->curl);

        curl = c->curl;

        if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &protocol_status) != CURLE_OK) {
                log_error("Failed to query response code");
                r = -EIO;
                goto finish;
        }

        if (IN_SET(arg_protocol, ARG_PROTOCOL_HTTP, ARG_PROTOCOL_HTTPS) && protocol_status != 200) {
                if (arg_verbose)
                        log_error("HTTP server failure %li while requesting %s.", protocol_status, ca_chunk_get_url(c));

                r = 0;
        } else if (arg_protocol == ARG_PROTOCOL_FTP && (protocol_status < 200 || protocol_status > 299)) {
                if (arg_verbose)
                        log_error("FTP server failure %li while requesting %s.", protocol_status, ca_chunk_get_url(c));

                r = 0;
        } else if (arg_protocol == ARG_PROTOCOL_SFTP && (protocol_status != 0)) {
                if (arg_verbose)
                        log_error("SFTP server failure %li while requesting %s.", protocol_status, ca_chunk_get_url(c));

                r = 0;
        } else
                r = 1;

finish:
        if (curlm)
                if (curl_multi_remove_handle(curlm, curl) != CURLM_OK)
                        log_error("Failed to call curl_multi_remove_handle for %s", ca_chunk_get_url(c));

        curl_easy_cleanup(curl);
        c->curl = NULL;

        return r;
}

static CaProcess *ca_process_new(CaRemote *rr) {
        CaProcess *p;
        CURLM *curlm;

        if (!rr)
                return NULL;

        p = new0(CaProcess, 1);
        if (!p)
                return NULL;

        LIST_HEAD_INIT(p->chunks);

        curlm = curl_multi_init();
        if (!curlm) {
                free(p);
                return NULL;
        }

        /* libcurl:
         * CURLMOPT_PIPELINING - enable HTTP pipelining and multiplexing
         * Added in 7.16.0. Multiplex support bit added in 7.43.0. HTTP/1 Pipelining support was disabled in 7.62.0. 
         * Since 7.62.0, CURLPIPE_MULTIPLEX is enabled by default. Before that, default was CURLPIPE_NOTHING.
         */
        if (curl_multi_setopt(curlm, CURLMOPT_PIPELINING, (long)CURLPIPE_HTTP1|CURLPIPE_MULTIPLEX) != CURLM_OK)
                log_error("Failed to turn on pipelining or multiplexing, ignoring.");

        p->curlm = curlm;
        p->remote = rr;
        return p;
}

static CaProcess *ca_process_free(CaProcess *p) {
        CaChunk *c;

        if (!p)
                return NULL;

        LIST_FOREACH(list, c, p->chunks) {
                ca_chunk_free(c);
        }

        if (p->curlm)
                curl_multi_cleanup(p->curlm);

        return mfree(p);
}

static int run(int argc, char *argv[]) {
        const char *base_url, *archive_url, *index_url, *wstore_url;
        size_t n_stores = 0, current_store = 0;
        CaProcess *p = NULL;
        CaChunk *c = NULL;
        _cleanup_(ca_remote_unrefp) CaRemote *rr = NULL;
        _cleanup_(realloc_buffer_free) ReallocBuffer chunk_buffer = {};
        _cleanup_free_ char *url_buffer = NULL;
        int r;

        if (argc < _CA_REMOTE_ARG_MAX) {
                log_error("Expected at least %d arguments.", _CA_REMOTE_ARG_MAX);
                return -EINVAL;
        }

        /* fprintf(stderr, "base=%s archive=%s index=%s wstore=%s\n", argv[1], argv[2], argv[3], argv[4]); */

        base_url = empty_or_dash_to_null(argv[CA_REMOTE_ARG_BASE_URL]);
        archive_url = empty_or_dash_to_null(argv[CA_REMOTE_ARG_ARCHIVE_URL]);
        index_url = empty_or_dash_to_null(argv[CA_REMOTE_ARG_INDEX_URL]);
        wstore_url = empty_or_dash_to_null(argv[CA_REMOTE_ARG_WSTORE_URL]);

        n_stores = !!wstore_url + (argc - _CA_REMOTE_ARG_MAX);

        if (base_url) {
                log_error("Pushing/pulling to base via HTTP not yet supported.");
                return -EOPNOTSUPP;
        }

        if (!archive_url && !index_url && n_stores == 0) {
                log_error("Nothing to do.");
                return -EINVAL;
        }

        rr = ca_remote_new();
        if (!rr) {
                r = log_oom();
                goto finish;
        }

        r = ca_remote_set_local_feature_flags(rr,
                                              (n_stores > 0 ? CA_PROTOCOL_READABLE_STORE : 0) |
                                              (index_url ? CA_PROTOCOL_READABLE_INDEX : 0) |
                                              (archive_url ? CA_PROTOCOL_READABLE_ARCHIVE : 0));
        if (r < 0) {
                log_error("Failed to set feature flags: %m");
                goto finish;
        }

        r = ca_remote_set_io_fds(rr, STDIN_FILENO, STDOUT_FILENO);
        if (r < 0) {
                log_error("Failed to set I/O file descriptors: %m");
                goto finish;
        }

        p = ca_process_new(rr);
        if (!p) {
                r = log_oom();
                goto finish;
        }

        if (archive_url) {
                r = acquire_file(archive_url, write_archive, p);
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        (void) ca_remote_abort(rr, EBADR, "Failed");
                        goto flush;
                }

                r = write_archive_eof(p);
                if (r < 0)
                        goto finish;
        }

        if (index_url) {
                r = acquire_file(index_url, write_index, p);
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        (void) ca_remote_abort(rr, EBADR, "Failed");
                        goto flush;
                }

                r = write_index_eof(p);
                if (r < 0)
                        goto finish;
        }

        for (;;) {
                const char *store_url;
                CaChunkID id;

                if (quit) {
                        log_info("Got exit signal, quitting.");
                        r = 0;
                        goto finish;
                }

                if (n_stores == 0)  /* No stores? Then we did all we could do */
                        goto flush;

                r = ca_process_remote(p, PROCESS_UNTIL_HAVE_REQUEST);
                if (r == -EPIPE) {
                        r = 0;
                        goto finish;
                }
                if (r < 0)
                        goto finish;

                r = ca_remote_next_request(rr, &id);
                if (r == -ENODATA)
                        continue;
                if (r < 0) {
                        log_error_errno(r, "Failed to determine next chunk to get: %m");
                        goto finish;
                }

                current_store = current_store % n_stores;
                if (wstore_url)
                        store_url = current_store == 0 ? wstore_url : argv[current_store + _CA_REMOTE_ARG_MAX - 1];
                else
                        store_url = argv[current_store + _CA_REMOTE_ARG_MAX];
                /* current_store++; */

                free(url_buffer);
                url_buffer = chunk_url(store_url, &id);
                if (!url_buffer) {
                        r = log_oom();
                        ca_chunk_free(c);
                        goto finish;
                }

                c = ca_chunk_new();
                if (!c) {
                        r = log_oom();
                        goto finish;
                }

                r = ca_chunk_acquire_file(c, p->curlm, url_buffer, &id);
                if (r < 0) {
                        ca_chunk_free(c);
                        goto finish;
                }

                LIST_APPEND(list, p->chunks, c);
        }

flush:
        r = ca_process_remote(p, PROCESS_UNTIL_FINISHED);

finish:
        ca_process_free(p);

        return r;
}

static void help(void) {
        printf("%s -- casync HTTP helper. Do not execute manually.\n", program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_RATE_LIMIT_BPS = 0x100,
        };

        static const struct option options[] = {
                { "help",           no_argument,       NULL, 'h'                },
                { "log-level",      required_argument, NULL, 'l'                },
                { "verbose",        no_argument,       NULL, 'v'                },
                { "rate-limit-bps", required_argument, NULL, ARG_RATE_LIMIT_BPS },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        if (strstr(argv[0], "https"))
                arg_protocol = ARG_PROTOCOL_HTTPS;
        else if (strstr(argv[0], "http"))
                arg_protocol = ARG_PROTOCOL_HTTP;
        else if (strstr(argv[0], "sftp"))
                arg_protocol = ARG_PROTOCOL_SFTP;
        else if (strstr(argv[0], "ftp"))
                arg_protocol = ARG_PROTOCOL_FTP;
        else {
                log_error("Failed to determine set of protocols to use, refusing.");
                return -EINVAL;
        }

        if (getenv_bool("CASYNC_VERBOSE") > 0)
                arg_verbose = true;

        while ((c = getopt_long(argc, argv, "hl:v", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case 'l':
                        r = set_log_level_from_string(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse log level \"%s\": %m", optarg);

                        arg_log_level = r;

                        break;

                case 'v':
                        arg_verbose = true;
                        break;

                case ARG_RATE_LIMIT_BPS:
                        r = parse_size(optarg, (uint64_t *)&arg_rate_limit_bps);
                        if (r < 0)
                                return log_error_errno(r, "Unable to parse rate limit %s: %m", optarg);
                        if (arg_rate_limit_bps == 0 || arg_rate_limit_bps > UINT32_MAX)
                                return log_error_errno(EINVAL, "Rate limit size cannot be zero or is out of range.");

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert(false);
                }
        }

        return 1;
}

static void exit_signal_handler(int signo) {
        quit = true;
}

int main(int argc, char* argv[]) {
        static const struct sigaction ign_sa = {
                .sa_handler = SIG_IGN,
                .sa_flags = SA_RESTART,
        };
        static const struct sigaction exit_sa = {
                .sa_handler = exit_signal_handler,
        };

        int r;

        assert_se(sigaction(SIGPIPE, &ign_sa, NULL) >= 0);
        assert_se(sigaction(SIGINT, &exit_sa, NULL) >= 0);
        assert_se(sigaction(SIGTERM, &exit_sa, NULL) >= 0);
        assert_se(sigaction(SIGHUP, &exit_sa, NULL) >= 0);

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        if (optind >= argc) {
                log_error("Verb expected.");
                r = -EINVAL;
                goto finish;
        }

        if (streq(argv[optind], "pull"))
                r = run(argc - optind, argv + optind);
        else {
                log_error("Unknown verb: %s", argv[optind]);
                r = -EINVAL;
        }

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
