/* SPDX-License-Identifier: LGPL-2.1+ */

#include <curl/curl.h>
#include <getopt.h>
#include <stddef.h>
#include <unistd.h>

#include "caprotocol.h"
#include "caremote.h"
#include "cautil.h"
#include "realloc-buffer.h"
#include "util.h"
#include "list.h"

static volatile sig_atomic_t quit = false;

static int arg_log_level = -1;
static bool arg_verbose = false;
static curl_off_t arg_rate_limit_bps = 0;
static long arg_max_host_connections = 1;

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
        PROCESS_UNTIL_ACQUIRE_COMPLETED,
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

static int process_remote(CaRemote *rr, ProcessUntil until) {
        int r;

        assert(rr);

        for (;;) {

                switch (until) {

                case PROCESS_UNTIL_CAN_PUT_CHUNK:

                        r = ca_remote_can_put_chunk(rr);
                        fprintf(stderr, "[%i] %s@%i PROCESS_UNTIL_CAN_PUT_CHUNK, r: %i\n", getpid(), __func__, __LINE__, r);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether we can add a chunk to the buffer: %m");
                        if (r > 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_CAN_PUT_INDEX:

                        r = ca_remote_can_put_index(rr);
                        fprintf(stderr, "[%i] %s@%i PROCESS_UNTIL_CAN_PUT_INDEX, r: %i\n", getpid(), __func__, __LINE__, r);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether we can add an index fragment to the buffer: %m");
                        if (r > 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_CAN_PUT_ARCHIVE:

                        r = ca_remote_can_put_archive(rr);
                        fprintf(stderr, "[%i] %s@%i PROCESS_UNTIL_CAN_PUT_ARCHIVE, r: %i\n", getpid(), __func__, __LINE__, r);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether we can add an archive fragment to the buffer: %m");
                        if (r > 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_HAVE_REQUEST:

                        r = ca_remote_has_pending_requests(rr);
                        fprintf(stderr, "[%i] %s@%i PROCESS_UNTIL_HAVE_REQUEST, r: %i\n", getpid(), __func__, __LINE__, r);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether there are pending requests.");
                        return r;

                        break;

                case PROCESS_UNTIL_WRITTEN:

                        r = ca_remote_has_unwritten(rr);
                        fprintf(stderr, "[%i] %s@%i PROCESS_UNTIL_WRITTEN, r: %i\n", getpid(), __func__, __LINE__, r);
                        if (r == -EPIPE)
                                return r;
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether there's more data to write.");
                        if (r == 0)
                                return 0;

                        break;

                case PROCESS_UNTIL_FINISHED:

                        fprintf(stderr, "[%i] %s@%i PROCESS_UNTIL_FINISHED\n", getpid(), __func__, __LINE__);
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

                r = ca_remote_poll(rr, UINT64_MAX, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to poll remoting engine: %m");
        }
}

static size_t write_index(const void *buffer, size_t size, size_t nmemb, void *userdata) {
        CaRemote *rr = userdata;
        size_t product;
        int r;

        product = size * nmemb;

        r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_INDEX);
        if (r < 0)
                return 0;

        r = ca_remote_put_index(rr, buffer, product);
        if (r < 0) {
                log_error("Failed to put index: %m");
                return 0;
        }

        r = process_remote(rr, PROCESS_UNTIL_WRITTEN);
        if (r < 0)
                return r;

        return product;
}

static int write_index_eof(CaRemote *rr) {
        int r;

        assert(rr);

        r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_INDEX);
        if (r < 0)
                return r;

        r = ca_remote_put_index_eof(rr);
        if (r < 0)
                return log_error_errno(r, "Failed to put index EOF: %m");

        r = process_remote(rr, PROCESS_UNTIL_WRITTEN);
        if (r < 0)
                return r;

        return 0;
}

static size_t write_archive(const void *buffer, size_t size, size_t nmemb, void *userdata) {
        CaRemote *rr = userdata;
        size_t product;
        int r;

        product = size * nmemb;

        r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_ARCHIVE);
        if (r < 0)
                return 0;

        r = ca_remote_put_archive(rr, buffer, product);
        if (r < 0) {
                log_error("Failed to put archive: %m");
                return 0;
        }

        r = process_remote(rr, PROCESS_UNTIL_WRITTEN);
        if (r < 0)
                return r;

        return product;
}

static int write_archive_eof(CaRemote *rr) {
        int r;

        assert(rr);

        r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_ARCHIVE);
        if (r < 0)
                return r;

        r = ca_remote_put_archive_eof(rr);
        if (r < 0)
                return log_error_errno(r, "Failed to put archive EOF: %m");

        r = process_remote(rr, PROCESS_UNTIL_WRITTEN);
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

static int acquire_file(CURLM *curlm,
                        const char *url,
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

        if (curlm) {
                if (curl_multi_add_handle(curlm, curl) != CURLM_OK) {
                        log_error("Failed to acquire %s", url);
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
                        log_error("Failed to acquire %s", url);
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
        if (curlm) {
                curl_multi_remove_handle(curlm, curl);
        }

        curl_easy_cleanup(curl);
        c->curl = NULL;

        return r;
}

static int run(int argc, char *argv[]) {
        const char *base_url, *archive_url, *index_url, *wstore_url;
        size_t n_stores = 0, current_store = 0;
        CURLM *curlm = NULL;
        CaChunk *c;
        LIST_HEAD(CaChunk, chunks);
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

        if (archive_url) {
                r = acquire_file(curlm, archive_url, write_archive, rr);
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        (void) ca_remote_abort(rr, EBADR, "Failed");
                        goto flush;
                }

                r = write_archive_eof(rr);
                if (r < 0)
                        goto finish;
        }

        if (index_url) {
                r = acquire_file(curlm, index_url, write_index, rr);
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        (void) ca_remote_abort(rr, EBADR, "Failed");
                        goto flush;
                }

                r = write_index_eof(rr);
                if (r < 0)
                        goto finish;
        }

#if 1
        curlm = curl_multi_init();
        if (!curlm) {
                r = log_oom();
                goto finish;
        }
#else
        curlm = NULL;
#endif

        /* libcurl:
	 * CURLMOPT_PIPELINING - enable HTTP pipelining and multiplexing
	 * Added in 7.16.0. Multiplex support bit added in 7.43.0. HTTP/1 Pipelining support was disabled in 7.62.0. 
	 * Since 7.62.0, CURLPIPE_MULTIPLEX is enabled by default. Before that, default was CURLPIPE_NOTHING.
	 */
        if (curl_multi_setopt(curlm, CURLMOPT_PIPELINING, (long)CURLPIPE_HTTP1|CURLPIPE_MULTIPLEX) != CURLM_OK)
                log_error("Failed to turn on pipelining or multiplexing, ignoring.");

        if (curl_multi_setopt(curlm, CURLMOPT_MAX_HOST_CONNECTIONS, arg_max_host_connections) != CURLM_OK)
                log_error("Failed to set max host connections.");

        LIST_HEAD_INIT(chunks);

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

                r = process_remote(rr, PROCESS_UNTIL_HAVE_REQUEST);
                if (r == -EPIPE) {
                        r = 0;
                        goto finish;
                }
                if (r < 0)
                        goto finish;
#if 1
                if (curlm && r == 0)
                        break;
#endif

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
                        goto finish;
                }

                if (curlm) {
                        c = ca_chunk_new(); /* TODO: use ref/unref and allocate a CaChunk for easy too to share the code */
                        if (!c) {
                                r = log_oom();
                                goto finish;
                        }

                        r = ca_chunk_acquire_file(c, curlm, url_buffer, &id);
                        if (r < 0)
                                goto finish;

                        LIST_APPEND(list, chunks, c);
                        continue;
                }

                r = acquire_file(curlm, url_buffer, write_chunk, &chunk_buffer);
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_CHUNK);
                        if (r == -EPIPE) {
                                r = 0;
                                goto finish;
                        }

                        r = ca_remote_put_missing(rr, &id);
                        if (r < 0) {
                                log_error_errno(r, "Failed to write missing message: %m");
                                goto finish;
                        }
                } else {
                        r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_CHUNK);
                        if (r == -EPIPE) {
                                r = 0;
                                goto finish;
                        }

                        r = ca_remote_put_chunk(rr, &id, CA_CHUNK_COMPRESSED, realloc_buffer_data(&chunk_buffer), realloc_buffer_size(&chunk_buffer));
                        if (r < 0) {
                                log_error_errno(r, "Failed to write chunk: %m");
                                goto finish;
                        }
                }

                realloc_buffer_empty(&chunk_buffer);

                r = process_remote(rr, PROCESS_UNTIL_WRITTEN);
                if (r == -EPIPE) {
                        r = 0;
                        goto finish;
                }
                if (r < 0)
                        goto finish;
        }

        if (!curlm)
                goto flush;

        LIST_FOREACH(list, c, chunks) {
                fprintf(stderr, "url: %s\n", ca_chunk_get_url(c));
        }

        int still_running = 0; /* keep number of running handles */
        CURLMsg *msg; /* for picking up messages with the transfer status */
        int msgs_left; /* how many messages are left */

        /* we start some action by calling perform right away */
        curl_multi_perform(curlm, &still_running);

fprintf(stderr, "still_running: %i\n", still_running);
        while (still_running) {
                struct timeval timeout;
                int rc; /* select() return code */
                CURLMcode mc; /* curl_multi_fdset() return code */

                fd_set fdread;
                fd_set fdwrite;
                fd_set fdexcep;
                int maxfd = -1;

                long curl_timeo = -1;

                FD_ZERO(&fdread);
                FD_ZERO(&fdwrite);
                FD_ZERO(&fdexcep);

                /* set a suitable timeout to play around with */
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;

                curl_multi_timeout(curlm, &curl_timeo);
                if (curl_timeo >= 0) {
                        timeout.tv_sec = curl_timeo / 1000;
                        if (timeout.tv_sec > 1)
                                timeout.tv_sec = 1;
                        else
                                timeout.tv_usec = (curl_timeo % 1000) * 1000;
                }

                /* get file descriptors from the transfers */
                mc = curl_multi_fdset(curlm, &fdread, &fdwrite, &fdexcep, &maxfd);

                if (mc != CURLM_OK) {
                        fprintf(stderr, "curl_multi_fdset() failed, code %d.\n", mc);
                        break;
                }

                /* On success the value of maxfd is guaranteed to be >= -1. We call
                 * select(maxfd + 1, ...); specially in case of (maxfd == -1) there are
                 * no fds ready yet so we call select(0, ...) --or Sleep() on Windows--
                 * to sleep 100ms, which is the minimum suggested value in the
                 * curl_multi_fdset() doc. */

                if (maxfd == -1) {
                        /* Portable sleep for platforms other than Windows. */
                        struct timeval wait = { 0, 100 * 1000 }; /* 100ms */
                        rc = select(0, NULL, NULL, NULL, &wait);
                } else {
                        /* Note that on some platforms 'timeout' may be modified by select().
                         * If you need access to the original value save a copy beforehand. */
                        rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);
                }

                switch (rc) {
                        case -1:
                                perror("select");
                                /* select error */
                                break;
                        case 0: /* timeout */
                                perror("select");
                                /* fallthrough */
                        default: /* action */
                                curl_multi_perform(curlm, &still_running);
                                fprintf(stderr, "still_running: %i...\n", still_running);
                                break;
                }
        }

        /* See how the transfers went */
static int done = 0;
        while ((msg = curl_multi_info_read(curlm, &msgs_left))) {
                if (msg->msg == CURLMSG_DONE) {
                        LIST_FOREACH(list, c, chunks) {
                                int found = (msg->easy_handle == c->curl);
                                if (found)
                                        break;
                        }

                        if (!c)
{
        fprintf(stderr, "No found!\n");
                                continue;
}

fprintf(stderr, "url: %s, done: %i\n", ca_chunk_get_url(c), ++done);

                        LIST_REMOVE(list, chunks, c);

                        r = ca_chunk_acquire_file_process(c, curlm);
                        if (r < 0)
                                goto finish;
                        if (r == 0) {
                                r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_CHUNK);
                                if (r == -EPIPE) {
                                        r = 0;
                                        goto finish;
                                }

                                r = ca_remote_put_missing(rr, &c->id);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to write missing message: %m");
                                        goto finish;
                                }

                                r = process_remote(rr, PROCESS_UNTIL_WRITTEN);
                                if (r == -EPIPE) {
                                        r = 0;
                                        goto finish;
                                }
                                if (r < 0)
                                        goto finish;
                        } else {
                                r = process_remote(rr, PROCESS_UNTIL_CAN_PUT_CHUNK);
                                if (r == -EPIPE) {
                                        r = 0;
                                        goto finish;
                                }

                                r = ca_remote_put_chunk(rr, &c->id, CA_CHUNK_COMPRESSED, realloc_buffer_data(&c->buffer), realloc_buffer_size(&c->buffer));
                                if (r < 0) {
                                        log_error_errno(r, "Failed to write chunk: %m");
                                        goto finish;
                                }

                                r = process_remote(rr, PROCESS_UNTIL_WRITTEN);
                                if (r == -EPIPE) {
                                        r = 0;
                                        goto finish;
                                }
                                if (r < 0)
                                        goto finish;
                        }
                }
        }
fprintf(stderr, "Terminated! done: %i\n", done);

flush:
        r = process_remote(rr, PROCESS_UNTIL_FINISHED);

finish:
        if (curlm)
                curl_multi_cleanup(curlm);

        LIST_FOREACH(list, c, chunks) {
                ca_chunk_free(c);
        }

        return r;
}

static void help(void) {
        printf("%s -- casync HTTP helper. Do not execute manually.\n", program_invocation_short_name);
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_RATE_LIMIT_BPS = 0x100,
                ARG_MAX_HOST_CONNECTIONS,
        };

        static const struct option options[] = {
                { "help",                 no_argument,       NULL, 'h'                      },
                { "log-level",            required_argument, NULL, 'l'                      },
                { "verbose",              no_argument,       NULL, 'v'                      },
                { "rate-limit-bps",       required_argument, NULL, ARG_RATE_LIMIT_BPS       },
                { "max-host-connections", required_argument, NULL, ARG_MAX_HOST_CONNECTIONS },
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
                        arg_rate_limit_bps = strtoll(optarg, NULL, 10);
                        break;

                case ARG_MAX_HOST_CONNECTIONS:
                        arg_max_host_connections = strtoll(optarg, NULL, 10);
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
