#include "../include/lkrequest.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    if (lk_abi_version() != 1) {
        fprintf(stderr, "unexpected abi version\n");
        return 1;
    }

    lk_client_t* client = NULL;
    lk_session_t* session = NULL;
    lk_request_t* request = NULL;
    lk_error_t* error = NULL;

    if (lk_client_new_default(&client, &error) != LK_OK) {
        fprintf(stderr, "lk_client_new_default failed\n");
        return 1;
    }

    if (lk_session_new(client, &session, &error) != LK_OK) {
        fprintf(stderr, "lk_session_new failed\n");
        lk_client_free(client);
        return 1;
    }

    const char* method = "GET";
    const char* url = "://bad";
    if (lk_request_new(
            session,
            method,
            strlen(method),
            url,
            strlen(url),
            &request,
            &error) != LK_OK) {
        fprintf(stderr, "lk_request_new failed\n");
        lk_session_free(session);
        lk_client_free(client);
        return 1;
    }

    lk_response_t* response = NULL;
    if (lk_request_send(request, &response, &error) != LK_ERR) {
        fprintf(stderr, "expected request failure for invalid URL\n");
        if (response != NULL) {
            lk_response_free(response);
        }
        lk_request_free(request);
        lk_session_free(session);
        lk_client_free(client);
        return 1;
    }

    const char* msg_ptr = NULL;
    size_t msg_len = 0;
    if (error == NULL || lk_error_message(error, &msg_ptr, &msg_len) != LK_OK) {
        fprintf(stderr, "missing error message\n");
        lk_request_free(request);
        lk_session_free(session);
        lk_client_free(client);
        return 1;
    }

    printf("abi=%u\n", (unsigned)lk_abi_version());
    printf("library=%s\n", lk_library_version());
    printf("expected error: %.*s\n", (int)msg_len, msg_ptr);

    if (error != NULL) {
        lk_error_free(error);
    }
    lk_request_free(request);
    lk_session_free(session);
    lk_client_free(client);
    return 0;
}
