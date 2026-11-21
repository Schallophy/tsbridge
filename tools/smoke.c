// Minimal smoke test for the C ABI: the calls a shell makes before it has a
// server, plus the ownership rule for every returned string.
//
// Build (Windows, from a VS developer prompt):
//   cl /nologo /Iinclude tools\smoke.c tsbridge.lib && smoke.exe
// Build (Linux/macOS):
//   cc -Iinclude tools/smoke.c -Ltarget/debug -ltsbridge -o smoke && ./smoke
//
// It deliberately never connects: a test that needs a server is not a smoke test.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tsbridge.h"

int main(void) {
    assert(tsbridge_abi_version() == TSBRIDGE_ABI_VERSION);

    char *info = tsbridge_info_json();
    assert(info != NULL);
    printf("info: %s\n", info);
    assert(strstr(info, "\"abi\"") != NULL);
    assert(strstr(info, "\"tsclientlib\"") != NULL);
    tsbridge_string_free(info);

    /* A malformed config must return NULL, not crash or half-open a session. */
    assert(tsbridge_create(NULL) == NULL);
    assert(tsbridge_create("{}") == NULL);
    assert(tsbridge_create("{\"address\":\"\"}") == NULL);

    /* Every accessor accepts NULL and answers with the "nothing" value. */
    assert(!tsbridge_is_connected(NULL));
    assert(tsbridge_snapshot_json(NULL) == NULL);
    assert(tsbridge_identity(NULL) == NULL);
    tsbridge_disconnect(NULL);
    tsbridge_audio_reset(NULL);
    assert(tsbridge_audio_write(NULL, NULL, 0) == 0);
    assert(tsbridge_audio_read(NULL, NULL, 0) == 0);
    tsbridge_destroy(NULL);

    /* Events on a NULL handle are an empty array, not NULL: a shell can decode
       it without a special case. */
    char *events = tsbridge_poll_events_json(NULL);
    assert(events != NULL);
    assert(strcmp(events, "[]") == 0);
    tsbridge_string_free(events);

    /* Freeing NULL is allowed, which is what makes `defer` a safe habit. */
    tsbridge_string_free(NULL);

    puts("c abi smoke test passed");
    return 0;
}
