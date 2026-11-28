// Minimal smoke test for the C ABI: the calls a shell makes before it has a
// server, plus the ownership rule for every returned string.
//
// Build (Windows, from a VS developer prompt):
//   cl /nologo /Iinclude tools\smoke.c litespeak.lib && smoke.exe
// Build (Linux/macOS):
//   cc -Iinclude tools/smoke.c -Ltarget/debug -llitespeak -o smoke && ./smoke
//
// It deliberately never connects: a test that needs a server is not a smoke test.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "litespeak.h"

int main(void) {
    assert(litespeak_abi_version() == LITESPEAK_ABI_VERSION);

    char *info = litespeak_info_json();
    assert(info != NULL);
    printf("info: %s\n", info);
    assert(strstr(info, "\"abi\"") != NULL);
    assert(strstr(info, "\"tsclientlib\"") != NULL);
    litespeak_string_free(info);

    /* A malformed config must return NULL, not crash or half-open a session. */
    assert(litespeak_create(NULL) == NULL);
    assert(litespeak_create("{}") == NULL);
    assert(litespeak_create("{\"address\":\"\"}") == NULL);

    /* An account handle needs no address, and its snapshot carries the account
       object the login pane reads. This is what makes sign-in-before-connect
       possible from a C shell. */
    LiteSpeakSession *account = litespeak_create_account("{}");
    assert(account != NULL);
    char *account_state = litespeak_snapshot_json(account);
    assert(account_state != NULL);
    assert(strstr(account_state, "\"account\"") != NULL);
    litespeak_string_free(account_state);

    assert(litespeak_create_account("{not json") == NULL);
    /* A null account connects without the proof; the connection config is still
       validated, so an empty one is rejected. */
    assert(litespeak_create_with_account(NULL, "{}") == NULL);
    litespeak_destroy(account);

    /* Every accessor accepts NULL and answers with the "nothing" value. */
    assert(!litespeak_is_connected(NULL));
    assert(litespeak_snapshot_json(NULL) == NULL);
    assert(litespeak_identity(NULL) == NULL);
    litespeak_disconnect(NULL);
    litespeak_audio_reset(NULL);
    assert(litespeak_audio_write(NULL, NULL, 0) == 0);
    assert(litespeak_audio_read(NULL, NULL, 0) == 0);
    litespeak_destroy(NULL);

    /* Events on a NULL handle are an empty array, not NULL: a shell can decode
       it without a special case. */
    char *events = litespeak_poll_events_json(NULL);
    assert(events != NULL);
    assert(strcmp(events, "[]") == 0);
    litespeak_string_free(events);

    /* Freeing NULL is allowed, which is what makes `defer` a safe habit. */
    litespeak_string_free(NULL);

    puts("c abi smoke test passed");
    return 0;
}
