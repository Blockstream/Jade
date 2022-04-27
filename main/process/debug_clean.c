#include "../jade_assert.h"
#include "../keychain.h"
#include "../multisig.h"
#include "../process.h"
#include "../storage.h"

#include "process_utils.h"

void debug_clean_reset_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "debug_clean_reset");

    // Clean keychain from memory and storage
    keychain_clear_network_type_restriction();
    keychain_clear();
    storage_erase_encrypted_blob();

    // Clean pinserver overrides from storage
    storage_erase_pinserver_cert();
    storage_erase_pinserver_details();

    // Clean multisig registrations from storage
    char names[MAX_MULTISIG_REGISTRATIONS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
    const size_t names_len = sizeof(names) / sizeof(names[0]);
    size_t num_multisigs = 0;
    bool ok = storage_get_all_multisig_registration_names(names, names_len, &num_multisigs);
    JADE_ASSERT(ok);

    for (int i = 0; i < num_multisigs; ++i) {
        ok = storage_erase_multisig_registration(names[i]);
        JADE_ASSERT(ok);
    }

    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

    return;
}
