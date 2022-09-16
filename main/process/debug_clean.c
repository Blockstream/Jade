#include "../jade_assert.h"
#include "../keychain.h"
#include "../multisig.h"
#include "../otpauth.h"
#include "../process.h"
#include "../storage.h"
#include "../ui.h"

#include "process_utils.h"

#ifdef CONFIG_DEBUG_MODE
void debug_clean_reset_process(void* process_ptr)
{
    JADE_LOGI("Starting: %u", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    // We expect a current message to be present
    ASSERT_CURRENT_MESSAGE(process, "debug_clean_reset");

    // Pop up a notification that the wallet is being wiped
    await_message_activity("Warning: debug wipe wallet");
    vTaskDelay(250 / portTICK_PERIOD_MS);

    // Clean keychain from memory and storage
    keychain_erase_encrypted();
    keychain_clear();

    // Clean pinserver overrides from storage
    storage_erase_pinserver_cert();
    storage_erase_pinserver_details();

    // Clean multisig registrations from storage
    char multisig_names[MAX_MULTISIG_REGISTRATIONS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
    const size_t num_multsig_names = sizeof(multisig_names) / sizeof(multisig_names[0]);
    size_t num_multisigs = 0;
    bool ok = storage_get_all_multisig_registration_names(multisig_names, num_multsig_names, &num_multisigs);
    JADE_ASSERT(ok);

    for (int i = 0; i < num_multisigs; ++i) {
        ok = storage_erase_multisig_registration(multisig_names[i]);
        JADE_ASSERT(ok);
    }

    // Clean OTP registrations from storage
    char otp_names[OTP_MAX_RECORDS][NVS_KEY_NAME_MAX_SIZE]; // Sufficient
    const size_t num_otp_names = sizeof(otp_names) / sizeof(otp_names[0]);
    size_t num_otps = 0;
    ok = storage_get_all_otp_names(otp_names, num_otp_names, &num_otps);
    JADE_ASSERT(ok);

    for (int i = 0; i < num_otps; ++i) {
        ok = storage_erase_otp(otp_names[i]);
        JADE_ASSERT(ok);
    }

    jade_process_reply_to_message_ok(process);
    JADE_LOGI("Success");

    return;
}
#endif // CONFIG_DEBUG_MODE
