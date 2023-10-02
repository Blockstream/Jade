#include "../button_events.h"
#include "../jade_assert.h"
#include "../storage.h"
#include "../ui.h"

#define UPDATE_WALLET_CAROUSEL(i)                                                                                      \
    do {                                                                                                               \
        if (i < num_multisigs) {                                                                                       \
            gui_update_text(label, "Multisig Wallet");                                                                 \
            gui_update_text(walletname, multisig_names[selected]);                                                     \
        } else if (i < num_registered_wallets) {                                                                       \
            gui_update_text(label, "Descriptor Wallet");                                                               \
            gui_update_text(walletname, descriptor_names[i - num_multisigs]);                                          \
        } else {                                                                                                       \
            gui_update_text(label, "");                                                                                \
            gui_update_text(walletname, "[Cancel]");                                                                   \
        }                                                                                                              \
    } while (false)

bool select_registered_wallet(const char multisig_names[][NVS_KEY_NAME_MAX_SIZE], const size_t num_multisigs,
    const char descriptor_names[][NVS_KEY_NAME_MAX_SIZE], const size_t num_descriptors, const char** wallet_name_out,
    bool* is_multisig)
{
    JADE_ASSERT(!num_multisigs || multisig_names);
    JADE_ASSERT(!num_descriptors || descriptor_names);
    JADE_ASSERT(num_multisigs || num_descriptors);
    JADE_INIT_OUT_PPTR(wallet_name_out);
    JADE_ASSERT(is_multisig);

    const size_t num_registered_wallets = num_multisigs + num_descriptors;

    size_t selected = 0;
    gui_view_node_t* label = NULL;
    gui_view_node_t* walletname = NULL;
    gui_activity_t* const act = make_carousel_activity("View Wallet", &label, &walletname);
    UPDATE_WALLET_CAROUSEL(0);
    gui_set_current_activity(act);
    int32_t ev_id;

    const size_t limit = num_registered_wallets + 1;
    bool done = false;
    while (!done) {
        JADE_ASSERT(selected < limit);
        UPDATE_WALLET_CAROUSEL(selected);

        if (gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            switch (ev_id) {
            case GUI_WHEEL_LEFT_EVENT:
                selected = (selected + limit - 1) % limit;
                break;

            case GUI_WHEEL_RIGHT_EVENT:
                selected = (selected + 1) % limit;
                break;

            default:
                if (ev_id == gui_get_click_event()) {
                    done = true;
                    break;
                }
            }
        }
    }
    if (selected >= num_registered_wallets) {
        // Back/exit
        return false;
    }

    *is_multisig = selected < num_multisigs;
    *wallet_name_out = *is_multisig ? multisig_names[selected] : descriptor_names[selected - num_multisigs];
    return true;
}