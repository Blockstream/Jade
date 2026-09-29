#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../ui.h"
#include "jade_assert.h"

// Shared confirmation activity for a given identity string
// The identity is displayed to the user, who must explicitly approve or reject
static gui_activity_t* make_identity_activity(
    const char* title, const char* identity, const int32_t reject_ev_id, const int32_t accept_ev_id)
{
    JADE_ASSERT(title);
    JADE_ASSERT(identity);

    // third row, buttons
    btn_data_t hdrbtns[] = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = reject_ev_id },
        { .txt = "S", .font = VARIOUS_SYMBOLS_FONT, .ev_id = accept_ev_id /**/ BTN_IS_CRITICAL } };

    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* const parent = add_title_bar(act, title, hdrbtns, 2, NULL);
    gui_view_node_t* node;

    gui_make_text(&node, identity, TFT_WHITE);
    gui_set_parent(node, parent);
    gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 24, 0, 0, 4);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_TOP);

    return act;
}

static bool show_identity_activity(const char* title, const char* identity, const size_t identity_len,
    const int32_t reject_ev_id, const int32_t accept_ev_id)
{
    JADE_ASSERT(title);
    JADE_ASSERT(identity);
    JADE_ASSERT(identity_len < MAX_DISPLAY_MESSAGE_LEN);

    char display_str[MAX_DISPLAY_MESSAGE_LEN];
    int ret = snprintf(display_str, sizeof(display_str), "%.*s", identity_len, identity);
    JADE_ASSERT(ret > 0 && ret < sizeof(display_str));

    gui_activity_t* const act = make_identity_activity(title, display_str, reject_ev_id, accept_ev_id);
    gui_set_current_activity(act);

    while (true) {
        const int32_t ev_id = gui_activity_wait_button(act, accept_ev_id);
        if (ev_id == reject_ev_id) {
            return false;
        } else if (ev_id == accept_ev_id) {
            return true;
        }
    }
}

bool show_sign_identity_activity(const char* identity, const size_t identity_len)
{
    return show_identity_activity(
        "Sign Identity", identity, identity_len, BTN_SIGNIDENTITY_REJECT, BTN_SIGNIDENTITY_ACCEPT);
}

bool show_get_identity_shared_key_activity(const char* identity, const size_t identity_len)
{
    return show_identity_activity(
        "Share Identity Key", identity, identity_len, BTN_IDENTITY_SHARED_KEY_REJECT, BTN_IDENTITY_SHARED_KEY_ACCEPT);
}
#endif // AMALGAMATED_BUILD
