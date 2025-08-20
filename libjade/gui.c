#include <stdarg.h>
#include <string.h>

#include "gui.h"
#include "jade_assert.h"
#include "utils/event.h"
#include "utils/malloc_ext.h"

// display.c constants
const color_t TFT_BLACK = 0x0000;
const color_t TFT_NAVY = 0x0F00;
const color_t TFT_DARKGREEN = 0xE003;
const color_t TFT_DARKCYAN = 0xEF03;
const color_t TFT_MAROON = 0x0078;
const color_t TFT_PURPLE = 0x0F78;
const color_t TFT_OLIVE = 0xE07B;
const color_t TFT_LIGHTGREY = 0x18C6;
const color_t TFT_DARKGREY = 0xEF7B;
const color_t TFT_BLUE = 0x1F00;
const color_t TFT_GREEN = 0xE007;
const color_t TFT_CYAN = 0xFF07;
const color_t TFT_RED = 0x00F8;
const color_t TFT_MAGENTA = 0x1FF8;
const color_t TFT_YELLOW = 0xE0FF;
const color_t TFT_WHITE = 0xFFFF;
const color_t TFT_ORANGE = 0x20FD;
const color_t TFT_GREENYELLOW = 0xE5AF;
const color_t TFT_PINK = 0x19FE;
// end display.c constants

ESP_EVENT_DEFINE_BASE(GUI_BUTTON_EVENT);
ESP_EVENT_DEFINE_BASE(GUI_EVENT);

const color_t GUI_BLOCKSTREAM_JADE_GREEN = 0x4C04;
const color_t GUI_BLOCKSTREAM_BUTTONBORDER_GREY = 0x0421;

const color_t GUI_BLOCKSTREAM_HIGHTLIGHT_DEFAULT = GUI_BLOCKSTREAM_JADE_GREEN;
const color_t GUI_BLOCKSTREAM_HIGHTLIGHT_ORANGE = 0xE0D3;
const color_t GUI_BLOCKSTREAM_HIGHTLIGHT_BLUE = 0xD318;
const color_t GUI_BLOCKSTREAM_HIGHTLIGHT_DARKGREY = 0xA210;
const color_t GUI_BLOCKSTREAM_HIGHTLIGHT_LIGHTGREY = 0xB294;
const color_t GUI_BLOCKSTREAM_UNHIGHTLIGHTED_DEFAULT = 0x494A;

typedef struct _activity_holder_t activity_holder_t;
struct _activity_holder_t {
    gui_activity_t activity;
    activity_holder_t* next;
};

typedef struct {
    gui_view_node_t* node_to_repaint;
    gui_activity_t* new_activity;
    activity_holder_t* to_free;
} gui_task_job_t;

// current activity being drawn on screen
static gui_activity_t* current_activity = NULL;
// stack of activities that currently exist
static activity_holder_t* existing_activities = NULL;

// Click/select event (ie. which button counts as 'click'/select)
// and which gui highlight colour is in use
static gui_event_t gui_click_event = GUI_FRONT_CLICK_EVENT;

// status bar
struct {
    bool unused;
} status_bar;

gui_event_t gui_get_click_event(void) { return gui_click_event; }

void gui_set_click_event(const bool use_wheel_click)
{
    gui_click_event = use_wheel_click ? GUI_WHEEL_CLICK_EVENT : GUI_FRONT_CLICK_EVENT;
}

color_t gui_get_highlight_color(void) { return GUI_BLOCKSTREAM_HIGHTLIGHT_DEFAULT; }

void gui_set_highlight_color(const uint8_t theme) {}

bool gui_get_flipped_orientation(void) { return false; }

bool gui_set_flipped_orientation(const bool flipped_orientation) { return false; }

void gui_init(TaskHandle_t* gui_h)
{
    // create a blank activity
    current_activity = gui_make_activity();
}

bool gui_initialized(void) { return true; } // gui task started

void gui_set_active(gui_view_node_t* node, bool value) {}

void gui_make_activity_ex(gui_activity_t** ppact, const bool has_status_bar, const char* title, const bool managed)
{
    JADE_INIT_OUT_PPTR(ppact);
    JADE_ASSERT(!title || has_status_bar);

    if (managed) {
        // Managed activity - add to activities list
        activity_holder_t* holder = JADE_CALLOC(1, sizeof(activity_holder_t));

        // Add to the stack of existing activities
        holder->next = existing_activities;
        existing_activities = holder;

        // Return the activity from within this holder
        *ppact = &holder->activity;
    } else {
        // Unmanaged - just create the activity to return
        *ppact = JADE_CALLOC(1, sizeof(gui_activity_t));
        JADE_LOGW("Created unmanaged gui activity at %p", *ppact);
    }
}

gui_activity_t* gui_make_activity(void)
{
    gui_activity_t* activity = NULL;
    gui_make_activity_ex(&activity, false, NULL, true);
    JADE_ASSERT(activity);
    activity->selectables_wrap = true;
    return activity;
}

int32_t gui_activity_wait_button(gui_activity_t* activity, const int32_t default_event_id)
{
    int32_t ev_id = default_event_id;
#ifndef CONFIG_DEBUG_UNATTENDED_CI
    if (!gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
        ev_id = BTN_EVENT_TIMEOUT;
    }
#else
    gui_activity_wait_event(activity, GUI_BUTTON_EVENT, ESP_EVENT_ANY_ID, NULL, NULL, NULL,
        CONFIG_DEBUG_UNATTENDED_CI_TIMEOUT_MS / portTICK_PERIOD_MS);
#endif
    return ev_id;
}

void gui_chain_activities(const link_activity_t* link_act, linked_activities_info_t* pActInfo) {}

void gui_set_parent(gui_view_node_t* child, gui_view_node_t* parent) {}

void gui_make_hsplit(gui_view_node_t** ptr, enum gui_split_type kind, uint8_t parts, ...) { *ptr = NULL; }

void gui_make_vsplit(gui_view_node_t** ptr, enum gui_split_type kind, uint8_t parts, ...) { *ptr = NULL; }

void gui_make_button(
    gui_view_node_t** ptr, const color_t color, const color_t selected_color, const uint32_t event_id, void* args)
{
    *ptr = NULL;
}

void gui_make_fill(gui_view_node_t** ptr, color_t color, enum fill_node_kind fill_type, gui_view_node_t* parent)
{
    *ptr = NULL;
}

void gui_make_text(gui_view_node_t** ptr, const char* text, color_t color) { *ptr = NULL; }

void gui_make_text_font(gui_view_node_t** ptr, const char* text, color_t color, uint32_t font) { *ptr = NULL; }

void gui_make_icon(gui_view_node_t** ptr, const Icon* icon, color_t color, const color_t* bg_color) { *ptr = NULL; }

void gui_set_icon_animation(gui_view_node_t* node, Icon* icons, const size_t num_icons, const size_t frames_per_icon) {}

void gui_set_icon_to_qr(gui_view_node_t* node) {}

void gui_next_qrcode_color(void) {}

void gui_make_picture(gui_view_node_t** ptr, const Picture* picture) { *ptr = NULL; }

void gui_make_qrguide(gui_view_node_t** ptr, color_t color) { *ptr = NULL; }

void gui_set_margins(gui_view_node_t* node, uint32_t sides, ...) {}

void gui_set_padding(gui_view_node_t* node, uint32_t sides, ...) {}

void gui_set_borders(gui_view_node_t* node, const color_t color, const uint16_t thickness, const uint8_t borders) {}

void gui_set_borders_selected_color(gui_view_node_t* node, color_t selected_color) {}

void gui_set_borders_inactive_color(gui_view_node_t* node, color_t inactive_color) {}

void gui_set_colors(gui_view_node_t* node, color_t color, color_t selected_color) {}

void gui_set_color(gui_view_node_t* node, color_t color) {}

void gui_set_align(gui_view_node_t* node, enum gui_horizontal_align halign, enum gui_vertical_align valign) {}

void gui_set_text_scroll(gui_view_node_t* node, color_t background_color) {}

void gui_set_text_scroll_selected(
    gui_view_node_t* node, bool only_when_selected, color_t background_color, color_t selected_background_color)
{
}

void gui_set_text_noise(gui_view_node_t* node, color_t background_color) {}

void gui_set_text_font(gui_view_node_t* node, uint32_t font) {}

void gui_set_text_default_font(gui_view_node_t* node) {}

void gui_update_text(gui_view_node_t* node, const char* text) {}

void gui_update_icon(gui_view_node_t* node, const Icon icon, const bool repaint_parent) {}

void gui_update_picture(gui_view_node_t* node, const Picture* picture, const bool repaint_parent) {}

void gui_wheel_click(void) {}

void gui_front_click(void) {}

void gui_next(void) {}

void gui_prev(void) {}

void gui_set_activity_initial_selection(gui_view_node_t* node) {}

void gui_activity_set_active_selection(
    gui_activity_t* activity, gui_view_node_t** nodes, size_t num_nodes, const bool* active, gui_view_node_t* selected)
{
}

void gui_repaint(gui_view_node_t* node) {}

// Call to initiate a change of current activity - optionally freeing other managed activities.
// Can also pass a 'retain' activity which is not made current, but is retained and not freed.
void gui_set_current_activity_ex(gui_activity_t* new_current, const bool free_managed_activities)
{
    JADE_ASSERT(new_current);

    // We will post the gui task the new activity, and the list of activities it can free
    gui_task_job_t switch_info = { .node_to_repaint = NULL, .new_activity = new_current, .to_free = NULL };

    // If freeing others, partition existing activities into those to keep (new current and the
    //  passed 'retain' activity) and those to free (all others).
    if (free_managed_activities) {
        activity_holder_t* holder = existing_activities;
        existing_activities = NULL;

        while (holder) {
            activity_holder_t* const next = holder->next;

            if (&holder->activity == new_current) {
                // Retain this activity
                holder->next = existing_activities;
                existing_activities = holder;
            } else {
                // Discard this activity
                holder->next = switch_info.to_free;
                switch_info.to_free = holder;
            }
            holder = next;
        }

        // Sanity check
        // 'existing_activities' should be the new current activity only, or be completely empty
        // (if current activity is an "unmanaged" activity)
        JADE_ASSERT(
            !existing_activities || ((&existing_activities->activity == new_current) && !existing_activities->next));
    }
}

// Initiate change of 'current' activity
void gui_set_current_activity(gui_activity_t* new_current)
{
    // Set a new activity without freeing any other activities
    gui_set_current_activity_ex(new_current, false);
}

struct wait_event_data_t {
    bool unused;
};
static wait_event_data_t fake_wait_event_data;

wait_event_data_t* gui_activity_make_wait_event_data(gui_activity_t* activity) { return &fake_wait_event_data; }

void gui_activity_register_event(
    gui_activity_t* activity, const char* event_base, uint32_t event_id, esp_event_handler_t handler, void* args)
{
}

bool gui_activity_wait_event(gui_activity_t* activity, const char* event_base, uint32_t event_id,
    esp_event_base_t* trigger_event_base, int32_t* trigger_event_id, void** trigger_event_data, TickType_t max_wait)
{
    if (trigger_event_id) {
        *trigger_event_id = ESP_NO_EVENT;
    }
    return ESP_OK;
}

void gui_set_activity_title(gui_activity_t* activity, const char* title) {}

gui_activity_t* gui_current_activity(void) { return current_activity; }

gui_activity_t* gui_display_splash(void) { return gui_make_activity(); }
