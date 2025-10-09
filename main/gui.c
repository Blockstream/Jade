#ifndef AMALGAMATED_BUILD
#include <stdarg.h>
#include <string.h>

#include <freertos/FreeRTOS.h>
#include <freertos/ringbuf.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

#include "display.h"

#include "ble/ble.h"
#include "gui.h"
#include "idletimer.h"
#include "jade_assert.h"
#include "jade_tasks.h"
#include "power.h"
#include "qrcode.h"
#include "random.h"
#include "serial.h"
#include "storage.h"
#include "utils/event.h"
#include "utils/malloc_ext.h"
#include "utils/util.h"

// A genuine production v2 Jade may be awaiting mandatory attestation data
#if defined(CONFIG_BOARD_TYPE_JADE_V2) && defined(CONFIG_SECURE_BOOT)                                                  \
    && defined(CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS)
#include "attestation/attestation.h"
static inline bool gui_awaiting_attestation_data(void) { return !attestation_initialised(); }
#else
// Jade v1.x and diy devices are never awaiting mandatory attestation data
static inline bool gui_awaiting_attestation_data(void) { return false; }
#endif

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

// Main mutex used to synchronize all gui node and activity data
// notably the current activity and the list of managed activities
// and any calls to the underlying screen-driver library.
static SemaphoreHandle_t gui_mutex = NULL;
// current activity being drawn on screen
static gui_activity_t* current_activity = NULL;
// stack of activities that currently exist
static activity_holder_t* existing_activities = NULL;

// handle to the task running to update the gui
static TaskHandle_t* gui_task_handle = NULL;
// queue for gui task to receive items to process (eg. repaint node, switch activities, etc.)
static RingbufHandle_t gui_input_queue = NULL;

// Click/select event (ie. which button counts as 'click'/select)
// and which gui highlight colour is in use
static gui_event_t gui_click_event = GUI_FRONT_CLICK_EVENT;
static color_t gui_highlight_color = 0;
static const color_t gui_qrcode_colors[5] = { 0xa210, 0x494a, 0xef7b, 0x18c6, 0xffff };
#ifdef CONFIG_IDF_TARGET_ESP32S3
// V2 QR codes scan better with a higher contrast background
static uint8_t gui_qrcode_color_idx = 4;
#else
static uint8_t gui_qrcode_color_idx = 1;
#endif
static bool gui_orientation_flipped = false;

// status bar
struct {
    gui_view_node_t* root;

    gui_view_node_t* title;
    gui_view_node_t* battery_text;
    gui_view_node_t* usb_text;
    gui_view_node_t* ble_text;

    uint8_t last_battery_val;
    bool last_usb_val;
    bool last_ble_val;
    uint8_t battery_update_counter;

    TaskHandle_t task_handle;

    bool updated;
} status_bar;

// Utils
static void gui_task(void* args);
static void repaint_node(gui_view_node_t* node);

#if HOME_SCREEN_DEEP_STATUS_BAR
extern const uint8_t statusbar_logo_start[] asm("_binary_statusbar_large_bin_gz_start");
extern const uint8_t statusbar_logo_end[] asm("_binary_statusbar_large_bin_gz_end");
#else
extern const uint8_t statusbar_logo_start[] asm("_binary_statusbar_small_bin_gz_start");
extern const uint8_t statusbar_logo_end[] asm("_binary_statusbar_small_bin_gz_end");
#endif

static void free_view_node(gui_view_node_t* node);

static void make_status_bar(void)
{
    gui_view_node_t* status_parent = NULL;
    enum gui_horizontal_align name_alignment = GUI_ALIGN_CENTER;

    // Black fill background as the root node
    gui_make_fill(&status_bar.root, TFT_BLACK, FILL_PLAIN, NULL);
    status_bar.root->parent = NULL;

    gui_view_node_t* name_parent;
    gui_make_fill(&name_parent, TFT_BLACK, FILL_PLAIN, NULL);

    // Status bar logo image (size appropriate)
    const Picture* const logopic = get_picture(statusbar_logo_start, statusbar_logo_end);

#if HOME_SCREEN_DEEP_STATUS_BAR
    // Make an hsplit for the logo on the left, and info on the right
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 2, 65, 35);
    gui_set_padding(hsplit, GUI_MARGIN_ALL_DIFFERENT, 0, 2, 0, 2);
    gui_set_parent(hsplit, status_bar.root);

    // LHS - logo image
    gui_view_node_t* logo;
    gui_make_picture(&logo, logopic);
    gui_set_align(logo, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(logo, hsplit);

    // RHS - Info ; vsplit, the status icons above and the name below
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 50, 50);
    gui_set_parent(vsplit, hsplit);

    // Status icons - hsplit above the name
    gui_make_hsplit(&status_parent, GUI_SPLIT_RELATIVE, 3, 28, 28, 44);
    gui_set_padding(status_parent, GUI_MARGIN_ALL_DIFFERENT, 0, 4, 0, 2);
    gui_set_parent(status_parent, vsplit);

    // The name beneath, aligned to the right
    gui_set_parent(name_parent, vsplit);
    name_alignment = GUI_ALIGN_RIGHT;
#else
    // Make an hsplit for the icon, name, and status icons
    gui_make_hsplit(&status_parent, GUI_SPLIT_RELATIVE, 5, 10, 57, 8, 8, 17);
    gui_set_padding(status_parent, GUI_MARGIN_ALL_DIFFERENT, 3, 0, 0, 4);
    gui_set_parent(status_parent, status_bar.root);

    // LHS - logo image
    gui_view_node_t* logo;
    gui_make_picture(&logo, logopic);
    gui_set_align(logo, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(logo, status_parent);

    // The first part is for the name, aligned left
    gui_set_parent(name_parent, status_parent);
    name_alignment = GUI_ALIGN_LEFT;
#endif // HOME_SCREEN_DEEP_STATUS_BAR

    // Status icons onto the status parent (hsplit)
    JADE_ASSERT(status_parent);
    JADE_ASSERT(status_parent->kind == HSPLIT);
    gui_make_text_font(&status_bar.usb_text, "D", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(status_bar.usb_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(status_bar.usb_text, status_parent);

    gui_make_text_font(&status_bar.ble_text, "F", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(status_bar.ble_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(status_bar.ble_text, status_parent);

    gui_make_text_font(&status_bar.battery_text, "0", TFT_WHITE, JADE_SYMBOLS_16x32_FONT);
    gui_set_align(status_bar.battery_text, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(status_bar.battery_text, status_parent);

    JADE_ASSERT(name_parent);
    JADE_ASSERT(name_parent->kind == FILL);
    JADE_ASSERT(name_alignment != GUI_ALIGN_CENTER);
    gui_make_text_font(&status_bar.title, "Jade", TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(status_bar.title, name_alignment, GUI_ALIGN_MIDDLE);
    gui_set_parent(status_bar.title, name_parent);

    // Status bar data fields for tracking updates
    status_bar.updated = false;
    status_bar.last_battery_val = 0xFF;
    status_bar.battery_update_counter = 0;
}

gui_event_t gui_get_click_event(void) { return gui_click_event; }

void gui_set_click_event(const bool use_wheel_click)
{
    gui_click_event = use_wheel_click ? GUI_WHEEL_CLICK_EVENT : GUI_FRONT_CLICK_EVENT;
}

color_t gui_get_highlight_color(void) { return gui_highlight_color; }

void gui_set_highlight_color(const uint8_t theme)
{
    switch (theme) {
    case 1:
        gui_highlight_color = GUI_BLOCKSTREAM_HIGHTLIGHT_ORANGE;
        break;
    case 2:
        gui_highlight_color = GUI_BLOCKSTREAM_HIGHTLIGHT_BLUE;
        break;
    case 3:
        gui_highlight_color = GUI_BLOCKSTREAM_HIGHTLIGHT_DARKGREY;
        break;
    case 4:
        gui_highlight_color = GUI_BLOCKSTREAM_HIGHTLIGHT_LIGHTGREY;
        break;
    default:
        gui_highlight_color = GUI_BLOCKSTREAM_HIGHTLIGHT_DEFAULT; // jade green
        break;
    }
}

color_t gui_get_qrcode_color(void) { return gui_qrcode_colors[gui_qrcode_color_idx]; }

void gui_next_qrcode_color(void)
{
    uint8_t idx = gui_qrcode_color_idx + 1;
    if (idx >= sizeof(gui_qrcode_colors) / sizeof(gui_qrcode_colors[0])) {
        idx = 0; // wrap around
    }
    gui_qrcode_color_idx = idx;
}

bool gui_get_flipped_orientation(void) { return gui_orientation_flipped; }

bool gui_set_flipped_orientation(const bool flipped_orientation)
{
    gui_orientation_flipped = display_flip_orientation(flipped_orientation);
    return gui_orientation_flipped;
}

void gui_init(TaskHandle_t* gui_h)
{
    // Create mutex semaphore
    gui_mutex = xSemaphoreCreateMutex();
    JADE_ASSERT(gui_mutex);

    // Which button event are we to use as a click / 'select item'
    // and which menu highlight colour to use
    const uint8_t gui_flags = storage_get_gui_flags();
    gui_set_click_event(gui_flags & GUI_FLAGS_USE_WHEEL_CLICK);
    gui_set_highlight_color(gui_flags & GUI_FLAGS_THEMES_MASK);
    gui_set_flipped_orientation(gui_flags & GUI_FLAGS_FLIP_ORIENTATION);

    // create a blank activity
    current_activity = gui_make_activity();

    // create the default event loop used by btns
    const esp_err_t rc = esp_event_loop_create_default();
    JADE_ASSERT(rc == ESP_OK);

    // Create main input queue (ringbuffer)
    gui_input_queue = xRingbufferCreate(32 * sizeof(gui_task_job_t), RINGBUF_TYPE_NOSPLIT);
    JADE_ASSERT(gui_input_queue);

    // Create status-bar
    make_status_bar();

    // Create (high priority) gui task
    BaseType_t retval
        = xTaskCreatePinnedToCore(gui_task, "gui", 3 * 1024, NULL, JADE_TASK_PRIO_GUI, gui_h, JADE_CORE_GUI);
    gui_task_handle = gui_h;
    JADE_ASSERT_MSG(retval == pdPASS, "Failed to create GUI task, xTaskCreatePinnedToCore() returned %d", retval);
}

bool gui_initialized(void) { return *gui_task_handle; } // gui task started

// Is this kind of node selectable?
static inline bool is_kind_selectable(enum view_node_kind kind) { return kind == BUTTON; }

// Is node a "before" node b on-screen? (i.e. is it above or more left?)
static inline bool is_before(const selectable_t* a, const selectable_t* b)
{
    return a->y < b->y || (a->y == b->y && a->x < b->x);
}

// Traverse the tree from `node` downward and set the `is_selected` of every node to `value`
static void set_tree_selection(gui_view_node_t* node, bool value)
{
    JADE_ASSERT(node);

    node->is_selected = value;

    gui_view_node_t* child = node->child;
    while (child) {
        set_tree_selection(child, value);
        child = child->sibling;
    }
}

// Traverse the tree from `node` downward and set the `is_active` of every node to `value`
static void set_tree_active(gui_view_node_t* node, bool value)
{
    JADE_ASSERT(node);

    node->is_active = value;

    gui_view_node_t* child = node->child;
    while (child) {
        set_tree_active(child, value);
        child = child->sibling;
    }
}

// Function to set the passed node as active or inactive, depending on 'value'.
void gui_set_active(gui_view_node_t* node, const bool value)
{
    JADE_ASSERT(node);

    // Set passed node to active/inactive and redraw
    set_tree_active(node, value);
    gui_repaint(node);
}

static gui_view_node_t* get_first_active_node(gui_activity_t* activity)
{
    JADE_ASSERT(activity);

    // Ignore on screen with no selectable elements
    if (activity->selectables) {
        selectable_t* current = activity->selectables;
        selectable_t* const end = current;
        do {
            // Return the first node that is flagged as 'active'
            if (current->node->is_active) {
                return current->node;
            }
            current = current->next;
        } while (current != end);
    }
    return NULL;
}

// select the previous item in the selectables list
// Returns true if the selection is 'moved' to a prior item, or false if not (and selection left unchanged)
// eg. no current item selected, no other selectable items, no prior selectable items [and not wrapping] etc.
static bool select_prev(gui_activity_t* activity)
{
    JADE_ASSERT(activity);

    // Ignore next/prev on screen with no selectable elements
    if (!activity->selectables) {
        return false;
    }

    selectable_t* const end = activity->selectables->next;
    selectable_t* current = activity->selectables;

    // Look for a selected node
    while (current != end && !current->node->is_selected) {
        current = current->prev;
    }

    // no selected nodes
    if (current == end && !current->node->is_selected) {
        return false;
    }

    // no wrapping
    if (!activity->selectables_wrap && current->is_first) {
        return false;
    }

    selectable_t* prev_active = current->prev;
    while (!prev_active->node->is_active) {
        // end condition, we couldn't find any other active node
        if (prev_active == current) {
            return false;
        }
        // we are about to wrap, return if it's disabled
        if (!activity->selectables_wrap && prev_active->is_first) {
            return false;
        }

        prev_active = prev_active->prev;
    }

    set_tree_selection(current->node, false);
    gui_repaint(current->node);

    set_tree_selection(prev_active->node, true);
    gui_repaint(prev_active->node);

    activity->selectables = prev_active;

    return true;
}

// Note: node must exist and be active/selectable.
// Any prior selection will be cleared.
static void select_node(gui_view_node_t* node)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->activity);
    JADE_ASSERT(node->is_active);

    // If there are no selectables, it (probably) means the gui element
    // has not been fully initialised/rendered yet.
    // In this case we mark the node as the one to initially select when
    // the activity is drawn for the first time, rather than trying to
    // set the selection immediately.
    if (!node->activity->selectables) {
        gui_set_activity_initial_selection(node);
        return;
    }

    selectable_t* const begin = node->activity->selectables;
    selectable_t* current = begin;

    selectable_t* old_selected = NULL;
    selectable_t* new_selected = NULL;

    // look for both the selected node and `node`
    do {
        JADE_ASSERT(current->node->activity == node->activity);
        if (current->node->is_selected) {
            old_selected = current;
        }
        if (current->node == node) {
            new_selected = current;
        }
        current = current->next;
    } while (current != begin && (!new_selected || !old_selected));

    // Must have found node
    JADE_ASSERT(new_selected);
    JADE_ASSERT(new_selected->node == node);

    // Deactivate prior selection
    if (old_selected) {
        set_tree_selection(old_selected->node, false);
        gui_repaint(old_selected->node);
    }

    // Select passed node
    set_tree_selection(new_selected->node, true);
    gui_repaint(new_selected->node);

    node->activity->selectables = new_selected;
}

// select the next item in the selectables list
// Returns true if the selection is 'moved' to a subsequent item, or false if not (and selection left unchanged)
// eg. no current item selected, no other selectable items, no later selectable items [and not wrapping] etc.
static bool select_next(gui_activity_t* activity)
{
    JADE_ASSERT(activity);

    // Ignore next/prev on screen with no selectable elements
    if (!activity->selectables) {
        return false;
    }

    selectable_t* const end = activity->selectables->prev;
    selectable_t* current = activity->selectables;

    // Look for a selected node
    while (current != end && !current->node->is_selected) {
        current = current->next;
    }

    // no selected nodes
    if (current == end && !current->node->is_selected) {
        return false;
    }

    // no wrapping
    if (!activity->selectables_wrap && current->next->is_first) {
        return false;
    }

    selectable_t* next_active = current->next;
    while (!next_active->node->is_active) {
        // end condition, we couldn't find any other active node
        if (next_active == current) {
            return false;
        }
        // we are about to wrap, return if it's disabled
        if (!activity->selectables_wrap && next_active->is_first) {
            return false;
        }

        next_active = next_active->next;
    }

    // remove selection from `current`
    set_tree_selection(current->node, false);
    gui_repaint(current->node);

    // add selection to `next_active`
    set_tree_selection(next_active->node, true);
    gui_repaint(next_active->node);

    activity->selectables = next_active;

    return true;
}

// trigger the action for the selected element
static void select_action(gui_activity_t* activity)
{
    JADE_ASSERT(activity);

    selectable_t* const current = activity->selectables;
    if (current && current->node->is_selected && current->node->button->click_event_id != GUI_BUTTON_EVENT_NONE) {
        JADE_ASSERT(current->node->activity == activity);
        const esp_err_t rc = esp_event_post(GUI_BUTTON_EVENT, current->node->button->click_event_id,
            &current->node->button->args, sizeof(void*), 100 / portTICK_PERIOD_MS);
        JADE_ASSERT(rc == ESP_OK);
    }
}

// Mark a collection of nodes as active or inactive, select one, and redraw the entire activity.
void gui_activity_set_active_selection(gui_activity_t* activity, gui_view_node_t** nodes, const size_t num_nodes,
    const bool* active, gui_view_node_t* selected)
{
    JADE_ASSERT(activity);
    JADE_ASSERT(nodes);
    JADE_ASSERT(num_nodes);
    JADE_ASSERT(active);
    JADE_ASSERT(selected);

    bool set_selected = false;
    JADE_SEMAPHORE_TAKE(gui_mutex);
    for (size_t i = 0; i < num_nodes; ++i) {
        JADE_ASSERT(nodes[i]->activity == activity);
        set_tree_active(nodes[i], active[i]);
        if (nodes[i] == selected) {
            JADE_ASSERT(active[i]); // can only select active node
            select_node(nodes[i]);
            set_selected = true;
        }
    }
    JADE_SEMAPHORE_GIVE(gui_mutex);

    // 'selected' should have been seen in 'nodes'
    JADE_ASSERT(set_selected);

    // May as well repaint the whole activity
    gui_repaint(activity->root_node);
}

// push a selectable element to the `selectables` list of `activity`
static void push_selectable(gui_activity_t* activity, gui_view_node_t* node, uint16_t x, uint16_t y)
{
    JADE_ASSERT(activity);
    JADE_ASSERT(node);
    JADE_ASSERT(is_kind_selectable(node->kind));

    selectable_t* us = JADE_CALLOC(1, sizeof(selectable_t));

    us->node = node;
    us->x = x;
    us->y = y;

    // first one
    if (!activity->selectables) {
        us->is_first = true;

        us->prev = us;
        us->next = us;

        activity->selectables = us;
    } else {
        selectable_t* const begin = activity->selectables->prev;
        selectable_t* current = activity->selectables;
        while (begin != current && is_before(current->next, us)) {
            current = current->next;
        }

        us->prev = current;
        current->next->prev = us;

        us->next = current->next;
        current->next = us;

        // TODO: is the second condition required??
        if (us->next->is_first && is_before(us, us->next)) {
            // we are first now
            us->is_first = true;
            us->next->is_first = false;

            activity->selectables = us;
        }
    }
}

static void push_updatable(gui_view_node_t* node, gui_updatable_callback_t callback, void* extra_args)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->activity);

    // allocate & fill all the fields
    updatable_t* us = JADE_CALLOC(1, sizeof(updatable_t));

    us->node = node;

    us->callback = callback;
    us->extra_args = extra_args;

    // first one!
    gui_activity_t* const activity = node->activity;
    if (!activity->updatables) {
        activity->updatables = us;
    } else {
        // add to tail
        updatable_t* current = activity->updatables;
        while (current->next) {
            current = current->next;
        }
        current->next = us;
    }
}

// Create a new/initialised activity
// If 'managed' (the preferred/default), add to the stack of existing activities - these
// activities must not be explicitly freed by the caller but are freed by a subsequent
// call to 'gui_set_current_activity_ex()' passing 'free_other_activities' as true.
// eg. when the main loop reaches some known point (eg. getting back to the main dashboard
// screen between actions) it can call this to 'garbage collect' all outstanding gui elements.
// If not 'managed', we are making the dashboard activity, which persists as long as the
// firmware is running, and will never be freed.
void gui_make_activity_ex(gui_activity_t** ppact, const bool has_status_bar, const char* title, const bool managed)
{
    JADE_INIT_OUT_PPTR(ppact);
    JADE_ASSERT(!title || has_status_bar);

    if (managed) {
        // Managed activity - add to activities list
        activity_holder_t* holder = JADE_CALLOC(1, sizeof(activity_holder_t));

        // Add to the stack of existing activities
        JADE_SEMAPHORE_TAKE(gui_mutex);
        holder->next = existing_activities;
        existing_activities = holder;
        JADE_SEMAPHORE_GIVE(gui_mutex);

        // Return the activity from within this holder
        *ppact = &holder->activity;
    } else {
        // Unmanaged - just create the activity to return
        *ppact = JADE_CALLOC(1, sizeof(gui_activity_t));
        JADE_LOGW("Created unmanaged gui activity at %p", *ppact);
    }
    gui_activity_t* const activity = *ppact;

    // Initialise any non-NULL activity fields
    activity->win = GUI_DISPLAY_WINDOW;
    if (has_status_bar) {
        // offset the display window since the top-part will contain the status bar
        activity->win.y1 += GUI_STATUS_BAR_HEIGHT;
    }
    activity->status_bar = has_status_bar;

    if (title) {
        activity->title = strdup(title);
        JADE_ASSERT(activity->title);
    }

    gui_view_node_t* bg;
    gui_make_fill(&bg, TFT_BLACK, FILL_PLAIN, NULL);
    activity->root_node = bg;
    activity->root_node->activity = activity;
#ifdef CONFIG_UI_WRAP_ALL_MENUS
    activity->selectables_wrap = true; // allow the button cursor to wrap
#endif
}

// Create a new/initialised 'managed' activity without a status bar,
// and with the 'wrapped' selection style
gui_activity_t* gui_make_activity(void)
{
    gui_activity_t* activity = NULL;
    gui_make_activity_ex(&activity, false, NULL, true);
    JADE_ASSERT(activity);
    activity->selectables_wrap = true;
    return activity;
}

// free a linked list of selectable_t
static void free_selectables(gui_activity_t* activity)
{
    JADE_ASSERT(activity);

    selectable_t* const begin = activity->selectables;
    if (begin) {
        selectable_t* current = begin->next;
        free(begin);

        while (current != begin) {
            selectable_t* const next = current->next;
            free(current);
            current = next;
        }
    }
}

// free a linked list of updatable_t
static void free_updatables(gui_activity_t* activity)
{
    JADE_ASSERT(activity);

    updatable_t* current = activity->updatables;
    while (current) {
        updatable_t* const next = current->next;
        free(current);
        current = next;
    }
}

// free a linked list of activity_event_t
static void free_activity_events(gui_activity_t* activity)
{
    JADE_ASSERT(activity);

    activity_event_t* current = activity->activity_events;
    while (current) {
        activity_event_t* const next = current->next;
        free(current);
        current = next;
    }
}

// free a linked list of wait_data_t
static void free_wait_data_items(gui_activity_t* activity)
{
    JADE_ASSERT(activity);

    wait_data_t* current = activity->wait_data_items;
    while (current) {
        wait_data_t* const next = current->next;
        free_wait_event_data(current->event_data);
        free(current);
        current = next;
    }
}

// Free all of the activity contents (title, selectables/updatables etc.)
// (but note, not the 'activity' itself)
static void free_activity_internals(gui_activity_t* activity)
{
    JADE_ASSERT(activity);
    JADE_ASSERT(activity != current_activity);

    free_selectables(activity);
    free_updatables(activity);
    free_activity_events(activity);
    free_wait_data_items(activity);

    free_view_node(activity->root_node);

    if (activity->title) {
        free(activity->title);
    }
}

// Free an activity-holder and all of the activity contents (title, selectables/updatables etc.)
static void free_managed_activity(activity_holder_t* holder)
{
    JADE_ASSERT(holder);
    free_activity_internals(&holder->activity);
    free(holder);
}

static void switch_activity_callback(void* handler_arg, esp_event_base_t base, int32_t id, void* event_data)
{
    JADE_ASSERT(handler_arg);
    gui_activity_t* activity = (gui_activity_t*)handler_arg;
    gui_set_current_activity(activity);
}

static void connect_button_activity(gui_view_node_t* node, gui_activity_t* activity)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->activity);
    JADE_ASSERT(node->kind == BUTTON);
    JADE_ASSERT(activity);

    gui_activity_register_event(
        node->activity, GUI_BUTTON_EVENT, node->button->click_event_id, switch_activity_callback, activity);
}

// Link activities eg. by prev/next buttons
void gui_chain_activities(const link_activity_t* link_act, linked_activities_info_t* pActInfo)
{
    JADE_ASSERT(link_act);
    JADE_ASSERT(link_act->activity);
    JADE_ASSERT(pActInfo);

    // Record the first activity
    if (!pActInfo->first_activity) {
        pActInfo->first_activity = link_act->activity;
    }

    // Link activities together by prev and next buttons
    if (pActInfo->last_activity) {
        if (link_act->prev_button) {
            // connect our "prev" btn to prev activity
            connect_button_activity(link_act->prev_button, pActInfo->last_activity);
        }

        // connect prev "next" btn to this activity
        if (pActInfo->last_activity_next_button) {
            connect_button_activity(pActInfo->last_activity_next_button, link_act->activity);
        }
    }

    // Update 'last activity' information to this new activity
    pActInfo->last_activity = link_act->activity;
    pActInfo->last_activity_next_button = link_act->next_button;
}

// attach a view node (recusively) to an activity, by inheriting the activity from the parent
static void set_tree_activity(gui_view_node_t* node)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->parent);

    // node should not already have an activity
    JADE_ASSERT(!node->activity);

    // NOTE: activity can be null if ultimate parent not attached yet
    // ie. making a node subtree before attaching subtree root to activity tree
    node->activity = node->parent->activity;

    // set child nodes (depth first recursion)
    gui_view_node_t* child = node->child;
    while (child) {
        set_tree_activity(child);
        child = child->sibling;
    }
}

// Helper function to check if node or any of its ancestors are selectable
static bool has_selectable_ancestor(gui_view_node_t* node)
{
    while (node) {
        if (is_kind_selectable(node->kind)) {
            return true;
        }
        node = node->parent;
    }
    return false;
}

void gui_set_parent(gui_view_node_t* child, gui_view_node_t* parent)
{
    JADE_ASSERT(child);
    JADE_ASSERT(parent);
    // NOTE: parent->activity can be null if parent not attached yet
    // ie. making a node subtree before attaching subtree root to activity tree

    // child should not already have a parent
    JADE_ASSERT(!child->parent);

    // Check that if child is selectable, none of its ancestors are selectable
    if (is_kind_selectable(child->kind)) {
        JADE_ASSERT_MSG(
            !has_selectable_ancestor(parent), "Cannot set parent: selectable child cannot have selectable ancestors");
    }

    child->parent = parent;

    // also inherits the activity
    set_tree_activity(child);

    // first child
    if (!parent->child) {
        parent->child = child;
    } else {
        // Add to tail of siblings list
        gui_view_node_t* ptr = parent->child;
        while (ptr->sibling) {
            ptr = ptr->sibling;
        };
        ptr->sibling = child;
    }
}

// Free a view_node
void free_view_node(gui_view_node_t* node)
{
    JADE_ASSERT(node);

    // call the destructor if it's set
    if (node->free_callback) {
        node->free_callback(node->data);
    }

    // free any borders
    free(node->borders);

    // free the extra data struct
    free(node->data);

    if (node->child) {
        free_view_node(node->child);
    }

    if (node->sibling) {
        free_view_node(node->sibling);
    }

    free(node);
}

// destructor for {v,h}split nodes
static void free_view_node_split_data(void* vdata)
{
    JADE_ASSERT(vdata);
    struct view_node_split_data* data = vdata;
    free(data->values);
}

// destructor for text nodes
static void free_view_node_text_data(void* vdata)
{
    JADE_ASSERT(vdata);
    struct view_node_text_data* data = vdata;

    // free the char* that we allocated
    free(data->text);

    // also the scroll struct if present
    if (data->scroll) {
        free(data->scroll);
    }

    // and also the noise struct if present
    if (data->noise) {
        free(data->noise);
    }
}

// destructor for text nodes
static void free_view_node_icon_data(void* vdata)
{
    JADE_ASSERT(vdata);
    struct view_node_icon_data* data = vdata;

    // free the animation struct if present
    if (data->animation) {
        // NOTE: we owned the animation frames
        for (int i = 0; i < data->animation->num_icons; ++i) {
            // Free the icon data
            free(data->animation->icons[i].data);
        }
        free(data->animation->icons);
        free(data->animation);
    }
}

// destructor for picture nodes
static void free_view_node_picture_data(void* vdata)
{
    JADE_ASSERT(vdata);
    struct view_node_picture_data* data = vdata;
    JADE_ASSERT(data->picture);
    JADE_ASSERT(data->picture->data_8);
    free((void*)data->picture->data_8);
    free((void*)data->picture);
}

// make the underlying view node, common across all the gui_make_* functions
static void make_view_node(gui_view_node_t** ptr, enum view_node_kind kind, void* data, free_callback_t free_callback)
{
    JADE_INIT_OUT_PPTR(ptr);

    *ptr = JADE_CALLOC(1, sizeof(gui_view_node_t));

    (*ptr)->render_data.is_first_time = true;

    (*ptr)->is_selected = false;
    // by default active
    (*ptr)->is_active = true;

    (*ptr)->kind = kind;
    (*ptr)->data = data;
    (*ptr)->free_callback = free_callback;
}

// Generic function to make a {v,h}split node
static void make_split_node(
    gui_view_node_t** ptr, enum view_node_kind split_kind, enum gui_split_type kind, uint8_t parts, va_list values)
{
    JADE_INIT_OUT_PPTR(ptr);
    JADE_ASSERT(split_kind == HSPLIT || split_kind == VSPLIT);

    struct view_node_split_data* data = JADE_CALLOC(1, sizeof(struct view_node_split_data));

    data->kind = kind;
    data->parts = parts;

    // copy the values
    data->values = JADE_CALLOC(1, sizeof(uint16_t) * parts);

    for (uint8_t i = 0; i < parts; ++i) {
        data->values[i] = (uint16_t)va_arg(values, uint32_t);
    };

    // ... and also set a destructor to free them later
    make_view_node(ptr, split_kind, data, free_view_node_split_data);
}

void gui_make_hsplit(gui_view_node_t** ptr, enum gui_split_type kind, uint8_t parts, ...)
{
    JADE_INIT_OUT_PPTR(ptr);

    va_list args;
    va_start(args, parts);
    make_split_node(ptr, HSPLIT, kind, parts, args);
    va_end(args);
}

void gui_make_vsplit(gui_view_node_t** ptr, enum gui_split_type kind, uint8_t parts, ...)
{
    JADE_INIT_OUT_PPTR(ptr);

    va_list args;
    va_start(args, parts);
    make_split_node(ptr, VSPLIT, kind, parts, args);
    va_end(args);
}

void gui_make_button(
    gui_view_node_t** ptr, const color_t color, const color_t selected_color, const uint32_t event_id, void* args)
{
    JADE_INIT_OUT_PPTR(ptr);

    struct view_node_button_data* data = JADE_CALLOC(1, sizeof(struct view_node_button_data));

    // If the un-selected colour is the same as the selected colour, it implies
    // the button is transparent when not selected, so we can skip filling the content.
    // NOTE: requires the parent is redrawn otherwise button will remain in 'selected' appearance
    // when selection moves on to another item.
    data->color = color;
    data->selected_color = selected_color;

    data->click_event_id = event_id;
    data->args = args;

    make_view_node(ptr, BUTTON, data, NULL);
}

void gui_make_fill(gui_view_node_t** ptr, color_t color, enum fill_node_kind fill_type, gui_view_node_t* parent)
{
    JADE_INIT_OUT_PPTR(ptr);

    struct view_node_fill_data* data = JADE_CALLOC(1, sizeof(struct view_node_fill_data));

    // by default same color
    data->color = color;
    data->selected_color = color;
    data->fill_type = fill_type;

    make_view_node(ptr, FILL, data, NULL);
    if (parent) {
        gui_set_parent(*ptr, parent);
    }
}

void gui_make_text(gui_view_node_t** ptr, const char* text, color_t color)
{
    gui_make_text_font(ptr, text, color, GUI_DEFAULT_FONT);
}

void gui_make_text_font(gui_view_node_t** ptr, const char* text, color_t color, uint32_t font)
{
    JADE_INIT_OUT_PPTR(ptr);
    JADE_ASSERT(text);

    struct view_node_text_data* data = JADE_CALLOC(1, sizeof(struct view_node_text_data));

    // max chars limited to GUI_MAX_TEXT_LENGTH
    const size_t len = min_u16(GUI_MAX_TEXT_LENGTH, strlen(text) + 1);
    data->text = JADE_MALLOC(len);
    const int ret = snprintf(data->text, len, "%s", text); // cut to len
    JADE_ASSERT(ret >= 0); // truncation is acceptable here, as is empty string

    // by default same color
    data->color = color;
    data->selected_color = color;

    // default font initially
    data->font = font;

    // and top-left
    data->halign = GUI_ALIGN_LEFT;
    data->valign = GUI_ALIGN_TOP;

    // without scroll
    data->scroll = NULL;

    // without noise
    data->noise = NULL;

    // also set free_view_node_text_data as destructor to free data->text
    make_view_node(ptr, TEXT, data, free_view_node_text_data);
}

void gui_make_icon(gui_view_node_t** ptr, const Icon* icon, color_t color, const color_t* bg_color)
{
    JADE_INIT_OUT_PPTR(ptr);
    JADE_ASSERT(icon);

    struct view_node_icon_data* data = JADE_CALLOC(1, sizeof(struct view_node_icon_data));

    data->icon = *icon;

    // by default same color
    data->color = color;
    data->selected_color = color;

    // background color is set to foreground color to imply transparency
    data->bg_color = bg_color ? *bg_color : color;

    // without animation
    data->animation = NULL;

    // and top-left, normal icon
    data->halign = GUI_ALIGN_LEFT;
    data->valign = GUI_ALIGN_TOP;
    data->icon_type = ICON_PLAIN;

    // also set free_view_node_icon_data as destructor to free any animation data
    make_view_node(ptr, ICON, data, free_view_node_icon_data);
}

static bool icon_animation_frame_callback(gui_view_node_t* node, void* extra_args)
{
    // no node, invalid node, not yet rendered...
    if (!node || node->kind != ICON || node->render_data.is_first_time) {
        return false;
    }

    // animation not applicable
    struct view_node_icon_animation_data* animation_data = node->icon->animation;
    if (!animation_data || !animation_data->frames_per_icon || animation_data->num_icons <= 1) {
        return false;
    }

    if (animation_data->current_frame > 0) {
        // do nothing this frame, just count
        --animation_data->current_frame;
        return false;
    }

    // Update main icon
    animation_data->current_icon = (animation_data->current_icon + 1) % animation_data->num_icons;
    node->icon->icon = animation_data->icons[animation_data->current_icon];

    // Reset frame counter
    animation_data->current_frame = animation_data->frames_per_icon;

    // Redraw icon
    return true;
}

// NOTE: takes ownership of icons
void gui_set_icon_animation(gui_view_node_t* node, Icon* icons, const size_t num_icons, const size_t frames_per_icon)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == ICON);
    JADE_ASSERT(icons);
    JADE_ASSERT(num_icons);
    JADE_ASSERT(frames_per_icon || num_icons == 1);

    struct view_node_icon_animation_data* animation_data = JADE_CALLOC(1, sizeof(struct view_node_icon_animation_data));

    animation_data->icons = icons;
    animation_data->num_icons = num_icons;
    animation_data->current_icon = 0;

    animation_data->frames_per_icon = frames_per_icon;
    animation_data->current_frame = 0;

    node->icon->animation = animation_data;

    // If there are multiple icons, push this to the list of updatable elements so
    // that the image gets periodically updated.
    if (num_icons > 1) {
        push_updatable(node, icon_animation_frame_callback, NULL);
    }
}

void gui_set_icon_to_qr(gui_view_node_t* node)
{
    JADE_ASSERT(node);
    node->icon->icon_type = ICON_QR;
}

void gui_make_picture(gui_view_node_t** ptr, const Picture* picture)
{
    JADE_INIT_OUT_PPTR(ptr);
    // picture optional at creation time

    struct view_node_picture_data* data = JADE_CALLOC(1, sizeof(struct view_node_picture_data));

    data->picture = picture;

    // top-left by default
    data->halign = GUI_ALIGN_LEFT;
    data->valign = GUI_ALIGN_TOP;

    // if the picture node is created without providing a picture then the caller
    // is responsable for freeing the picture data
    make_view_node(ptr, PICTURE, data, picture ? free_view_node_picture_data : NULL);
}

static void set_vals_with_varargs(gui_margin_t* margins, const uint8_t sides, va_list args)
{
    JADE_ASSERT(margins);

    int val;

    switch (sides) {
    case GUI_MARGIN_ALL_EQUAL:
        // we only pop one value
        val = va_arg(args, int);
        JADE_ASSERT(val <= UINT8_MAX);
        margins->top = val;
        margins->right = val;
        margins->bottom = val;
        margins->left = val;
        break;

    case GUI_MARGIN_TWO_VALUES:
        // two values, top/bottom and right/left
        val = va_arg(args, int);
        JADE_ASSERT(val <= UINT8_MAX);
        margins->top = val;
        margins->bottom = val;

        val = va_arg(args, int);
        JADE_ASSERT(val <= UINT8_MAX);
        margins->right = val;
        margins->left = val;
        break;

    case GUI_MARGIN_ALL_DIFFERENT:
        // four different values
        val = va_arg(args, int);
        JADE_ASSERT(val <= UINT8_MAX);
        margins->top = val;

        val = va_arg(args, int);
        JADE_ASSERT(val <= UINT8_MAX);
        margins->right = val;

        val = va_arg(args, int);
        JADE_ASSERT(val <= UINT8_MAX);
        margins->bottom = val;

        val = va_arg(args, int);
        JADE_ASSERT(val <= UINT8_MAX);
        margins->left = val;
        break;

    default:
        JADE_ASSERT_MSG(false, "set_vals_with_varargs() - unexpected 'sides' value: %u", sides);
    }
}

// get the thickness for border "border_bit" (which should have the value of one of the BIT constants)
static inline uint16_t get_border_thickness(gui_border_t* const borders, const uint8_t border_bit)
{
    // thickness is either "border->thickness" if that specific border is enabled or 0
    return borders ? borders->thickness * ((borders->borders >> border_bit) & 1) : 0;
}

static void calc_render_data(gui_view_node_t* node)
{
    JADE_ASSERT(node);

    // constraints haven't been set yet, we can't do much
    if (node->render_data.is_first_time) {
        return;
    }

    dispWin_t constraints = node->render_data.original_constraints;

    // margins affect borders and all contents
    constraints.y1 += node->margins.top;
    constraints.x2 -= node->margins.right;
    constraints.y2 -= node->margins.bottom;
    constraints.x1 += node->margins.left;

    // if we have borders, remove the border thickness
    if (node->borders) {
        constraints.y1 += get_border_thickness(node->borders, GUI_BORDER_TOP_BIT);
        constraints.x2 -= get_border_thickness(node->borders, GUI_BORDER_RIGHT_BIT);
        constraints.y2 -= get_border_thickness(node->borders, GUI_BORDER_BOTTOM_BIT);
        constraints.x1 += get_border_thickness(node->borders, GUI_BORDER_LEFT_BIT);
    }

    // apply padding
    constraints.y1 += node->padding.top;
    constraints.x2 -= node->padding.right;
    constraints.y2 -= node->padding.bottom;
    constraints.x1 += node->padding.left;

    // cache these padded constraints
    node->render_data.padded_constraints = constraints;
}

void gui_set_margins(gui_view_node_t* node, uint32_t sides, ...)
{
    JADE_ASSERT(node);

    va_list args;
    va_start(args, sides);
    set_vals_with_varargs(&node->margins, sides, args);
    va_end(args);

    // update constraints
    calc_render_data(node);
}

void gui_set_padding(gui_view_node_t* node, uint32_t sides, ...)
{
    JADE_ASSERT(node);

    va_list args;
    va_start(args, sides);
    set_vals_with_varargs(&node->padding, sides, args);
    va_end(args);

    // update constraints
    calc_render_data(node);
}

void gui_set_borders(gui_view_node_t* node, const color_t color, const uint16_t thickness, const uint8_t borders)
{
    JADE_ASSERT(node);

    if (!node->borders) {
        node->borders = JADE_MALLOC(sizeof(gui_border_t));
    }
    // by default same color
    node->borders->color = color;
    node->borders->selected_color = color;
    node->borders->inactive_color = color;

    node->borders->thickness = thickness;
    node->borders->borders = borders;

    // update constraints
    calc_render_data(node);
}

void gui_set_borders_selected_color(gui_view_node_t* node, color_t selected_color)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->borders);
    node->borders->selected_color = selected_color;
}

void gui_set_borders_inactive_color(gui_view_node_t* node, color_t inactive_color)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->borders);
    node->borders->inactive_color = inactive_color;
}

void gui_set_colors(gui_view_node_t* node, color_t color, color_t selected_color)
{
    JADE_ASSERT(node);

    switch (node->kind) {
    case TEXT:
        node->text->color = color;
        node->text->selected_color = selected_color;
        break;
    case FILL:
        node->fill->color = color;
        node->fill->selected_color = selected_color;
        break;
    case BUTTON:
        node->button->color = color;
        node->button->selected_color = selected_color;
        break;
    case ICON:
        node->icon->color = color;
        node->icon->selected_color = selected_color;
        break;
    default:
        JADE_ASSERT_MSG(false, "gui_set_colors() - Unexpected node kind: %u", node->kind);
    }
}

void gui_set_color(gui_view_node_t* node, color_t color) { gui_set_colors(node, color, color); }

void gui_set_align(gui_view_node_t* node, enum gui_horizontal_align halign, enum gui_vertical_align valign)
{
    JADE_ASSERT(node);

    enum gui_horizontal_align* halign_ptr;
    enum gui_vertical_align* valign_ptr;
    switch (node->kind) {
    case TEXT:
        halign_ptr = &node->text->halign;
        valign_ptr = &node->text->valign;
        break;
    case ICON:
        halign_ptr = &node->icon->halign;
        valign_ptr = &node->icon->valign;
        break;
    case PICTURE:
        halign_ptr = &node->picture->halign;
        valign_ptr = &node->picture->valign;
        break;

    default:
        JADE_ASSERT_MSG(false, "gui_set_align() - Unexpected node kind: %u", node->kind);
    }

    *halign_ptr = halign;
    *valign_ptr = valign;
}

static inline bool can_text_fit(const char* text, uint32_t font, dispWin_t cs)
{
    JADE_ASSERT(text);

    display_set_font(font, NULL); // measure relative to this font
    return display_get_string_width(text) <= cs.x2 - cs.x1;
}

// move to the next frame of a scrolling text node
static bool text_scroll_frame_callback(gui_view_node_t* node, void* extra_args)
{
    // no node, invalid node, not yet rendered...
    if (!node || node->kind != TEXT || node->render_data.is_first_time) {
        return false;
    }

    // check if scrolling is only enabled when the item is selected, and node
    // NOT currently selected - if so redraw at 'start' position
    if (!node->is_selected && node->text->scroll->only_when_selected) {
        // if text already at start position, just exit, nothing to do
        if (!node->text->scroll->going_back && !node->text->scroll->offset) {
            return false;
        }

        // set text to start position and return true so item repainted
        node->text->scroll->prev_offset = node->text->scroll->offset;
        node->text->scroll->going_back = false;
        node->text->scroll->offset = 0;
        node->text->scroll->wait = GUI_SCROLL_WAIT_END;
        return true;
    }

    // do nothing this frame
    if (node->text->scroll->wait > 0) {
        node->text->scroll->wait--;
        return false;
    }

    // the string can fit entirely in its box, no need to scroll. we might need to reset stuff though, if the text has
    // changed
    if (can_text_fit(node->render_data.resolved_text, node->text->font, node->render_data.padded_constraints)) {
        const size_t old_offset = node->text->scroll->offset;

        // set offset to zero and wait a little before checking again
        node->text->scroll->going_back = false;
        node->text->scroll->offset = 0;
        node->text->scroll->wait = GUI_SCROLL_WAIT_END;

        // only repaint on screen if the offset was not zero
        return old_offset != 0;
    }

    // update the offset based on the direction
    node->text->scroll->prev_offset = node->text->scroll->offset;
    if (node->text->scroll->going_back) {
        JADE_ASSERT(node->text->scroll->offset > 0); // we should "catch" this before and set going_back to false
        node->text->scroll->offset--;
    } else if (node->text->scroll->offset
        <= node->render_data.resolved_text_length - 1) { // never go out of bounds with the offset
        node->text->scroll->offset++;
    }

    // since we scrolled this frame, wait some frames before doing the next one
    node->text->scroll->wait = GUI_SCROLL_WAIT_FRAME;

    // check if we are done going forward
    if (!node->text->scroll->going_back) {
        bool can_fit = can_text_fit(node->render_data.resolved_text + node->text->scroll->offset, node->text->font,
            node->render_data.padded_constraints);
        bool end_of_string = node->text->scroll->offset == node->render_data.resolved_text_length - 1;

        // done, let's go back. we can fit OR we reached the end of the string
        if (can_fit || end_of_string) {
            node->text->scroll->going_back = true;
            node->text->scroll->wait = GUI_SCROLL_WAIT_END;
        }
    }

    // start again
    if (node->text->scroll->going_back && node->text->scroll->offset == 0) {
        node->text->scroll->going_back = false;
        node->text->scroll->wait = GUI_SCROLL_WAIT_END;
    }

    // repaint on screen
    return true;
}

void gui_set_text_scroll(gui_view_node_t* node, color_t background_color)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == TEXT);
    JADE_ASSERT(!node->text->scroll); // the node is not already scrolling...
    JADE_ASSERT(!node->text->noise); // if the node has noise added we will not allow scrolling ...

    struct view_node_text_scroll_data* scroll_data = JADE_CALLOC(1, sizeof(struct view_node_text_scroll_data));

    // wait a little before it starts moving
    scroll_data->offset = 0;
    scroll_data->wait = GUI_SCROLL_WAIT_END;
    scroll_data->background_color = background_color;
    scroll_data->selected_background_color = background_color;

    node->text->scroll = scroll_data;

    // now push this to the list of updatable elements so that it gets updated every frame
    push_updatable(node, text_scroll_frame_callback, NULL);
}

void gui_set_text_scroll_selected(
    gui_view_node_t* node, bool only_when_selected, color_t background_color, color_t selected_background_color)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == TEXT);

    gui_set_text_scroll(node, background_color);

    node->text->scroll->only_when_selected = only_when_selected;
    node->text->scroll->background_color = background_color;
    node->text->scroll->selected_background_color = selected_background_color;
}

void gui_set_text_noise(gui_view_node_t* node, color_t background_color)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == TEXT);
    JADE_ASSERT(!node->text->scroll); // if the node is scrolling we will not allow adding noise ...

    struct view_node_text_noise_data* noise_data = JADE_MALLOC(sizeof(struct view_node_text_noise_data));
    noise_data->background_color = background_color;

    node->text->noise = noise_data;
}

void gui_set_text_font(gui_view_node_t* node, uint32_t font)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == TEXT);

    // TODO: "validate" the font?
    node->text->font = font;
}

void gui_set_text_default_font(gui_view_node_t* node) { gui_set_text_font(node, GUI_DEFAULT_FONT); }

// resolve translated strings/etc
static void resolve_text(gui_view_node_t* node)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == TEXT);

    const char* resolved_text = NULL;
    if (strncmp("@string/", node->text->text, 8) == 0) {
        const char* key = node->text->text + 8;

        const locale_multilang_string_t* str = locale_get(key);
        if (str) {
            resolved_text = locale_lang_with_fallback(str, GUI_LOCALE);
        }
    }

    // set the resolved text. if we weren't able to resolve it (not a ref, not translated, missing for this lang, etc)
    // we just use the original value
    node->render_data.resolved_text = resolved_text ? resolved_text : node->text->text;
    node->render_data.resolved_text_length = strlen(node->render_data.resolved_text);
}

// Helper function to just update the text node internal text data - does not repaint,
// so several nodes can be updated then a single repaint issued - eg. the status bar
static void update_text_node_text(gui_view_node_t* node, const char* text)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == TEXT);
    JADE_ASSERT(text);

    // max chars limited to GUI_MAX_TEXT_LENGTH
    const size_t len = min_u16(GUI_MAX_TEXT_LENGTH, strlen(text) + 1);
    char* new_text = JADE_MALLOC(len);
    const int ret = snprintf(new_text, len, "%s", text);
    JADE_ASSERT(ret >= 0); // truncation is acceptable here, as is empty string

    // free the old text node and replace with the new pointer
    free(node->text->text);
    node->text->text = new_text;

    // resolve text references
    resolve_text(node);
}

// Takes the gui_mutex, updates the text node, and then only draws the
// updated item if it is part of the 'current activity'.
void gui_update_text(gui_view_node_t* node, const char* text)
{
    JADE_ASSERT(node);
    JADE_ASSERT(text);

    // Get the activity mutex, update the text node text and
    // if part of current activity release the mutex and post
    // a message to the gui task to repaint it.
    JADE_SEMAPHORE_TAKE(gui_mutex);
    update_text_node_text(node, text);
    const bool repaint = current_activity && node->activity == current_activity;
    JADE_SEMAPHORE_GIVE(gui_mutex);

    if (repaint) {
        // repaint the parent (so that the old string is cleared). Usually a parent should
        // be present, because it's unlikely that a root node is of type "text"
        if (node->parent) {
            gui_repaint(node->parent);
        } else {
            gui_repaint(node);
        }
    }
}

// Takes the gui_mutex, updates the icon, and then only draws the
// updated item if it is part of the 'current activity'.
void gui_update_icon(gui_view_node_t* node, const Icon icon, const bool repaint_parent)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == ICON);
    JADE_ASSERT(!node->icon->animation); // animated

    // Get the activity mutex, update the icon data and
    // if part of current activity release the mutex and post
    // a message to the gui task to repaint it.
    JADE_SEMAPHORE_TAKE(gui_mutex);
    node->icon->icon = icon;
    const bool repaint = current_activity && node->activity == current_activity;
    JADE_SEMAPHORE_GIVE(gui_mutex);

    if (repaint) {
        // Maybe repaint the parent (so that the old icon is cleared). Usually a parent should
        // be present, because it's unlikely that a root node is of type "icon"
        if (repaint_parent && node->parent) {
            // Redraw parent (ie. background), then children
            gui_repaint(node->parent);
        } else {
            // Simply redraw over the top - eg. if icon same size or larger and not transparent
            gui_repaint(node);
        }
    }
}

// Takes the gui_mutex, updates the picture, and then only draws the
// updated item if it is part of the 'current activity'.
void gui_update_picture(gui_view_node_t* node, const Picture* picture, const bool repaint_parent)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == PICTURE);
    JADE_ASSERT(picture);

    // Get the activity mutex, update the picture data and
    // if part of current activity release the mutex and post
    // a message to the gui task to repaint it.
    JADE_SEMAPHORE_TAKE(gui_mutex);
    node->picture->picture = picture;
    const bool repaint = current_activity && node->activity == current_activity;
    JADE_SEMAPHORE_GIVE(gui_mutex);

    // If part of current activity, draw it immediately
    if (repaint) {
        // Maybe repaint the parent (so that the old picture is cleared). Usually a parent should
        // be present, because it's unlikely that a root node is of type "picture"
        if (repaint_parent && node->parent) {
            // Redraw parent (ie. background), then children
            gui_repaint(node->parent);
        } else {
            // Simply redraw over the top - eg. if picture same size or larger
            gui_repaint(node);
        }
    }
}

static inline color_t DEBUG_COLOR(const uint8_t depth)
{
    switch (depth) {
    case 0:
        return TFT_RED;
    case 1:
        return TFT_ORANGE;
    case 2:
        return TFT_YELLOW;
    case 3:
        return TFT_GREENYELLOW;
    case 4:
        return TFT_GREEN;
    case 5:
        return TFT_CYAN;

    default:
        return TFT_PINK;
    }
}

// get the "step" based on the width of the parent element, our value and the type of split
static inline uint16_t get_step(enum gui_split_type kind, uint16_t total, uint16_t value)
{
    switch (kind) {
    case GUI_SPLIT_ABSOLUTE:
        return value;
        break;

    case GUI_SPLIT_RELATIVE:
        return total * value / 100;
        break;
    }

    return 0;
}

// Fully render a node, meaning that it also re-calculates the constraints, push elements to the selectables list, etc
static void render_node(gui_view_node_t* node, const dispWin_t constraints, const uint8_t depth)
{
    JADE_ASSERT(node);

    if (node->render_data.is_first_time) {
        // now that we know the coordinates of this node we can push it to the list of selectable elements
        if (is_kind_selectable(node->kind)) {
            push_selectable(node->activity, node, constraints.x1, constraints.y1);
        }

        // resolve the value for text objects
        if (node->kind == TEXT) {
            resolve_text(node);
        }

        node->render_data.is_first_time = false;
    }

    // remember the original constrains, we will calculate the others based on those
    node->render_data.original_constraints = constraints;
    calc_render_data(node);

    node->render_data.depth = depth;

    // actually paint the node on-screen
    repaint_node(node);
}

static void render_button(gui_view_node_t* node, const dispWin_t cs, const uint8_t depth)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == BUTTON);

    // If the un-selected colour is the same as the selected colour, it implies
    // the button is transparent when not selected, so we can skip filling the content.
    // NOTE: requires the parent is redrawn otherwise button will remain in 'selected' appearance
    // when selection moves on to another item.
    if (node->is_selected || node->button->color != node->button->selected_color) {
        display_fill_rect(cs.x1, cs.y1, cs.x2 - cs.x1, cs.y2 - cs.y1,
            node->is_selected ? node->button->selected_color : node->button->color);
    }

    // Draw any children directly over the current node
    gui_view_node_t* ptr = node->child;
    if (ptr) {
        render_node(ptr, cs, depth + 1);
    }
}

static void render_vsplit(gui_view_node_t* node, const dispWin_t constraints, const uint8_t depth)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == VSPLIT);

    uint16_t count = 0;
    uint16_t y = constraints.y1;
    uint16_t max_y = constraints.y2;
    uint16_t width = max_y - y;

    // Draw children in the divided area parts
    gui_view_node_t* ptr = node->child;
    while (ptr && count < node->split->parts) {
        uint16_t step;

        if (node->split->values[count] == GUI_SPLIT_FILL_REMAINING) {
            step = max_y - y;
        } else {
            step = get_step(node->split->kind, width, node->split->values[count]);
        }

        dispWin_t child_constraints = {
            .x1 = constraints.x1,
            .x2 = constraints.x2,
            .y1 = y,
            .y2 = min_u16(y + step, max_y),
        };

        render_node(ptr, child_constraints, depth + 1);

        ++count;
        y = child_constraints.y2;
        ptr = ptr->sibling;
    }
}

static void render_hsplit(gui_view_node_t* node, const dispWin_t constraints, const uint8_t depth)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == HSPLIT);

    uint16_t count = 0;
    uint16_t x = constraints.x1;
    uint16_t max_x = constraints.x2;
    uint16_t width = max_x - x;

    // Draw children in the divided area parts
    gui_view_node_t* ptr = node->child;
    while (ptr && count < node->split->parts) {
        uint16_t step;
        if (node->split->values[count] == GUI_SPLIT_FILL_REMAINING) {
            step = max_x - x;
        } else {
            step = get_step(node->split->kind, width, node->split->values[count]);
        }

        dispWin_t child_constraints
            = { .x1 = x, .x2 = min_u16(x + step, max_x), .y1 = constraints.y1, .y2 = constraints.y2 };

        render_node(ptr, child_constraints, depth + 1);

        ++count;
        x = child_constraints.x2;
        ptr = ptr->sibling;
    }
}

static void render_fill(gui_view_node_t* node, const dispWin_t cs, const uint8_t depth)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == FILL);

    color_t color;
    if (node->fill->fill_type == FILL_PLAIN) {
        color = node->is_selected ? node->fill->selected_color : node->fill->color;
    } else if (node->fill->fill_type == FILL_HIGHLIGHT) {
        color = gui_get_highlight_color();
    } else if (node->fill->fill_type == FILL_QR) {
        color = gui_get_qrcode_color();
    } else {
        JADE_ASSERT(false); // Unknown fill type
    }

    display_fill_rect(cs.x1, cs.y1, cs.x2 - cs.x1, cs.y2 - cs.y1, color);

    // Draw any children directly over the current node
    gui_view_node_t* ptr = node->child;
    if (ptr) {
        render_node(ptr, cs, depth + 1);
    }
}

static inline int resolve_halign(int x, enum gui_horizontal_align halign)
{
    switch (halign) {
    case GUI_ALIGN_LEFT:
        return 0;
    case GUI_ALIGN_CENTER:
        return CENTER;
    case GUI_ALIGN_RIGHT:
        return RIGHT;
    }

    // no modifiers
    return x;
}

static inline int resolve_valign(int y, enum gui_vertical_align valign)
{
    switch (valign) {
    case GUI_ALIGN_TOP:
        return 0;
    case GUI_ALIGN_MIDDLE:
        return CENTER;
    case GUI_ALIGN_BOTTOM:
        return BOTTOM;
    }

    // no modifiers
    return y;
}

// render a text node to screen in the window constrained by cs
static void render_text(gui_view_node_t* node, dispWin_t cs)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == TEXT);

    display_set_font(node->text->font, NULL);

    if (node->text->scroll) {
        // this text has the scroll enable, so disable wrap

        // set the foreground color to the "background color" to remove the previous string
        _fg = node->is_selected ? node->text->scroll->selected_background_color : node->text->scroll->background_color;
        display_print_in_area(node->render_data.resolved_text + node->text->scroll->prev_offset,
            resolve_halign(0, node->text->halign), resolve_valign(0, node->text->valign), cs, 0);

        // and now we write the new one using the correct color
        _fg = node->is_selected ? node->text->selected_color : node->text->color;
        display_print_in_area(node->render_data.resolved_text + node->text->scroll->offset,
            resolve_halign(0, node->text->halign), resolve_valign(0, node->text->valign), cs, 0);

    } else {
        // normal print with wrap
        if (node->text->noise) { // with noise
            const color_t color = node->is_selected ? node->text->selected_color : node->text->color;

            int pos_x = 0;
            switch (node->text->halign) {
            case GUI_ALIGN_LEFT:
                pos_x = 0;
                break;
            case GUI_ALIGN_CENTER:
                pos_x = (cs.x2 - cs.x1 - display_get_string_width(node->render_data.resolved_text)) / 2;
                break;
            case GUI_ALIGN_RIGHT:
                pos_x = cs.x2 - cs.x1 - display_get_string_width(node->render_data.resolved_text);
                break;
            }

            const int pos_y = resolve_valign(0, node->text->valign);

            uint16_t offset_x = 0;
            uint16_t offset_y = 0;
            char buf[2] = { '\0', '\0' };
            for (size_t i = 0; i < node->render_data.resolved_text_length; ++i) {
                buf[0] = node->render_data.resolved_text[i];
                const int char_width = display_get_string_width(buf);
                if (pos_x + offset_x + char_width >= cs.x2 - cs.x1) {
                    offset_y += display_get_font_height();
                    offset_x = 0;
                }

                _fg = node->text->noise->background_color;
                buf[0] = 0x61 + get_uniform_random_byte(0x7a - 0x61);
                display_print_in_area(buf, pos_x + offset_x, pos_y + offset_y, cs, 1);
                _fg = color;
                buf[0] = node->render_data.resolved_text[i];
                display_print_in_area(buf, pos_x + offset_x, pos_y + offset_y, cs, 1);
                offset_x += char_width;
            }
        } else { // without noise
            _fg = node->is_selected ? node->text->selected_color : node->text->color;

            display_print_in_area(node->render_data.resolved_text, resolve_halign(0, node->text->halign),
                resolve_valign(0, node->text->valign), cs, 1);
        }
    }
}

// render an icon to screen
static void render_icon(gui_view_node_t* node, const dispWin_t cs, const uint8_t depth)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == ICON);

    if (node->icon) {
        color_t color, bg_color;
        if (node->icon->icon_type == ICON_PLAIN) {
            color = node->is_selected ? node->icon->selected_color : node->icon->color;
            bg_color = node->icon->bg_color;
        } else if (node->icon->icon_type == ICON_QR) {
            color = node->is_selected ? node->icon->selected_color : node->icon->color;
            bg_color = gui_get_qrcode_color();
        } else {
            JADE_ASSERT(false); // Unknown fill type
        }

        const bool transparent = bg_color == color;
        display_icon(&node->icon->icon, resolve_halign(0, node->icon->halign), resolve_valign(0, node->icon->valign),
            color, cs, transparent ? NULL : &bg_color);
    }

    // Draw any children directly over the current node
    gui_view_node_t* ptr = node->child;
    if (ptr) {
        render_node(ptr, cs, depth + 1);
    }
}

// render a picture to screen
static void render_picture(gui_view_node_t* node, const dispWin_t cs, const uint8_t depth)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == PICTURE);

    if (node->picture && node->picture->picture) {
        display_picture(node->picture->picture, resolve_halign(0, node->picture->halign),
            resolve_valign(0, node->picture->valign), cs);
    }

    // Draw any children directly over the current node
    gui_view_node_t* ptr = node->child;
    if (ptr) {
        render_node(ptr, cs, depth + 1);
    }
}

// paint the borders for a view_node
static void paint_borders(gui_view_node_t* node, const dispWin_t cs)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->borders);

    const uint16_t width = cs.x2 - cs.x1;
    const uint16_t height = cs.y2 - cs.y1;

    color_t* color = NULL;
    if (node->is_selected) {
        color = &node->borders->selected_color;
    } else if (!node->is_active) {
        color = &node->borders->inactive_color;
    } else {
        color = &node->borders->color;
    }

    JADE_ASSERT(color);

    uint16_t thickness;

    if ((thickness = get_border_thickness(node->borders, GUI_BORDER_TOP_BIT))) {
        display_fill_rect(cs.x1, cs.y1, width, thickness, *color); // top
    }
    if ((thickness = get_border_thickness(node->borders, GUI_BORDER_RIGHT_BIT))) {
        display_fill_rect(cs.x2 - thickness, cs.y1, thickness, height, *color); // right
    }
    if ((thickness = get_border_thickness(node->borders, GUI_BORDER_BOTTOM_BIT))) {
        display_fill_rect(cs.x1, cs.y2 - thickness, width, thickness, *color); // bottom
    }
    if ((thickness = get_border_thickness(node->borders, GUI_BORDER_LEFT_BIT))) {
        display_fill_rect(cs.x1, cs.y1, thickness, height, *color); // left
    }
}

// Actually repaint a node on the display - calls underlying display library
static void repaint_node(gui_view_node_t* node)
{
    JADE_ASSERT(node);

    // Ensure we only call the underlying dislay library from the gui_task
    JADE_ASSERT_MSG(xTaskGetCurrentTaskHandle() == *gui_task_handle,
        "ERROR: repaint_node() called from non-gui-task: %s", pcTaskGetName(NULL));

    // borders use the un-padded constraints
    if (node->borders) {
        dispWin_t constraints = node->render_data.original_constraints;

        // margins affect borders
        constraints.y1 += node->margins.top;
        constraints.x2 -= node->margins.right;
        constraints.y2 -= node->margins.bottom;
        constraints.x1 += node->margins.left;

        paint_borders(node, constraints);
    }

    switch (node->kind) {
    case HSPLIT:
        render_hsplit(node, node->render_data.padded_constraints, node->render_data.depth);
        break;
    case VSPLIT:
        render_vsplit(node, node->render_data.padded_constraints, node->render_data.depth);
        break;
    case TEXT:
        render_text(node, node->render_data.padded_constraints); // text does not have child nodes
        break;
    case FILL:
        render_fill(node, node->render_data.padded_constraints, node->render_data.depth);
        break;
    case BUTTON:
        render_button(node, node->render_data.padded_constraints, node->render_data.depth);
        break;
    case ICON:
        render_icon(node, node->render_data.padded_constraints, node->render_data.depth);
        break;
    case PICTURE:
        render_picture(node, node->render_data.padded_constraints, node->render_data.depth);
        break;
    }
}

static void render_activity(gui_activity_t* activity)
{
    JADE_ASSERT(activity);
    JADE_ASSERT(activity->root_node);

    const bool first_time = activity->root_node->render_data.is_first_time;
    render_node(activity->root_node, activity->win, 0);

    if (first_time && activity->selectables) {
        // If the activity has an 'initial_selection' and it appears active, select it now
        // If not, select the first active item
        if (activity->initial_selection && activity->initial_selection->is_active) {
            JADE_ASSERT(activity->initial_selection->activity == activity);
            select_node(activity->initial_selection);
        } else {
            gui_view_node_t* const node = get_first_active_node(activity);
            if (node) {
                JADE_ASSERT(node->activity == activity);
                select_node(node);
            }
        }
    }
}

static void free_activities(activity_holder_t* to_free)
{
    while (to_free) {
        JADE_ASSERT(&to_free->activity != current_activity);
        activity_holder_t* const next = to_free->next;
        free_managed_activity(to_free);
        to_free = next;
    }
}

// update the status bar
static bool update_status_bar(const bool force_redraw)
{
    // No-op if no status bar
    if (!current_activity || !current_activity->status_bar) {
        return false;
    }

    bool updated = false;

    dispWin_t status_bar_cs = GUI_DISPLAY_WINDOW;
    status_bar_cs.y2 = status_bar_cs.y1 + GUI_STATUS_BAR_HEIGHT;

    // NOTE: we use the internal 'update_text_node_text()' method here
    // since we don't want to redraw each update individually, but rather
    // capture in a single repaint after all nodes are updated.
    if ((status_bar.battery_update_counter % 10) == 0) {
#ifdef CONFIG_BT_ENABLED
        const bool new_ble = ble_enabled();
#else
        const bool new_ble = false;
#endif

        if (new_ble != status_bar.last_ble_val) {
            status_bar.last_ble_val = new_ble;
            if (new_ble) {
                update_text_node_text(status_bar.ble_text, (char[]){ 'E', '\0' });
            } else {
                update_text_node_text(status_bar.ble_text, (char[]){ 'F', '\0' });
            }
            status_bar.updated = true;
        }

        const bool new_usb = usb_connected();
        if (new_usb != status_bar.last_usb_val) {
            status_bar.last_usb_val = new_usb;
            if (new_usb) {
                update_text_node_text(status_bar.usb_text, (char[]){ 'C', '\0' });
                // FIXME: change to charging rather than usb connected
                // serial_start();
            } else {
                update_text_node_text(status_bar.usb_text, (char[]){ 'D', '\0' });
                // FIXME: change to no power rather than usb connected
                // serial_stop();
            }
            status_bar.updated = true;
            status_bar.battery_update_counter = 0; // Force battery icon update
        }
    }

    if (status_bar.battery_update_counter == 0) {
        uint8_t new_bat = power_get_battery_status();
        color_t color = new_bat == 0 ? TFT_RED : new_bat == 1 ? TFT_ORANGE : TFT_WHITE;
        if (power_get_battery_charging()) {
            new_bat = new_bat + 12;
        }
        if (new_bat != status_bar.last_battery_val) {
            status_bar.last_battery_val = new_bat;
            gui_set_color(status_bar.battery_text, color);
            update_text_node_text(status_bar.battery_text, (char[]){ new_bat + '0', '\0' });
            status_bar.updated = true;
        }
        status_bar.battery_update_counter = 60;
    }

    status_bar.battery_update_counter--;

    if (status_bar.updated || force_redraw) {
        render_node(status_bar.root, status_bar_cs, 0);
        status_bar.updated = false;
        updated = true;
    }

    return updated;
}

// Process queue of jobs - always drain entire queue
static size_t handle_gui_input_queue(bool* switched_activities)
{
    JADE_ASSERT(switched_activities);
    JADE_ASSERT(gui_input_queue);

    size_t jobs_handled = 0;
    *switched_activities = false;

    gui_task_job_t* job = NULL;
    size_t item_size = 0;

    while ((job = xRingbufferReceive(gui_input_queue, &item_size, 10 / portTICK_PERIOD_MS))) {
        JADE_ASSERT(item_size == sizeof(gui_task_job_t));

        // *Either* repainting a node *or* moving to a whole new activity
        JADE_ASSERT(!job->node_to_repaint != !job->new_activity);
        activity_holder_t* to_free = job->to_free;

        if (job->new_activity && job->new_activity != current_activity) {
            *switched_activities = true;

            // Unregister the old activity's event handlers
            if (current_activity) {
                activity_event_t* l = current_activity->activity_events;
                while (l) {
                    esp_event_handler_instance_unregister(l->event_base, l->event_id, l->instance);
                    l->instance = NULL;
                    l = l->next;
                }
            }

            // Set the current_activity to the new one, and render it
            current_activity = job->new_activity;

            // If passed a 'to_free' list, free these activities now.
            // This does not really need to be protected by the semaphore - however we want to
            // free the old activities *before* the code below runs, as it makes allocations.
            // If we defer the 'frees' until later, we end up fragmenting the memory, which is
            // particularly detrimental to no-psram devices.
            if (to_free) {
                free_activities(to_free);
                to_free = NULL;
            }

            // Update the status bar text for the new activity
            if (current_activity->status_bar) {
                const bool force_redraw = true;
                update_text_node_text(status_bar.title, current_activity->title ? current_activity->title : "");
                update_status_bar(force_redraw);
            }

            // Draw the new activity
            render_activity(current_activity);

            // Register new events
            activity_event_t* l = current_activity->activity_events;
            while (l) {
                JADE_ASSERT(!l->instance);
                esp_event_handler_instance_register(l->event_base, l->event_id, l->handler, l->args, &(l->instance));
                l = l->next;
            }
        }

        // May have been passed a node to repaint
        // Only do so if it belongs on the current activity and we haven't just switched
        if (job->node_to_repaint && job->node_to_repaint->activity == current_activity && !job->new_activity) {
            // Issue repaint command on the node passed
            repaint_node(job->node_to_repaint);
        }

        // Return the ringbuffer slot
        vRingbufferReturnItem(gui_input_queue, job);

        // Free any outstanding activities, if required (and not already done)
        free_activities(to_free);

        // Count jobs handled so we can return
        ++jobs_handled;
    }

    return jobs_handled;
}

// updatables task, this task runs to update elements in the `updatables` list of the current activity
static bool update_updateables(void)
{
    if (!current_activity) {
        return false;
    }

    bool updated = false;

    updatable_t* current = current_activity->updatables;
    while (current) {
        // this shouldn't really happen but better add a check anyways
        if (!current->callback) {
            continue;
        }

        // let's see if we need to repaint this
        bool result = current->callback(current->node, current->extra_args);
        if (result) {
            // repaint the node on-screen
            // TODO: we are ignoring the return code here...
            repaint_node(current->node);
            updated = true;
        }
        current = current->next;
    }
    return updated;
}

// gui task, for managing display/activities
static void gui_task(void* args)
{
    // Flush/clear display as soon as we're able
    JADE_SEMAPHORE_TAKE(gui_mutex);
    display_flush();
    JADE_SEMAPHORE_GIVE(gui_mutex);

    // Loop to periodically handle gui events
    const TickType_t period = 1000 / GUI_TARGET_FRAMERATE / portTICK_PERIOD_MS;
    TickType_t last_wake = xTaskGetTickCount();

    for (;;) {

        // Wait for the next frame
        // Note: this task is never suspended, so no need to re-fetch the tick-
        // time each loop, just let vTaskDelayUntil() track the 'last_wake' count.
        vTaskDelayUntil(&last_wake, period);

        // Take the gui semaphore while the gui task is awake
        JADE_SEMAPHORE_TAKE(gui_mutex);

        // Check the input queue - repaint node or set new activity if need be
        // Note: this can also free all the old/completed activities
        bool switched_activities = false;
        const size_t jobs_handled = handle_gui_input_queue(&switched_activities);
        if (jobs_handled > 4) {
            JADE_LOGW("gui task handled %u jobs", jobs_handled);
        }

        bool updated = true;
        if (!switched_activities) {
            // Not switching activities, update any 'updatable' gui elements on this activity
            updated = update_updateables();
        }

        // Update status bar if required
        const bool force_redraw = false;
        if (update_status_bar(force_redraw) || updated || jobs_handled) {
            // Flush
            display_flush();
        }

        JADE_SEMAPHORE_GIVE(gui_mutex);
    }

    vTaskDelete(NULL);
}

// TODO: different functions for different types of click
void gui_wheel_click(void)
{
    if (!idletimer_register_activity(true)) {
        if (gui_click_event == GUI_WHEEL_CLICK_EVENT) {
            select_action(current_activity);
        }
        esp_event_post(GUI_EVENT, GUI_WHEEL_CLICK_EVENT, NULL, 0, 50 / portTICK_PERIOD_MS);
    }
}

void gui_front_click(void)
{
    if (!idletimer_register_activity(true)) {
        if (gui_click_event == GUI_FRONT_CLICK_EVENT) {
            select_action(current_activity);
        }
        esp_event_post(GUI_EVENT, GUI_FRONT_CLICK_EVENT, NULL, 0, 50 / portTICK_PERIOD_MS);
    }
}

void select_next_right(void)
{
    if (!idletimer_register_activity(true)) {
        select_next(current_activity);
        esp_event_post(GUI_EVENT, GUI_WHEEL_RIGHT_EVENT, NULL, 0, 50 / portTICK_PERIOD_MS);
    }
}

void select_prev_left(void)
{
    if (!idletimer_register_activity(true)) {
        select_prev(current_activity);
        esp_event_post(GUI_EVENT, GUI_WHEEL_LEFT_EVENT, NULL, 0, 50 / portTICK_PERIOD_MS);
    }
}

void gui_next(void)
{
    if (gui_orientation_flipped) {
        select_prev_left();
    } else {
        select_next_right();
    }
}

void gui_prev(void)
{
    if (gui_orientation_flipped) {
        select_next_right();
    } else {
        select_prev_left();
    }
}

// Set the item to be initally selected when the activity is activated/switched-to
// 'node' can be NULL to unset any specific initial selection
void gui_set_activity_initial_selection(gui_view_node_t* node)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->activity);
    node->activity->initial_selection = node;
}

// Post a node to the gui task to be repainted
// Should ultimately result in a call to repaint_node() from the gui_task.
// This ensures all calls to the undlerying display driver come from the gui_task
// and are serialised, such that no mutexing should be required.
void gui_repaint(gui_view_node_t* node)
{
    JADE_ASSERT(node);

    // If we are called from the gui task we can immediately repaint the node.
    // If not, we should enqueue a message to the gui task to repaint.
    if (xTaskGetCurrentTaskHandle() == *gui_task_handle) {
        repaint_node(node);
        return;
    }

    // Post the node to the gui task
    const gui_task_job_t node_repaint_info = { .node_to_repaint = node, .new_activity = NULL, .to_free = NULL };
    while (xRingbufferSend(gui_input_queue, &node_repaint_info, sizeof(node_repaint_info), 500 / portTICK_PERIOD_MS)
        != pdTRUE) {
        // wait for a spot in the ringbuffer
        JADE_LOGW("Failed to send node repaint info using gui ringbuffer");
    }
}

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
        JADE_SEMAPHORE_TAKE(gui_mutex);
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

        JADE_SEMAPHORE_GIVE(gui_mutex);
    }

    // Post the new activity and the list to free to the gui task
    while (xRingbufferSend(gui_input_queue, &switch_info, sizeof(switch_info), 500 / portTICK_PERIOD_MS) != pdTRUE) {
        // wait for a spot in the ringbuffer
        JADE_LOGW("Failed to send new activity using gui ringbuffer");
    }
}

// Initiate change of 'current' activity
void gui_set_current_activity(gui_activity_t* new_current)
{
    // Set a new activity without freeing any other activities
    gui_set_current_activity_ex(new_current, false);
}

// Create a new event_data structure, and attach to the activity
// (so it has the same lifetime as the parent activity)
wait_event_data_t* gui_activity_make_wait_event_data(gui_activity_t* activity)
{
    JADE_ASSERT(activity);

    // Create item to hold new event data object
    wait_data_t* const item = JADE_MALLOC(sizeof(wait_data_t));
    item->event_data = make_wait_event_data();

    // Put into activity's list
    item->next = activity->wait_data_items;
    activity->wait_data_items = item;

    // Return new wait_event_data
    return item->event_data;
}

void gui_activity_register_event(
    gui_activity_t* activity, const char* event_base, uint32_t event_id, esp_event_handler_t handler, void* args)
{
    JADE_ASSERT(activity);
    JADE_ASSERT(event_base);

    // Store the event registration so we can re-apply when switching between activities
    activity_event_t* link = JADE_CALLOC(1, sizeof(activity_event_t));

    link->event_base = event_base;
    link->event_id = event_id;
    link->handler = handler;
    link->args = args;

    // Get the main gui mutex before we update the activity events
    // or check the current activity, as can be concurrent with 'handle_gui_input_queue()'
    JADE_SEMAPHORE_TAKE(gui_mutex);

    if (!activity->activity_events) {
        activity->activity_events = link;
    } else {
        activity_event_t* last = activity->activity_events;
        while (last->next) {
            last = last->next;
        }
        last->next = link;
    }

    // If this activity is already active, immediately add the event handler
    if (activity == current_activity) {
        const esp_err_t rc
            = esp_event_handler_instance_register(event_base, event_id, handler, args, &(link->instance));
        JADE_ASSERT(rc == ESP_OK);
    }

    // Return the main gui mutex
    JADE_SEMAPHORE_GIVE(gui_mutex);
}

// Registers an event handler, then blocks waiting for it to fire.  A timeout can be passed.
// Returns true if the event fires, false if the timeout elapsed without the event occuring.
bool gui_activity_wait_event(gui_activity_t* activity, const char* event_base, uint32_t event_id,
    esp_event_base_t* trigger_event_base, int32_t* trigger_event_id, void** trigger_event_data, TickType_t max_wait)
{
    JADE_ASSERT(activity);

    // create a new wait-event-data structure and attach to the activity, which takes ownership
    wait_event_data_t* const wait_event_data = gui_activity_make_wait_event_data(activity);
    JADE_ASSERT(wait_event_data);

    // register it so that it gets removed when the activity is swapped out
    gui_activity_register_event(activity, event_base, event_id, sync_wait_event_handler, wait_event_data);

    // immediately start waiting
    const esp_err_t ret
        = sync_wait_event(wait_event_data, trigger_event_base, trigger_event_id, trigger_event_data, max_wait);

    return ret == ESP_OK;
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

// Update the title associated with the passed activity
void gui_set_activity_title(gui_activity_t* activity, const char* title)
{
    JADE_ASSERT(activity);
    JADE_ASSERT(title);

    JADE_SEMAPHORE_TAKE(gui_mutex);
    if (activity->title) {
        free(activity->title);
    }
    activity->title = strdup(title);

    // If setting title for the current activity, update status bar
    const bool repaint = current_activity && activity == current_activity;
    JADE_SEMAPHORE_GIVE(gui_mutex);

    if (repaint) {
        gui_repaint(status_bar.root);
    }
}

gui_activity_t* gui_current_activity(void) { return current_activity; }

#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1) || defined(CONFIG_BOARD_TYPE_JADE_V2)
extern const uint8_t splashstart[] asm("_binary_splash_bin_gz_start");
extern const uint8_t splashend[] asm("_binary_splash_bin_gz_end");
#endif

gui_activity_t* gui_display_splash(void)
{
    gui_activity_t* const act = gui_make_activity();
    gui_view_node_t* splash_node = NULL;

    // Blank screen while awaiting attestation data upload
    if (!gui_awaiting_attestation_data()) {
#if defined(CONFIG_BOARD_TYPE_JADE) || defined(CONFIG_BOARD_TYPE_JADE_V1_1) || defined(CONFIG_BOARD_TYPE_JADE_V2)
        Picture* const pic = get_picture(splashstart, splashend);
        gui_make_picture(&splash_node, pic);
#else
        gui_make_text(&splash_node, "Jade DIY", TFT_WHITE);
#endif
        gui_set_align(splash_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(splash_node, act->root_node);
    }

    // set the current activity and draw it on screen
    gui_set_current_activity(act);
    return act;
}
#endif // AMALGAMATED_BUILD
