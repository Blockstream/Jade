#include <stdarg.h>
#include <string.h>

#include <freertos/FreeRTOS.h>
#include <freertos/ringbuf.h>
#include <freertos/task.h>

#include <tftspi.h>

#include "gui.h"
#include "idletimer.h"
#include "jade_assert.h"
#include "power.h"
#include "qrcode.h"
#include "random.h"
#include "storage.h"
#include "utils/event.h"
#include "utils/malloc_ext.h"

#ifndef CONFIG_ESP32_NO_BLOBS
#include "ble/ble.h"
#endif

ESP_EVENT_DEFINE_BASE(GUI_BUTTON_EVENT);
ESP_EVENT_DEFINE_BASE(GUI_EVENT);

static const uint8_t GUI_TASK_PRIORITY = 5;

typedef struct {
    gui_activity_t* old_activity;
    gui_activity_t* new_activity;
} activity_switch_info_t;

typedef struct _activity_holder_t activity_holder_t;
struct _activity_holder_t {
    gui_activity_t activity;
    activity_holder_t* next;
};

// global mutex used to synchronize tft paint commands. global across activities
static SemaphoreHandle_t paint_mutex = NULL;
// current activity being drawn on screen
static gui_activity_t* current_activity = NULL;
// stack of activities that currently exist
static activity_holder_t* existing_activities = NULL;
// handle to the task running to update updatable elements
static TaskHandle_t updatables_task_handle;

// Click/select event (ie. which button counts as 'click'/select)
static gui_event_t gui_click_event = GUI_FRONT_CLICK_EVENT;

// Queues and handles for activities tasks
static RingbufHandle_t free_activities = NULL;
static RingbufHandle_t switch_activities = NULL;
static TaskHandle_t free_activities_task_handle;
static TaskHandle_t switch_activities_task_handle;

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

// Some definitions that we don't want to expose so we keep them here instead of adding them to the header
static void free_activities_task(void* args);
static void switch_activities_task(void* args);
static void updatables_task(void* args);
static void status_bar_task(void* args);

typedef struct selectable_element selectable_t;

// Utils

static inline uint16_t min(uint16_t a, uint16_t b) { return a < b ? a : b; }

static void make_status_bar()
{
    gui_view_node_t* root;
    gui_make_fill(&root, TFT_BLACK);
    root->parent = NULL;

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_ABSOLUTE, 4, 160, 20, 20, 40);
    gui_set_borders(hsplit, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);
    gui_set_parent(hsplit, root);

    gui_view_node_t* black_title_bg;
    gui_make_fill(&black_title_bg, TFT_BLACK);
    gui_set_parent(black_title_bg, hsplit);

    gui_view_node_t* title_text;
    gui_make_text(&title_text, "Jade", TFT_WHITE);
    gui_set_parent(title_text, black_title_bg);
    gui_set_align(title_text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(title_text, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 4);

    gui_view_node_t* usb_text;
    gui_make_text(&usb_text, "D", TFT_WHITE);
    gui_set_text_font(usb_text, JADE_SYMBOLS_16x16_FONT);
    gui_set_parent(usb_text, hsplit);
    gui_set_align(usb_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_view_node_t* ble_text;
    gui_make_text(&ble_text, "F", TFT_WHITE);
    gui_set_text_font(ble_text, JADE_SYMBOLS_16x16_FONT);
    gui_set_parent(ble_text, hsplit);
    gui_set_align(ble_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_view_node_t* battery_text;
    gui_make_text(&battery_text, "0", TFT_WHITE);
    gui_set_text_font(battery_text, JADE_SYMBOLS_16x32_FONT);
    gui_set_parent(battery_text, hsplit);
    gui_set_align(battery_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    status_bar.root = root;
    status_bar.title = title_text;
    status_bar.battery_text = battery_text;
    status_bar.usb_text = usb_text;
    status_bar.ble_text = ble_text;

    status_bar.updated = false;
    status_bar.last_battery_val = 0xFF;
    status_bar.battery_update_counter = 0;
}

gui_event_t gui_get_click_event() { return gui_click_event; }

void gui_set_click_event(gui_event_t event)
{
    JADE_ASSERT(event == GUI_FRONT_CLICK_EVENT || event == GUI_WHEEL_CLICK_EVENT);
    storage_set_click_event(event);
    gui_click_event = event;
}

// TODO: improve error checks
void gui_init()
{
    // Create semaphore.  Note it has to be 'preloaded' so it can be taken later
    paint_mutex = xSemaphoreCreateBinary();
    JADE_ASSERT(paint_mutex);
    xSemaphoreGive(paint_mutex);

    // Which button event are we to use as a click / 'select item' - sanity checked
    const gui_event_t loaded_click_event = storage_get_click_event();
    if (loaded_click_event == GUI_FRONT_CLICK_EVENT || loaded_click_event == GUI_WHEEL_CLICK_EVENT) {
        gui_click_event = loaded_click_event;
    } else {
        gui_set_click_event(GUI_FRONT_CLICK_EVENT);
    }
    JADE_ASSERT(gui_click_event == GUI_FRONT_CLICK_EVENT || gui_click_event == GUI_WHEEL_CLICK_EVENT);

    // create a blank activity
    gui_make_activity(&current_activity, false, NULL);

    // create the default event loop used by btns
    const esp_err_t rc = esp_event_loop_create_default();
    JADE_ASSERT(rc == ESP_OK);

    // Create 'switch activities' and 'free activities' input queues (ringbuffers)
    free_activities = xRingbufferCreate(32, RINGBUF_TYPE_NOSPLIT);
    JADE_ASSERT(free_activities);
    switch_activities = xRingbufferCreate(32, RINGBUF_TYPE_NOSPLIT);
    JADE_ASSERT(switch_activities);

    // Create 'free activities' task
    BaseType_t retval = xTaskCreatePinnedToCore(free_activities_task, "free_activities", 2 * 1024, NULL,
        tskIDLE_PRIORITY, &free_activities_task_handle, GUI_CORE);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create free_activities task, xTaskCreatePinnedToCore() returned %d", retval);

    // Create 'switch activities' task
    retval = xTaskCreatePinnedToCore(switch_activities_task, "switch_activities", 4 * 1024, NULL, GUI_TASK_PRIORITY,
        &switch_activities_task_handle, GUI_CORE);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create switch_activities task, xTaskCreatePinnedToCore() returned %d", retval);

    // Create gui_updateables task
    retval = xTaskCreatePinnedToCore(
        updatables_task, "gui_updatables", 2 * 1024, NULL, GUI_TASK_PRIORITY, &updatables_task_handle, GUI_CORE);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create gui_updatables task, xTaskCreatePinnedToCore() returned %d", retval);

    make_status_bar();

    // Create status-bar task
    retval = xTaskCreatePinnedToCore(
        status_bar_task, "status_bar", 2 * 1024, NULL, GUI_TASK_PRIORITY, &status_bar.task_handle, GUI_CORE);
    JADE_ASSERT_MSG(
        retval == pdPASS, "Failed to create status_bar task, xTaskCreatePinnedToCore() returned %d", retval);

    vTaskSuspend(status_bar.task_handle); // this will be started when necessary
}

bool gui_initialized() { return switch_activities; }

// Is this kind of node selectable?
static inline bool is_kind_selectable(enum view_node_kind kind)
{
    switch (kind) {
    case BUTTON:
        return true;
    default:
        return false;
    }
}

// Is node a "before" node b on-screen? (i.e. is it above or more left?)
static inline bool is_before(const selectable_t* a, const selectable_t* b)
{
    return a->y < b->y || (a->y == b->y && a->x < b->x);
}

// Traverse the tree from `node` downward and set the `is_selected` of every node to `value`
static void set_tree_selection(gui_view_node_t* node, bool value)
{
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
    node->is_active = value;

    gui_view_node_t* child = node->child;
    while (child) {
        set_tree_active(child, value);
        child = child->sibling;
    }
}

// Function to set the passed node as active or inactive, depending on 'value'.
// Returns true if the node was found and marked active or inactive as requested.
// Returns false if node not found or if it would deactivate the only active node,
// in which case no 'active' nodes are changed.
bool gui_set_active(gui_activity_t* activity, gui_view_node_t* node, bool value)
{
    JADE_ASSERT(activity);
    JADE_ASSERT(node);

    // TODO: make sure that `node` is part of `activity`

    if (value) {
        // Set passed node to active
        set_tree_active(node, true);
        gui_repaint(node, true);
        return true;
    }

    // Check other active nodes exist
    selectable_t* const begin = activity->selectables;
    if (!begin) {
        return false;
    }

    bool other_active_nodes_exist = false;
    selectable_t* current = begin;
    do {
        other_active_nodes_exist = current->node != node && current->node->is_active;
        current = current->next;
    } while (current != begin && !other_active_nodes_exist);

    // no other active nodes, we can't de-activate it
    if (!other_active_nodes_exist) {
        return false;
    }

    set_tree_active(node, false);
    gui_repaint(node, true);
    return true;
}

static gui_view_node_t* gui_get_first_active_node(gui_activity_t* activity)
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
bool gui_select_prev(gui_activity_t* activity)
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
    gui_repaint(current->node, true);

    set_tree_selection(prev_active->node, true);
    gui_repaint(prev_active->node, true);

    activity->selectables = prev_active;

    return true;
}

// Note: node must exist and be part of passed activity.
// Any prior selection will be cleared.
void gui_select_node(gui_activity_t* activity, gui_view_node_t* node)
{
    JADE_ASSERT(activity);
    JADE_ASSERT(activity->selectables);
    JADE_ASSERT(node);
    JADE_ASSERT(node->is_active);

    selectable_t* const begin = activity->selectables;
    selectable_t* current = begin;

    selectable_t* old_selected = NULL;
    selectable_t* new_selected = NULL;

    // look for both the selected node and `node`
    do {
        if (current->node->is_selected) {
            old_selected = current;
        }
        if (current->node == node) {
            new_selected = current;
        }
        current = current->next;
    } while (current != begin && (!new_selected || !old_selected));

    // Must have found node - ie. passed node must be part of 'activity'
    JADE_ASSERT(new_selected);

    // Deactivate prior selection
    if (old_selected) {
        set_tree_selection(old_selected->node, false);
        gui_repaint(old_selected->node, true);
    }

    // Select passed node
    set_tree_selection(new_selected->node, true);
    gui_repaint(new_selected->node, true);

    activity->selectables = new_selected;
}

// select the next item in the selectables list
// Returns true if the selection is 'moved' to a subsequent item, or false if not (and selection left unchanged)
// eg. no current item selected, no other selectable items, no later selectable items [and not wrapping] etc.
bool gui_select_next(gui_activity_t* activity)
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
    gui_repaint(current->node, true);

    // add selection to `next_active`
    set_tree_selection(next_active->node, true);
    gui_repaint(next_active->node, true);

    activity->selectables = next_active;

    return true;
}

// trigger the action for the selected element
static void select_action(gui_activity_t* activity)
{
    JADE_ASSERT(activity);

    selectable_t* const current = activity->selectables;
    if (current && current->node->is_selected && current->node->button->click_event_id != GUI_BUTTON_EVENT_NONE) {
        const esp_err_t rc = esp_event_post(GUI_BUTTON_EVENT, current->node->button->click_event_id,
            &current->node->button->args, sizeof(void*), 100 / portTICK_PERIOD_MS);
        JADE_ASSERT(rc == ESP_OK);
    }
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

static void push_updatable(
    gui_activity_t* activity, gui_view_node_t* node, gui_updatable_callback_t callback, void* extra_args)
{
    JADE_ASSERT(activity);
    JADE_ASSERT(node);

    // allocate & fill all the fields
    updatable_t* us = JADE_CALLOC(1, sizeof(updatable_t));

    us->node = node;

    us->callback = callback;
    us->extra_args = extra_args;

    // first one!
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

// Create a new empty/placeholder activity, and add to the stack of existing activities
static void create_activity(gui_activity_t** ppact)
{
    JADE_ASSERT(ppact);

    activity_holder_t* holder = JADE_MALLOC(sizeof(activity_holder_t));

    // Add to the stack of existing activities
    holder->next = existing_activities;
    existing_activities = holder;

    // Return the activity from within this holder
    *ppact = &holder->activity;
}

// Create a new/initialised activity (and add to the stack of existing activities)
void gui_make_activity(gui_activity_t** ppact, bool has_status_bar, const char* title)
{
    JADE_ASSERT(ppact);

    gui_activity_t* activity = NULL;
    create_activity(&activity);
    JADE_ASSERT(activity);

    // Initialise the activity
    activity->win = GUI_DISPLAY_WINDOW;
    if (has_status_bar) {
        // offset the display window since the top-part will contain the status bar
        activity->win.y1 += GUI_STATUS_BAR_HEIGHT;
    }

    activity->status_bar = has_status_bar;
    activity->title = NULL;
    if (title) {
        activity->title = strdup(title);
        JADE_ASSERT(activity->title);
    }

    activity->root_node = NULL;
    gui_make_fill(&(activity->root_node), TFT_BLACK);

    activity->root_node->activity = activity;

    activity->selectables = NULL;
    activity->selectables_wrap = false; // normally we don't wrap around

    // Nothing explicitly selected (so will default to first selectable item)
    // Can be set with gui_set_activity_initial_selection()
    activity->initial_selection = NULL;

    activity->updatables = NULL;

    activity->activity_events = NULL;

    *ppact = activity;
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
static void free_activity_events(activity_event_t* tip)
{
    if (tip) {
        activity_event_t* current = tip;
        while (current) {
            activity_event_t* const next = current->next;
            free(current);
            current = next;
        }
    }
}

// free an activity-holder and all of the activity contents (title, selectables/updatables etc.)
static void gui_free_activity(activity_holder_t* holder)
{
    JADE_ASSERT(holder);

    gui_activity_t* activity = &holder->activity;
    JADE_ASSERT(activity != current_activity);

    free_selectables(activity);
    free_updatables(activity);
    free_activity_events(activity->activity_events);
    free_view_node(activity->root_node);

    if (activity->title) {
        free(activity->title);
    }

    // Free the activity holder
    free(holder);
}

// Task waits on a queue - when a list of activities is received, they are freed.
static void free_activities_task(void* unused)
{
    JADE_ASSERT(free_activities);

    while (true) {
        size_t item_size = 0;
        activity_holder_t** item = xRingbufferReceive(free_activities, &item_size, portMAX_DELAY);

        if (item != NULL) {
            JADE_ASSERT(item_size == sizeof(activity_holder_t*));
            activity_holder_t* activities = *item;

            while (activities) {
                activity_holder_t* holder = activities;
                activities = holder->next;

                // Should not be the current activity
                JADE_ASSERT(&holder->activity != current_activity);
                gui_free_activity(holder);
            }

            // Return the ringbuffer slot
            vRingbufferReturnItem(free_activities, item);
        }
    }
}

// schedule job to free all existing activities, except the current activity
void gui_free_noncurrent_activities()
{
    activity_holder_t* scrapheap = NULL;

    // Ensure current activity not put in scrapheap
    if (existing_activities) {
        // If the first/latest activity is the current activity, skip it.
        if (&existing_activities->activity == current_activity) {
            scrapheap = existing_activities->next;
            existing_activities->next = NULL;
        } else {
            // Otherwise check entire list
            scrapheap = existing_activities;
            for (activity_holder_t* holder = scrapheap; holder && holder->next; holder = holder->next) {
                if (&holder->next->activity == current_activity) {
                    // Skip the next activity (as current) and link to following
                    existing_activities = holder->next;
                    holder->next = holder->next->next;
                    existing_activities->next = NULL;
                }
            }
        }
        JADE_ASSERT(
            existing_activities && (&existing_activities->activity == current_activity) && !existing_activities->next);
    }

    // post to low-priority task to free all scrapped activities, if there are any
    if (scrapheap) {
        while (xRingbufferSend(free_activities, &scrapheap, sizeof(scrapheap), portMAX_DELAY) != pdTRUE) {
            // wait for a spot in the ring
        }
    }
}

// attach a view node (recusively) to an activity
static void set_tree_activity(gui_view_node_t* node, gui_activity_t* activity)
{
    JADE_ASSERT(node);
    // JADE_ASSERT(activity); TODO: does it make sense to allow to set a NULL activity? we use it for the status bar

    JADE_ASSERT(!node->activity);

    // set our
    node->activity = activity;

    // and then all the others
    gui_view_node_t* current = node->child;
    while (current) {
        set_tree_activity(current, activity);
        current = current->sibling;
    }
}

// set a parent for a node and also add the node to the parent's children list
// TODO: if `child` is selectable, check that there are no other selectable items in its subtree (from parent to root)
void gui_set_parent(gui_view_node_t* child, gui_view_node_t* parent)
{
    JADE_ASSERT(child);
    JADE_ASSERT(parent);

    // child should not already have a parent
    JADE_ASSERT(!child->parent);
    child->parent = parent;

    // also inherits the activity
    set_tree_activity(child, parent->activity);

    // first child
    if (!parent->child) {
        parent->child = child;
    } else {
        // Add to tail
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

// make the underlying view node, common across all the gui_make_* functions
static void make_view_node(gui_view_node_t** ptr, enum view_node_kind kind, void* data, free_callback_t free_callback)
{
    JADE_ASSERT(ptr);

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
    JADE_ASSERT(ptr);
    JADE_ASSERT(split_kind == HSPLIT || split_kind == VSPLIT);

    struct view_node_split_data* data = JADE_CALLOC(1, sizeof(struct view_node_split_data));

    data->kind = kind;
    data->parts = parts;

    // copy the values
    data->values = JADE_CALLOC(1, sizeof(uint8_t) * parts);

    for (uint8_t i = 0; i < parts; i++) {
        data->values[i] = va_arg(values, int);
    };

    // ... and also set a destructor to free them later
    make_view_node(ptr, split_kind, data, free_view_node_split_data);
}

void gui_make_hsplit(gui_view_node_t** ptr, enum gui_split_type kind, uint8_t parts, ...)
{
    va_list args;
    va_start(args, parts);
    make_split_node(ptr, HSPLIT, kind, parts, args);
    va_end(args);
}

void gui_make_vsplit(gui_view_node_t** ptr, enum gui_split_type kind, uint8_t parts, ...)
{
    va_list args;
    va_start(args, parts);
    make_split_node(ptr, VSPLIT, kind, parts, args);
    va_end(args);
}

void gui_make_button(gui_view_node_t** ptr, color_t color, uint32_t event_id, void* args)
{
    JADE_ASSERT(ptr);

    struct view_node_button_data* data = JADE_CALLOC(1, sizeof(struct view_node_button_data));

    // by default same color
    data->color = color;
    data->selected_color = color;

    data->click_event_id = event_id;
    data->args = args;

    make_view_node(ptr, BUTTON, data, NULL);
}

void gui_make_fill(gui_view_node_t** ptr, color_t color)
{
    JADE_ASSERT(ptr);

    struct view_node_fill_data* data = JADE_CALLOC(1, sizeof(struct view_node_fill_data));

    // by default same color
    data->color = color;
    data->selected_color = color;

    make_view_node(ptr, FILL, data, NULL);
}

void gui_make_text(gui_view_node_t** ptr, const char* text, color_t color)
{
    gui_make_text_font(ptr, text, color, GUI_DEFAULT_FONT);
}

void gui_make_text_font(gui_view_node_t** ptr, const char* text, color_t color, uint32_t font)
{
    JADE_ASSERT(ptr);
    JADE_ASSERT(text);

    struct view_node_text_data* data = JADE_CALLOC(1, sizeof(struct view_node_text_data));

    // max chars limited to GUI_MAX_TEXT_LENGTH
    const size_t len = min(GUI_MAX_TEXT_LENGTH, strlen(text) + 1);
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

void gui_make_icon(gui_view_node_t** ptr, const Icon* icon, color_t color)
{
    JADE_ASSERT(ptr);

    struct view_node_icon_data* data = JADE_CALLOC(1, sizeof(struct view_node_icon_data));

    data->icon = *icon;

    // by default same color
    data->color = color;
    data->selected_color = color;

    // and top-left
    data->halign = GUI_ALIGN_LEFT;
    data->valign = GUI_ALIGN_TOP;

    make_view_node(ptr, ICON, data, NULL);
}

void gui_make_picture(gui_view_node_t** ptr, const Picture* picture)
{
    JADE_ASSERT(ptr);

    struct view_node_picture_data* data = JADE_CALLOC(1, sizeof(struct view_node_picture_data));

    data->picture = picture;

    // top-left by default
    data->halign = GUI_ALIGN_LEFT;
    data->valign = GUI_ALIGN_TOP;

    make_view_node(ptr, PICTURE, data, NULL);
}

static void set_vals_with_varargs(gui_margin_t* margins, uint8_t sides, va_list args)
{
    uint16_t val;

    switch (sides) {
    case GUI_MARGIN_ALL_EQUAL:
        // we only pop one value
        val = va_arg(args, int);
        margins->top = val;
        margins->right = val;
        margins->bottom = val;
        margins->left = val;
        break;

    case GUI_MARGIN_TWO_VALUES:
        // two values, top/bottom and right/left
        val = va_arg(args, int);
        margins->top = val;
        margins->bottom = val;

        val = va_arg(args, int);
        margins->right = val;
        margins->left = val;
        break;

    case GUI_MARGIN_ALL_DIFFERENT:
        // four different values
        margins->top = va_arg(args, int);
        margins->right = va_arg(args, int);
        margins->bottom = va_arg(args, int);
        margins->left = va_arg(args, int);
        break;

    default:
        JADE_ASSERT_MSG(false, "set_vals_with_varargs() - unexpected 'sides' value: %u", sides);
    }
}

// get the thickness for border "border_bit" (which should have the value of one of the BIT constants)
static inline uint8_t get_border_thickness(gui_border_t* borders, uint16_t border_bit)
{
    // thickness is either "border->thickness" if that specific border is enabled or 0
    return borders->thickness * ((borders->borders >> border_bit) & 1);
}

static void calc_render_data(gui_view_node_t* node)
{
    JADE_ASSERT(node);

    // constraints haven't been set yet, we can't do much
    if (node->render_data.is_first_time) {
        return;
    }

    dispWin_t constraints = node->render_data.original_constraints;

    // margins affect borders
    constraints.y1 += node->margins.top;
    constraints.x2 -= node->margins.right;
    constraints.y2 -= node->margins.bottom;
    constraints.x1 += node->margins.left;

    // constrains without padding (used for borders)
    node->render_data.constraints = constraints;

    // remove the border + padding area from constraints
    constraints.y1 += node->padding.top + get_border_thickness(&node->borders, GUI_BORDER_TOP_BIT);
    constraints.x2 -= node->padding.right + get_border_thickness(&node->borders, GUI_BORDER_RIGHT_BIT);
    constraints.y2 -= node->padding.bottom + get_border_thickness(&node->borders, GUI_BORDER_BOTTOM_BIT);
    constraints.x1 += node->padding.left + get_border_thickness(&node->borders, GUI_BORDER_LEFT_BIT);

    node->render_data.padded_constraints = constraints;
}

void gui_set_margins(gui_view_node_t* node, uint8_t sides, ...)
{
    JADE_ASSERT(node);

    va_list args;
    va_start(args, sides);
    set_vals_with_varargs(&node->margins, sides, args);
    va_end(args);

    // update constraints
    calc_render_data(node);
}

void gui_set_padding(gui_view_node_t* node, uint8_t sides, ...)
{
    JADE_ASSERT(node);

    va_list args;
    va_start(args, sides);
    set_vals_with_varargs(&node->padding, sides, args);
    va_end(args);

    // update constraints
    calc_render_data(node);
}

void gui_set_borders(gui_view_node_t* node, color_t color, uint8_t thickness, uint16_t borders)
{
    JADE_ASSERT(node);

    // by default same color
    node->borders.color = color;
    node->borders.selected_color = color;
    node->borders.inactive_color = color;

    node->borders.thickness = thickness;
    node->borders.borders = borders;

    // update constraints
    calc_render_data(node);
}

void gui_set_borders_selected_color(gui_view_node_t* node, color_t selected_color)
{
    JADE_ASSERT(node);
    node->borders.selected_color = selected_color;
}

void gui_set_borders_inactive_color(gui_view_node_t* node, color_t inactive_color)
{
    JADE_ASSERT(node);
    node->borders.inactive_color = inactive_color;
}

void gui_set_selected_color(gui_view_node_t* node, color_t selected_color)
{
    JADE_ASSERT(node);

    color_t* color_ptr;
    switch (node->kind) {
    case TEXT:
        color_ptr = &node->text->selected_color;
        break;
    case FILL:
        color_ptr = &node->fill->selected_color;
        break;
    case BUTTON:
        color_ptr = &node->fill->selected_color;
        break;
    case ICON:
        color_ptr = &node->icon->selected_color;
        break;
    default:
        JADE_ASSERT_MSG(false, "gui_set_selected_color() - Unexpected node kind: %u", node->kind);
    }

    *color_ptr = selected_color;
}

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
    TFT_setFont(font, NULL); // measure relative to this font
    return TFT_getStringWidth(text) <= cs.x2 - cs.x1;
}

// move to the next frame of a scrolling text node
bool text_scroll_frame_callback(gui_view_node_t* node, void* extra_args)
{
    // no node, invalid node, not yet renreded...
    if (!node || node->kind != TEXT || node->render_data.is_first_time) {
        return false;
    }

    // do nothing this frame
    if (node->text->scroll->wait > 0) {
        node->text->scroll->wait--;
        return false;
    }

    // the string can fit entirely in its box, no need to scroll. we might need to reset stuff though, if the text has
    // changed
    if (can_text_fit(node->render_data.resolved_text, node->text->font, node->render_data.padded_constraints)) {
        uint8_t old_offset = node->text->scroll->offset;

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
    JADE_ASSERT(!node->text->scroll); // the node is already scrolling...

    struct view_node_text_scroll_data* scroll_data = JADE_CALLOC(1, sizeof(struct view_node_text_scroll_data));

    // wait a little before it starts moving
    scroll_data->offset = 0;
    scroll_data->wait = GUI_SCROLL_WAIT_END;
    scroll_data->background_color = background_color;

    node->text->scroll = scroll_data;

    // now push this to the list of updatable elements so that it gets updated every frame
    push_updatable(node->activity, node, text_scroll_frame_callback, NULL);
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

// resolve transalted strings/etc
static void gui_resolve_text(gui_view_node_t* node)
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

void gui_update_text(gui_view_node_t* node, const char* text)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == TEXT);

    // max chars limited to GUI_MAX_TEXT_LENGTH
    const size_t len = min(GUI_MAX_TEXT_LENGTH, strlen(text) + 1);
    char* new_text = JADE_MALLOC(len);
    const int ret = snprintf(new_text, len, "%s", text);
    JADE_ASSERT(ret >= 0); // truncation is acceptable here, as is empty string

    // free the old one and replace with the new pointer
    free(node->text->text);
    node->text->text = new_text;

    // resolve text references
    gui_resolve_text(node);

    // repaint the parent (so that the old string is cleared). Usually a parent should
    // be present, because it's unlikely that a root node is of type "text"
    if (node->parent) {
        gui_repaint(node->parent, true);
    } else {
        gui_repaint(node, true);
    }
}

void gui_update_picture(gui_view_node_t* node, const Picture* picture)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == PICTURE);

    node->picture->picture = picture;
    gui_repaint(node, true);
}

static inline color_t DEBUG_COLOR(uint8_t depth)
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
static void render_node(gui_view_node_t* node, dispWin_t constraints, uint8_t depth)
{
    JADE_ASSERT(node);

    if (node->render_data.is_first_time) {
        // now that we know the coordinates of this node we can push it to the list of selectable elements
        if (is_kind_selectable(node->kind)) {
            push_selectable(node->activity, node, constraints.x1, constraints.y1);
        }

        // resolve the value for text objects
        if (node->kind == TEXT) {
            gui_resolve_text(node);
        }

        node->render_data.is_first_time = false;
    }

    // remember the original constrains, we will calculate the others based on those
    node->render_data.original_constraints = constraints;
    calc_render_data(node);

    node->render_data.depth = depth;

    // actually paint the node on-screen, taking the mutex only if we are the root
    gui_repaint(node, !node->parent);
}

static void render_button(gui_view_node_t* node, dispWin_t cs, uint8_t depth)
{
    TFT_fillRect(cs.x1, cs.y1, cs.x2 - cs.x1, cs.y2 - cs.y1,
        node->is_selected ? node->button->selected_color : node->button->color);

    gui_view_node_t* ptr = node->child;
    if (ptr) {
        render_node(ptr, cs, depth + 1);
    }
}

static void render_vsplit(gui_view_node_t* node, dispWin_t constraints, uint8_t depth)
{
    uint16_t count = 0;
    uint16_t y = constraints.y1;
    uint16_t max_y = constraints.y2;
    uint16_t width = max_y - y;

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
            .y2 = min(y + step, max_y),
        };

        render_node(ptr, child_constraints, depth + 1);

        count++;
        y = child_constraints.y2;
        ptr = ptr->sibling;
    }
}

static void render_hsplit(gui_view_node_t* node, dispWin_t constraints, uint8_t depth)
{
    uint16_t count = 0;
    uint16_t x = constraints.x1;
    uint16_t max_x = constraints.x2;
    uint16_t width = max_x - x;

    gui_view_node_t* ptr = node->child;
    while (ptr && count < node->split->parts) {
        uint16_t step;
        if (node->split->values[count] == GUI_SPLIT_FILL_REMAINING) {
            step = max_x - x;
        } else {
            step = get_step(node->split->kind, width, node->split->values[count]);
        }

        dispWin_t child_constraints
            = { .x1 = x, .x2 = min(x + step, max_x), .y1 = constraints.y1, .y2 = constraints.y2 };

        render_node(ptr, child_constraints, depth + 1);

        count++;
        x = child_constraints.x2;
        ptr = ptr->sibling;
    }
}

static void render_fill(gui_view_node_t* node, dispWin_t cs, uint8_t depth)
{
    color_t* color = node->is_selected ? &node->fill->selected_color : &node->fill->color;

    TFT_fillRect(cs.x1, cs.y1, cs.x2 - cs.x1, cs.y2 - cs.y1, *color);

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

    TFT_setFont(node->text->font, NULL);

    if (node->text->scroll) {
        // this text has the scroll enable, so disable wrap
        text_wrap = 0;

        // set the foreground color to the "background color" to remove the previous string
        _fg = node->text->scroll->background_color;
        TFT_print_in_area(node->render_data.resolved_text + node->text->scroll->prev_offset,
            resolve_halign(0, node->text->halign), resolve_valign(0, node->text->valign), cs);

        // and now we write the new one using the correct color
        _fg = node->is_selected ? node->text->selected_color : node->text->color;
        TFT_print_in_area(node->render_data.resolved_text + node->text->scroll->offset,
            resolve_halign(0, node->text->halign), resolve_valign(0, node->text->valign), cs);

        text_wrap = 1;
    } else {
        // normal print with wrap
        text_wrap = 1;
        if (node->text->noise) { // with noise
            color_t color = node->is_selected ? node->text->selected_color : node->text->color;

            int pos_x = 0;
            switch (node->text->halign) {
            case GUI_ALIGN_LEFT:
                pos_x = 0;
                break;
            case GUI_ALIGN_CENTER:
                pos_x = (cs.x2 - cs.x1 - TFT_getStringWidth(node->render_data.resolved_text)) / 2;
                break;
            case GUI_ALIGN_RIGHT:
                pos_x = cs.x2 - cs.x1 - TFT_getStringWidth(node->render_data.resolved_text);
                break;
            }

            const int pos_y = resolve_valign(0, node->text->valign);

            uint8_t offset = 0;

            for (size_t i = 0; i < node->render_data.resolved_text_length; i++) {
                char buff[2];
                _fg = node->text->noise->background_color;
                buff[0] = 0x61 + get_uniform_random_byte(0x7a - 0x61);
                buff[1] = '\0';
                TFT_print_in_area(buff, pos_x + offset, pos_y, cs);
                _fg = color;
                buff[0] = node->render_data.resolved_text[i];
                buff[1] = '\0';
                TFT_print_in_area(buff, pos_x + offset, pos_y, cs);
                offset += TFT_getStringWidth(buff);
            }
        } else { // without noise
            _fg = node->is_selected ? node->text->selected_color : node->text->color;

            TFT_print_in_area(node->render_data.resolved_text, resolve_halign(0, node->text->halign),
                resolve_valign(0, node->text->valign), cs);
        }
    }
}

// render an icon to screen
static void render_icon(gui_view_node_t* node, dispWin_t cs)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == ICON);

    if (node->icon) {
        color_t* color = node->is_selected ? &node->icon->selected_color : &node->icon->color;
        TFT_icon(&node->icon->icon, resolve_halign(0, node->icon->halign), resolve_valign(0, node->icon->valign),
            *color, cs);
    }
}

// render a picture to screen
static void render_picture(gui_view_node_t* node, dispWin_t cs)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->kind == PICTURE);

    if (node->picture && node->picture->picture) {
        TFT_picture(node->picture->picture, resolve_halign(0, node->picture->halign),
            resolve_valign(0, node->picture->valign), cs);
    }
}

// paint the borders for a view_node
static void paint_borders(gui_view_node_t* node, dispWin_t cs)
{
    uint16_t width = cs.x2 - cs.x1;
    uint16_t height = cs.y2 - cs.y1;

    color_t* color = NULL;
    if (node->is_selected) {
        color = &node->borders.selected_color;
    } else if (!node->is_active) {
        color = &node->borders.inactive_color;
    } else {
        color = &node->borders.color;
    }

    JADE_ASSERT(color);

    uint8_t thickness;

    if ((thickness = get_border_thickness(&node->borders, GUI_BORDER_TOP_BIT))) {
        TFT_fillRect(cs.x1, cs.y1, width, thickness, *color); // top
    }
    if ((thickness = get_border_thickness(&node->borders, GUI_BORDER_RIGHT_BIT))) {
        TFT_fillRect(cs.x2 - thickness, cs.y1, thickness, height, *color); // right
    }
    if ((thickness = get_border_thickness(&node->borders, GUI_BORDER_BOTTOM_BIT))) {
        TFT_fillRect(cs.x1, cs.y2 - thickness, width, thickness, *color); // bottom
    }
    if ((thickness = get_border_thickness(&node->borders, GUI_BORDER_LEFT_BIT))) {
        TFT_fillRect(cs.x1, cs.y1, thickness, height, *color); // left
    }
}

// repaint a node to screen
void gui_repaint(gui_view_node_t* node, bool take_mutex)
{
    JADE_ASSERT(node);

    JADE_ASSERT(paint_mutex);

    if (take_mutex) {
        // obtain a lock on the paint mutex
        if (xSemaphoreTake(paint_mutex, GUI_PAINT_MUTEX_WAIT / portTICK_PERIOD_MS) != pdTRUE) {
            // we couldn't obtain the lock, return with an error
            return; // GUI_FAILED_PAINT_MUTEX_LOCK_ERROR;
        }
    }

    // borders use the un-padded constraints
    paint_borders(node, node->render_data.constraints);

    switch (node->kind) {
    case HSPLIT:
        render_hsplit(node, node->render_data.padded_constraints, node->render_data.depth);
        break;
    case VSPLIT:
        render_vsplit(node, node->render_data.padded_constraints, node->render_data.depth);
        break;
    case TEXT:
        render_text(node, node->render_data.padded_constraints);
        break;
    case FILL:
        render_fill(node, node->render_data.padded_constraints, node->render_data.depth);
        break;
    case BUTTON:
        render_button(node, node->render_data.padded_constraints, node->render_data.depth);
        break;
    case ICON:
        render_icon(node, node->render_data.padded_constraints);
        break;
    case PICTURE:
        render_picture(node, node->render_data.padded_constraints);
        break;
    }

    if (GUI_VIEW_DEBUG) {
        uint16_t width = node->render_data.padded_constraints.x2 - node->render_data.padded_constraints.x1;
        uint16_t height = node->render_data.padded_constraints.y2 - node->render_data.padded_constraints.y1;

        TFT_drawRect(node->render_data.padded_constraints.x1, node->render_data.padded_constraints.y1, width, height,
            DEBUG_COLOR(node->render_data.depth));
    }

    if (take_mutex) {
        // release the paint mutex lock
        xSemaphoreGive(paint_mutex);
    }
}

// updatables task, this task runs to update elements in the `updatables` list of the current activity
void updatables_task(void* args)
{
    const TickType_t frequency = 1000 / GUI_TARGET_FRAMERATE / portTICK_PERIOD_MS;

    TickType_t last_wake = xTaskGetTickCount();
    for (;;) {
        // Wait for the next frame
        // Note: this task is never suspended, so no need to re-fetch the tick-
        // time each loop, just let vTaskDelayUntil() track the 'last_wake' count.
        vTaskDelayUntil(&last_wake, frequency);

        updatable_t* current = current_activity->updatables;
        while (current) {
            // this shouldn't really happen but better add a check anyways
            if (!current->callback) {
                continue;
            }

            // let's see if we need to repaint this
            bool result = current->callback(current->node, current->extra_args);
            if (result) {
                // repaint and take the mutex
                // TODO: we are ignoring the return code here...
                gui_repaint(current->node, true);
            }

            current = current->next;
        }
    }

    vTaskDelete(NULL);
}

// update the status bar. this task might be suspended/resumed without notice when the `current_activity` changes.
// no "critical" checks should run in here since there's no guarantee this will be constantly running
static void status_bar_task(void* ignore)
{
    const TickType_t frequency = 1000 / GUI_TARGET_FRAMERATE / portTICK_PERIOD_MS;

    dispWin_t status_bar_cs = GUI_DISPLAY_WINDOW;
    status_bar_cs.y2 = status_bar_cs.y1 + GUI_STATUS_BAR_HEIGHT;

    TickType_t last_wake = xTaskGetTickCount();
    for (;;) {
        // NOTE: because this task can be suspended/resumed arbitrarily we re-fetch
        // the currnet tick time each loop, and don't rely on vTaskDelayUntil() to
        // update it (as that returns the prior value plus frequency, which can result
        // in a 'backlog' developing when suspended, which all run in succession when
        // the task is resumed.
        vTaskDelayUntil(&last_wake, frequency);
        last_wake = xTaskGetTickCount(); // required if task may have been suspended

        if ((status_bar.battery_update_counter % 10) == 0) {

#ifndef CONFIG_ESP32_NO_BLOBS
            const bool new_ble = ble_enabled();
#else
            const bool new_ble = false;
#endif

            if (new_ble != status_bar.last_ble_val) {
                status_bar.last_ble_val = new_ble;
                if (new_ble) {
                    gui_update_text(status_bar.ble_text, (char[]){ 'E', '\0' });
                } else {
                    gui_update_text(status_bar.ble_text, (char[]){ 'F', '\0' });
                }
                status_bar.updated = true;
            }

            const bool new_usb = usb_connected();
            if (new_usb != status_bar.last_usb_val) {
                status_bar.last_usb_val = new_usb;
                if (new_usb) {
                    gui_update_text(status_bar.usb_text, (char[]){ 'C', '\0' });
                } else {
                    gui_update_text(status_bar.usb_text, (char[]){ 'D', '\0' });
                }
                status_bar.updated = true;
                status_bar.battery_update_counter = 0; // Force battery icon update
            }
        }

        if (status_bar.battery_update_counter == 0) {
            uint8_t new_bat = power_get_battery_status();
            if (power_get_battery_charging()) {
                new_bat = new_bat + 12;
            }
            if (new_bat != status_bar.last_battery_val) {
                status_bar.last_battery_val = new_bat;
                gui_update_text(status_bar.battery_text, (char[]){ new_bat + '0', '\0' });
                status_bar.updated = true;
            }
            status_bar.battery_update_counter = 60;
        }

        status_bar.battery_update_counter--;

        if (!status_bar.updated) {
            continue;
        }

        // TODO: check the return code
        render_node(status_bar.root, status_bar_cs, 0);

        // TODO: do we need a mutex here?
        status_bar.updated = false;
    }
}

// TODO: different functions for different types of click
void gui_wheel_click()
{
    if (gui_click_event == GUI_WHEEL_CLICK_EVENT) {
        select_action(current_activity);
    }

    esp_event_post(GUI_EVENT, GUI_WHEEL_CLICK_EVENT, NULL, 0, 50 / portTICK_PERIOD_MS);
    idletimer_register_activity();
}

void gui_front_click()
{
    if (gui_click_event == GUI_FRONT_CLICK_EVENT) {
        select_action(current_activity);
    }

    esp_event_post(GUI_EVENT, GUI_FRONT_CLICK_EVENT, NULL, 0, 50 / portTICK_PERIOD_MS);
    idletimer_register_activity();
}

void gui_next()
{
    gui_select_next(current_activity);

    esp_event_post(GUI_EVENT, GUI_WHEEL_RIGHT_EVENT, NULL, 0, 50 / portTICK_PERIOD_MS);
    idletimer_register_activity();
}

void gui_prev()
{
    gui_select_prev(current_activity);

    esp_event_post(GUI_EVENT, GUI_WHEEL_LEFT_EVENT, NULL, 0, 50 / portTICK_PERIOD_MS);
    idletimer_register_activity();
}

// Set the item to be initally selected when the activity is activated/switched-to
// 'node' can be NULL to unset any specific initial selection
void gui_set_activity_initial_selection(gui_activity_t* activity, gui_view_node_t* node)
{
    JADE_ASSERT(activity);
    activity->initial_selection = node;
}

static void gui_render_activity(gui_activity_t* activity)
{
    JADE_ASSERT(activity);
    JADE_ASSERT(activity->root_node);

    const bool first_time = activity->root_node->render_data.is_first_time;
    render_node(activity->root_node, activity->win, 0);

    if (first_time && activity->selectables) {
        // If the activity has an 'initial_selection' and it appears active, select it now
        // If not, select the first active item
        if (activity->initial_selection && activity->initial_selection->is_active) {
            gui_select_node(activity, activity->initial_selection);
        } else {
            gui_view_node_t* const node = gui_get_first_active_node(activity);
            if (node) {
                gui_select_node(activity, node);
            }
        }
    }
}

static void switch_activities_task(void* arg_ptr)
{
    JADE_ASSERT(switch_activities);

    while (true) {
        size_t item_size = 0;
        activity_switch_info_t* activities = xRingbufferReceive(switch_activities, &item_size, portMAX_DELAY);

        if (activities != NULL) {
            JADE_ASSERT(item_size == sizeof(activity_switch_info_t));
            JADE_ASSERT(activities->new_activity);

            // Unregister the old activity's event handlers
            if (activities->old_activity) {
                activity_event_t* l = activities->old_activity->activity_events;
                while (l) {
                    esp_event_handler_unregister(l->event_base, l->event_id, l->handler);
                    l = l->next;
                }
            }

            // Render the current activity
            gui_render_activity(activities->new_activity);

            // Register new events
            activity_event_t* l = activities->new_activity->activity_events;
            while (l) {
                esp_event_handler_register(l->event_base, l->event_id, l->handler, l->args);
                l = l->next;
            }

            // Return the ringbuffer slot
            vRingbufferReturnItem(switch_activities, activities);
        }
    }
}

void gui_set_current_activity(gui_activity_t* activity)
{
    JADE_ASSERT(activity);

    // Record the old and new 'current' switch_activities_task
    const activity_switch_info_t activities = { .old_activity = current_activity, .new_activity = activity };

    // set the current_activity to the new
    current_activity = activity;

    if (activity->status_bar) {
        if (activity->title) {
            gui_update_text(status_bar.title, activity->title);
        }

        // TODO: do we need a mutex here?
        status_bar.updated = true;

        vTaskResume(status_bar.task_handle);
    } else {
        vTaskSuspend(status_bar.task_handle);
    }

    // Post the activity switch to the gui task
    while (xRingbufferSend(switch_activities, &activities, sizeof(activities), portMAX_DELAY) != pdTRUE) {
        // wait for a spot in the ring
    }
}

static void push_activity_event(
    gui_activity_t* activity, const char* event_base, uint32_t event_id, esp_event_handler_t handler, void* args)
{
    activity_event_t* link = JADE_CALLOC(1, sizeof(activity_event_t));

    link->event_base = event_base;
    link->event_id = event_id;
    link->handler = handler;
    link->args = args;

    if (!activity->activity_events) {
        activity->activity_events = link;
    } else {
        activity_event_t* last = activity->activity_events;
        while (last->next) {
            last = last->next;
        }
        last->next = link;
    }
}

void gui_activity_register_event(
    gui_activity_t* activity, const char* event_base, uint32_t event_id, esp_event_handler_t handler, void* args)
{
    JADE_ASSERT(activity);

    push_activity_event(activity, event_base, event_id, handler, args);

    // this activity is already active, immediately add the event handler
    if (activity == current_activity) {
        const esp_err_t rc = esp_event_handler_register(event_base, event_id, handler, args);
        JADE_ASSERT(rc == ESP_OK);
    }
}

// Registers and event handler, then blocks waiting for it to fire.  A timeout can be passed.
// Returns true if the event fires, false if the timeout elapsed without the event occuring.
bool gui_activity_wait_event(gui_activity_t* activity, const char* event_base, uint32_t event_id,
    esp_event_base_t* trigger_event_base, int32_t* trigger_event_id, void** trigger_event_data, TickType_t max_wait)
{
    JADE_ASSERT(activity);

    wait_event_data_t* const wait_event_data = make_wait_event_data();

    // push it so that it gets removed when the activity is swapped
    gui_activity_register_event(activity, event_base, event_id, sync_wait_event_handler, wait_event_data);

    // immediately start waiting
    const esp_err_t ret = sync_wait_event(
        event_base, event_id, wait_event_data, trigger_event_base, trigger_event_id, trigger_event_data, max_wait);
    free_wait_event_data(wait_event_data);

    return ret == ESP_OK;
}

static void switch_activity_callback(void* handler_arg, esp_event_base_t base, int32_t id, void* event_data)
{
    JADE_ASSERT(handler_arg);
    gui_activity_t* activity = (gui_activity_t*)handler_arg;
    gui_set_current_activity(activity);
}

void gui_connect_button_activity(gui_view_node_t* node, gui_activity_t* activity)
{
    JADE_ASSERT(node);
    JADE_ASSERT(node->activity);
    JADE_ASSERT(node->kind == BUTTON);
    JADE_ASSERT(activity);

    gui_activity_register_event(
        node->activity, GUI_BUTTON_EVENT, node->button->click_event_id, switch_activity_callback, activity);
}

void gui_set_title(const char* title)
{
    JADE_ASSERT(title);
    gui_update_text(status_bar.title, title);
}

gui_activity_t* gui_current_activity() { return current_activity; }
