#ifndef GUI_H_
#define GUI_H_

#include <esp_event.h>
#include <tft.h>

#include "jlocale.h"

extern int _width;
extern int _height;
extern uint32_t max_rdclock;
extern color_t _fg;
extern color_t _bg;
extern uint8_t orientation;
extern uint16_t font_rotate;
extern uint8_t font_transparent;
extern uint8_t font_forceFixed;
extern uint8_t text_wrap;
extern uint8_t tft_disp_type;
extern uint8_t gray_scale;

// -------------- Configuration -----------------

// Locale used to translate strings
extern jlocale_t GUI_LOCALE;
// If true, adds some borders to show nodes' boundaries
extern bool GUI_VIEW_DEBUG;
// Set the "target" framerate for updatables nodes
extern uint16_t GUI_TARGET_FRAMERATE;
// How many frames should a scroll wait when an end is reached
extern uint16_t GUI_SCROLL_WAIT_END;
// How many frames should we wait between each 1-char scroll
extern uint16_t GUI_SCROLL_WAIT_FRAME;
// On which core should all the GUI stuff run
extern BaseType_t GUI_CORE;
// Display window
extern dispWin_t GUI_DISPLAY_WINDOW;
// Height for the system status bar
extern uint16_t GUI_STATUS_BAR_HEIGHT;
// Default font
extern uint32_t GUI_DEFAULT_FONT;

// -------------- Constants -----------------

// Fill all the remaining space in an {h,v}split
#define GUI_SPLIT_FILL_REMAINING 0xFF

// Bits used to enable or disable a border
#define GUI_BORDER_TOP_BIT 0
#define GUI_BORDER_RIGHT_BIT 1
#define GUI_BORDER_BOTTOM_BIT 2
#define GUI_BORDER_LEFT_BIT 3

// And their value (= 2^bit)
#define GUI_BORDER_TOP (1 << GUI_BORDER_TOP_BIT)
#define GUI_BORDER_RIGHT (1 << GUI_BORDER_RIGHT_BIT)
#define GUI_BORDER_BOTTOM (1 << GUI_BORDER_BOTTOM_BIT)
#define GUI_BORDER_LEFT (1 << GUI_BORDER_LEFT_BIT)

// Shorthands for some common border configurations
#define GUI_BORDER_ALL (GUI_BORDER_TOP | GUI_BORDER_RIGHT | GUI_BORDER_BOTTOM | GUI_BORDER_LEFT)
#define GUI_BORDER_SIDES (GUI_BORDER_RIGHT | GUI_BORDER_LEFT)

// How many ms should we wait to obtain a lock on the paint mutex before giving up
#define GUI_PAINT_MUTEX_WAIT 500

// How should the parameters to set_margin/set_padding be interpreted
#define GUI_MARGIN_ALL_EQUAL 1 // one value for all
#define GUI_MARGIN_TWO_VALUES 2 // first value for top/bottom, second for right/left
#define GUI_MARGIN_ALL_DIFFERENT 3 // four different values

// Event base for button clicks
ESP_EVENT_DECLARE_BASE(GUI_BUTTON_EVENT);
// Event base for gui events
ESP_EVENT_DECLARE_BASE(GUI_EVENT);
// Button-click special events
#define GUI_BUTTON_EVENT_NONE 0xFFFFFFFE

// GUI_EVENTS
typedef enum {
    GUI_WHEEL_LEFT_EVENT,
    GUI_WHEEL_RIGHT_EVENT,

    GUI_WHEEL_CLICK_EVENT,
    GUI_FRONT_CLICK_EVENT
} gui_event_t;

// How should split values be interpreted
enum gui_split_type { GUI_SPLIT_RELATIVE, GUI_SPLIT_ABSOLUTE };

// Struct used for margins and padding. Contains four values applied on the four edges of a node
typedef struct {
    uint16_t top;
    uint16_t right;
    uint16_t bottom;
    uint16_t left;
} gui_margin_t;

// Definition of borders. The `borders` can be used to enable/disable one side of the border using the
// GUI_BORDER_* constants
typedef struct {
    color_t color;
    color_t selected_color;
    color_t inactive_color;

    uint8_t thickness;

    uint16_t borders;
} gui_border_t;

// Horizontal align constants for text, icons and pictures
enum gui_horizontal_align { GUI_ALIGN_LEFT, GUI_ALIGN_CENTER, GUI_ALIGN_RIGHT };

// Vertical align constants for text, icons and pictures
enum gui_vertical_align { GUI_ALIGN_TOP, GUI_ALIGN_MIDDLE, GUI_ALIGN_BOTTOM };

typedef struct gui_view_node_t gui_view_node_t;
typedef struct gui_activity_t gui_activity_t;

// Callback called before repainting an updatable node.
//     return true to actually paint the node, false otherwise
typedef bool (*gui_updatable_callback_t)(gui_view_node_t* node, void* extra_args);

// Wrapper for items that need repaint at each frame, possibly with an extra callback
typedef struct updatable_element {
    // node to update and callback to run before updating it
    gui_view_node_t* node;

    // callback (and its args) to run at each frame, it will tell us if it's necessary to repaint the node
    gui_updatable_callback_t callback;
    void* extra_args;

    // next in the linked list
    struct updatable_element* next;
} updatable_t;

// Element in the "selectable" linked list
typedef struct selectable_element {
    // ref to the selectable node itself
    gui_view_node_t* node;

    // coords on screen
    uint16_t x;
    uint16_t y;

    // is this the first of the list (top-left-most item)
    bool is_first;

    // double linked list
    struct selectable_element* prev;
    struct selectable_element* next;
} selectable_t;

typedef struct activity_event {
    const char* event_base;
    uint32_t event_id;

    esp_event_handler_t handler;
    void* args;

    // next element
    struct activity_event* next;
} activity_event_t;

// Values calculated by the render that can be useful later
struct view_node_render_data {
    dispWin_t original_constraints;
    // area of the node *after* margins are applied but *before* padding and borders
    dispWin_t constraints;
    // area of the node *after* margins, padding and borders have been applied
    dispWin_t padded_constraints;

    // depth of the node in the tree of this activity
    uint8_t depth;

    // is this the first rendering of the node?
    bool is_first_time;

    // used as a cache for translated strings
    const char* resolved_text;
    size_t resolved_text_length;
};

// Data for a {v,h}split
struct view_node_split_data {
    // type of split
    enum gui_split_type kind;

    // how many parts
    uint8_t parts;
    // their values
    uint8_t* values;
};

// Data for a "fill" node
struct view_node_fill_data {
    color_t color;
    color_t selected_color;
};

// Data appended to a text node when it's scrolling
struct view_node_text_scroll_data {
    // is the text moving right?
    bool going_back;

    // chars to skip
    uint8_t offset;
    // chars we skipped the last time we rendered it
    uint8_t prev_offset;
    // iterations left to wait here (without moving the text)
    // used when we reach one end of the string and we want to wait a while there
    uint8_t wait;

    // color to repaint in background to remove the previous rendering
    color_t background_color;
};

// Data appended to a text node when noise is needed
struct view_node_text_noise_data {
    // color to paint noise
    color_t background_color;
};

// Data for a text node
struct view_node_text_data {
    char* text;

    color_t color;
    color_t selected_color;

    uint32_t font;

    enum gui_horizontal_align halign;
    enum gui_vertical_align valign;

    // if != NULL the text will scroll <-> instead of wrapping to the next line
    struct view_node_text_scroll_data* scroll;

    // noise data structure, if != NULL noise chars will be added
    struct view_node_text_noise_data* noise;
};

// Data for a button node
struct view_node_button_data {
    color_t color;
    color_t selected_color;

    // event id
    uint32_t click_event_id;
    // args passed to the event handler as event_data when the button is clicked
    void* args;
};

// Data for an icon node
struct view_node_icon_data {
    Icon icon;

    color_t color;
    color_t selected_color;

    enum gui_horizontal_align halign;
    enum gui_vertical_align valign;
};

// Data for a picture node
struct view_node_picture_data {
    const Picture* picture;

    enum gui_horizontal_align halign;
    enum gui_vertical_align valign;
};

// Possible types of a view_node
enum view_node_kind { HSPLIT, VSPLIT, TEXT, FILL, BUTTON, ICON, PICTURE };

// Struct that contains an "activity", basically a tree of nodes that can be rendered on screen
struct gui_activity_t {
    // "window" used by the tft library to paint on screen
    dispWin_t win;
    // root view_node
    gui_view_node_t* root_node;

    // add the status bar on top of this activity (top 24px)
    bool status_bar;
    // title shown in the status bar (if enabled)
    char* title;

    // linked list of selectable elements
    selectable_t* selectables;
    // should that cursor "wrap around" when you reach one end?
    bool selectables_wrap;
    // The node intially selected when activated/switched-to
    gui_view_node_t* initial_selection;

    // linked list of updatable elements
    updatable_t* updatables;

    // linked list of event handlers that should be registered when the activity is rendered
    activity_event_t* activity_events;
};

// Optional callback called when a view_node is destructed. Basically a custom destructor
typedef void (*free_callback_t)(void*);

// Generic struct representing a node in the view tree
struct gui_view_node_t {
    // NULL for the root node
    gui_view_node_t* parent;

    // type of node
    enum view_node_kind kind;

    // activity that contains this node
    gui_activity_t* activity;

    // stuff set by the renderer
    struct view_node_render_data render_data;

    // is this node currently selected (highlighted)?
    bool is_selected;

    // is this node active (highlitable)?
    bool is_active;

    // margin, padding values
    gui_margin_t margins;
    gui_margin_t padding;

    // borders
    gui_border_t borders;

    // all the possible data-types
    union {
        void* data;

        struct view_node_split_data* split;
        struct view_node_text_data* text;
        struct view_node_fill_data* fill;
        struct view_node_button_data* button;
        struct view_node_icon_data* icon;
        struct view_node_picture_data* picture;
    };
    // (optional) destructor
    free_callback_t free_callback;

    // ptr to the first child of the list
    gui_view_node_t* child;

    // next sibling in the linked list
    gui_view_node_t* sibling;
};

typedef struct {
    gui_view_node_t* progress_bar;
    gui_view_node_t* pcnt_txt;
} progress_bar_t;

gui_event_t gui_get_click_event();
void gui_set_click_event(gui_event_t event);

void gui_init();
bool gui_initialized();

void gui_make_activity(gui_activity_t** ppact, bool has_status_bar, const char* title);
void gui_free_noncurrent_activities();
void gui_set_parent(gui_view_node_t* child, gui_view_node_t* parent);
void free_view_node(gui_view_node_t* node);
void gui_make_hsplit(gui_view_node_t** ptr, enum gui_split_type kind, uint8_t parts, ...);
void gui_make_vsplit(gui_view_node_t** ptr, enum gui_split_type kind, uint8_t parts, ...);
void gui_make_button(gui_view_node_t** ptr, color_t color, uint32_t event_id, void* args);
void gui_make_fill(gui_view_node_t** ptr, color_t color);
void gui_make_text(gui_view_node_t** ptr, const char* text, color_t color);
void gui_make_text_font(gui_view_node_t** ptr, const char* text, color_t color, uint32_t font);
void gui_make_icon(gui_view_node_t** ptr, const Icon* icon, color_t color);
void gui_make_picture(gui_view_node_t** ptr, const Picture* picture);
void gui_set_margins(gui_view_node_t* node, uint8_t sides, ...);
void gui_set_padding(gui_view_node_t* node, uint8_t sides, ...);
void gui_set_borders(gui_view_node_t* node, color_t color, uint8_t thickness, uint16_t borders);
void gui_set_borders_selected_color(gui_view_node_t* node, color_t selected_color);
void gui_set_borders_inactive_color(gui_view_node_t* node, color_t inactive_color);
void gui_set_selected_color(gui_view_node_t* node, color_t selected_color);
void gui_set_align(gui_view_node_t* node, enum gui_horizontal_align halign, enum gui_vertical_align valign);
void gui_set_text_scroll(gui_view_node_t* node, color_t background_color);
void gui_set_text_noise(gui_view_node_t* node, color_t background_color);
void gui_set_text_font(gui_view_node_t* node, uint32_t font);
void gui_set_text_default_font(gui_view_node_t* node);
void gui_update_text(gui_view_node_t* node, const char* text);
void gui_update_picture(gui_view_node_t* node, const Picture* picture);
void gui_repaint(gui_view_node_t* node, bool take_mutex);
void gui_set_current_activity(gui_activity_t* activity);

void gui_connect_button_activity(gui_view_node_t* node, gui_activity_t* activity);
void gui_activity_register_event(
    gui_activity_t* activity, const char* event_base, uint32_t event_id, esp_event_handler_t handler, void* args);
bool gui_activity_wait_event(gui_activity_t* activity, const char* event_base, uint32_t event_id,
    esp_event_base_t* trigger_event_base, int32_t* trigger_event_id, void** trigger_event_data, TickType_t max_wait);

void gui_set_activity_initial_selection(gui_activity_t* activity, gui_view_node_t* node);
bool gui_set_active(gui_activity_t* activity, gui_view_node_t* node, bool value);
bool gui_select_next(gui_activity_t* activity);
bool gui_select_prev(gui_activity_t* activity);
void gui_select_node(gui_activity_t* activity, gui_view_node_t* node);

void gui_set_title(const char* title);
gui_activity_t* gui_current_activity();

void gui_wheel_click();
void gui_front_click();
void gui_next();
void gui_prev();

#endif /* GUI_H_ */
