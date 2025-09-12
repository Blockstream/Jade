#ifndef GUI_H_
#define GUI_H_

#include "display.h"
#include <arch/sys_arch.h>
#include <utils/event.h>

#include "jlocale.h"

extern color_t _fg;

// Additional colour tokens
extern const color_t GUI_BLOCKSTREAM_JADE_GREEN;
extern const color_t GUI_BLOCKSTREAM_BUTTONBORDER_GREY;
extern const color_t GUI_BLOCKSTREAM_QR_PALE;

extern const color_t GUI_BLOCKSTREAM_HIGHTLIGHT_DEFAULT;
extern const color_t GUI_BLOCKSTREAM_HIGHTLIGHT_ORANGE;
extern const color_t GUI_BLOCKSTREAM_HIGHTLIGHT_BLUE;
extern const color_t GUI_BLOCKSTREAM_HIGHTLIGHT_DARKGREY;
extern const color_t GUI_BLOCKSTREAM_HIGHTLIGHT_LIGHTGREY;
extern const color_t GUI_BLOCKSTREAM_UNHIGHTLIGHTED_DEFAULT;

// -------------- Configuration -----------------

// Display window
extern dispWin_t GUI_DISPLAY_WINDOW;
// Locale used to translate strings
extern jlocale_t GUI_LOCALE;
// Set the "target" framerate for updatables nodes
extern uint8_t GUI_TARGET_FRAMERATE;
// How many frames should a scroll wait when an end is reached
extern uint8_t GUI_SCROLL_WAIT_END;
// How many frames should we wait between each 1-char scroll
extern uint8_t GUI_SCROLL_WAIT_FRAME;
// Height for the system status bar
extern uint8_t GUI_STATUS_BAR_HEIGHT;
// The default title/status-bar font
extern uint8_t GUI_TITLE_FONT;
// The default body font
extern uint8_t GUI_DEFAULT_FONT;

// -------------- Constants -----------------

// Whether to use a deep status bar on the home screen, better suited to larger displays
#define HOME_SCREEN_DEEP_STATUS_BAR (CONFIG_DISPLAY_HEIGHT >= 170)

// Fill all the remaining space in an {h,v}split
#define GUI_SPLIT_FILL_REMAINING 0xFF

// Number of GUI themes
#define GUI_NUM_DISPLAY_THEMES 5

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
#define GUI_BORDER_TOPBOTTOM (GUI_BORDER_TOP | GUI_BORDER_BOTTOM)
#define GUI_BORDER_TOPLEFT (GUI_BORDER_TOP | GUI_BORDER_LEFT)
#define GUI_BORDER_TOPRIGHT (GUI_BORDER_TOP | GUI_BORDER_RIGHT)

// How should the parameters to set_margin/set_padding be interpreted
#define GUI_MARGIN_ALL_EQUAL 1 // one value for all
#define GUI_MARGIN_TWO_VALUES 2 // first value for top/bottom, second for right/left
#define GUI_MARGIN_ALL_DIFFERENT 3 // four different values

// Maximum size of single displayable text string
#define GUI_MAX_TEXT_LENGTH 256

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
enum __attribute__((__packed__)) gui_split_type { GUI_SPLIT_RELATIVE, GUI_SPLIT_ABSOLUTE };

// Struct used for margins and padding. Contains four values applied on the four edges of a node
typedef struct {
    uint8_t top;
    uint8_t right;
    uint8_t bottom;
    uint8_t left;
} gui_margin_t;

// Definition of borders. The `borders` can be used to enable/disable one side of the border using the
// GUI_BORDER_* constants
typedef struct {
    color_t color;
    color_t selected_color;
    color_t inactive_color;

    uint16_t thickness;
    uint8_t borders;
} gui_border_t;

// Horizontal align constants for text, icons and pictures
enum __attribute__((__packed__)) gui_horizontal_align { GUI_ALIGN_LEFT, GUI_ALIGN_CENTER, GUI_ALIGN_RIGHT };

// Vertical align constants for text, icons and pictures
enum __attribute__((__packed__)) gui_vertical_align { GUI_ALIGN_TOP, GUI_ALIGN_MIDDLE, GUI_ALIGN_BOTTOM };

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

    // double linked list
    struct selectable_element* prev;
    struct selectable_element* next;

    // coords on screen
    uint16_t x;
    uint16_t y;

    // is this the first of the list (top-left-most item)
    bool is_first;
} selectable_t;

typedef struct activity_event {
    const char* event_base;
    uint32_t event_id;

    esp_event_handler_t handler;
    void* args;

    esp_event_handler_instance_t instance;

    // next element
    struct activity_event* next;
} activity_event_t;

// Values calculated by the render that can be useful later
struct __attribute__((__packed__)) view_node_render_data {
    dispWin_t original_constraints;

    // area of the node *after* margins, padding and borders have been applied
    dispWin_t padded_constraints;

    // used as a cache for translated strings
    const char* resolved_text;
    size_t resolved_text_length;

    // is this the first rendering of the node?
    bool is_first_time;

    // depth of the node in the tree of this activity
    uint8_t depth;
};

// Data for a {v,h}split
struct view_node_split_data {
    // type of split
    enum gui_split_type kind;
    // their values
    uint16_t* values;
    // how many parts
    uint8_t parts;
};

enum __attribute__((__packed__)) fill_node_kind { FILL_PLAIN, FILL_HIGHLIGHT, FILL_QR };

// Data for a "fill" node
struct view_node_fill_data {
    color_t color;
    color_t selected_color;
    enum fill_node_kind fill_type;
};

// Data appended to a text node when it's scrolling
struct view_node_text_scroll_data {
    // color to repaint in background to remove the previous rendering
    color_t background_color;
    color_t selected_background_color;
    bool only_when_selected;

    // is the text moving right?
    bool going_back;

    // chars to skip
    size_t offset;
    // chars we skipped the last time we rendered it
    size_t prev_offset;
    // iterations left to wait here (without moving the text)
    // used when we reach one end of the string and we want to wait a while there
    uint8_t wait;
};

// Data appended to a text node when noise is needed
struct view_node_text_noise_data {
    // color to paint noise
    color_t background_color;
};

// Data for a text node
struct __attribute__((__packed__)) view_node_text_data {
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

enum __attribute__((__packed__)) icon_node_kind { ICON_PLAIN, ICON_QR };

// Data for an icon node
// NOTE: animated icons ARE owned here
struct view_node_icon_animation_data {
    Icon* icons;
    size_t num_icons;
    size_t current_icon;

    size_t frames_per_icon;
    size_t current_frame;
};

// NOTE: underlying icon data is not owned here
struct view_node_icon_data {
    Icon icon;

    color_t color;
    color_t selected_color;

    // background color is set to foreground color to imply transparency
    color_t bg_color;

    // if != NULL the icon will be regularly updated and so appear animated
    struct view_node_icon_animation_data* animation;

    enum gui_horizontal_align halign;
    enum gui_vertical_align valign;
    enum icon_node_kind icon_type;
};

// Data for a picture node
// NOTE: picture data IS owned here unless driven from the camera
struct view_node_picture_data {
    const Picture* picture;

    enum gui_horizontal_align halign;
    enum gui_vertical_align valign;
};

// Possible types of a view_node
enum __attribute__((__packed__)) view_node_kind { HSPLIT, VSPLIT, TEXT, FILL, BUTTON, ICON, PICTURE };

typedef struct wait_data {
    wait_event_data_t* event_data;
    struct wait_data* next;
} wait_data_t;

// Struct that contains an "activity", basically a tree of nodes that can be rendered on screen
struct __attribute__((__packed__)) gui_activity_t {
    // "window" used by the tft library to paint on screen
    dispWin_t win;
    // root view_node
    gui_view_node_t* root_node;

    // linked list of selectable elements
    selectable_t* selectables;
    // The node intially selected when activated/switched-to
    gui_view_node_t* initial_selection;

    // linked list of updatable elements
    updatable_t* updatables;

    // linked list of event handlers that should be registered when the activity is rendered
    activity_event_t* activity_events;

    // linked list of wait_event_data structures associated with this activity
    wait_data_t* wait_data_items;

    // add the status bar on top of this activity (top 24px)
    bool status_bar;
    // title shown in the status bar (if enabled)
    char* title;
    // should that cursor "wrap around" when you reach one end?
    bool selectables_wrap;
};

// Optional callback called when a view_node is destructed. Basically a custom destructor
typedef void (*free_callback_t)(void*);

// Generic struct representing a node in the view tree
struct __attribute__((__packed__)) gui_view_node_t {
    // stuff set by the renderer
    struct view_node_render_data render_data;

    // NULL for the root node
    gui_view_node_t* parent;

    // type of node
    enum view_node_kind kind;

    // activity that contains this node
    gui_activity_t* activity;

    // margin, padding values
    gui_margin_t margins;
    gui_margin_t padding;

    // borders if set/applicable
    gui_border_t* borders;

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

    // is this node currently selected (highlighted)?
    bool is_selected;

    // is this node active (highlitable)?
    bool is_active;
};

// Structs to facilitate chaining screens
typedef struct {
    gui_activity_t* activity;
    gui_view_node_t* prev_button;
    gui_view_node_t* next_button;
} link_activity_t;

typedef struct {
    gui_activity_t* first_activity;
    gui_activity_t* last_activity;
    gui_view_node_t* last_activity_next_button;
} linked_activities_info_t;

gui_event_t gui_get_click_event(void);
void gui_set_click_event(bool use_wheel_click);

color_t gui_get_highlight_color(void);
void gui_set_highlight_color(uint8_t theme);

color_t gui_get_qrcode_color(void);
void gui_next_qrcode_color(void);

bool gui_get_flipped_orientation(void);
bool gui_set_flipped_orientation(bool flipped_orientation);

void gui_init(TaskHandle_t* gui_h);
bool gui_initialized(void);

void gui_make_activity_ex(gui_activity_t** ppact, const bool has_status_bar, const char* title, const bool managed);
gui_activity_t* gui_make_activity(void);

void gui_set_parent(gui_view_node_t* child, gui_view_node_t* parent);
void gui_chain_activities(const link_activity_t* link_act, linked_activities_info_t* pActInfo);
void gui_make_hsplit(gui_view_node_t** ptr, enum gui_split_type kind, uint8_t parts, ...);
void gui_make_vsplit(gui_view_node_t** ptr, enum gui_split_type kind, uint8_t parts, ...);
void gui_make_button(gui_view_node_t** ptr, color_t color, color_t selected_color, uint32_t event_id, void* args);
void gui_make_fill(gui_view_node_t** ptr, color_t color, enum fill_node_kind fill_type, gui_view_node_t* parent);
void gui_make_text(gui_view_node_t** ptr, const char* text, color_t color);
void gui_make_text_font(gui_view_node_t** ptr, const char* text, color_t color, uint32_t font);
void gui_make_icon(gui_view_node_t** ptr, const Icon* icon, color_t color, const color_t* bg_color);
void gui_make_picture(gui_view_node_t** ptr, const Picture* picture);
void gui_set_margins(gui_view_node_t* node, uint32_t sides, ...);
void gui_set_padding(gui_view_node_t* node, uint32_t sides, ...);
void gui_set_borders(gui_view_node_t* node, color_t color, uint16_t thickness, uint8_t borders);
void gui_set_borders_selected_color(gui_view_node_t* node, color_t selected_color);
void gui_set_borders_inactive_color(gui_view_node_t* node, color_t inactive_color);
void gui_set_colors(gui_view_node_t* node, color_t color, color_t selected_color);
void gui_set_color(gui_view_node_t* node, color_t color);
void gui_set_align(gui_view_node_t* node, enum gui_horizontal_align halign, enum gui_vertical_align valign);
void gui_set_icon_animation(gui_view_node_t* node, Icon* icons, size_t num_icons, size_t frames_per_icon);
void gui_set_icon_to_qr(gui_view_node_t* node);
void gui_set_text_scroll(gui_view_node_t* node, color_t background_color);
void gui_set_text_scroll_selected(
    gui_view_node_t* node, bool only_when_selected, color_t background_color, color_t selected_background_color);
void gui_set_text_noise(gui_view_node_t* node, color_t background_color);
void gui_set_text_font(gui_view_node_t* node, uint32_t font);
void gui_set_text_default_font(gui_view_node_t* node);
void gui_update_text(gui_view_node_t* node, const char* text);
void gui_update_icon(gui_view_node_t* node, Icon icon, bool repaint_parent);
void gui_update_picture(gui_view_node_t* node, const Picture* picture, bool repaint_parent);
void gui_repaint(gui_view_node_t* node);

void gui_set_current_activity_ex(gui_activity_t* new_current, bool free_managed_activities);
void gui_set_current_activity(gui_activity_t* new_current);

wait_event_data_t* gui_activity_make_wait_event_data(gui_activity_t* activity);
void gui_activity_register_event(
    gui_activity_t* activity, const char* event_base, uint32_t event_id, esp_event_handler_t handler, void* args);
bool gui_activity_wait_event(gui_activity_t* activity, const char* event_base, uint32_t event_id,
    esp_event_base_t* trigger_event_base, int32_t* trigger_event_id, void** trigger_event_data, TickType_t max_wait);

void gui_set_activity_initial_selection(gui_view_node_t* node);
void gui_set_active(gui_view_node_t* node, bool value);
void gui_activity_set_active_selection(
    gui_activity_t* activity, gui_view_node_t** nodes, size_t num_nodes, const bool* active, gui_view_node_t* selected);

void gui_set_activity_title(gui_activity_t* activity, const char* title);

gui_activity_t* gui_current_activity(void);
gui_activity_t* gui_display_splash(void);

void gui_wheel_click(void);
void gui_front_click(void);
void gui_next(void);
void gui_prev(void);

#endif /* GUI_H_ */
