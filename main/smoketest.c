#ifndef AMALGAMATED_BUILD
#include <esp_flash.h>

#include "camera.h"
#include "jade_assert.h"
#include "power.h"
#include "sensitive.h"
#include "smoketest.h"

static void log_mem(void)
{
    // Print the main stack usage (high water mark), and the DRAM usage
    JADE_LOGI("Main task stack HWM: %u free", uxTaskGetStackHighWaterMark(NULL));
    JADE_LOGI("DRAM block / free: %u / %u", heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL),
        heap_caps_get_free_size(MALLOC_CAP_DEFAULT | MALLOC_CAP_INTERNAL));
}

static void check_template(gui_activity_t** act, const char* title, const char* message, bool left, bool right,
    gui_view_node_t** status_text, uint16_t color)
{
    // Base gui with title and icons
    gui_make_activity_ex(act, true, title, true);
    JADE_ASSERT(act);

    // Two rows plus title: main and footer
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 2, 76, 24);
    gui_set_parent(vsplit, (*act)->root_node);

    // Main area, scrolling horizontal menu
    gui_view_node_t* node;
    gui_make_fill(&node, color);
    gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 20, 0, 20, 0);
    gui_set_parent(node, vsplit);

    // l-arrow, item-txt, r-arrow
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 10, 80, 10);
    gui_set_parent(hsplit, node);

    gui_make_text_font(&node, left ? "H" : "", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(node, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    gui_view_node_t* item_text;
    gui_make_fill(&node, color);
    gui_set_parent(node, hsplit);
    gui_make_text_font(&item_text, message, TFT_WHITE, GUI_DEFAULT_FONT);
    gui_set_align(item_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(item_text, node);

    gui_make_text_font(&node, right ? "I" : "", TFT_WHITE, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(node, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(node, hsplit);

    // Footer, three labels - status light + status, fw-version/wallet-id label
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 9, 70, 20);
    gui_set_parent(hsplit, vsplit);

    gui_view_node_t* status_light;
    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(&status_light, "M", TFT_DARKGREY, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(status_light, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(status_light, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 2);
    gui_set_parent(status_light, node);

    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(status_text, "", TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(*status_text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(*status_text, node);

    gui_view_node_t* label;
    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(&label, "TEST", TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(label, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_padding(label, GUI_MARGIN_ALL_DIFFERENT, 0, 2, 0, 0);
    gui_set_parent(label, node);
}

static void check_template_display(gui_activity_t** act, const char* title, gui_view_node_t** item_text,
    gui_view_node_t** item_text2, gui_view_node_t** status_text, uint16_t color)
{
    // Base gui with title and icons
    gui_make_activity_ex(act, true, title, true);
    JADE_ASSERT(act);

    // Three rows plus title: line one, line two and footer
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 38, 38, 24);
    gui_set_parent(vsplit, (*act)->root_node);

    // Main area, line one
    gui_view_node_t* node;
    gui_make_fill(&node, color);
    gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 5, 0, 5, 0);
    gui_set_parent(node, vsplit);

    // Main area, line two
    gui_view_node_t* node2;
    gui_make_fill(&node2, color);
    gui_set_padding(node2, GUI_MARGIN_ALL_DIFFERENT, 5, 0, 5, 0);
    gui_set_parent(node2, vsplit);

    // just one line
    gui_make_text_font(item_text, "", TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(*item_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(*item_text, node);

    // just one line
    gui_make_text_font(item_text2, "", TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(*item_text2, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(*item_text2, node2);

    gui_view_node_t* hsplit;
    // Footer, three labels - status light + status, fw-version/wallet-id label
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 9, 70, 20);
    gui_set_parent(hsplit, vsplit);

    gui_view_node_t* status_light;
    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(&status_light, "M", TFT_DARKGREY, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(status_light, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(status_light, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 2);
    gui_set_parent(status_light, node);

    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(status_text, "", TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(*status_text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(*status_text, node);

    gui_view_node_t* label;
    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(&label, "TEST", TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(label, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_padding(label, GUI_MARGIN_ALL_DIFFERENT, 0, 2, 0, 0);
    gui_set_parent(label, node);
}

static void check_template_two(gui_activity_t** act, const char* title, const char* message, const char* message2,
    gui_view_node_t** status_text, uint16_t color)
{
    // Base gui with title and icons
    gui_make_activity_ex(act, true, title, true);
    JADE_ASSERT(act);

    // Three rows plus title: line one, line two and footer
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 38, 38, 24);
    gui_set_parent(vsplit, (*act)->root_node);

    // Main area, line one
    gui_view_node_t* node;
    gui_make_fill(&node, color);
    gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 5, 0, 5, 0);
    gui_set_parent(node, vsplit);

    // Main area, line two
    gui_view_node_t* node2;
    gui_make_fill(&node2, color);
    gui_set_padding(node2, GUI_MARGIN_ALL_DIFFERENT, 5, 0, 5, 0);
    gui_set_parent(node2, vsplit);

    // just one line
    gui_view_node_t* item_text;
    gui_make_text_font(&item_text, message, TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(item_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(item_text, node);

    // just one line
    gui_view_node_t* item_text2;
    gui_make_text_font(&item_text2, message2, TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(item_text2, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(item_text2, node2);

    // Footer, three labels - status light + status, fw-version/wallet-id label
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 9, 70, 20);
    gui_set_parent(hsplit, vsplit);

    gui_view_node_t* status_light;
    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(&status_light, "M", TFT_DARKGREY, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(status_light, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(status_light, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 2);
    gui_set_parent(status_light, node);

    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(status_text, "", TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(*status_text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(*status_text, node);

    gui_view_node_t* label;
    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(&label, "TEST", TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(label, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_padding(label, GUI_MARGIN_ALL_DIFFERENT, 0, 2, 0, 0);
    gui_set_parent(label, node);
}

static void check_template_three(gui_activity_t** act, const char* title, const char* message, const char* message2,
    const char* message3, gui_view_node_t** status_text, uint16_t color)
{
    // Base gui with title and icons
    gui_make_activity_ex(act, true, title, true);
    JADE_ASSERT(act);

    // Four rows plus title: line one, line two, line three and footer
    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 25, 25, 26, 24);
    gui_set_parent(vsplit, (*act)->root_node);

    // Main area, line one
    gui_view_node_t* node;
    gui_make_fill(&node, color);
    gui_set_padding(node, GUI_MARGIN_ALL_DIFFERENT, 2, 0, 2, 0);
    gui_set_parent(node, vsplit);

    // Main area, line two
    gui_view_node_t* node2;
    gui_make_fill(&node2, color);
    gui_set_padding(node2, GUI_MARGIN_ALL_DIFFERENT, 2, 0, 2, 0);
    gui_set_parent(node2, vsplit);

    // Main area, line threee
    gui_view_node_t* node3;
    gui_make_fill(&node3, color);
    gui_set_padding(node3, GUI_MARGIN_ALL_DIFFERENT, 2, 0, 2, 0);
    gui_set_parent(node3, vsplit);

    // just one line
    gui_view_node_t* item_text;
    gui_make_text_font(&item_text, message, TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(item_text, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(item_text, node);

    // just one line
    gui_view_node_t* item_text2;
    gui_make_text_font(&item_text2, message2, TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(item_text2, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(item_text2, node2);

    // just one line
    gui_view_node_t* item_text3;
    gui_make_text_font(&item_text3, message3, TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(item_text3, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(item_text3, node3);

    // Footer, three labels - status light + status, fw-version/wallet-id label
    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 9, 70, 20);
    gui_set_parent(hsplit, vsplit);

    gui_view_node_t* status_light;
    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(&status_light, "M", TFT_DARKGREY, JADE_SYMBOLS_16x16_FONT);
    gui_set_align(status_light, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_padding(status_light, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 2);
    gui_set_parent(status_light, node);

    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(status_text, "", TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(*status_text, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_parent(*status_text, node);

    gui_view_node_t* label;
    gui_make_fill(&node, TFT_BLACK);
    gui_set_parent(node, hsplit);
    gui_make_text_font(&label, "TEST", TFT_WHITE, GUI_TITLE_FONT);
    gui_set_align(label, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_padding(label, GUI_MARGIN_ALL_DIFFERENT, 0, 2, 0, 0);
    gui_set_parent(label, node);
}

static void check_memory(void)
{
    char buff[100];
    char buff2[100];
    uint16_t color = gui_get_highlight_color();
    uint32_t flash_size;
    esp_flash_get_size(NULL, &flash_size);
    uint32_t psram_size = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    snprintf(buff, 100, "FLASH size: %lu", flash_size);
    snprintf(buff2, 100, "PSRAM size: %lu", psram_size);

    // Create GUI object
    gui_activity_t* act = NULL;
    gui_view_node_t* status_text = NULL;
    check_template_two(&act, "Test memory", buff, buff2, &status_text, color);
    gui_set_current_activity_ex(act, true);
    gui_update_text(status_text, "Click front button");

    int32_t ev_id;
    while (true) {
        if (gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            if (ev_id == GUI_FRONT_CLICK_EVENT) {
                break;
            }
        }
    }
}

static void get_random_string(char* str, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len; i++) {
        str[i] = (rand() % ('~' - ' ')) + ' ';
    }
    str[i] = '\0';
}

static void check_display(void)
{
    // Create GUI objectrandom
    gui_activity_t* act = NULL;
    gui_view_node_t* status_text = NULL;
    gui_view_node_t* item_text = NULL;
    gui_view_node_t* item_text2 = NULL;
    bool continue_loop = true;
    while (continue_loop) {
        uint16_t color = (uint16_t)rand();
        check_template_display(&act, "Test display", &item_text, &item_text2, &status_text, color);
        gui_set_current_activity_ex(act, true);
        gui_update_text(status_text, "Click front button");
        char random_str[21] = { 0 };
        get_random_string(random_str, 20);
        gui_update_text(item_text, random_str);
        get_random_string(random_str, 20);
        gui_update_text(item_text2, random_str);

        int32_t ev_id;
        while (true) {
            if (gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
                if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                    break;
                } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                    break;
                } else if (ev_id == GUI_WHEEL_CLICK_EVENT) {
                    break;
                } else if (ev_id == GUI_FRONT_CLICK_EVENT) {
                    continue_loop = false;
                    break;
                }
            }
        }
    }
}

static void check_front(void)
{
    // Create GUI object
    gui_activity_t* act = NULL;
    gui_view_node_t* status_text = NULL;
    check_template(&act, "Test button", "Click front button", false, false, &status_text, gui_get_highlight_color());
    gui_set_current_activity_ex(act, true);
    gui_update_text(status_text, "Click front button");

    int32_t ev_id;
    while (true) {
        if (gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                gui_update_text(status_text, "Left");
            } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                gui_update_text(status_text, "Right");
            } else if (ev_id == GUI_WHEEL_CLICK_EVENT) {
                gui_update_text(status_text, "Wheel");
            } else if (ev_id == GUI_FRONT_CLICK_EVENT) {
                gui_update_text(status_text, "Front");
                break;
            } else {
                gui_update_text(status_text, "Unknown");
            }
        }
    }
}

static void check_left(void)
{
    // Create GUI object
    gui_activity_t* act = NULL;
    gui_view_node_t* status_text = NULL;
    check_template(&act, "Test wheel", "Click left", true, false, &status_text, gui_get_highlight_color());
    gui_set_current_activity_ex(act, true);
    gui_update_text(status_text, "Click left");

    int32_t ev_id;
    while (true) {
        if (gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                gui_update_text(status_text, "Left");
                break;
            } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                gui_update_text(status_text, "Right");
            } else if (ev_id == GUI_WHEEL_CLICK_EVENT) {
                gui_update_text(status_text, "Wheel");
            } else if (ev_id == GUI_FRONT_CLICK_EVENT) {
                gui_update_text(status_text, "Front");
            } else {
                gui_update_text(status_text, "Unknown");
            }
        }
    }
}

static void check_right(void)
{
    // Create GUI object
    gui_activity_t* act = NULL;
    gui_view_node_t* status_text = NULL;
    check_template(&act, "Test wheel", "Click right", false, true, &status_text, gui_get_highlight_color());
    gui_set_current_activity_ex(act, true);
    gui_update_text(status_text, "Click right");

    int32_t ev_id;
    while (true) {
        if (gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            if (ev_id == GUI_WHEEL_LEFT_EVENT) {
                gui_update_text(status_text, "Left");
            } else if (ev_id == GUI_WHEEL_RIGHT_EVENT) {
                gui_update_text(status_text, "Right");
                break;
            } else if (ev_id == GUI_WHEEL_CLICK_EVENT) {
                gui_update_text(status_text, "Wheel");
            } else if (ev_id == GUI_FRONT_CLICK_EVENT) {
                gui_update_text(status_text, "Front");
            } else {
                gui_update_text(status_text, "Unknown");
            }
        }
    }
}

static void check_battery(void)
{
    char buff[100];
    char buff2[100];
    char buff3[100];
    uint16_t color = gui_get_highlight_color();
    snprintf(buff, 100, "VUSB = %u mV", power_get_vusb());
    snprintf(buff2, 100, "VBAT = %d mV", power_get_vbat());
    snprintf(buff3, 100, "TEMP = %d C", power_get_temp());

    // Create GUI object
    gui_activity_t* act = NULL;
    gui_view_node_t* status_text = NULL;
    check_template_three(&act, "Test battery", buff, buff2, buff3, &status_text, color);
    gui_set_current_activity_ex(act, true);
    gui_update_text(status_text, "Click front button");

    // Register for all events
    int32_t ev_id;
    while (true) {
        if (gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            if (ev_id == GUI_FRONT_CLICK_EVENT) {
                break;
            }
        }
    }
}

static bool camera_cb(const size_t width, const size_t height, const uint8_t* data, const size_t len, void* ctx_data)
{
    JADE_ASSERT(data);
    JADE_ASSERT(len);
    JADE_ASSERT(ctx_data);

    // Check image as expected
    JADE_ASSERT(width == CAMERA_IMAGE_WIDTH);
    JADE_ASSERT(height == CAMERA_IMAGE_HEIGHT);

    // greyscale == 1 byte per pixel
    JADE_ASSERT(len == width * height);

    // Set 'returned' flag
    bool* const ok = (bool*)ctx_data;
    *ok = true;

    return false; // ie. keep running camera
}

static void check_camera(void)
{
    // Run the camera task until the user quits
    bool ok = false;
    jade_camera_process_images(camera_cb, &ok, true, "Click front button", false, QR_GUIDES_NONE, NULL, NULL);
    JADE_ASSERT(ok); // Must have processed at least one good image
}

static void check_end(void)
{
    // Create GUI object
    gui_activity_t* act = NULL;
    gui_view_node_t* status_text = NULL;
    check_template(&act, "END", "Turn off Jade", false, false, &status_text, gui_get_highlight_color());
    gui_set_current_activity_ex(act, true);
    gui_update_text(status_text, "Turn off jade");

    int32_t ev_id;
    while (true) {
        if (gui_activity_wait_event(act, GUI_EVENT, ESP_EVENT_ANY_ID, NULL, &ev_id, NULL, 0)) {
            if (ev_id == GUI_FRONT_CLICK_EVENT) {
                break;
            }
        }
    }
}

void start_smoketest(void)
{
    JADE_LOGI("Starting smoketest on core %u, with priority %u", xPortGetCoreID(), uxTaskPriorityGet(NULL));
    log_mem();

    check_memory();
    check_display();
    check_front();
    check_left();
    check_right();
    check_battery();
    log_mem();

    check_camera();
    check_end();
    log_mem();

    power_shutdown();
}
#endif // AMALGAMATED_BUILD
