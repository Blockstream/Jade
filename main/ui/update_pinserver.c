#include "../button_events.h"
#include "../ui.h"
#include "jade_assert.h"

void make_confirm_pinserver_details_activity(
    gui_activity_t** activity_ptr, const char* urlA, const char* urlB, const char* pubkey_hex)
{
    JADE_ASSERT(activity_ptr);
    JADE_ASSERT(urlA);
    JADE_ASSERT(urlB);

    gui_make_activity(activity_ptr, true, "Confirm PinServer");
    gui_activity_t* activity = *activity_ptr;
    JADE_ASSERT(activity);

    char buf[128];

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 22, 22, 22, 34);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, activity->root_node);

    // first row, url
    gui_view_node_t* hsplit_text1;
    gui_make_hsplit(&hsplit_text1, GUI_SPLIT_RELATIVE, 2, 30, 70);
    gui_set_parent(hsplit_text1, vsplit);

    gui_view_node_t* text1;
    gui_make_text(&text1, "URL", TFT_WHITE);
    gui_set_parent(text1, hsplit_text1);
    gui_set_align(text1, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text1, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    if (urlA[0] == '\0') {
        const int ret = snprintf(buf, sizeof(buf), "<None>");
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    } else {
        const int ret = snprintf(buf, sizeof(buf), "} %s {", urlA);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    }

    gui_view_node_t* text_url1;
    gui_make_text(&text_url1, buf, TFT_WHITE);
    gui_set_parent(text_url1, hsplit_text1);
    gui_set_align(text_url1, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_text_scroll(text_url1, TFT_BLACK);

    // second row, alternative URL
    gui_view_node_t* hsplit_text2;
    gui_make_hsplit(&hsplit_text2, GUI_SPLIT_RELATIVE, 2, 30, 70);
    gui_set_parent(hsplit_text2, vsplit);

    gui_view_node_t* text2;
    gui_make_text(&text2, "2nd URL", TFT_WHITE);
    gui_set_parent(text2, hsplit_text2);
    gui_set_align(text2, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text2, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    if (urlB[0] == '\0') {
        const int ret = snprintf(buf, sizeof(buf), "<None>");
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    } else {
        const int ret = snprintf(buf, sizeof(buf), "} %s {", urlB);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    }

    gui_view_node_t* text_url2;
    gui_make_text(&text_url2, buf, TFT_WHITE);
    gui_set_parent(text_url2, hsplit_text2);
    gui_set_align(text_url2, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_text_scroll(text_url2, TFT_BLACK);

    // third row, pubkey
    gui_view_node_t* hsplit_text3;
    gui_make_hsplit(&hsplit_text3, GUI_SPLIT_RELATIVE, 2, 30, 70);
    gui_set_parent(hsplit_text3, vsplit);

    gui_view_node_t* text3;
    gui_make_text(&text3, "PubKey", TFT_WHITE);
    gui_set_parent(text3, hsplit_text3);
    gui_set_align(text3, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text3, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    if (!pubkey_hex) {
        const int ret = snprintf(buf, sizeof(buf), "<No Change>");
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    } else {
        const int ret = snprintf(buf, sizeof(buf), "} %s {", pubkey_hex);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    }

    gui_view_node_t* text_pubkey;
    gui_make_text(&text_pubkey, buf, TFT_WHITE);
    gui_set_parent(text_pubkey, hsplit_text3);
    gui_set_align(text_pubkey, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_text_scroll(text_pubkey, TFT_BLACK);

    // fourth row, buttons
    gui_view_node_t* hsplit_btn;
    gui_make_hsplit(&hsplit_btn, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(hsplit_btn, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 0);
    gui_set_parent(hsplit_btn, vsplit);

    gui_view_node_t* btn1;
    gui_make_button(&btn1, TFT_BLACK, BTN_PINSERVER_DETAILS_DENY, NULL);
    gui_set_margins(btn1, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn1, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn1, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn1, hsplit_btn);

    gui_view_node_t* textbtn1;
    gui_make_text(&textbtn1, "X", TFT_WHITE);
    gui_set_parent(textbtn1, btn1);
    gui_set_align(textbtn1, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_view_node_t* black_fill;
    gui_make_fill(&black_fill, TFT_BLACK);
    gui_set_parent(black_fill, hsplit_btn);

    gui_view_node_t* btn3;
    gui_make_button(&btn3, TFT_BLACK, BTN_PINSERVER_DETAILS_CONFIRM, NULL);
    gui_set_margins(btn3, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn3, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn3, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn3, hsplit_btn);

    gui_view_node_t* textbtn3;
    gui_make_text_font(&textbtn3, "S", TFT_WHITE, VARIOUS_SYMBOLS_FONT);
    gui_set_parent(textbtn3, btn3);
    gui_set_align(textbtn3, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
}

void make_confirm_pinserver_certificate_activity(gui_activity_t** activity_ptr, const char* cert_hash_hex)
{
    JADE_ASSERT(activity_ptr);

    gui_make_activity(activity_ptr, true, "Confirm PinServer");
    gui_activity_t* activity = *activity_ptr;
    JADE_ASSERT(activity);

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 4, 22, 22, 22, 34);
    gui_set_padding(vsplit, GUI_MARGIN_ALL_DIFFERENT, 2, 2, 2, 2);
    gui_set_parent(vsplit, activity->root_node);

    // first row, text
    gui_view_node_t* text1;
    gui_make_text(&text1, "Confirm hash of certificate", TFT_WHITE);
    gui_set_parent(text1, vsplit);
    gui_set_align(text1, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);

    // second row, hash
    gui_view_node_t* hsplit_text2;
    gui_make_hsplit(&hsplit_text2, GUI_SPLIT_RELATIVE, 2, 30, 70);
    gui_set_parent(hsplit_text2, vsplit);

    gui_view_node_t* text2;
    gui_make_text(&text2, "Hash", TFT_WHITE);
    gui_set_parent(text2, hsplit_text2);
    gui_set_align(text2, GUI_ALIGN_LEFT, GUI_ALIGN_MIDDLE);
    gui_set_borders(text2, TFT_BLOCKSTREAM_GREEN, 2, GUI_BORDER_BOTTOM);

    char buf[128];
    if (cert_hash_hex == NULL) {
        const int ret = snprintf(buf, sizeof(buf), "<None>");
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    } else {
        const int ret = snprintf(buf, sizeof(buf), "} %s {", cert_hash_hex);
        JADE_ASSERT(ret > 0 && ret < sizeof(buf));
    }

    gui_view_node_t* text_hash;
    gui_make_text(&text_hash, buf, TFT_WHITE);
    gui_set_parent(text_hash, hsplit_text2);
    gui_set_align(text_hash, GUI_ALIGN_RIGHT, GUI_ALIGN_MIDDLE);
    gui_set_text_scroll(text_hash, TFT_BLACK);

    // third row, dummy black bg
    gui_view_node_t* dummy_bg3;
    gui_make_fill(&dummy_bg3, TFT_BLACK);
    gui_set_parent(dummy_bg3, vsplit);

    // fourth row, buttons
    gui_view_node_t* hsplit_btn;
    gui_make_hsplit(&hsplit_btn, GUI_SPLIT_RELATIVE, 3, 33, 34, 33);
    gui_set_margins(hsplit_btn, GUI_MARGIN_ALL_DIFFERENT, 0, 0, 0, 0);
    gui_set_parent(hsplit_btn, vsplit);

    gui_view_node_t* btn1;
    gui_make_button(&btn1, TFT_BLACK, BTN_PINSERVER_DETAILS_DENY, NULL);
    gui_set_margins(btn1, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn1, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn1, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn1, hsplit_btn);

    gui_view_node_t* textbtn1;
    gui_make_text(&textbtn1, "X", TFT_WHITE);
    gui_set_parent(textbtn1, btn1);
    gui_set_align(textbtn1, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);

    gui_view_node_t* black_fill;
    gui_make_fill(&black_fill, TFT_BLACK);
    gui_set_parent(black_fill, hsplit_btn);

    gui_view_node_t* btn3;
    gui_make_button(&btn3, TFT_BLACK, BTN_PINSERVER_DETAILS_CONFIRM, NULL);
    gui_set_margins(btn3, GUI_MARGIN_ALL_EQUAL, 2);
    gui_set_borders(btn3, TFT_BLACK, 2, GUI_BORDER_ALL);
    gui_set_borders_selected_color(btn3, TFT_BLOCKSTREAM_GREEN);
    gui_set_parent(btn3, hsplit_btn);

    gui_view_node_t* textbtn3;
    gui_make_text_font(&textbtn3, "S", TFT_WHITE, VARIOUS_SYMBOLS_FONT);
    gui_set_parent(textbtn3, btn3);
    gui_set_align(textbtn3, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
}
