#ifndef AMALGAMATED_BUILD
#include "../button_events.h"
#include "../jade_assert.h"
#include "../ui.h"

// QR frame guides around the central part of the frame
// NOTE: these are different for esp32s3(vga) and esp32(qvga)
#ifdef CONFIG_IDF_TARGET_ESP32S3
extern const uint8_t icon_qr_large_frame_guide_start[] asm("_binary_icon_qrguide_vga_large_bin_gz_start");
extern const uint8_t icon_qr_large_frame_guide_end[] asm("_binary_icon_qrguide_vga_large_bin_gz_end");
extern const uint8_t icon_qr_small_frame_guide_start[] asm("_binary_icon_qrguide_vga_small_bin_gz_start");
extern const uint8_t icon_qr_small_frame_guide_end[] asm("_binary_icon_qrguide_vga_small_bin_gz_end");
#else
extern const uint8_t icon_qr_large_frame_guide_start[] asm("_binary_icon_qrguide_qvga_large_bin_gz_start");
extern const uint8_t icon_qr_large_frame_guide_end[] asm("_binary_icon_qrguide_qvga_large_bin_gz_end");
extern const uint8_t icon_qr_small_frame_guide_start[] asm("_binary_icon_qrguide_qvga_small_bin_gz_start");
extern const uint8_t icon_qr_small_frame_guide_end[] asm("_binary_icon_qrguide_qvga_small_bin_gz_end");
#endif

gui_activity_t* make_camera_activity(gui_view_node_t** image_node, gui_view_node_t** label_node,
    const bool show_click_btn, const qr_frame_guides_t qr_frame_guides, progress_bar_t* progress_bar,
    const bool show_help_btn)
{
    // progress bar is optional
    JADE_INIT_OUT_PPTR(image_node);
    JADE_INIT_OUT_PPTR(label_node);

    // NOTE: atm show_click_btn and help_url are mutually exclusive
    JADE_ASSERT(!show_click_btn || !show_help_btn);

    gui_activity_t* const act = gui_make_activity();

    // Whole screen image
    gui_make_picture(image_node, NULL);
    gui_set_align(*image_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(*image_node, act->root_node);
    gui_view_node_t* parent = *image_node;

    // QR frame guide if applicable
    if (qr_frame_guides != QR_GUIDES_NONE) {
        Icon* const qr_guide_icon = qr_frame_guides == QR_GUIDES_LARGE
            ? get_icon(icon_qr_large_frame_guide_start, icon_qr_large_frame_guide_end)
            : qr_frame_guides == QR_GUIDES_SMALL
            ? get_icon(icon_qr_small_frame_guide_start, icon_qr_small_frame_guide_end)
            : NULL;
        JADE_ASSERT(qr_guide_icon);

        gui_make_icon(&parent, qr_guide_icon, TFT_WHITE, NULL);
        gui_set_icon_animation(parent, qr_guide_icon, 1, 0); // to transfer ownership
        gui_set_align(parent, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
        gui_set_parent(parent, *image_node);
    }

    gui_view_node_t* vsplit;
    gui_make_vsplit(&vsplit, GUI_SPLIT_RELATIVE, 3, 20, 60, 20);
    gui_set_parent(vsplit, parent);

    // Header row buttons - back and either help or 'click'
    btn_data_t hdrbtns[]
        = { { .txt = "=", .font = JADE_SYMBOLS_16x16_FONT, .ev_id = BTN_CAMERA_EXIT, .borders = GUI_BORDER_ALL },
              { .txt = "?", .font = GUI_TITLE_FONT, .ev_id = BTN_CAMERA_HELP, .borders = GUI_BORDER_ALL } };

    if (show_click_btn) {
        hdrbtns[1].txt = "S";
        hdrbtns[1].font = VARIOUS_SYMBOLS_FONT;
        hdrbtns[1].ev_id = BTN_CAMERA_CLICK;
    }

    gui_view_node_t* hsplit;
    gui_make_hsplit(&hsplit, GUI_SPLIT_RELATIVE, 3, 15, 70, 15);
    gui_set_parent(hsplit, vsplit);

    // Back/cancel button
    add_button(hsplit, &hdrbtns[0]);

    // Any help or 'click' button, if required
    if (show_help_btn || show_click_btn) {
        gui_view_node_t* spacer;
        gui_make_vsplit(&spacer, GUI_SPLIT_RELATIVE, 1, 100); // no-op transparent spacer
        gui_set_parent(spacer, hsplit);
        add_button(hsplit, &hdrbtns[1]);
    }

    // Text label across the centre
    gui_make_text(label_node, "Initializing...", TFT_WHITE);
    gui_set_align(*label_node, GUI_ALIGN_CENTER, GUI_ALIGN_MIDDLE);
    gui_set_parent(*label_node, vsplit);

    // Bottom part, any progress bar if applicable (transparent)
    if (progress_bar) {
        progress_bar->transparent = true;
        make_progress_bar(vsplit, progress_bar);
        gui_set_borders(progress_bar->container, GUI_BLOCKSTREAM_BUTTONBORDER_GREY, 1, GUI_BORDER_ALL);
        gui_set_margins(progress_bar->container, GUI_MARGIN_ALL_DIFFERENT, 12, 12, 4, 12);
    }

    return act;
}
#endif // AMALGAMATED_BUILD
