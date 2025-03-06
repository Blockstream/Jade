#ifndef AMALGAMATED_BUILD
#include "input.h"
#include "sdkconfig.h"

#if defined(CONFIG_ETH_USE_OPENETH)
#include <input/noinput.inc>
#elif defined(CONFIG_DISPLAY_TOUCHSCREEN)
#include <input/touchscreen.inc>
#elif defined(CONFIG_BOARD_TYPE_M5_STICKC_PLUS) || defined(CONFIG_INPUT_ONE_BUTTON_MODE)
#include <input/singlebtn.inc>
#elif defined(CONFIG_BOARD_TYPE_JADE)
#include <input/selectbtn.inc>
#include <input/wheel.inc>
#else
#include <input/navbtns.inc>
#include <input/selectbtn.inc>
#endif

void input_init(void)
{
    navigation_init();
    select_init();
}
#endif // AMALGAMATED_BUILD
