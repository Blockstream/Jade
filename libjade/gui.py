from ctypes import POINTER, c_ubyte, c_size_t, byref
import logging
import tkinter as tk

from jadepy.jade import JadeAPI, JadeError

# Enable jade logging
jadehandler = logging.StreamHandler()
logger = logging.getLogger('jadepy.jade')
logger.setLevel(logging.INFO)
logger.addHandler(jadehandler)

# set global logging level to info
logging.basicConfig(level=logging.INFO)

# Set when we connect to the software implementation
libjade = None

# enum for GUI event types (left, right, enter)
TK_EVENT_KEY_LEFT = 1
TK_EVENT_KEY_RIGHT = 2
TK_EVENT_KEY_ENTER = 3

_root = None
_label = None

def _window_close():
    global _root
    if _root:
        _root.destroy()
        _root = None

def _key_press(event):
    if event.keysym == 'Left' or event.keysym == 'Up':
        libjade.libjade_handle_gui_event(TK_EVENT_KEY_LEFT)
    elif event.keysym == 'Right' or event.keysym == 'Down':
        libjade.libjade_handle_gui_event(TK_EVENT_KEY_RIGHT)
    elif event.keysym == 'Return' or event.keysym == 'space':
        libjade.libjade_handle_gui_event(TK_EVENT_KEY_ENTER)

def _get_display_buffer():
    # Fetch the raw bytes of the display buffer
    buffer = POINTER(c_ubyte)()
    buffer_len = c_size_t()
    width = c_size_t()
    height = c_size_t()
    libjade.libjade_get_display_buffer(byref(buffer), byref(buffer_len), byref(width), byref(height))

    # Convert to a binary PPM image
    width = width.value
    height = height.value
    header = bytearray(f'P6\n{width} {height}\n255\n'.encode())
    ppm = bytearray(header + bytearray(width * height * 3))
    offset = len(header)
    for i in range(width * height):
        rgb565 = buffer[i*2] << 8 | buffer[i*2 + 1]
        ppm[offset] = ((rgb565 >> 11) & 0x1F) << 3
        offset += 1
        ppm[offset] = ((rgb565 >> 5) & 0x3F) << 2
        offset += 1
        ppm[offset] = (rgb565 & 0x1F) << 3
        offset += 1

    # create PhotoImage from display PPM
    img = tk.PhotoImage(data=bytes(ppm))

    # update label
    _label.config(image=img)
    _label.image = img # hold on to reference
    # if window is smaller than image, resize
    if _root.winfo_width() < width or _root.winfo_height() < height:
        _root.geometry(f'{width}x{height}')
        _label.pack()
        pass

    _root.after(10, _get_display_buffer)

def tk_basic_gui():
    global _root, _label
    _root = tk.Tk()
    _root.title('libjade GUI')
    _root.geometry('200x100')
    _label = tk.Label(_root, text='Waiting for framebuffer updates...')
    _label.pack()
    _root.protocol("WM_DELETE_WINDOW", _window_close)
    _root.bind('<Key>', _key_press)
    _root.after(10, _get_display_buffer)
    _root.mainloop()

if __name__ == '__main__':
    # Connect jade
    jade = JadeAPI.create_libjade(timeout=0)
    jade.connect()
    libjade = jade.jade.impl.libjade
    # start GUI
    tk_basic_gui()
    logger.debug('gui closed')
    jade.disconnect()
    logger.debug('jade disconnected')
    exit(0)
