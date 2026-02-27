import argparse
import builtins
import io
import logging
import os
import re
import sys
import threading
import tkinter as tk
from tkinter import font as tkfont
import types

from jadepy.jade import JadeAPI, JadeError

# Enable jade logging
jadehandler = logging.StreamHandler()
logger = logging.getLogger('jadepy.jade')
logger.setLevel(logging.WARNING)
logger.addHandler(jadehandler)

# set global logging level (overridden in __main__ via --log-level)
logging.basicConfig(level=logging.WARNING)

# mappings from --log-level string to python logging level and ESP log level integer
_PY_LOG_LEVELS = {
    'none': logging.CRITICAL,
    'error': logging.ERROR,
    'warn': logging.WARNING,
    'info': logging.INFO,
    'debug': logging.DEBUG,
    'verbose': logging.DEBUG,
}
_ESP_LOG_LEVELS = {
    'none': 0, 'error': 1, 'warn': 2, 'info': 3, 'debug': 4, 'verbose': 5
}

# Set when we connect to the software implementation
_libjade_mutex = threading.Lock()
_last_frame_data = None
_display_width = 0
_display_height = 0
_camera = None


def locked_jadeRpc(self, method, params=None, inputid=None, http_request_fn=None, long_timeout=False):
    with _libjade_mutex:
        return self.unlocked_jadeRpc(method, params, inputid, http_request_fn, long_timeout)


def rpc_monkey_patch(jade):
    jade.unlocked_jadeRpc = jade._jadeRpc
    jade._jadeRpc = types.MethodType(locked_jadeRpc, jade)


class CameraManager:
    """Manages the camera capture thread and static-frame injection."""

    FRAME_W = 320  # CAMERA_IMAGE_WIDTH
    FRAME_H = 240  # CAMERA_IMAGE_HEIGHT

    def __init__(self, jade):
        self.jade = jade
        self._thread_stop = threading.Event()
        self._thread = None
        self._static_frame = None
        self._enabled = False

    def use_live_camera(self):
        self._static_frame = None
        self._enabled = True
        self._restart_thread()

    def set_static_frame(self, frame_bytes):
        self._static_frame = frame_bytes
        self._enabled = True
        self._restart_thread()

    def stop(self):
        self._enabled = False
        self._thread_stop.set()

    def shutdown(self):
        self._thread_stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def _restart_thread(self):
        self._thread_stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread_stop.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def _send_frame(self, frame_data):
        params = {'request': 'set_camera_bytes', 'bytes': frame_data}
        self.jade._jadeRpc('libjade_request', params)

    def _capture_loop(self):
        """Serve static frame (once) or live webcam frames via push_fn at ~5 fps."""
        static_frame = self._static_frame
        if static_frame:
            logger.info('Camera capture thread: pushing static frame')
            if not self._thread_stop.is_set():
                self._send_frame(static_frame)
            logger.info('Static camera thread stopped')
            return

        try:
            import cv2
        except ImportError:
            logger.warning('cv2 not available, camera frames will not be pushed')
            return

        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            logger.warning('Failed to open host webcam, camera frames will not be pushed')
            return

        logger.info('Camera capture thread started')
        frames_per_second = 5
        try:
            while not self._thread_stop.is_set():
                ret, frame = cap.read()
                if not ret:
                    logger.warning('Camera read failed, stopping camera thread')
                    break
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                resized = cv2.resize(gray, (self.FRAME_W, self.FRAME_H))
                self._send_frame(resized.tobytes())
                self._thread_stop.wait(1.0 / frames_per_second)
        finally:
            cap.release()
            logger.info('Camera capture thread stopped')


_root = None
_label = None
TEST_MNEMONIC = 'fish inner face ginger orchard permit useful method fence \
kidney chuckle party favorite sunset draw limb science crane oval letter \
slot invite sadness banana'


class ConsoleManager:
    """Manages the interactive Python console: history, execution, and UI widgets."""

    HISTORY_FILE = os.path.expanduser('~/.jade_console_history')
    HISTORY_MAX = 1000

    def __init__(self):
        self._history = self._load_history()
        self._history_idx = len(self._history)
        self.locals = {}    # persistent execution namespace
        self._output = None  # tk.Text widget, set by build_ui
        self._entry = None   # tk.Entry widget, set by build_ui
        self.body = None     # tk.Frame widget, set by build_ui

    #
    # History persistence
    #

    def _load_history(self):
        try:
            with open(self.HISTORY_FILE, encoding='utf-8') as f:
                lines = [line.rstrip('\n') for line in f if line.strip()]
            if len(lines) > self.HISTORY_MAX:
                lines = lines[-self.HISTORY_MAX:]
                with open(self.HISTORY_FILE, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(lines) + '\n')
            return lines
        except FileNotFoundError:
            return []

    def _append_history(self, cmd):
        try:
            with open(self.HISTORY_FILE, 'a', encoding='utf-8') as f:
                f.write(cmd + '\n')
        except OSError as e:
            logger.warning('Could not write console history: %s', e)

    #
    # Thread-safe output
    #

    def write(self, text, tag='output'):
        """Write text to the console output widget (thread-safe)."""
        def _do():
            self._output.config(state=tk.NORMAL)
            self._output.insert(tk.END, text, tag)
            self._output.see(tk.END)
            self._output.config(state=tk.DISABLED)
        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            _root.after(0, _do)

    def set_busy(self, busy):
        """Disable/enable the entry widget while a command is running (thread-safe)."""
        def _do():
            self._entry.config(state=tk.DISABLED if busy else tk.NORMAL)
            if not busy:
                self._entry.focus_set()
        if threading.current_thread() is threading.main_thread():
            _do()
        else:
            _root.after(0, _do)

    #
    # Command execution
    #

    def _run_command(self, cmd):
        stdout_cap, stderr_cap = io.StringIO(), io.StringIO()
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = stdout_cap, stderr_cap
        try:
            try:
                result = eval(cmd, self.locals)  # noqa: S307
                if result is not None:
                    print(repr(result))
            except SyntaxError:
                exec(cmd, self.locals)  # noqa: S102
        except Exception as e:
            print(f'{type(e).__name__}: {e}', file=sys.stderr)
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr
        out = stdout_cap.getvalue()
        err = stderr_cap.getvalue()
        if out:
            self.write(out, 'output')
        if err:
            self.write(err, 'error')
        self.set_busy(False)

    #
    # Key event handlers
    #

    def on_execute(self, event=None):
        """Bound to <Return>: dispatch the typed command to a background thread."""
        if self._entry['state'] == tk.DISABLED:
            return 'break'  # already running
        cmd = self._entry.get().strip()
        self._entry.delete(0, tk.END)
        if not cmd:
            return 'break'
        self._history.append(cmd)
        self._history_idx = len(self._history)
        self._append_history(cmd)
        self.write(f'>>> {cmd}\n', 'input')
        self.set_busy(True)
        threading.Thread(target=self._run_command, args=(cmd,), daemon=True).start()
        return 'break'

    def on_history_prev(self, event):
        """Bound to <Up>: navigate to the previous history entry."""
        if not self._history:
            return 'break'
        self._history_idx = max(0, self._history_idx - 1)
        self._entry.delete(0, tk.END)
        self._entry.insert(0, self._history[self._history_idx])
        return 'break'

    def on_history_next(self, event):
        """Bound to <Down>: navigate to the next history entry."""
        self._history_idx = min(len(self._history), self._history_idx + 1)
        self._entry.delete(0, tk.END)
        if self._history_idx < len(self._history):
            self._entry.insert(0, self._history[self._history_idx])
        return 'break'

    def on_autocomplete(self, event=None):
        """Bound to <Control-space>: complete the token at the cursor.

        - 'obj.prefix'  -> attribute completion via dir(obj)
        - 'prefix'      -> name completion from console locals + builtins
        Single match: complete inline.  Multiple matches: list in output.
        """
        text = self._entry.get()
        cursor = self._entry.index(tk.INSERT)
        before = text[:cursor]
        m = re.search(r'[\w.]+$', before)
        if not m:
            return 'break'
        token = m.group()
        if '.' in token:
            obj_expr, attr_prefix = token.rsplit('.', 1)
            try:
                obj = eval(obj_expr, self.locals)  # noqa: S307
                candidates = sorted(a for a in dir(obj)
                                    if a.startswith(attr_prefix) and not a.startswith('__'))
            except Exception:
                return 'break'
        else:
            attr_prefix = token
            all_names = list(self.locals.keys()) + dir(builtins)
            candidates = sorted(set(n for n in all_names if n.startswith(attr_prefix)))
        if not candidates:
            return 'break'
        if len(candidates) == 1:
            self._entry.insert(cursor, candidates[0][len(attr_prefix):])
        else:
            common = os.path.commonprefix(candidates)
            extra = common[len(attr_prefix):]
            if extra:
                self._entry.insert(cursor, extra)
            self.write('  '.join(candidates) + '\n', 'output')
        return 'break'

    #
    # UI construction
    #

    def build_ui(self, root, font, on_entry_focus=None):
        """Create console widgets as children of *root*. Sets self.body and self._entry."""
        self.body = tk.Frame(root, bg='#1e1e1e')

        scrollbar = tk.Scrollbar(self.body)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._output = tk.Text(
            self.body, height=10, bg='#1e1e1e', fg='#d4d4d4',
            font=font, state=tk.DISABLED, wrap=tk.WORD,
            yscrollcommand=scrollbar.set)
        self._output.pack(fill=tk.BOTH, expand=True)
        self._output.tag_config('input', foreground='#569cd6')
        self._output.tag_config('output', foreground='#d4d4d4')
        self._output.tag_config('error', foreground='#f44747')
        scrollbar.config(command=self._output.yview)

        entry_frame = tk.Frame(self.body, bg='#1e1e1e')
        entry_frame.pack(fill=tk.X)
        tk.Label(entry_frame, text='>>>', bg='#1e1e1e', fg='#569cd6', font=font).pack(
            side=tk.LEFT, padx=(4, 0))
        self._entry = tk.Entry(
            entry_frame, bg='#252526', fg='#d4d4d4', insertbackground='white', font=font)
        self._entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(2, 4), pady=2)
        self._entry.bind('<Return>', self.on_execute)
        self._entry.bind('<Control-space>', self.on_autocomplete)
        self._entry.bind('<Up>', self.on_history_prev)
        self._entry.bind('<Down>', self.on_history_next)
        if on_entry_focus:
            self._entry.bind('<FocusIn>', lambda e: on_entry_focus())


_console = ConsoleManager()


def hex_to_bin(hex_str):
    """Convert a hex string (with or without 0x prefix / spaces) to bytes."""
    return bytes.fromhex(hex_str.replace('0x', '').replace(' ', ''))


def bin_to_hex(data):
    """Convert bytes (or any iterable of ints) to a lowercase hex string."""
    return bytes(data).hex()


def _window_close():
    global _root
    _camera.shutdown()
    if _root:
        _root.destroy()
        _root = None


def _render_display_frame(data, width, height):
    """Convert an RGB565 frame to a tkinter PhotoImage and update the display."""
    header = bytearray(f'P6\n{width} {height}\n255\n'.encode())
    ppm = bytearray(header + bytearray(width * height * 3))
    offset = len(header)
    for i in range(width * height):
        rgb565 = data[i*2] << 8 | data[i*2 + 1]
        ppm[offset] = ((rgb565 >> 11) & 0x1F) << 3
        offset += 1
        ppm[offset] = ((rgb565 >> 5) & 0x3F) << 2
        offset += 1
        ppm[offset] = (rgb565 & 0x1F) << 3
        offset += 1
    img = tk.PhotoImage(data=bytes(ppm))
    _label.config(image=img)
    _label.image = img
    if _root.winfo_width() < width or _root.winfo_height() < height:
        _root.geometry(f'{width}x{height + 28}')  # +28 for console toggle bar
        _label.pack()


def jade_send_input(jade, event):
    """Send a button click event to the connected libjade"""
    if event.keysym in ('Left', 'Up'):
        ev = 'left'
    elif event.keysym in ('Right', 'Down'):
        ev = 'right'
    elif event.keysym in ('Return', 'space'):
        ev = 'click'
    jade._jadeRpc('libjade_request', {'request': 'send_input', 'event': ev})


def jade_update_display(jade):
    """Fetch the libjade screen contents and display them"""
    global _last_frame_data, _display_width, _display_height
    if not _display_width:
        # First time through: fetch the jade display properties
        display_size = jade._jadeRpc('libjade_request', {'request': 'get_display_size'})
        _display_width = display_size['width']
        _display_height = display_size['height']
    # Fetch the current display contents
    display_bytes = jade._jadeRpc('libjade_request', {'request': 'get_display_bytes'})
    if display_bytes != _last_frame_data:
        # Contents have changed: re-render the display
        _last_frame_data = display_bytes
        _render_display_frame(display_bytes, _display_width, _display_height)
    # Queue another update 200ms from now
    _root.after(200, lambda: jade_update_display(jade))


def _open_camera_dialog(on_static_confirmed_cb, on_live_camera_cb):
    """Open a modal dialog to either use the live webcam or load/crop a static image.

    Requires Pillow (pip install Pillow) for the static-image path.
    """
    try:
        from PIL import Image, ImageTk
    except ImportError:
        import tkinter.messagebox
        tkinter.messagebox.showerror(
            'Missing dependency',
            'Pillow is required for the static image feature.\nInstall with: pip install Pillow')
        # Still open the dialog so the live-camera option is accessible
        Image = None
        ImageTk = None

    PREVIEW_MAX_W = 480
    PREVIEW_MAX_H = 360
    TARGET_W = CameraManager.FRAME_W
    TARGET_H = CameraManager.FRAME_H
    HANDLE_R = 6

    dlg = tk.Toplevel(_root)
    dlg.title('Camera Source')
    dlg.configure(bg='#1e1e1e')
    dlg.resizable(True, True)
    dlg.grab_set()

    state = {
        'pil_img': None,
        'scale': 1.0,
        'crop': [0.0, 0.0, 0.0, 0.0],
        'drag': None,
    }

    #
    # Load / source buttons
    #
    load_frame = tk.Frame(dlg, bg='#252526')
    load_frame.pack(fill=tk.X, padx=8, pady=(8, 4))

    _btn_style = dict(bg='#3c3c3c', fg='white', activebackground='#505050',
                      activeforeground='white', relief=tk.FLAT, padx=8, pady=4)

    def _use_live_camera():
        on_live_camera_cb()
        dlg.destroy()

    tk.Button(load_frame, text='\U0001f3a5 Use Live Camera',
              command=_use_live_camera, **_btn_style).pack(side=tk.LEFT, padx=(0, 8))

    def _paste_from_clipboard():
        import tkinter.messagebox
        try:
            from PIL import ImageGrab
            img = ImageGrab.grabclipboard()
        except Exception as exc:
            tkinter.messagebox.showerror('Clipboard error', str(exc), parent=dlg)
            return
        if not isinstance(img, Image.Image):
            tkinter.messagebox.showinfo('Clipboard', 'No image found in clipboard.', parent=dlg)
            return
        _set_image(img)

    def _choose_file():
        import tkinter.messagebox
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            parent=dlg, title='Choose image',
            filetypes=[('Images', '*.png *.jpg *.jpeg *.bmp *.gif *.tiff *.webp'),
                       ('All files', '*.*')])
        if not path:
            return
        try:
            _set_image(Image.open(path))
        except Exception as exc:
            tkinter.messagebox.showerror('Error opening image', str(exc), parent=dlg)

    if Image is not None:
        tk.Button(load_frame, text='Paste from Clipboard',
                  command=_paste_from_clipboard, **_btn_style).pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(load_frame, text='Choose File\u2026',
                  command=_choose_file, **_btn_style).pack(side=tk.LEFT)

    #
    # Preview canvas (only when Pillow is available)
    #
    confirm_btn = None
    if Image is not None:
        canvas = tk.Canvas(dlg, width=PREVIEW_MAX_W, height=PREVIEW_MAX_H,
                           bg='#333333', cursor='crosshair',
                           highlightthickness=1, highlightbackground='#555555')
        canvas.pack(padx=8, pady=4)
        ph_ref = [None]  # keeps PhotoImage alive

        #
        # Coordinate helpers
        #
        def _img_to_canvas(x, y):
            s = state['scale']
            return x * s, y * s

        def _canvas_to_img(cx, cy):
            s = state['scale']
            img = state['pil_img']
            if img is None:
                return 0.0, 0.0
            return (max(0.0, min(float(img.width), cx / s)),
                    max(0.0, min(float(img.height), cy / s)))

        #
        # Crop overlay drawing
        #
        def _draw_crop():
            canvas.delete('crop')
            img = state['pil_img']
            c = state['crop']
            if img is None or c[2] <= c[0] or c[3] <= c[1]:
                return
            cx1, cy1 = _img_to_canvas(c[0], c[1])
            cx2, cy2 = _img_to_canvas(c[2], c[3])
            iw_c = img.width * state['scale']
            ih_c = img.height * state['scale']
            # Dim everything outside the crop rectangle
            for x0, y0, x1, y1 in [
                (0, 0, iw_c, cy1),
                (0, cy1, cx1, cy2),
                (cx2, cy1, iw_c, cy2),
                (0, cy2, iw_c, ih_c),
            ]:
                if x1 > x0 and y1 > y0:
                    canvas.create_rectangle(x0, y0, x1, y1,
                                            fill='black', stipple='gray50', outline='', tags='crop')
            canvas.create_rectangle(cx1, cy1, cx2, cy2,
                                    outline='#00aaff', width=2, tags='crop')
            for hx, hy in [(cx1, cy1), (cx2, cy1), (cx1, cy2), (cx2, cy2)]:
                canvas.create_oval(hx - HANDLE_R, hy - HANDLE_R,
                                   hx + HANDLE_R, hy + HANDLE_R,
                                   fill='#00aaff', outline='', tags='crop')
            w_crop, h_crop = int(c[2] - c[0]), int(c[3] - c[1])
            info_var.set(
                f'Crop: ({int(c[0])}, {int(c[1])})  {w_crop}x{h_crop}'
                f'  ->  {TARGET_W}x{TARGET_H} (grayscale)')

        def _set_image(img):
            state['pil_img'] = img.convert('RGB')
            iw, ih = img.width, img.height
            s = min(PREVIEW_MAX_W / iw, PREVIEW_MAX_H / ih)
            state['scale'] = s
            pw, ph = max(1, int(iw * s)), max(1, int(ih * s))
            canvas.config(width=pw, height=ph)
            ph_ref[0] = ImageTk.PhotoImage(state['pil_img'].resize((pw, ph), Image.LANCZOS))
            canvas.delete('all')
            canvas.create_image(0, 0, anchor=tk.NW, image=ph_ref[0], tags='img')
            # Default crop: centred rectangle matching TARGET aspect ratio
            aspect = TARGET_W / TARGET_H
            if iw / ih > aspect:
                cw = int(ih * aspect)
                ch = ih
                cx0, cy0 = (iw - cw) // 2, 0
            else:
                cw = iw
                ch = int(iw / aspect)
                cx0, cy0 = 0, (ih - ch) // 2
            state['crop'] = [float(cx0), float(cy0), float(cx0 + cw), float(cy0 + ch)]
            _draw_crop()
            confirm_btn.config(state=tk.NORMAL)

        #
        # Mouse drag for crop rect
        #
        _CURSORS = {
            None: 'crosshair', 'move': 'fleur',
            'nw': 'top_left_corner', 'ne': 'top_right_corner',
            'sw': 'bottom_left_corner', 'se': 'bottom_right_corner',
            'n': 'top_side', 's': 'bottom_side', 'w': 'left_side', 'e': 'right_side',
        }

        def _hit_test(cx, cy):
            c = state['crop']
            if state['pil_img'] is None:
                return None
            x1, y1 = _img_to_canvas(c[0], c[1])
            x2, y2 = _img_to_canvas(c[2], c[3])
            H = HANDLE_R + 2
            for name, hx, hy in [('nw', x1, y1), ('ne', x2, y1),
                                   ('sw', x1, y2), ('se', x2, y2)]:
                if abs(cx - hx) <= H and abs(cy - hy) <= H:
                    return name
            if abs(cx - x1) <= 4 and y1 <= cy <= y2:
                return 'w'
            if abs(cx - x2) <= 4 and y1 <= cy <= y2:
                return 'e'
            if abs(cy - y1) <= 4 and x1 <= cx <= x2:
                return 'n'
            if abs(cy - y2) <= 4 and x1 <= cx <= x2:
                return 's'
            if x1 < cx < x2 and y1 < cy < y2:
                return 'move'
            return None

        def _on_press(e):
            mode = _hit_test(e.x, e.y)
            if mode:
                state['drag'] = (mode, e.x, e.y, list(state['crop']))
            else:
                ix, iy = _canvas_to_img(e.x, e.y)
                state['crop'] = [ix, iy, ix, iy]
                state['drag'] = ('se', e.x, e.y, list(state['crop']))
            canvas.config(cursor=_CURSORS.get(state['drag'][0], 'crosshair'))

        def _on_drag(e):
            if not state['drag']:
                return
            mode, x0, y0, orig = state['drag']
            s = state['scale']
            dx, dy = (e.x - x0) / s, (e.y - y0) / s
            img = state['pil_img']
            iw, ih = float(img.width), float(img.height)
            c = list(orig)
            if mode == 'move':
                cw, ch = c[2] - c[0], c[3] - c[1]
                nx = max(0.0, min(iw - cw, c[0] + dx))
                ny = max(0.0, min(ih - ch, c[1] + dy))
                c = [nx, ny, nx + cw, ny + ch]
            else:
                if 'w' in mode:
                    c[0] = max(0.0, min(c[2] - 1, c[0] + dx))
                if 'e' in mode:
                    c[2] = max(c[0] + 1, min(iw, c[2] + dx))
                if 'n' in mode:
                    c[1] = max(0.0, min(c[3] - 1, c[1] + dy))
                if 's' in mode:
                    c[3] = max(c[1] + 1, min(ih, c[3] + dy))
            state['crop'] = c
            _draw_crop()

        def _on_release(e):
            state['drag'] = None
            c = state['crop']
            state['crop'] = [min(c[0], c[2]), min(c[1], c[3]),
                             max(c[0], c[2]), max(c[1], c[3])]
            _draw_crop()
            canvas.config(cursor='crosshair')

        def _on_motion(e):
            if state['drag']:
                return
            canvas.config(cursor=_CURSORS.get(_hit_test(e.x, e.y), 'crosshair'))

        canvas.bind('<ButtonPress-1>', _on_press)
        canvas.bind('<B1-Motion>', _on_drag)
        canvas.bind('<ButtonRelease-1>', _on_release)
        canvas.bind('<Motion>', _on_motion)

        #
        # Info bar
        #
        info_var = tk.StringVar(value='Load an image above to begin')
        info_frame = tk.Frame(dlg, bg='#252526')
        info_frame.pack(fill=tk.X, padx=8, pady=(0, 4))
        tk.Label(info_frame, textvariable=info_var, bg='#252526', fg='#a0a0a0',
                 font=('Monospace', 8), anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(info_frame, text='Reset Crop',
                  command=lambda: _set_image(state['pil_img']) if state['pil_img'] else None,
                  bg='#3c3c3c', fg='white', activebackground='#505050', activeforeground='white',
                  relief=tk.FLAT, padx=6, pady=2).pack(side=tk.RIGHT)

    #
    # Bottom buttons
    #
    btn_frame = tk.Frame(dlg, bg='#1e1e1e')
    btn_frame.pack(fill=tk.X, padx=8, pady=(4, 10))
    tk.Button(btn_frame, text='Cancel', command=dlg.destroy,
              bg='#3c3c3c', fg='white', activebackground='#505050', activeforeground='white',
              relief=tk.FLAT, padx=12, pady=5).pack(side=tk.LEFT)

    if Image is not None:
        def _confirm():
            img = state['pil_img']
            if img is None:
                return
            c = state['crop']
            cropped = img.crop((int(c[0]), int(c[1]), int(c[2]), int(c[3])))
            frame = cropped.convert('L').resize((TARGET_W, TARGET_H), Image.LANCZOS)
            on_static_confirmed_cb(frame.tobytes())
            dlg.destroy()

        confirm_btn = tk.Button(btn_frame, text='Feed to Camera', command=_confirm,
                                bg='#1c6b38', fg='white', activebackground='#238a4a',
                                activeforeground='white', relief=tk.FLAT,
                                padx=12, pady=5, state=tk.DISABLED)
        confirm_btn.pack(side=tk.RIGHT)
    dlg.focus_set()


def tk_basic_gui(jade, args):
    """Launch the Tkinter GUI"""
    global _root, _label

    _console.locals.update({'jade': jade, 'JadeAPI': JadeAPI, 'JadeError': JadeError,
                            'hex_to_bin': hex_to_bin, 'bin_to_hex': bin_to_hex,
                            'TEST_MNEMONIC': TEST_MNEMONIC})

    _root = tk.Tk()
    _root.title('libjade GUI')
    _root.resizable(True, True)

    mono = tkfont.Font(family='Monospace', size=9)

    # display area
    display_frame = tk.Frame(_root, bg='black', highlightthickness=2, highlightbackground='#444', highlightcolor='#00aaff')
    display_frame.pack(fill=tk.X)
    _label = tk.Label(display_frame, text='Waiting for framebuffer...', bg='black', fg='white', takefocus=True)
    _label.pack()

    # bind navigation keys to the display label
    for key in ('<Left>', '<Right>', '<Up>', '<Down>', '<Return>', '<space>'):
        _label.bind(key, lambda event: jade_send_input(jade, event))
    _label.bind('<Button-1>', lambda e: _label.focus_set())
    display_frame.bind('<Button-1>', lambda e: _label.focus_set())
    # highlight the display frame border to show which area is active
    _label.bind('<FocusIn>', lambda e: display_frame.config(highlightbackground='#00aaff'))
    _label.bind('<FocusOut>', lambda e: display_frame.config(highlightbackground='#444'))
    _label.focus_set()

    # console toggle bar
    _console_visible = False
    _console_welcomed = False

    toggle_bar = tk.Frame(_root, bg='#252526', cursor='hand2')
    toggle_bar.pack(fill=tk.X)
    toggle_lbl = tk.Label(toggle_bar, text='>>>', bg='#252526', fg='#569cd6',
                           font=mono, cursor='hand2', padx=6, pady=3)
    toggle_lbl.pack(side=tk.LEFT)

    _console.build_ui(_root, mono,
                      on_entry_focus=lambda: display_frame.config(highlightbackground='#444'))

    def _toggle_console():
        nonlocal _console_visible, _console_welcomed
        if not _console_visible:
            # Open: reveal console
            _console.body.pack(fill=tk.BOTH, expand=True)
            if not _console_welcomed:
                _console.write(
                    "Python console - 'jade', 'hex_to_bin()', 'bin_to_hex()', "
                    "'TEST_MNEMONIC' are in scope\n", 'output')
                _console_welcomed = True
            _console._entry.focus_set()
            toggle_lbl.config(text='▼▼▼')
            _console_visible = True
        else:
            # Close: hide console
            _console.body.pack_forget()
            toggle_lbl.config(text='>>>')
            _console_visible = False
            _label.focus_set()
        # let Tkinter shrink/grow the window to exactly fit visible widgets
        _root.update_idletasks()
        _root.geometry('')

    toggle_bar.bind('<Button-1>', lambda e: _toggle_console())
    toggle_lbl.bind('<Button-1>', lambda e: _toggle_console())

    # Camera button
    def _stop_camera():
        _camera.stop()
        camera_btn.config(
            text='\U0001f4f7',
            bg='#3c3c3c',
            command=lambda: _open_camera_dialog(_on_static_confirmed, _on_live_camera))

    def _on_static_confirmed(frame_bytes):
        _camera.set_static_frame(frame_bytes)
        camera_btn.config(text='\u23f9 \U0001f4f7', bg='#8b2020', command=_stop_camera)

    def _on_live_camera():
        _camera.use_live_camera()
        camera_btn.config(text='\u23f9 \U0001f4f7', bg='#8b2020', command=_stop_camera)

    camera_btn = tk.Button(
        toggle_bar, text='\U0001f4f7', font=mono,
        command=lambda: _open_camera_dialog(_on_static_confirmed, _on_live_camera),
        bg='#3c3c3c', fg='white', activebackground='#505050', activeforeground='white',
        relief=tk.FLAT, padx=6, pady=3)
    camera_btn.pack(side=tk.RIGHT, padx=(0, 4))

    _root.protocol("WM_DELETE_WINDOW", _window_close)
    _root.after(500, lambda: jade_update_display(jade))
    _root.mainloop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Jade libjade GUI')
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument('--device', metavar='DEVICE',
                     help='Connect to daemon for CBOR via this device '
                          '(e.g. tcp:/tmp/jade.sock or tcp:localhost:30121). '
                          'Passed directly to JadeAPI.create_serial().')
    parser.add_argument('--log-level', metavar='LEVEL',
                        choices=['none', 'error', 'warn', 'info', 'debug', 'verbose'],
                        default='none',
                        help='Log verbosity level (default: none)')
    parser.add_argument('--nvs-file', metavar='PATH',
                        default='nvs_flash.bin',
                        help='NVS flash storage filename (default: "nvs_flash.bin", use "none" to avoid storing')
    args = parser.parse_args()

    # set python logging level
    py_level = _PY_LOG_LEVELS[args.log_level]
    logging.getLogger().setLevel(py_level)
    logger.setLevel(py_level)

    if args.device:
        # daemon mode
        jade = JadeAPI.create_serial(args.device, timeout=120)
        jade.connect()
    else:
        # in-process mode
        jade = JadeAPI.create_libjade(timeout=120)
        jade.connect()
        libjade = jade.jade.impl.libjade
        libjade.libjade_set_log_level(_ESP_LOG_LEVELS[args.log_level])

    _camera = CameraManager(jade)

    # Monkey patch our connected libjade to mutex RPC requests:
    # This ensures that RPC calls don't interfere with GUI calls.
    rpc_monkey_patch(jade)
    if args.nvs_file != 'none':
        # Load NVS storage into the libjade instance
        try:
            with open(args.nvs_file, 'rb') as f:
                jade._jadeRpc('libjade_request', {'request': 'set_nvs', 'bytes': f.read()})
        except FileNotFoundError:
            # Ignore failure to load, so we can initialize a new file
            pass

    # Start GUI
    tk_basic_gui(jade, args)
    logger.debug('gui closed')

    _camera.shutdown()

    if args.nvs_file != 'none':
        # Save NVS storage to the given file
        data = jade._jadeRpc('libjade_request', {'request': 'get_nvs'})
        with open(args.nvs_file, 'wb') as f:
            f.write(data)

    try:
        jade.disconnect()
    except Exception:
        pass
    logger.debug('jade disconnected')
