"""生成 CSDN 宣传稿用的真实界面截图（不注入任何演示数据）。"""
import importlib.util
import os
import sys
import time

from PIL import ImageGrab

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "screenshots")
os.makedirs(OUT, exist_ok=True)

sys.argv = ["asm_gui.pyw"]
spec = importlib.util.spec_from_file_location("asm_gui",
                                              os.path.join(ROOT, "asm_gui.pyw"))
gui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gui)


def grab(widget, path, topmost=False):
    if topmost:
        try:
            widget.attributes("-topmost", True)
        except Exception:
            pass
    widget.update_idletasks()
    widget.update()
    time.sleep(0.8)
    x = widget.winfo_rootx()
    y = widget.winfo_rooty()
    w = widget.winfo_width()
    h = widget.winfo_height()
    img = ImageGrab.grab(bbox=(x, y, x + w, y + h))
    img.save(path)
    print("saved", path, img.size)


def main():
    app = gui.App()
    app.geometry("1180x1000+40+20")
    try:
        app.tabview.configure(height=360)
    except Exception:
        pass
    app.tabview.set("资产列表")
    app.deiconify()
    app.update()
    grab(app, os.path.join(OUT, "01-main.png"), topmost=True)

    # 高级参数窗口（真实控件，未改任何值；加宽避免右侧控件被裁）
    app._open_adv()
    app.adv_win.geometry("1000x700")
    app.update()
    time.sleep(0.4)
    grab(app.adv_win, os.path.join(OUT, "02-advanced.png"), topmost=True)

    # 报告格式选择窗口（不点“生成”，只展示 7 种格式开关）
    app._last_engine = object()
    app._open_report_dialog()
    app.update()
    time.sleep(0.4)
    dialogs = [w for w in app.winfo_children()
               if isinstance(w, gui.ctk.CTkToplevel) and w is not app.adv_win]
    if dialogs:
        dialogs[-1].geometry("600x470")
        dialogs[-1].update()
        time.sleep(0.3)
        grab(dialogs[-1], os.path.join(OUT, "03-report.png"), topmost=True)
    app.destroy()


if __name__ == "__main__":
    main()
