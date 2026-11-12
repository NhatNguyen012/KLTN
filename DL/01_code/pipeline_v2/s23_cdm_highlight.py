#!/usr/bin/env python3
"""S23 - Tô sáng các trường CDM dùng cho đề tài trên sơ đồ thực thể CDM (ảnh người dùng gửi). Cách dùng: python s23_cdm_highlight.py <ảnh sơ đồ> <ảnh ra>"""
import sys

from PIL import Image, ImageDraw, ImageFont

sys.stdout.reconfigure(encoding="utf-8")
src, dst = sys.argv[1], sys.argv[2]
im = Image.open(src).convert("RGBA")
W, H = im.size
LEG = 330
canvas = Image.new("RGBA", (W, H + LEG), (255, 255, 255, 255))
canvas.paste(im, (0, 0))
ov = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
d = ImageDraw.Draw(ov)
G, Y, R = ((40, 180, 80), (255, 205, 40), (235, 90, 90))
# (x1, x2, y trung tâm dòng, màu)
EV = (440, 696)
SU = (10, 303)
NF = (1170, 1424)
PR = (17, 256)
ROWS = [
    (*EV, 576, G), (*EV, 629, G), (*EV, 709, G), (*EV, 736, G), (*EV, 842, G), (*EV, 1002, G), (*EV, 869, Y), (*EV, 949, Y),
    (*SU, 697, G), (*SU, 778, Y), (*SU, 831, Y), (*SU, 964, Y), (*SU, 1071, Y),
    (*NF, 308, G), (*NF, 414, G), (*NF, 441, G), (*NF, 361, Y), (*NF, 388, Y), (*NF, 468, R),
    (*PR, 332, R),
]
for x1, x2, y, c in ROWS:
    d.rounded_rectangle([x1, y - 13, x2, y + 13], radius=6, fill=c + (85,), outline=c + (255,), width=2)
canvas = Image.alpha_composite(canvas, ov)
dd = ImageDraw.Draw(canvas)
fb = ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf", 21)
f = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 19)
y = H + 14
dd.line([0, H + 4, W, H + 4], fill=(150, 150, 150), width=2)


def block(color, title, lines, y):
    dd.rounded_rectangle([14, y + 2, 44, y + 24], radius=5, fill=color + (110,), outline=color + (255,), width=2)
    dd.text((54, y), title, font=fb, fill=(20, 20, 20))
    y += 28
    for ln in lines:
        dd.text((54, y), ln, font=f, fill=(40, 40, 40))
        y += 25
    return y + 8


y = block(G, "Xanh lá – dùng trực tiếp (5 đầu vào bản B và nối nhãn)", [
    "Event.uuid: khóa tra nhãn cạnh  |  type: loại sự kiện (CONNECT, SENDTO, RECVFROM...)  |  timestampNanos: giờ → cửa sổ và delta_t",
    "Event.subject → Subject.uuid (tiến trình; cũng là khóa tra nhãn tiến trình)  |  Event.predicateObject → NetFlowObject.uuid (ổ cắm)",
    "Event.properties: ở sự kiện EVENT_EXECUTE chứa cmdLine = tên chương trình THẬT → app_family, image_dir_class",
    "NetFlowObject.remotePort → resp_port_class  |  remoteAddress: loại ổ cắm không có đầu xa (NA, LOCAL, NETLINK, 127.0.0.1)"], y)
y = block(Y, "Vàng – lấy ra làm cột audit, dự phòng hoặc cho đầu vào mở rộng sau này", [
    "Subject.cmdLine, Subject.properties (path, ppid): tên/lệnh LÚC FORK (ví dụ ghi fluxbox dù sau đó exec thành firefox) → chỉ dùng dự phòng",
    "Subject.parentSubject (tiến trình cha), Subject.localPrincipal (người dùng)  |  NetFlowObject.localAddress, localPort  |  Event.name, size"], y)
y = block(R, "Đỏ nhạt – có trong lược đồ nhưng THEIA luôn để trống", [
    "NetFlowObject.ipProtocol = null → proto thiếu (id 1)  |  Principal.username = null"], y)
canvas.convert("RGB").save(dst)
print("ok", canvas.size)
