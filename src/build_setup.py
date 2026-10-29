"""Đóng gói setup_lab.sh: nhúng dữ liệu Night Shift (tar.gz, base64) vào template."""
import base64, hashlib, io, os, sys, tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = r"D:\dientap\lab_night_shift"
OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else r"D:\dientap\lab_setup"
FILES = ["night_shift.csv", "nightshift_sample.json", "gen_night_shift.py", "ns_helper.py", "ns_to_wazuh.py"]

buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
    for name in FILES:
        raw = open(os.path.join(DATA, name), "rb").read().replace(b"\r\n", b"\n")
        ti = tarfile.TarInfo(name)
        ti.size, ti.mode, ti.mtime = len(raw), 0o644, 1791331200  # 2026-10-07
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = "root"
        tar.addfile(ti, io.BytesIO(raw))
b64 = base64.encodebytes(buf.getvalue()).decode().rstrip("\n")

tpl = open(os.path.join(HERE, "setup_lab.template.sh"), encoding="utf-8").read().replace("\r\n", "\n")
assert tpl.count("@@PAYLOAD@@") == 1
script = tpl.replace("@@PAYLOAD@@", b64)

os.makedirs(OUT_DIR, exist_ok=True)
out = os.path.join(OUT_DIR, "setup_lab.sh")
with open(out, "w", encoding="utf-8", newline="\n") as f:
    f.write(script)
data = script.encode("utf-8")
print("wrote", out, len(data), "bytes")
print("sha256", hashlib.sha256(data).hexdigest())
