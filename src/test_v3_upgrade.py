import os
import shutil
import subprocess
import sys

base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, base)
sys.path.insert(0, os.path.join(base, "src"))

from api.scan import ai_classify_payload, scan_source_code
from code_scanner import AISourceCodeScanner


def main():
    r1 = ai_classify_payload("/search?q=select+best+laptop+and+update+windows")
    r2 = ai_classify_payload("/products?id=10' UNION SELECT username,password FROM users--")
    r3 = scan_source_code(
        'API_KEY = "sk-live-1234567890abcdef123456"\n'
        'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
        'os.system("ping -c 2 " + host)'
    )
    print(f"[+] Real Cloud ML (Benign): {r1['prediction']} ({r1['confidence']}%) | Engine: {r1['engine']}")
    print(f"[+] Real Cloud ML (SQLi)  : {r2['prediction']} ({r2['confidence']}%) | Engine: {r2['engine']}")
    print(f"[+] SAST Code Scanner     : {r3['status']} | Findings: {r3['vulnerabilities_count']} | Score: {r3['security_score']}/100")

    assert r1["prediction"] == "Normal", f"Expected Normal, got {r1['prediction']}"
    assert r2["prediction"] == "SQLi", f"Expected SQLi, got {r2['prediction']}"
    assert r3["vulnerabilities_count"] == 3, f"Expected 3 SAST findings, got {r3['vulnerabilities_count']}"

    with open(os.path.join(base, "index.html"), "r", encoding="utf-8") as f:
        html = f.read()

    scripts = html.split("<script>")
    assert len(scripts) == 2, f"Expected 1 inline <script> block, found {len(scripts) - 1}"
    js_code = scripts[1].split("</script>")[0]
    js_tmp = os.path.join(base, "tmp_check.js")
    with open(js_tmp, "w", encoding="utf-8") as f:
        f.write(js_code)

    res = subprocess.run(["node", "--check", js_tmp], capture_output=True, text=True)
    os.remove(js_tmp)
    assert res.returncode == 0, f"JS syntax error: {res.stderr}"
    print("[+] index.html JS Syntax Check: PASSED (0 errors)")

    # Sync to Desktop folder if present
    desktop_dir = r"C:\Users\lenovo\Desktop\AI_Web_Vulnerability_Graduation_Project"
    if os.path.exists(desktop_dir):
        vercel_sub = os.path.join(desktop_dir, "vercel-web-app")
        os.makedirs(os.path.join(vercel_sub, "api"), exist_ok=True)
        shutil.copy2(os.path.join(base, "index.html"), os.path.join(vercel_sub, "index.html"))
        shutil.copy2(os.path.join(base, "api", "scan.py"), os.path.join(vercel_sub, "api", "scan.py"))
        shutil.copy2(os.path.join(base, "api", "model_weights.json"), os.path.join(vercel_sub, "api", "model_weights.json"))
        print("[+] Synced updated v3.0 files to Desktop folder.")


if __name__ == "__main__":
    main()
