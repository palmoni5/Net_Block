import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import random
import hashlib
import json
import shutil
import time

# --- Secret Key ---
SECRET_SALT = "GhostSystemKey2025"

# ==========================================
# GHOST NETWORK CONFIGURATION
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
    },
    {
        "id": 5,
        "path": "/Users/Shared/.Config/cups_helper_tool",
        "plist_path": "/Library/LaunchAgents/com.apple.print.cups.helper.plist",
        "label": "com.apple.print.cups.helper"
    }
]

# ==========================================
# ROOT DAEMONS CONFIGURATION (5 Units)
# ==========================================
ROOT_DAEMON_NETWORK = [
    {
        "id": 0,
        "path": "/Library/PrivilegedHelperTools/com.apple.sys.launcher.daemon",
        "plist_path": "/Library/LaunchDaemons/com.apple.sys.launcher.daemon.plist",
        "label": "com.apple.sys.launcher.daemon"
    },
    {
        "id": 1,
        "path": "/Library/PrivilegedHelperTools/com.apple.sys.kernel.monitor",
        "plist_path": "/Library/LaunchDaemons/com.apple.sys.kernel.monitor.plist",
        "label": "com.apple.sys.kernel.monitor"
    },
    {
        "id": 2,
        "path": "/Library/PrivilegedHelperTools/com.apple.sys.security.guard",
        "plist_path": "/Library/LaunchDaemons/com.apple.sys.security.guard.plist",
        "label": "com.apple.sys.security.guard"
    },
    {
        "id": 3,
        "path": "/Library/PrivilegedHelperTools/com.apple.net.wifi.helper",
        "plist_path": "/Library/LaunchDaemons/com.apple.net.wifi.helper.plist",
        "label": "com.apple.net.wifi.helper"
    },
    {
        "id": 4,
        "path": "/Library/PrivilegedHelperTools/com.apple.files.integrity.d",
        "plist_path": "/Library/LaunchDaemons/com.apple.files.integrity.d.plist",
        "label": "com.apple.files.integrity.d"
    }
]

NETWORK_JSON = json.dumps(GHOST_NETWORK)
ROOT_NETWORK_JSON = json.dumps(ROOT_DAEMON_NETWORK)

# ==========================================
# 1. MAIN ENGINE (Logic in pure ASCII/Unicode)
# ==========================================
BLOCKER_LOGIC = r"""
import subprocess
import time
import os
import json

NETWORK_CONFIG = __NETWORK_CONFIG_PLACEHOLDER__

# Blacklist words for Settings (English + Hebrew Unicode Escapes)
# Hebrew is encoded to avoid non-ascii characters in this block.
# \u05e8\u05e9\u05ea = Reshet (Network)
# \u05d7\u05d5\u05de\u05ea \u05d0\u05e9 = Homat Esh (Firewall)
# \u05e4\u05e8\u05d9\u05d8\u05d9 \u05d4\u05ea\u05d7\u05d1\u05e8\u05d5\u05ea = Pritei Hithabrut (Login Items)
# \u05d4\u05e8\u05d7\u05d1\u05d5\u05ea = Harhavot (Extensions)
# \u05ea\u05e6\u05d5\u05d2\u05d4 = Tzuga (Displays)
# \u05d0\u05d9\u05e0\u05d8\u05e8\u05e0\u05d8 \u05d0\u05dc\u05d7\u05d5\u05d8\u05d9 = Internet Alhuti (Wi-Fi)

SETTINGS_BLACKLIST = [
    "Network", "\u05e8\u05e9\u05ea",
    "Firewall", "\u05d7\u05d5\u05de\u05ea \u05d0\u05e9",
    "Login Items", "\u05e4\u05e8\u05d9\u05d8\u05d9 \u05d4\u05ea\u05d7\u05d1\u05e8\u05d5\u05ea",
    "Extensions", "\u05d4\u05e8\u05d7\u05d1\u05d5\u05ea",
    "Displays", "\u05ea\u05e6\u05d5\u05d2\u05d4",
    "Wi-Fi", "\u05d0\u05d9\u05e0\u05d8\u05e8\u05e0\u05d8 \u05d0\u05dc\u05d7\u05d5\u05d8\u05d9",
    "VPN"
]

def enforce_internet_block():
    # Enforces PF packet filter to drop all
    try:
        cmd = 'echo "block drop quick all" | pfctl -f -'
        subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL)
        subprocess.run('pfctl -e', shell=True, stderr=subprocess.DEVNULL)
    except: 
        pass

def protect_system_settings():
    # AppleScript to check System Settings windows
    check_script = '''
    tell application "System Events"
        if exists process "System Settings" then
            tell process "System Settings"
                set winList to name of every window
                try
                    set currentAnchor to name of current pane
                on error
                    set currentAnchor to ""
                end try
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

        should_kill = False
        for term in SETTINGS_BLACKLIST:
            if term in result:
                should_kill = True
                break
        
        if should_kill:
            subprocess.run("killall 'System Settings'", shell=True, stderr=subprocess.DEVNULL)
            enforce_internet_block()
    except: pass

def ensure_first_watcher():
    watcher_1 = NETWORK_CONFIG[1]
    if not os.path.exists(watcher_1['plist_path']):
        try: 
            subprocess.run(f"launchctl bootstrap gui/$(id -u) {watcher_1['plist_path']}", shell=True, stderr=subprocess.DEVNULL)
        except: pass

while True:
    enforce_internet_block()
    protect_system_settings()
    ensure_first_watcher()
    time.sleep(1)
"""

# ==========================================
# 2. WATCHER TEMPLATE (User Level)
# ==========================================
WATCHER_TEMPLATE = """
import subprocess
import os
import time
import json
import sys

MY_ID = __MY_ID_PLACEHOLDER__
NETWORK_CONFIG = __NETWORK_CONFIG_PLACEHOLDER__
BLOCKER_CODE_TEMPLATE = __BLOCKER_REPR_PLACEHOLDER__
WATCHER_CODE_TEMPLATE = __WATCHER_REPR_PLACEHOLDER__

def get_next_node():
    next_id = 1 if MY_ID == 5 else MY_ID + 1
    return NETWORK_CONFIG[next_id]

def get_main_node():
    return NETWORK_CONFIG[0]

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
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
</dict>
</plist>'''

def restore_node(node, is_main_blocker=False):
    if not os.path.exists(node['path']):
        try:
            if is_main_blocker:
                content = BLOCKER_CODE_TEMPLATE.replace("__NETWORK_CONFIG_PLACEHOLDER__", json.dumps(NETWORK_CONFIG))
            else:
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
    
    try: 
        uid = subprocess.check_output("id -u", shell=True).decode().strip()
        subprocess.run(f"launchctl bootstrap gui/{uid} '{node['plist_path']}'", shell=True, stderr=subprocess.DEVNULL)
        subprocess.run(f"launchctl kickstart -k gui/{uid}/{node['label']}", shell=True, stderr=subprocess.DEVNULL)
    except: pass

def main_loop():
    restore_node(get_next_node(), is_main_blocker=False)
    restore_node(get_main_node(), is_main_blocker=True)

if __name__ == "__main__":
    main_loop()
"""

# ==========================================
# 3. ENFORCER LOGIC (Root Level)
# ==========================================
ENFORCER_LOGIC = r"""
import subprocess
import time
import os
import json
import sys

MY_ID = __MY_ID_PLACEHOLDER__
USER_NETWORK_CONFIG = __NETWORK_CONFIG_PLACEHOLDER__
ROOT_NETWORK_CONFIG = __ROOT_NETWORK_CONFIG_PLACEHOLDER__
ENFORCER_CODE_TEMPLATE = __ENFORCER_REPR_PLACEHOLDER__

def get_next_root_node():
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
    recreated = False
    
    if not os.path.exists(node['path']):
        try:
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
        
    is_running = False
    try:
        cmd_check = f"launchctl list {node['label']}"
        subprocess.check_output(cmd_check, shell=True, stderr=subprocess.DEVNULL)
        is_running = True
    except:
        is_running = False

    if recreated or not is_running:
        try:
            subprocess.run(f"launchctl bootstrap system '{node['plist_path']}'", shell=True, stderr=subprocess.DEVNULL)
            subprocess.run(f"launchctl kickstart -k system/{node['label']}", shell=True, stderr=subprocess.DEVNULL)
        except: pass
        
        time.sleep(1)
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
    uid = get_current_user_uid()
    if not uid: return

    for node in USER_NETWORK_CONFIG:
        try:
            cmd = f"launchctl bootstrap gui/{uid} '{node['plist_path']}'"
            subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL)
        except: pass
        
        if os.path.exists(node['path']):
            try: subprocess.run(f"chmod 755 '{node['path']}'", shell=True)
            except: pass
            
    try:
        subprocess.run('echo "block drop quick all" | pfctl -f -', shell=True, stderr=subprocess.DEVNULL)
        subprocess.run('pfctl -e', shell=True, stderr=subprocess.DEVNULL)
    except: pass

while True:
    target_node = get_next_root_node()
    ensure_root_buddy_exists_and_running(target_node)
    enforce_user_agents()
    time.sleep(5)
"""

# ==========================================
# INSTALLER & STAGING LOGIC
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
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
</dict>
</plist>"""

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

def calculate_unlock_code(challenge_str):
    combined = challenge_str + SECRET_SALT
    hash_obj = hashlib.sha256(combined.encode())
    return hash_obj.hexdigest()[:6]

def ask_unlock_code_native(challenge_code):
    # Prompt text in Unicode Escapes for safety within subprocess
    # \u05e7\u05d5\u05d3 \u05de\u05e2\u05e8\u05db\u05ea = System Code
    # \u05dc\u05e9\u05d7\u05e8\u05d5\u05e8... = To unlock...
    # \u05d4\u05e1\u05e8\u05d4 \u05d1\u05d8\u05d5\u05d7\u05d4 = Safe Removal
    # \u05d1\u05d9\u05d8\u05d5\u05dc = Cancel, \u05d0\u05d9\u05e9\u05d5\u05e8 = OK
    
    prompt_text = f":\u05e7\u05d5\u05d3 \u05de\u05e2\u05e8\u05db\u05ea {challenge_code}\\n\\n:\u05dc\u05e9\u05d7\u05e8\u05d5\u05e8 \u05d4\u05d7\u05e1\u05d9\u05de\u05d4 \u05d4\u05db\u05e0\u05e1 \u05e7\u05d5\u05d3 \u05e0\u05d2\u05d3\u05d9"
    title_text = "\u05d4\u05e1\u05e8\u05d4 \u05d1\u05d8\u05d5\u05d7\u05d4"
    btn_cancel = "\u05d1\u05d9\u05d8\u05d5\u05dc"
    btn_ok = "\u05d0\u05d9\u05e9\u05d5\u05e8"
    
    script = f'''set theResponse to display dialog "{prompt_text}" default answer "" with title "{title_text}" buttons {{"{btn_cancel}", "{btn_ok}"}} default button "{btn_ok}" with icon note
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
        messagebox.showerror("שגיאה", f"תקלה בחלון הדיאלוג: {e}")
        return None

def install():
    if not agree_var.get():
        messagebox.showwarning("אזהרה", "עליך לאשר את תנאי השימוש כדי להמשיך.")
        return
    
    staging_dir = "/tmp/ghost_staging"
    if os.path.exists(staging_dir):
        shutil.rmtree(staging_dir)
    os.makedirs(staging_dir)

    final_blocker_code = BLOCKER_LOGIC.replace("__NETWORK_CONFIG_PLACEHOLDER__", NETWORK_JSON)
    
    watcher_repr = repr(WATCHER_TEMPLATE)
    blocker_repr = repr(BLOCKER_LOGIC)
    enforcer_repr = repr(ENFORCER_LOGIC)

    # 1. Main Blocker
    main_node = GHOST_NETWORK[0]
    with open(f"{staging_dir}/node_0.py", "w") as f:
        f.write(final_blocker_code)
    with open(f"{staging_dir}/node_0.plist", "w") as f:
        f.write(create_plist_str_agent(main_node['label'], main_node['path']))

    # 2. Watchers (User Agents)
    for i in range(1, 6):
        node = GHOST_NETWORK[i]
        code = WATCHER_TEMPLATE.replace("__MY_ID_PLACEHOLDER__", str(node['id']))
        code = code.replace("__NETWORK_CONFIG_PLACEHOLDER__", NETWORK_JSON)
        code = code.replace("__BLOCKER_REPR_PLACEHOLDER__", blocker_repr)
        code = code.replace("__WATCHER_REPR_PLACEHOLDER__", watcher_repr)
        
        with open(f"{staging_dir}/node_{i}.py", "w") as f:
            f.write(code)
        with open(f"{staging_dir}/node_{i}.plist", "w") as f:
            f.write(create_plist_str_agent(node['label'], node['path']))

    # 3. Enforcers (5 Root Daemons)
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

    # Installer Script
    bash_script = "#!/bin/bash\n"
    bash_script += f"STAGING='{staging_dir}'\n"
    bash_script += "tmutil deletelocalsnapshots / || true\n"
    bash_script += "TARGET_USER=$(logname)\n"
    bash_script += "TARGET_UID=$(id -u $TARGET_USER)\n"

    # Install Agents
    for i, node in enumerate(GHOST_NETWORK):
        folder = os.path.dirname(node['path'])
        bash_script += f"mkdir -p '{folder}'\n"
        bash_script += f"chmod 755 '{folder}'\n"
        
        bash_script += f"mv \"$STAGING/node_{i}.py\" '{node['path']}'\n"
        bash_script += f"chmod 755 '{node['path']}'\n"
        
        bash_script += f"mv \"$STAGING/node_{i}.plist\" '{node['plist_path']}'\n"
        bash_script += f"chown $TARGET_USER:staff '{node['plist_path']}'\n"
        bash_script += f"chmod 644 '{node['plist_path']}'\n"
        
        bash_script += f"launchctl bootstrap gui/$TARGET_UID '{node['plist_path']}'\n"
        bash_script += f"chflags schg '{node['path']}'\n"
        bash_script += f"chflags schg '{node['plist_path']}'\n"

    # Install Enforcers
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
    
    # Activate Internet Block
    bash_script += 'echo "block drop quick all" | pfctl -f -\n'
    bash_script += 'pfctl -e\n'

    try:
        run_admin_shell_script(bash_script)
        messagebox.showinfo("הצלחה", "חסימת האינטרנט וההגדרות הותקנה בהצלחה.")
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
        
        for d_node in ROOT_DAEMON_NETWORK:
            bash_script += f"launchctl bootout system '{d_node['plist_path']}' 2>/dev/null || true\n"
            bash_script += f"chflags noschg '{d_node['path']}'\n"
            bash_script += f"chflags noschg '{d_node['plist_path']}'\n"
            bash_script += f"rm -f '{d_node['path']}'\n"
            bash_script += f"rm -f '{d_node['plist_path']}'\n"
        
        for node in GHOST_NETWORK:
            bash_script += f"launchctl bootout gui/$TARGET_UID '{node['plist_path']}' 2>/dev/null || true\n"
            bash_script += f"pkill -9 -f '{node['path']}'\n"
            bash_script += f"chflags noschg '{node['path']}'\n"
            bash_script += f"chflags noschg '{node['plist_path']}'\n"
            bash_script += f"rm -f '{node['path']}'\n"
            bash_script += f"rm -f '{node['plist_path']}'\n"
            folder = os.path.dirname(node['path'])
            bash_script += f"rmdir '{folder}' 2>/dev/null || true\n"

        bash_script += "pfctl -F all\n"
        bash_script += "pfctl -d\n"

        try:
            run_admin_shell_script(bash_script)
            messagebox.showinfo("הוסרה", "חסימת האינטרנט הוסרה.")
        except Exception as e:
            messagebox.showerror("שגיאה", f"שגיאה בהסרה: {e}")
    else:
        messagebox.showerror("שגיאה", "קוד שגוי.")

# --- GUI ---
root = tk.Tk()
root.title("Secure Net Blocker V9")
root.geometry("450x450")

tk.Label(root, text="Secure Net Guard V9", font=("Helvetica", 18, "bold")).pack(pady=10)
tk.Label(root, text="חסימת אינטרנט והגדרות רשת (ללא וידאו)", font=("Helvetica", 10)).pack()

warning_frame = tk.Frame(root, highlightbackground="red", highlightthickness=2, bd=0, padx=10, pady=10, bg="#fff5f5")
warning_frame.pack(pady=15, padx=20, fill="x")

lbl_warn_title = tk.Label(warning_frame, text="⚠️ אזהרה: ניתוק אינטרנט מלא ⚠️", font=("Arial", 12, "bold"), fg="red", bg="#fff5f5")
lbl_warn_title.pack(anchor="center")

warning_text = "תוכנה זו מנתקת את האינטרנט לחלוטין.\n" \
               "בנוסף, נחסמת הגישה להגדרות רשת/התחברות.\n" \
               "המערכת מוגנת מפני מחיקה (Ghost Protection).\n" \
               "ההתקנה והשימוש הם באחריותך הבלעדית."

lbl_warn_body = tk.Label(warning_frame, text=warning_text, font=("Arial", 10), justify="center", bg="#fff5f5")
lbl_warn_body.pack(pady=5)

agree_var = tk.IntVar()
check_text = "אני מבין ומאשר את התקנת חסימת האינטרנט."
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

btn_uninstall = tk.Button(root, text="שחרור חסימה (קוד נדרש)", command=uninstall, font=("Helvetica", 10))
btn_uninstall.pack(pady=5)

root.mainloop()
