import asyncio
import logging
import subprocess
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
from bson import ObjectId
import re
from functools import wraps
import html
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

# ---- SAFE ENVIRONMENT VARIABLE PARSING ----
def parse_admin_ids(env_value: str, default: str = "1793697840") -> List[int]:
    """Safely parse ADMIN_IDS from environment variable"""
    if not env_value or env_value.strip() == "":
        env_value = default
    ids = []
    for part in env_value.split(","):
        part = part.strip()
        if part and part.isdigit():
            ids.append(int(part))
    if not ids:
        ids = [1793697840]  # fallback
    return ids

BOT_TOKEN = os.getenv("BOT_TOKEN")
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "attack_bot")
API_URL = os.getenv("API_URL")
API_KEY = os.getenv("API_KEY")
ADMIN_IDS = parse_admin_ids(os.getenv("ADMIN_IDS", ""), "1793697840")

# ---- CHECK REQUIRED VARIABLES ----
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
    error_msg = f"❌ Missing required environment variables: {', '.join(missing)}"
    logger.error(error_msg)
    print(error_msg)
    exit(1)

# Blocked ports (must match backend)
BLOCKED_PORTS = {8700, 20000, 443, 17500, 9031, 20002, 20001}

# Allowed port range
MIN_PORT = 1
MAX_PORT = 65535

# Helper function to make datetime timezone-aware
def make_aware(dt):
    """Convert naive datetime to timezone-aware UTC datetime"""
    if dt is None:
        return None
    if hasattr(dt, 'tzinfo') and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def get_current_time():
    """Get current UTC time with timezone"""
    return datetime.now(timezone.utc)

def escape_markdown(text: str) -> str:
    """Escape special characters for MarkdownV2"""
    if not text:
        return ""
    special_chars = r'_*[]()~`>#+-=|{}.!'
    return ''.join(f'\\{char}' if char in special_chars else char for char in str(text))

# MongoDB Connection
class Database:
    def __init__(self):
        self.client = MongoClient(MONGODB_URI)
        self.db = self.client[DATABASE_NAME]
        self.users = self.db.users
        self.attacks = self.db.attacks
        
        # Clean up any documents with null user_id
        try:
            result = self.users.delete_many({"user_id": None})
            if result.deleted_count > 0:
                logger.info(f"Deleted {result.deleted_count} documents with null user_id")
            result = self.users.delete_many({"user_id": {"$exists": False}})
            if result.deleted_count > 0:
                logger.info(f"Deleted {result.deleted_count} documents without user_id")
        except Exception as e:
            logger.error(f"Error cleaning users collection: {e}")
        
        # Drop existing indexes to avoid conflicts
        try:
            self.users.drop_indexes()
            logger.info("Dropped all existing indexes from users collection")
        except Exception as e:
            logger.info(f"No existing indexes to drop: {e}")
        
        try:
            self.attacks.drop_indexes()
            logger.info("Dropped all existing indexes from attacks collection")
        except Exception as e:
            logger.info(f"No existing indexes to drop: {e}")
        
        # Create new indexes
        try:
            self.attacks.create_index([("timestamp", DESCENDING)])
            self.attacks.create_index([("user_id", ASCENDING)])
            self.attacks.create_index([("status", ASCENDING)])
            logger.info("Created indexes for attacks collection")
        except Exception as e:
            logger.error(f"Error creating attacks indexes: {e}")
        
        try:
            self.users.create_index([("user_id", ASCENDING)], unique=True, sparse=True)
            logger.info("Created unique index on user_id for users collection")
        except Exception as e:
            logger.error(f"Error creating users index: {e}")
        
    def get_user(self, user_id: int) -> Optional[Dict]:
        user = self.users.find_one({"user_id": user_id})
        if user:
            if user.get("created_at"):
                user["created_at"] = make_aware(user["created_at"])
            if user.get("approved_at"):
                user["approved_at"] = make_aware(user["approved_at"])
            if user.get("expires_at"):
                user["expires_at"] = make_aware(user["expires_at"])
        return user
    
    def create_user(self, user_id: int, username: str = None) -> Dict:
        existing_user = self.get_user(user_id)
        if existing_user:
            return existing_user
            
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
            logger.info(f"Created new user: {user_id}")
        except pymongo.errors.DuplicateKeyError:
            user_data = self.get_user(user_id)
            logger.info(f"User {user_id} already exists")
        except Exception as e:
            logger.error(f"Error creating user: {e}")
        return user_data
    
    def approve_user(self, user_id: int, days: int) -> bool:
        expires_at = get_current_time() + timedelta(days=days)
        result = self.users.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "approved": True,
                    "approved_at": get_current_time(),
                    "expires_at": expires_at
                }
            }
        )
        return result.modified_count > 0
    
    def disapprove_user(self, user_id: int) -> bool:
        result = self.users.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "approved": False,
                    "expires_at": None
                }
            }
        )
        return result.modified_count > 0
    
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
            self.users.update_one(
                {"user_id": user_id},
                {"$inc": {"total_attacks": 1}}
            )
            logger.info(f"Logged attack for user {user_id}: {status}")
        except Exception as e:
            logger.error(f"Failed to log attack: {e}")
    
    def get_all_users(self) -> List[Dict]:
        users = list(self.users.find({"user_id": {"$ne": None, "$exists": True}}))
        for user in users:
            if user.get("created_at"):
                user["created_at"] = make_aware(user["created_at"])
            if user.get("approved_at"):
                user["approved_at"] = make_aware(user["approved_at"])
            if user.get("expires_at"):
                user["expires_at"] = make_aware(user["expires_at"])
            if "total_attacks" not in user:
                user["total_attacks"] = 0
        return users
    
    def get_approved_users(self) -> List[Dict]:
        users = list(self.users.find({"approved": True, "is_banned": False, "user_id": {"$ne": None}}))
        for user in users:
            if user.get("created_at"):
                user["created_at"] = make_aware(user["created_at"])
            if user.get("approved_at"):
                user["approved_at"] = make_aware(user["approved_at"])
            if user.get("expires_at"):
                user["expires_at"] = make_aware(user["expires_at"])
        return users
    
    def get_user_attack_stats(self, user_id: int) -> Dict:
        total_attacks = self.attacks.count_documents({"user_id": user_id})
        successful_attacks = self.attacks.count_documents({"user_id": user_id, "status": "success"})
        failed_attacks = self.attacks.count_documents({"user_id": user_id, "status": "failed"})
        
        recent_attacks = list(self.attacks.find(
            {"user_id": user_id}
        ).sort("timestamp", -1).limit(10))
        
        for attack in recent_attacks:
            if attack.get("timestamp"):
                attack["timestamp"] = make_aware(attack["timestamp"])
        
        return {
            "total": total_attacks,
            "successful": successful_attacks,
            "failed": failed_attacks,
            "recent": recent_attacks
        }

# Initialize database
print("🔄 Initializing database connection...")
db = Database()
print("✅ Database initialized successfully!")

# Port validation functions
def is_port_blocked(port: int) -> bool:
    return port in BLOCKED_PORTS

def get_blocked_ports_list() -> str:
    return ", ".join(str(port) for port in sorted(BLOCKED_PORTS))

# Authentication decorator for admin commands
def admin_required(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not in ADMIN_IDS:
            await update.message.reply_text("❌ You are not authorized to use this command.")
            return
        return await func(update, context, *args, **kwargs)
    return wrapper

# Check if user is approved
async def is_user_approved(user_id: int) -> bool:
    user = db.get_user(user_id)
    if not user:
        return False
    if not user.get("approved", False):
        return False
    expires_at = user.get("expires_at")
    if expires_at:
        expires_at = make_aware(expires_at)
        if expires_at < get_current_time():
            return False
    return True

# API Functions
def check_api_health() -> Dict:
    try:
        response = requests.get(
            f"{API_URL}/api/v1/health",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"status": "error", "error": f"HTTP {response.status_code}"}
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {"status": "error", "error": str(e)}

def check_running_attacks() -> Dict:
    try:
        response = requests.get(
            f"{API_URL}/api/v1/active",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"success": False, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        logger.error(f"Running attacks error: {e}")
        return {"success": False, "error": str(e)}

def get_user_stats() -> Dict:
    try:
        response = requests.get(
            f"{API_URL}/api/v1/stats",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"success": False, "error": f"HTTP {response.status_code}"}
    except Exception as e:
        logger.error(f"Get stats error: {e}")
        return {"success": False, "error": str(e)}

def launch_attack(ip: str, port: int, duration: int) -> Dict:
    try:
        response = requests.post(
            f"{API_URL}/api/v1/attack",
            json={"ip": ip, "port": port, "duration": duration},
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=15
        )
        return response.json()
    except Exception as e:
        logger.error(f"Attack launch error: {e}")
        return {"error": str(e), "success": False}

# Bot Command Handlers
@admin_required
async def approve_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if len(context.args) < 2:
            await update.message.reply_text(
                "❌ Usage: /approve <user_id> <days>\n\nExample: /approve 123456789 30"
            )
            return
        
        user_id = int(context.args[0])
        days = int(context.args[1])
        
        if days <= 0:
            await update.message.reply_text("❌ Days must be a positive number.")
            return
        
        user = db.get_user(user_id)
        if not user:
            db.create_user(user_id)
        
        if db.approve_user(user_id, days):
            expires_at = get_current_time() + timedelta(days=days)
            await update.message.reply_text(
                f"✅ User {user_id} approved for {days} days!\n📅 Expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S')} UTC"
            )
            try:
                await context.bot.send_message(
                    user_id,
                    f"✅ Your account has been approved for {days} days.\n📅 Expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S')} UTC\n\nUse /help for commands."
                )
            except Exception as e:
                logger.error(f"Failed to notify user: {e}")
        else:
            await update.message.reply_text("❌ Failed to approve user.")
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID or days.")
    except Exception as e:
        logger.error(f"Approve error: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")

@admin_required
async def disapprove_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if len(context.args) < 1:
            await update.message.reply_text("❌ Usage: /disapprove <user_id>")
            return
        user_id = int(context.args[0])
        if db.disapprove_user(user_id):
            await update.message.reply_text(f"✅ User {user_id} disapproved.")
            try:
                await context.bot.send_message(user_id, "❌ Your access has been revoked. Contact admin.")
            except Exception as e:
                logger.error(f"Failed to notify user: {e}")
        else:
            await update.message.reply_text("❌ Failed to disapprove user.")
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID.")
    except Exception as e:
        logger.error(f"Disapprove error: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")

@admin_required
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    status_msg = await update.message.reply_text("🔄 Checking API health...")
    health = check_api_health()
    if health.get("status") == "ok":
        message = f"✅ API Status: Healthy\n🕐 {health.get('timestamp', 'N/A')}\n📦 Version: {health.get('version', 'N/A')}\n🌐 {API_URL}"
    else:
        message = f"❌ API Unhealthy\nError: {health.get('error', 'Unknown')}\n🌐 {API_URL}"
    await status_msg.edit_text(message)

@admin_required
async def running_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    status_msg = await update.message.reply_text("🔄 Fetching active attacks...")
    attacks = check_running_attacks()
    if attacks.get("success"):
        active = attacks.get("activeAttacks", [])
        if active:
            message = f"🎯 Active Attacks ({len(active)})\n\n"
            for a in active:
                message += f"🔹 {a['target']}:{a['port']} - expires in {a['expiresIn']}s\n"
        else:
            message = "✅ No active attacks."
        message += f"\n📊 Usage: {attacks.get('count',0)}/{attacks.get('maxConcurrent',0)}"
    else:
        message = f"❌ Failed: {attacks.get('error','Unknown')}"
    await status_msg.edit_text(message)

@admin_required
async def users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        users = db.get_all_users()
        if not users:
            await update.message.reply_text("📭 No users found.")
            return
        approved = sum(1 for u in users if u.get("approved"))
        total_attacks = sum(u.get("total_attacks",0) for u in users)
        message = f"👥 Users: {len(users)} | ✅ Approved: {approved} | 🎯 Attacks: {total_attacks}\n\n"
        for idx, u in enumerate(users[:10],1):
            uid = u.get('user_id','?')
            status = "✅" if u.get("approved") else "❌"
            if u.get("approved") and u.get("expires_at"):
                exp = make_aware(u["expires_at"])
                if exp > get_current_time():
                    days_left = (exp - get_current_time()).days
                    status += f"({days_left}d)"
                else:
                    status += "(Expired)"
            message += f"{idx}. {uid} {status} - {u.get('total_attacks',0)} attacks\n"
        if len(users)>10:
            message += f"\n*And {len(users)-10} more…*"
        if len(message)>4000:
            message = message[:4000] + "\n…(truncated)"
        await update.message.reply_text(message)
    except Exception as e:
        logger.error(f"Users command error: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")

@admin_required
async def blocked_ports_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"🚫 Blocked Ports\n\n{get_blocked_ports_list()}\n\nTotal: {len(BLOCKED_PORTS)} ports"
    )

@admin_required
async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        users = db.get_all_users()
        approved = [u for u in users if u.get("approved")]
        total_attacks = sum(u.get("total_attacks",0) for u in users)
        yesterday = get_current_time() - timedelta(days=1)
        recent = db.attacks.count_documents({"timestamp": {"$gte": yesterday}})
        success = db.attacks.count_documents({"status": "success"})
        failed = db.attacks.count_documents({"status": "failed"})
        message = (
            f"📊 Bot Stats\n\n"
            f"👥 Users: {len(users)} (Approved: {len(approved)})\n"
            f"🎯 Attacks: {total_attacks} total, {recent} last 24h\n"
            f"✅ {success} success | ❌ {failed} failed\n"
            f"🚫 Blocked ports: {len(BLOCKED_PORTS)}"
        )
        await update.message.reply_text(message)
    except Exception as e:
        logger.error(f"Stats error: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")

# User commands
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_id = update.effective_user.id
        username = update.effective_user.username
        db.create_user(user_id, username)
        
        if await is_user_approved(user_id):
            user_data = db.get_user(user_id)
            expires_at = user_data.get("expires_at")
            days_left = 0
            if expires_at:
                expires_at = make_aware(expires_at)
                days_left = max(0, (expires_at - get_current_time()).days)
            message = (
                f"✅ Welcome back, {username or user_id}!\n"
                f"Account active. Expires in {days_left} days.\n\n"
                f"🔹 /attack ip port duration\n"
                f"🔹 /myattacks\n"
                f"🔹 /myinfo\n"
                f"🔹 /mystats\n"
                f"🔹 /blockedports\n"
                f"🔹 /help"
            )
        else:
            message = (
                f"❌ Access Denied, {username or user_id}!\n\n"
                f"Your account is not approved yet.\n"
                f"Contact the administrator."
            )
        await update.message.reply_text(message)
    except Exception as e:
        logger.error(f"Start command error: {e}", exc_info=True)
        await update.message.reply_text("❌ An error occurred. Please try again later. (Check logs)")

async def attack_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ Access Denied! Your account is not approved or expired.")
        return
    
    if len(context.args) != 3:
        await update.message.reply_text(
            f"❌ Usage: /attack ip port duration\n\nExample: /attack 192.168.1.1 80 60\n\n🚫 Blocked ports: {get_blocked_ports_list()}"
        )
        return
    
    ip, port_str, duration_str = context.args[0], context.args[1], context.args[2]
    
    # Validate IP
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        await update.message.reply_text("❌ Invalid IP address.")
        return
    
    # Validate port
    try:
        port = int(port_str)
        if port < MIN_PORT or port > MAX_PORT:
            raise ValueError
        if is_port_blocked(port):
            await update.message.reply_text(f"❌ Port {port} is blocked! Allowed ports: all except {get_blocked_ports_list()}")
            return
    except ValueError:
        await update.message.reply_text(f"❌ Invalid port. Must be {MIN_PORT}-{MAX_PORT} and not blocked.")
        return
    
    # Validate duration
    try:
        duration = int(duration_str)
        if duration < 1 or duration > 300:
            raise ValueError
    except ValueError:
        await update.message.reply_text("❌ Invalid duration. Must be 1-300 seconds.")
        return
    
    status_msg = await update.message.reply_text(f"🎯 Launching attack on {ip}:{port} for {duration}s...")
    response = launch_attack(ip, port, duration)
    
    if response.get("success"):
        attack = response.get("attack", {})
        limits = response.get("limits", {})
        msg = (
            f"✅ Attack Launched!\n"
            f"🎯 {ip}:{port} for {duration}s\n"
            f"🆔 {attack.get('id','N/A')[:8]}\n"
            f"📊 Active: {limits.get('currentActive',0)}/{limits.get('maxConcurrent',0)}"
        )
        db.log_attack(user_id, ip, port, duration, "success", str(response))
        await status_msg.edit_text(msg)
    else:
        error = response.get("error", "Unknown error")
        await status_msg.edit_text(f"❌ Attack failed!\nError: {error}")
        db.log_attack(user_id, ip, port, duration, "failed", str(response))

async def myattacks_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ Not approved.")
        return
    attacks = check_running_attacks()
    if attacks.get("success"):
        active = attacks.get("activeAttacks", [])
        if active:
            msg = f"🎯 Your active attacks ({len(active)})\n\n"
            for a in active:
                msg += f"🔹 {a['target']}:{a['port']} - expires in {a['expiresIn']}s\n"
        else:
            msg = "✅ No active attacks."
        await update.message.reply_text(msg)
    else:
        await update.message.reply_text(f"❌ Failed: {attacks.get('error','Unknown')}")

async def myinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        user_id = update.effective_user.id
        user = db.get_user(user_id)
        if not user:
            await update.message.reply_text("❌ User not found. Use /start first.")
            return
        if user.get("approved"):
            expires = user.get("expires_at")
            if expires:
                expires = make_aware(expires)
                days = max(0, (expires - get_current_time()).days)
                hours = max(0, (expires - get_current_time()).seconds // 3600)
                expiry = f"{days}d {hours}h"
            else:
                expiry = "Never"
            msg = (
                f"📋 Your Info\n"
                f"🆔 {user['user_id']}\n"
                f"✅ Approved\n"
                f"⏰ Expires: {expiry}\n"
                f"🎯 Total attacks: {user.get('total_attacks',0)}"
            )
        else:
            msg = f"❌ Not approved. User since {user.get('created_at', get_current_time()).strftime('%Y-%m-%d')}"
        await update.message.reply_text(msg)
    except Exception as e:
        logger.error(f"myinfo error: {e}")
        await update.message.reply_text("❌ Error retrieving info.")

async def mystats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not await is_user_approved(user_id):
        await update.message.reply_text("❌ Not approved.")
        return
    stats = db.get_user_attack_stats(user_id)
    rate = (stats['successful']/stats['total']*100) if stats['total']>0 else 0
    msg = (
        f"📊 Your Attack Stats\n"
        f"🎯 Total: {stats['total']}\n"
        f"✅ Successful: {stats['successful']}\n"
        f"❌ Failed: {stats['failed']}\n"
        f"📈 Success rate: {rate:.1f}%\n"
    )
    if stats['recent']:
        msg += "\n🕐 Recent:\n"
        for a in stats['recent'][:5]:
            icon = "✅" if a['status']=="success" else "❌"
            ago = (get_current_time() - make_aware(a['timestamp'])).seconds // 60
            msg += f"{icon} {a['ip']}:{a['port']} - {a['duration']}s ({ago}m ago)\n"
    await update.message.reply_text(msg)

async def blocked_ports_user_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"🚫 Blocked Ports\n\n{get_blocked_ports_list()}\n\n✅ Allowed: all other ports 1-65535"
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    is_admin = user_id in ADMIN_IDS
    approved = await is_user_approved(user_id)
    msg = "🤖 Bot Commands\n\n"
    msg += "📱 User:\n/start, /help"
    if approved:
        msg += "\n/attack, /myattacks, /myinfo, /mystats, /blockedports"
    if is_admin:
        msg += "\n\n👑 Admin:\n/approve, /disapprove, /users, /status, /running, /stats, /blockedports"
    msg += "\n\n⚠️ Use responsibly."
    await update.message.reply_text(msg)

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Update {update} caused error {context.error}", exc_info=True)
    if update and update.effective_message:
        await update.effective_message.reply_text("❌ An error occurred. Please try again later.")

def main():
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Admin commands
    for cmd in ["approve","disapprove","status","running","users","stats","blockedports"]:
        application.add_handler(CommandHandler(cmd, globals()[f"{cmd}_command"]))
    
    # User commands
    for cmd in ["start","help","attack","myattacks","myinfo","mystats"]:
        application.add_handler(CommandHandler(cmd, globals()[f"{cmd}_command"]))
    application.add_handler(CommandHandler("blockedports", blocked_ports_user_command))
    
    application.add_error_handler(error_handler)
    
    # Get public IP (optional)
    try:
        ip = requests.get('https://ifconfig.me', timeout=5).text.strip()
    except:
        ip = "Unknown"
    
    print("🤖 Bot starting...")
    print(f"Server IP: {ip}")
    print(f"👑 Admins: {ADMIN_IDS}")
    print(f"🌐 API: {API_URL}")
    print(f"🔑 API Key: {API_KEY[:10]}...")
    print("✅ Ready.")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
