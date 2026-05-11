import logging
import sys
import re
import uuid
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

# Parse admin ids safely
admin_env = os.getenv("ADMIN_IDS", "8210011971").strip()
if admin_env.startswith('"') and admin_env.endswith('"'):
    admin_env = admin_env[1:-1]
ADMIN_IDS = [int(x.strip()) for x in admin_env.split(",") if x.strip().isdigit()]
if not ADMIN_IDS:
    ADMIN_IDS = [8210011971]

# Check required
if not BOT_TOKEN:
    print("❌ BOT_TOKEN missing")
    sys.exit(1)
if not MONGODB_URI:
    print("❌ MONGODB_URI missing")
    sys.exit(1)

BLOCKED_PORTS = {443, 8700, 9031, 17500, 20000, 20001, 20002}
MIN_PORT, MAX_PORT = 1, 65535
APPROVE_USER, APPROVE_DAYS = 1, 2
DISAPPROVE_USER = 3
SETAPI_URL, SETAPI_KEY = 4, 5

# ---------- TIME HELPERS ----------
def make_aware(dt):
    if dt and dt.tzinfo is None:
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
        self.settings = self.db.settings
        try:
            self.users.delete_many({"user_id": None})
            self.users.delete_many({"user_id": {"$exists": False}})
        except:
            pass
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
    
    def log_attack(self, user_id: int, ip: str, port: int, duration: int, status: str, response: str = ""):
        try:
            self.attacks.insert_one({"_id": str(uuid.uuid4()), "user_id": user_id, "ip": ip, "port": port,
                                     "duration": duration, "status": status, "response": response[:500],
                                     "timestamp": get_current_time()})
            self.users.update_one({"user_id": user_id}, {"$inc": {"total_attacks": 1}})
        except Exception as e:
            logger.error(f"Log attack failed: {e}")
    
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

# ---------- API CALL THAT NEVER RAISES EXCEPTION ----------
def send_attack(ip: str, port: int, duration: int):
    try:
        api_url, api_key = db.get_api_config()
        if not api_url:
            return False, "❌ API URL is not configured. Admin must use /setapi or Admin Panel → Set API URL/Key."
        if not api_key:
            return False, "❌ API Key is missing. Admin must set it."
        
        if not api_url.startswith(("http://", "https://")):
            api_url = "https://" + api_url
        
        params = {"ip": ip, "port": port, "duration": duration}
        headers = {"x-api-key": api_key}
        response = requests.get(api_url, params=params, headers=headers, timeout=15)
        
        if response.status_code == 200:
            return True, f"✅ Attack launched successfully! HTTP {response.status_code}\nResponse: {response.text[:150]}"
        else:
            return False, f"❌ API returned HTTP {response.status_code}: {response.text[:150]}"
    except requests.exceptions.NameResolutionError:
        return False, f"❌ Domain not resolved: {api_url}. Check the API URL (must be valid domain/IP)."
    except requests.exceptions.ConnectionError as e:
        return False, f"❌ Connection error: {str(e)[:150]}"
    except requests.exceptions.Timeout:
        return False, "❌ Request timeout (15s). API server may be slow or down."
    except Exception as e:
        return False, f"❌ Unexpected API error: {str(e)[:200]}"

# ---------- KEYBOARDS ----------
def main_menu(is_admin: bool, approved: bool):
    keyboard = []
    if approved:
        keyboard.append([InlineKeyboardButton("🚀 Attack", callback_data="attack_menu")])
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
        [InlineKeyboardButton("🚫 Blocked Ports", callback_data="admin_blockedports")],
        [InlineKeyboardButton("🔙 Back", callback_data="back_main")]
    ]
    return InlineKeyboardMarkup(kb)

def attack_back_kb():
    return InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data="back_main")]])

# ---------- COMMAND HANDLERS ----------
async def start_cmd(update, context):
    uid = update.effective_user.id
    name = update.effective_user.username
    db.create_user(uid, name)
    approved = await is_approved(uid)
    is_admin = uid in ADMIN_IDS
    if approved:
        exp = db.get_user(uid).get("expires_at")
        days = max(0, (make_aware(exp) - get_current_time()).days) if exp else 0
        text = f"✅ *Welcome {name or uid}!* Account active for {days} days.\nChoose option:"
    else:
        text = f"❌ *Access Denied, {name or uid}!* Not approved. Contact admin."
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
            f"🚀 *Launch Attack*\nSend: `/attack IP PORT DURATION`\nExample: `/attack 1.2.3.4 80 60`\n\nBlocked ports: {blocked_ports_str()}",
            parse_mode="Markdown", reply_markup=attack_back_kb()
        )
    elif data == "myinfo":
        if not approved:
            await query.edit_message_text("Not approved.", reply_markup=main_menu(is_admin, False))
            return
        u = db.get_user(uid)
        if u.get("approved"):
            exp = u.get("expires_at")
            days = max(0, (make_aware(exp) - get_current_time()).days) if exp else 0
            txt = f"📋 *Your Info*\n🆔 `{uid}`\n✅ Approved\n⏰ Expires in {days} days\n🎯 Total attacks: {u.get('total_attacks',0)}"
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
        txt = f"🚫 *Blocked ports*\n{blocked_ports_str()}\nAllowed: 1-65535 except these."
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=main_menu(is_admin, approved))
    elif data == "help":
        txt = "🤖 *Bot Help*\nUse buttons or commands:\n/attack, /myinfo, /mystats, /blockedports"
        if is_admin:
            txt += "\n\n👑 Admin commands via Admin Panel."
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=main_menu(is_admin, approved))
    elif data == "admin_panel":
        if not is_admin:
            await query.edit_message_text("Unauthorized.", reply_markup=main_menu(is_admin, approved))
            return
        url, key = db.get_api_config()
        url_disp = url if url else "Not set"
        key_disp = (key[:10]+"...") if key else "Not set"
        await query.edit_message_text(
            f"👑 *Admin Panel*\n🔗 API URL: `{url_disp}`\n🔑 API Key: `{key_disp}`\n\nChoose action:",
            parse_mode="Markdown", reply_markup=admin_panel_kb()
        )
    elif data == "back_main":
        await query.edit_message_text("Main menu:", parse_mode="Markdown", reply_markup=main_menu(is_admin, approved))
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
            if len(users) > 15:
                txt += f"\n+ {len(users)-15} more"
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=admin_panel_kb())
    elif data == "admin_stats":
        if not is_admin: return
        users = db.get_all_users()
        total_atk = sum(u.get('total_attacks',0) for u in users)
        txt = f"📊 *Bot Stats*\n👥 Users: {len(users)}\n🎯 Total attacks: {total_atk}\n🚫 Blocked ports: {len(BLOCKED_PORTS)}"
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=admin_panel_kb())
    elif data == "admin_status":
        if not is_admin: return
        url, key = db.get_api_config()
        if not url:
            await query.edit_message_text("API URL not set. Use 'Set API URL/Key'.", reply_markup=admin_panel_kb())
            return
        await query.edit_message_text("🔍 Testing API connection...")
        try:
            test_url = url if url.startswith(("http://","https://")) else "https://"+url
            resp = requests.get(test_url, headers={"x-api-key": key}, timeout=10)
            status = f"✅ API responded with HTTP {resp.status_code}"
        except Exception as e:
            status = f"❌ Error: {str(e)[:150]}"
        await query.edit_message_text(status, parse_mode="Markdown", reply_markup=admin_panel_kb())
    elif data == "admin_blockedports":
        if not is_admin: return
        await query.edit_message_text(f"🚫 Blocked ports: {blocked_ports_str()}", reply_markup=admin_panel_kb())
    elif data == "admin_setapi":
        if not is_admin: return
        await query.edit_message_text("🔧 *Set API URL*\nSend the full endpoint URL (must start with http:// or https://)\nExample: `https://yourdomain.com/api/attack`\nSend /cancel to abort.", parse_mode="Markdown")
        return SETAPI_URL
    elif data == "admin_approve":
        if not is_admin: return
        await query.edit_message_text("📝 Send the user ID (number):")
        return APPROVE_USER
    elif data == "admin_disapprove":
        if not is_admin: return
        await query.edit_message_text("❌ Send user ID to disapprove:")
        return DISAPPROVE_USER
    return ConversationHandler.END

# Conversation: Set API
async def setapi_url(update, context):
    url = update.message.text.strip()
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    context.user_data['api_url'] = url
    await update.message.reply_text("Now send the API Key (or /cancel):")
    return SETAPI_KEY

async def setapi_key(update, context):
    key = update.message.text.strip()
    url = context.user_data.get('api_url')
    if url and key:
        db.set_api_config(url, key)
        await update.message.reply_text(f"✅ API configured!\nURL: `{url}`\nKey: `{key[:10]}...`", parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ Invalid. Cancelled.")
    context.user_data.clear()
    uid = update.effective_user.id
    is_admin = uid in ADMIN_IDS
    approved = await is_approved(uid)
    await update.message.reply_text("Admin Panel:", reply_markup=admin_panel_kb())
    return ConversationHandler.END

# Conversation: Approve
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
        await update.message.reply_text(f"✅ User `{uid}` approved for {days} days.", parse_mode="Markdown")
        try:
            await context.bot.send_message(uid, f"✅ Your account has been approved for {days} days! Use /start.")
        except:
            pass
    else:
        await update.message.reply_text("❌ Approval failed.")
    context.user_data.clear()
    await update.message.reply_text("Admin Panel:", reply_markup=admin_panel_kb())
    return ConversationHandler.END

# Conversation: Disapprove
async def disapprove_uid(update, context):
    txt = update.message.text.strip()
    if not txt.isdigit():
        await update.message.reply_text("Invalid. /cancel")
        return DISAPPROVE_USER
    uid = int(txt)
    if db.disapprove_user(uid):
        await update.message.reply_text(f"✅ User `{uid}` disapproved.", parse_mode="Markdown")
        try:
            await context.bot.send_message(uid, "❌ Your access has been revoked.")
        except:
            pass
    else:
        await update.message.reply_text("❌ Failed.")
    context.user_data.clear()
    await update.message.reply_text("Admin Panel:", reply_markup=admin_panel_kb())
    return ConversationHandler.END

async def cancel_conv(update, context):
    context.user_data.clear()
    await update.message.reply_text("Cancelled.")
    return ConversationHandler.END

# ========== FIXED ATTACK COMMAND WITH TRY-EXCEPT ==========
async def attack_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        uid = update.effective_user.id
        if not await is_approved(uid):
            await update.message.reply_text("❌ Your account is not approved or expired. Contact admin.")
            return
        
        args = context.args
        if len(args) != 3:
            await update.message.reply_text(f"❌ Usage: /attack <IP> <PORT> <DURATION>\nExample: /attack 1.2.3.4 80 60\n\nBlocked ports: {blocked_ports_str()}")
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
            await update.message.reply_text("❌ Invalid port (1-65535, not blocked) or duration (1-300s).")
            return
        
        status_msg = await update.message.reply_text(f"🚀 Launching attack on `{ip}:{port}` for {duration}s...", parse_mode="Markdown")
        
        # Call API function (it already handles all exceptions internally)
        success, message = send_attack(ip, port, duration)
        
        # Log attack (ensure no exception here)
        try:
            db.log_attack(uid, ip, port, duration, "success" if success else "failed", message)
        except Exception as log_err:
            logger.error(f"Logging failed: {log_err}")
        
        await status_msg.edit_text(message, parse_mode="Markdown")
        
    except Exception as e:
        # Catch any unexpected error and send to user directly
        error_text = f"❌ Unexpected error: {str(e)[:200]}\nPlease check API URL/Key configuration."
        await update.message.reply_text(error_text)
        logger.error(f"Attack command exception: {e}", exc_info=True)

# Other user commands (simplified)
async def myinfo_cmd(update, context):
    uid = update.effective_user.id
    u = db.get_user(uid)
    if not u:
        await update.message.reply_text("Use /start first.")
        return
    if u.get("approved"):
        exp = u.get("expires_at")
        days = max(0, (make_aware(exp) - get_current_time()).days) if exp else 0
        await update.message.reply_text(f"✅ Approved\nUser: {uid}\nExpires: {days} days\nTotal attacks: {u.get('total_attacks',0)}")
    else:
        await update.message.reply_text("❌ Not approved. Contact admin.")

async def mystats_cmd(update, context):
    uid = update.effective_user.id
    if not await is_approved(uid):
        await update.message.reply_text("Not approved.")
        return
    s = db.get_user_stats(uid)
    rate = (s['successful']/s['total']*100) if s['total']>0 else 0
    txt = f"Total: {s['total']}\n✅ {s['successful']} | ❌ {s['failed']}\nSuccess rate: {rate:.1f}%"
    if s['recent']:
        txt += "\nRecent:\n"
        for a in s['recent'][:3]:
            ago = (get_current_time() - a['timestamp']).seconds // 60
            txt += f"{'✅' if a['status']=='success' else '❌'} {a['ip']}:{a['port']} - {a['duration']}s ({ago}m ago)\n"
    await update.message.reply_text(txt)

async def blocked_ports_cmd(update, context):
    await update.message.reply_text(f"🚫 Blocked ports: {blocked_ports_str()}")

async def help_cmd(update, context):
    await start_cmd(update, context)

async def error_handler(update, context):
    logger.error(f"Unhandled error: {context.error}", exc_info=True)
    if update and update.effective_message:
        await update.effective_message.reply_text("❌ An unexpected error occurred. Please try again later. Check bot logs for details.")

# ---------- MAIN ----------
def main():
    app = Application.builder().token(BOT_TOKEN).build()
    
    # Conversations
    setapi_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_handler, pattern="^admin_setapi$")],
        states={SETAPI_URL: [MessageHandler(filters.TEXT & ~filters.COMMAND, setapi_url)],
                SETAPI_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, setapi_key)]},
        fallbacks=[CommandHandler("cancel", cancel_conv)],
    )
    approve_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_handler, pattern="^admin_approve$")],
        states={APPROVE_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, approve_uid)],
                APPROVE_DAYS: [MessageHandler(filters.TEXT & ~filters.COMMAND, approve_days)]},
        fallbacks=[CommandHandler("cancel", cancel_conv)],
    )
    disapprove_conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_handler, pattern="^admin_disapprove$")],
        states={DISAPPROVE_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, disapprove_uid)]},
        fallbacks=[CommandHandler("cancel", cancel_conv)],
    )
    
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("attack", attack_cmd))
    app.add_handler(CommandHandler("myinfo", myinfo_cmd))
    app.add_handler(CommandHandler("mystats", mystats_cmd))
    app.add_handler(CommandHandler("blockedports", blocked_ports_cmd))
    app.add_handler(CommandHandler("help", help_cmd))
    
    app.add_handler(CallbackQueryHandler(button_handler, pattern="^(attack_menu|myinfo|mystats|blockedports|help|admin_panel|back_main|admin_users|admin_stats|admin_status|admin_blockedports)$"))
    app.add_handler(setapi_conv)
    app.add_handler(approve_conv)
    app.add_handler(disapprove_conv)
    
    app.add_error_handler(error_handler)
    
    print("🤖 Bot started. Admins:", ADMIN_IDS)
    url, _ = db.get_api_config()
    print(f"🌐 API URL: {url if url else 'Not set'}")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
