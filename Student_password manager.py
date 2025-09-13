import streamlit as st
import sqlite3
import os
import bcrypt
import random
import string
import requests
from cryptography.fernet import Fernet
from datetime import datetime
import time
import logging
import hashlib

st.set_page_config(page_title="LockedOut - Password Manager", page_icon="🔐", layout="wide")
logging.basicConfig(filename="password_manager.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def log_event(message): logging.info(message)
def load_key():
    key_path = "secret.key"
    if not os.path.exists(key_path):
        key = Fernet.generate_key()
        with open(key_path, "wb") as f: f.write(key)
        return key
    else:
        with open(key_path, "rb") as f: return f.read()
key = load_key()
cipher = Fernet(key)

conn = sqlite3.connect("password_manager.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, rollno TEXT, email TEXT, password_hash BLOB)""")
cursor.execute("""CREATE TABLE IF NOT EXISTS vault (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, service TEXT, category TEXT, login TEXT, password BLOB, created_at TEXT, FOREIGN KEY(user_id) REFERENCES users(id))""")
cursor.execute("""CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY AUTOINCREMENT, group_name TEXT, invite_code TEXT UNIQUE)""")
cursor.execute("""CREATE TABLE IF NOT EXISTS group_members (group_id INTEGER, user_id INTEGER, FOREIGN KEY(group_id) REFERENCES groups(id), FOREIGN KEY(user_id) REFERENCES users(id), PRIMARY KEY(group_id, user_id))""")
cursor.execute("""CREATE TABLE IF NOT EXISTS group_vault (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id INTEGER, service TEXT, category TEXT, login TEXT, password BLOB, created_at TEXT, FOREIGN KEY(group_id) REFERENCES groups(id))""")
cursor.execute("""CREATE TABLE IF NOT EXISTS forum_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, message TEXT, timestamp TEXT, FOREIGN KEY(user_id) REFERENCES users(id))""")
conn.commit()

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def password_strength(password):
    score = 0
    tests = [(len(password) >= 8, 1), (any(c.islower() for c in password), 1), (any(c.isupper() for c in password), 1), (any(c.isdigit() for c in password), 1), (any(c in "!@#$%^&*()" for c in password), 1)]
    score = sum(v for res,v in tests if res)
    levels = ["Very Weak ⛔", "Weak ⚠", "Medium 👍", "Strong 💪", "Very Strong 🔥"]
    return levels[min(score, 4)]

def is_strong_password(pw):
    return (len(pw) >= 8 and any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw) and any(c in "!@#$%^&*()" for c in pw))

def format_password_masked(password, mask_char='•'):
    return mask_char * len(password)

def get_username(user_id):
    cursor.execute("SELECT username FROM users WHERE id=?", (user_id,))
    result = cursor.fetchone()
    return result[0] if result else "User"

def check_pwned_password(password):
    sha1_pw = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_pw[:5], sha1_pw[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        res = requests.get(url, timeout=5)
        if res.status_code != 200:
            return False, "Could not verify breach status"
        hashes = (line.split(":") for line in res.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return True, f"Password found {count} times in breaches! Choose another."
        return False, "Password not found in known breaches"
    except Exception:
        return False, "Error checking breach status"

if "login_attempts" not in st.session_state: st.session_state["login_attempts"] = {}
SESSION_TIMEOUT_SECONDS = 1800

def register_user(username, rollno, email, password):
    try:
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, rollno, email, password_hash) VALUES (?, ?, ?, ?)", (username, rollno, email, password_hash))
        conn.commit()
        log_event(f"User registered: {username}")
        return True
    except sqlite3.IntegrityError:
        return False

def login_user(username, password):
    user_attempts = st.session_state["login_attempts"].get(username, 0)
    if user_attempts >= 5:
        st.error("Too many failed login attempts. Please try again later.")
        return None
    cursor.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if user and bcrypt.checkpw(password.encode(), user[1]):
        st.session_state["login_attempts"][username] = 0
        log_event(f"User {username} logged in successfully")
        return user[0]
    else:
        st.session_state["login_attempts"][username] = user_attempts + 1
        return None

def get_user_stats(user_id):
    cursor.execute("SELECT COUNT(*) FROM vault WHERE user_id=?", (user_id,))
    personal_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT group_id) FROM group_members WHERE user_id=?", (user_id,))
    group_count = cursor.fetchone()[0]
    return personal_count, group_count

def add_password(user_id, service, category, login, password):
    encrypted_pw = cipher.encrypt(password.encode())
    try:
        cursor.execute("INSERT INTO vault (user_id, service, category, login, password, created_at) VALUES (?, ?, ?, ?, ?, ?)", (user_id, service, category, login, encrypted_pw, datetime.now().isoformat()))
        conn.commit()
    except Exception as e:
        st.error(f"Error saving password: {e}")

def delete_password(pw_id, user_id):
    try:
        cursor.execute("DELETE FROM vault WHERE id=? AND user_id=?", (pw_id, user_id))
        conn.commit()
        st.toast("Password deleted.", icon="🗑")
        st.balloons()
    except Exception as e:
        st.error(f"Error deleting password: {e}")

def get_passwords(user_id, search_service="", filter_category=""):
    sql = "SELECT id, service, category, login, password, created_at FROM vault WHERE user_id=?"
    params = [user_id]
    if search_service: sql += " AND service LIKE ?"; params.append(f"%{search_service}%")
    if filter_category and filter_category != "All": sql += " AND category = ?"; params.append(filter_category)
    cursor.execute(sql, tuple(params))
    rows = cursor.fetchall()
    return [(sid, service, category, login, cipher.decrypt(pw).decode(), created_at) for sid, service, category, login, pw, created_at in rows]

def create_group(name):
    code = generate_password(6)
    cursor.execute("INSERT INTO groups (group_name, invite_code) VALUES (?, ?)", (name, code))
    conn.commit()
    log_event(f"Group created: {name} with code {code}")
    return code

def join_group(user_id, code):
    cursor.execute("SELECT id FROM groups WHERE invite_code=?", (code,))
    group = cursor.fetchone()
    if group:
        try:
            cursor.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group[0], user_id))
            conn.commit()
            log_event(f"User {user_id} joined group {group[0]}")
        except sqlite3.IntegrityError:
            pass
        return True
    return False

def get_user_groups(user_id):
    cursor.execute("SELECT g.id, g.group_name, g.invite_code FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id=?", (user_id,))
    return cursor.fetchall()

def add_group_password(group_id, service, category, login, password):
    encrypted_pw = cipher.encrypt(password.encode())
    try:
        cursor.execute("INSERT INTO group_vault (group_id, service, category, login, password, created_at) VALUES (?, ?, ?, ?, ?, ?)", (group_id, service, category, login, encrypted_pw, datetime.now().isoformat()))
        conn.commit()
    except Exception as e:
        st.error(f"Error adding group password: {e}")

def delete_group_password(gpw_id, group_id):
    try:
        cursor.execute("DELETE FROM group_vault WHERE id=? AND group_id=?", (gpw_id, group_id))
        conn.commit()
        st.toast("Password removed from team vault!", icon="🗑")
        st.snow()
    except Exception as e:
        st.error(f"Error deleting group password: {e}")

def get_group_passwords(group_id):
    cursor.execute("SELECT id, service, category, login, password, created_at FROM group_vault WHERE group_id=?", (group_id,))
    rows = cursor.fetchall()
    return [(sid, service, category, login, cipher.decrypt(pw).decode(), created_at) for sid, service, category, login, pw, created_at in rows]

def get_group_members(group_id):
    cursor.execute("SELECT u.username FROM users u JOIN group_members gm ON u.id = gm.user_id WHERE gm.group_id=?", (group_id,))
    return [user[0] for user in cursor.fetchall()]

def add_forum_message(user_id, message):
    timestamp = datetime.now().isoformat()
    cursor.execute("INSERT INTO forum_messages (user_id, message, timestamp) VALUES (?, ?, ?)", (user_id, message, timestamp))
    conn.commit()

def get_forum_messages():
    cursor.execute("SELECT u.username, fm.message, fm.timestamp FROM forum_messages fm JOIN users u ON fm.user_id = u.id ORDER BY fm.timestamp DESC LIMIT 50")
    return cursor.fetchall()

def display_password_entry(pw, sid, delete_fn=None, group=False, owner_id=None, category=None):
    showpw_key = f"showpw_{sid}_{group}"
    if showpw_key not in st.session_state:
        st.session_state[showpw_key] = False
    pw_to_show = pw if st.session_state[showpw_key] else format_password_masked(pw)
    col1, col2, col3, col4, col5 = st.columns([4,1,1,1,1])
    with col1:
        st.text_input("Password", value=pw_to_show, key=f"pw_{sid}_{group}", type="default" if st.session_state[showpw_key] else "password", disabled=True, label_visibility="collapsed")
    with col2:
        if st.button("👁", key=f"toggle_{sid}_{group}", help="Show/Hide"):
            st.session_state[showpw_key] = not st.session_state[showpw_key]
            st.rerun()
    with col3:
        if st.button("📋", key=f"copy_{sid}_{group}", help="Copy password"):
            st.toast("Password copied!", icon="📋")
    with col4:
        if group:
            st.markdown(f"<span title='Team Vault' style='font-size:1.5rem; color:#ff4081;'>👥</span>", unsafe_allow_html=True)
        else:
            st.markdown(f"<span title='Personal Vault' style='font-size:1.5rem; color:#20bdff;'>🔐</span>", unsafe_allow_html=True)
    with col5:
        if st.button("🗑", key=f"del_{sid}_{group}", help="Delete this password", type="secondary"):
            if st.session_state.get(f"confirm_del_{sid}_{group}", False):
                if group:
                    delete_group_password(sid, owner_id)
                else:
                    delete_password(sid, st.session_state["user_id"])
                st.session_state[f"confirm_del_{sid}_{group}"] = False
                st.rerun()
            else:
                st.session_state[f"confirm_del_{sid}_{group}"] = True
                st.warning("Click again to confirm delete.")

category_colors = {
    "Education": "cat-education",
    "Social": "cat-social",
    "Work": "cat-work",
    "Other": "cat-other",
}

st.markdown("""
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<style>
@import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@700;900&family=Poppins&display=swap');
body { background: linear-gradient(120deg, #21d4fd 0%, #b721ff 100%) !important; font-family: 'Poppins', sans-serif;}
.main { background-color: rgba(0,0,0,0.4); border-radius: 20px; box-shadow: 0 8px 32px 0 #48287033; padding: 1.5rem 2rem; }
h1, .main-title { font-family: 'Montserrat', sans-serif; font-weight: 900; font-size: 3rem; color: #fff; }
.feature-card { background: #fff; color: #3a6073; border-radius: 18px; box-shadow: 0 6px 24px #00c6fb55; padding: 2rem; margin: 1rem 0;
                transition: box-shadow 0.2s, transform 0.2s; }
.feature-card:hover { box-shadow: 0 12px 36px #5200ff77; transform: translateY(-5px);}
.stButton > button, .stTextInput > div > div > input { border-radius: 12px !important; font-size: 1.1rem !important; }
.stTabs [role="tab"] { font-size: 1.15rem !important; padding: 0.5rem 1rem; }
.stButton > button {
  background: linear-gradient(120deg, #fcff00 0%, #00dbde 100%);
  border: none;
  transition: background-position 0.3s;
  background-size: 200% 200%;
  background-position: left center;
}
.stButton > button:hover {
  background-position: right center;
  color: #fff !important;
}
.category-badge {
  display:inline-block;
  font-size:0.9rem;
  font-weight:bold;
  padding:0.15rem 0.7rem;
  border-radius:12px;
  color:#fff;
  margin-left:8px;
  user-select:none;
  font-family: 'Poppins', sans-serif;
  text-transform: uppercase;
}
.cat-education { background: #4caf50; }
.cat-social { background: #2196f3; }
.cat-work { background: #ff9800; }
.cat-other { background: #9c27b0; }
.forum-message {
  background: rgba(255,255,255,0.9);
  border-radius: 12px;
  padding: 1rem;
  margin-bottom: 1rem;
  box-shadow: 0 3px 8px rgb(0 0 0 / 0.12);
}
.forum-username {
  font-weight: 700;
  color: #5200ff;
}
.forum-timestamp {
  font-size: 0.8rem;
  color: #777;
}
</style>
""", unsafe_allow_html=True)


def show_landing_page():
    st.markdown("""
    <div class="main" style="text-align:center">
        <h1><i class="fas fa-lock"></i> LockedOut</h1>
        <h3>Your Trusted Student Password Manager<br>Secure. Simple. Shared.</h3>
    </div>
    """, unsafe_allow_html=True)
    st.write("")
    col1, col2, col3 = st.columns(3)
    for col, icon, title, desc in zip([col1, col2, col3],["shield-alt", "users", "bolt"],["Military-Grade Encryption", "Team Collaboration", "Easy to Use"],["Passwords encrypted with industry-standard AES.","Share passwords safely with study groups.","A beautiful, intuitive interface. Anytime, anywhere."]):
        with col:
            st.markdown(f"""<div class="feature-card"><div style="font-size:2.6rem"><i class="fas fa-{icon}"></i></div><div style="font-size:1.3rem; font-weight:700">{title}</div><div style="font-size:1rem;">{desc}</div></div>""", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🚀 Get Started Now", use_container_width=True, type="primary"):
        st.session_state["show_auth"] = True
        st.rerun()


def show_auth_page():
    st.markdown('<div class="main" style="max-width:500px;margin:auto">', unsafe_allow_html=True)
    tab1, tab2 = st.tabs(["🔑 Login", "📝 Register"])
    with tab1:
        with st.form("login_form"):
            st.markdown("### Sign In")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign In", use_container_width=True)
            if submitted:
                if username and password:
                    user_id = login_user(username.strip(), password)
                    if user_id:
                        st.session_state["user_id"] = user_id
                        st.success("Welcome back!")
                        time.sleep(0.7)
                        st.rerun()
                    else:
                        st.error("Invalid credentials.")
                else:
                    st.warning("Please fill in all fields")
    with tab2:
        with st.form("register_form"):
            st.markdown("### Create Account")
            col1, col2 = st.columns(2)
            username = col1.text_input("Username")
            rollno = col2.text_input("Roll Number")
            email = col1.text_input("Email")
            password = col2.text_input("Password", type="password")
            if password:
                st.caption(f"Password Strength: {password_strength(password)}")
                breached, info = check_pwned_password(password)
                if breached: st.warning(f"⚠️ {info}")
            confirm = st.text_input("Confirm Password", type="password")
            terms = st.checkbox("I agree to Terms and Privacy")
            submitted = st.form_submit_button("Register", use_container_width=True)
            if submitted:
                if not (username and email and rollno and password):
                    st.error("All fields required!")
                elif not terms:
                    st.error("Accept the terms.")
                elif password != confirm:
                    st.error("Passwords do not match!")
                elif not is_strong_password(password):
                    st.error("Password must be at least 8 chars, upper/lowercase, digit, special char.")
                else:
                    breached, info = check_pwned_password(password)
                    if breached:
                        st.error(f"Cannot register with compromised password: {info}")
                    else:
                        if register_user(username.strip(), rollno.strip(), email.strip(), password):
                            st.success("Account created! Login now.")
                            st.balloons()
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("Username already exists.")


    if st.button("← Home", use_container_width=True):
        st.session_state["show_auth"] = False
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)


def show_dashboard():
    username = get_username(st.session_state["user_id"])
    col1, col2 = st.columns([3,1])
    with col1:
        st.markdown(f"<h1 style='color:#fff;'><i class='fas fa-user-circle'></i> Hi, {username}!</h1>", unsafe_allow_html=True)
    with col2:
        if st.button("Logout", use_container_width=True, type="secondary"):
            st.session_state["user_id"] = None
            st.session_state["show_auth"] = False
            st.rerun()
    personal_count, group_count = get_user_stats(st.session_state["user_id"])
    st.markdown(f"""<div style="margin:1.8rem 0 1rem 0"><span style='font-size:1.8rem;color:#fff;background:#20bdff44;padding:0.5rem 1rem;border-radius:1rem;'>Personal Passwords: <b>{personal_count}</b></span><span style='font-size:1.8rem;color:#fff;background:#5200ff44;padding:0.5rem 1rem;border-radius:1rem;margin-left:1.1rem;'>Teams: <b>{group_count}</b></span></div>""", unsafe_allow_html=True)
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🔐 Personal Vault", "👥 Team Vaults", "⚙ Settings", "🎮 Cybersecurity Quiz", "💬 Community Forum"])

    with tab1:
        st.markdown("### Personal Vault")
        col1, col2 = st.columns([2, 1])
        with col1:
            search = st.text_input("🔍 Search", placeholder="Search by website/service...")
        with col2:
            filter_cat = st.selectbox("Category", ["All", "Education", "Social", "Work", "Other"])
        passwords = get_passwords(st.session_state["user_id"], search_service=search, filter_category=filter_cat)
        if passwords:
            for sid, service, category, login_, pw, created_at in passwords:
                with st.expander(f"{service} ", expanded=False):
                    st.markdown(f"<b>{service}</b> <span class='category-badge {category_colors.get(category, 'cat-other')}'>{category}</span>    |   Added: {created_at[:10]}", unsafe_allow_html=True)
                    st.write(f"Login: {login_}")
                    display_password_entry(pw, sid, delete_fn=delete_password, category=category)
        else:
            st.info("No passwords yet. Add your first one! 🎉")
        if st.button("➕ Add New", use_container_width=True, type="primary"):
            st.session_state["show_add_password"] = True
            st.rerun()
        if st.session_state.get("show_add_password", False):
            with st.form("add_password"):
                st.subheader("Add New Password")
                scol1, scol2 = st.columns(2)
                service = scol1.text_input("Service/Website")
                login_ = scol2.text_input("Username/Email")
                category = scol1.selectbox("Category", ["Education", "Social", "Work", "Other"])
                password_input = scol2.text_input("Password", type="password")
                if password_input:
                    st.caption(f"Strength: {password_strength(password_input)}")
                    breached, info = check_pwned_password(password_input)
                    if breached:
                        st.warning(f"⚠️ {info}")
                if st.form_submit_button("Save"):
                    if service and login_ and password_input:
                        if not is_strong_password(password_input):
                            st.error("Password not strong enough!")
                        elif check_pwned_password(password_input)[0]:
                            st.error("Password found in breaches, choose a stronger one.")
                        else:
                            add_password(st.session_state["user_id"], service, category, login_, password_input)
                            st.session_state["show_add_password"] = False
                            st.success("Saved!")
                            st.balloons()
                            st.rerun()
                    else:
                        st.warning("All fields required.")
                if st.form_submit_button("Cancel"):
                    st.session_state["show_add_password"] = False
                    st.rerun()

    with tab2:
        st.markdown("### Team Vaults")
        col1, col2 = st.columns(2)
        with col1:
            with st.form("create_team_form"):
                group_name = st.text_input("Team Name")
                if st.form_submit_button("Create Team"):
                    if group_name:
                        code = create_group(group_name)
                        join_group(st.session_state["user_id"], code)
                        st.success(f"Team created! Invite code: {code}")
                        st.snow()
                        st.rerun()
        with col2:
            with st.form("join_team_form"):
                code_input = st.text_input("Invite Code")
                if st.form_submit_button("Join Team"):
                    if code_input:
                        if join_group(st.session_state["user_id"], code_input):
                            st.success("Team joined!")
                            st.rerun()
                        else:
                            st.error("Invalid invite code")
        st.markdown("---")
        groups = get_user_groups(st.session_state["user_id"])
        if groups:
            st.markdown("#### Your Teams")
            for gid, name, code in groups:
                with st.expander(f"{name} (Invite: {code})"):
                    members = get_group_members(gid)
                    st.write(f"Members: {', '.join(members)}")
                    passwords = get_group_passwords(gid)
                    if passwords:
                        for sid, service, category, login_, pw, created_at in passwords:
                            with st.expander(f"{service} ({category}) - Added {created_at[:10]}"):
                                st.write(f"Login: {login_}")
                                display_password_entry(pw, sid, group=True, owner_id=gid, category=category)
                    else:
                        st.info("No shared passwords yet.")
                    with st.form(f"add_gpw_{gid}"):
                        scol1, scol2 = st.columns(2)
                        service = scol1.text_input("Service", key=f"gs_{gid}")
                        login_ = scol2.text_input("Login", key=f"gl_{gid}")
                        category = scol1.selectbox("Category", ["Education", "Social", "Work", "Other"], key=f"gc_{gid}")
                        password_input = scol2.text_input("Password", type="password", key=f"gp_{gid}")
                        if st.form_submit_button(f"Add"):
                            if service and login_ and password_input:
                                if not is_strong_password(password_input):
                                    st.error("Password not strong enough!")
                                else:
                                    add_group_password(gid, service, category, login_, password_input)
                                    st.success("Added to team vault!")
                                    st.balloons()
                                    st.rerun()
                            else:
                                st.error("Please fill fields.")
        else:
            st.info("Join a team or create a new one to get started.")

    with tab3:
        st.markdown("### Settings & Admin")
        st.info("Profile and settings coming soon! For now, enjoy using LockedOut.")

    with tab4:
        st.markdown("### 🎮 Cybersecurity Mini Quiz")
        quiz_questions = [
            {"question": "Which is the strongest password?", "options": ["password123", "Summer2025!", "Pa$$w0rd!", "abc123"], "answer": 2},
            {"question": "What does MFA stand for?", "options": ["Multi-Factor Authentication", "Multi-Failed Access", "Many Forms Allowed", "Most Frequent Access"], "answer": 0},
            {"question": "Which symbol is best to add to a password?", "options": ["@", "#", "&", "All of the above"], "answer": 3},
            {"question": "What is phishing?", "options": ["Fishing for fish", "Attempting to steal information via fake emails", "A firewall technique", "A password encryption method"], "answer": 1},
            {"question": "What should you NOT do to keep passwords secure?","options":["Use a password manager","Reuse passwords on multiple sites","Create complex passwords","Enable two-factor authentication"],"answer":1},
        ]
        if "quiz_index" not in st.session_state:
            st.session_state["quiz_index"] = 0
            st.session_state["quiz_score"] = 0
            st.session_state["quiz_submitted"] = False

        i = st.session_state["quiz_index"]
        q = quiz_questions[i]
        st.write(f"**Q{i+1}. {q['question']}**")
        choice = st.radio("Choose an answer:", q["options"], key=f"quiz_{i}")

        if st.button("Submit Answer"):
            st.session_state["quiz_submitted"] = True

        if st.session_state["quiz_submitted"]:
            correct_option = q["options"][q["answer"]]
            if choice == correct_option:
                st.success("Correct! 🎉")
                st.session_state["quiz_score"] += 1
            else:
                st.error(f"Wrong. Correct answer: {correct_option}")
            if st.button("Next Question"):
                st.session_state["quiz_submitted"] = False
                if st.session_state["quiz_index"] < len(quiz_questions)-1:
                    st.session_state["quiz_index"] += 1
                else:
                    st.success(f"Quiz Complete! Your score: {st.session_state['quiz_score']}/{len(quiz_questions)}")
                    if st.session_state["quiz_score"] == len(quiz_questions):
                        st.balloons()
                    st.session_state["quiz_index"] = 0
                    st.session_state["quiz_score"] = 0
                st.rerun()

    with tab5:
        st.markdown("### 💬 Community Forum - Share tips & ask questions")
        if st.session_state.get("user_id") is None:
            st.info("Log in to participate in the forum.")
        else:
            with st.form("forum_post_form"):
                msg = st.text_area("Write your message here:")
                if st.form_submit_button("Post"):
                    if msg.strip():
                        add_forum_message(st.session_state["user_id"], msg.strip())
                        st.success("Message posted!")
                        st.rerun()
                    else:
                        st.warning("Cannot post empty message.")
            st.markdown("---")
            messages = get_forum_messages()
            for uname, message, timestamp in messages:
                st.markdown(f"""<div class="forum-message"><div class="forum-username">{uname}</div><div>{message}</div><div class="forum-timestamp">{timestamp[:19].replace('T', ' ')}</div></div>""", unsafe_allow_html=True)

if "show_auth" not in st.session_state: st.session_state["show_auth"] = False
if "user_id" not in st.session_state: st.session_state["user_id"] = None
if "last_active" not in st.session_state: st.session_state["last_active"] = time.time()
if st.session_state["user_id"]:
    if time.time() - st.session_state["last_active"] > SESSION_TIMEOUT_SECONDS:
        st.warning("Session timed out. Please log in again.")
        st.session_state["user_id"] = None
        st.session_state["show_auth"] = False
        st.rerun()
    else:
        st.session_state["last_active"] = time.time()

if st.session_state["user_id"]:
    show_dashboard()
elif st.session_state["show_auth"]:
    show_auth_page()
else:
    show_landing_page()
