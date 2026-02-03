# SYNTRAF User Management Module
# SQLite-based user authentication with role-based access control

import sqlite3
import hashlib
import secrets
import re
import os
import logging
from datetime import datetime, timedelta
from functools import wraps

log = logging.getLogger("syntraf." + __name__)

# Password policy configuration
PASSWORD_POLICY = {
    'min_length': 8,
    'max_length': 128,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_digit': True,
    'require_special': True,
    'special_chars': '!@#$%^&*()_+-=[]{}|;:,.<>?',
    'max_age_days': 90,  # Password expires after 90 days
    'history_count': 5,  # Cannot reuse last 5 passwords
}

# User roles
ROLE_ADMIN = 'admin'
ROLE_READONLY = 'readonly'
VALID_ROLES = [ROLE_ADMIN, ROLE_READONLY]

# Database path (will be set during initialization)
_db_path = None


def init_database(db_path):
    """Initialize the user database with required tables."""
    global _db_path
    _db_path = db_path

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'readonly',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_login TEXT,
            password_changed_at TEXT NOT NULL,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            must_change_password INTEGER DEFAULT 0,
            description TEXT
        )
    ''')

    # Password history table (for preventing password reuse)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Session tokens table (for "remember me" and API tokens)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS session_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            token_type TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Audit log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            target_user_id INTEGER,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL
        )
    ''')

    conn.commit()

    # Create default admin user if no users exist
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        log.info("No users found, creating default admin user")
        create_user('admin', 'Syntraf123!', ROLE_ADMIN, email='admin@localhost',
                   description='Default administrator account')
        log.warning("Default admin user created with password 'Syntraf123!' - CHANGE THIS IMMEDIATELY!")

    conn.close()
    log.info(f"User database initialized at {db_path}")


def get_db():
    """Get database connection."""
    if _db_path is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    conn = sqlite3.connect(_db_path)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password, salt=None):
    """Hash a password with salt using SHA-256."""
    if salt is None:
        salt = secrets.token_hex(32)
    # Use PBKDF2-like approach with multiple iterations
    hash_input = f"{salt}{password}{salt}".encode('utf-8')
    for _ in range(10000):  # 10000 iterations for security
        hash_input = hashlib.sha256(hash_input).digest()
    password_hash = hashlib.sha256(hash_input).hexdigest()
    return password_hash, salt


def verify_password(password, password_hash, salt):
    """Verify a password against its hash."""
    computed_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, password_hash)


def validate_password_policy(password, username=None):
    """
    Validate password against policy.
    Returns (is_valid, list of error messages).
    """
    errors = []
    policy = PASSWORD_POLICY

    if len(password) < policy['min_length']:
        errors.append(f"Password must be at least {policy['min_length']} characters long")

    if len(password) > policy['max_length']:
        errors.append(f"Password must not exceed {policy['max_length']} characters")

    if policy['require_uppercase'] and not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")

    if policy['require_lowercase'] and not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")

    if policy['require_digit'] and not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")

    if policy['require_special']:
        special_regex = f"[{re.escape(policy['special_chars'])}]"
        if not re.search(special_regex, password):
            errors.append(f"Password must contain at least one special character ({policy['special_chars']})")

    # Check if password contains username
    if username and username.lower() in password.lower():
        errors.append("Password cannot contain your username")

    return len(errors) == 0, errors


def check_password_history(user_id, password):
    """Check if password was used recently."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT password_hash, salt FROM password_history
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
    ''', (user_id, PASSWORD_POLICY['history_count']))

    for row in cursor.fetchall():
        if verify_password(password, row['password_hash'], row['salt']):
            conn.close()
            return False  # Password was used before

    conn.close()
    return True  # Password is new


def add_to_password_history(user_id, password_hash, salt):
    """Add password to history."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO password_history (user_id, password_hash, salt, created_at)
        VALUES (?, ?, ?, ?)
    ''', (user_id, password_hash, salt, datetime.now().isoformat()))

    # Keep only the last N passwords
    cursor.execute('''
        DELETE FROM password_history
        WHERE user_id = ? AND id NOT IN (
            SELECT id FROM password_history
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        )
    ''', (user_id, user_id, PASSWORD_POLICY['history_count']))

    conn.commit()
    conn.close()


def create_user(username, password, role=ROLE_READONLY, email=None, description=None):
    """
    Create a new user.
    Returns (success, user_id or error message).
    """
    # Validate username
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters"

    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username can only contain letters, numbers, underscores and hyphens"

    # Validate role
    if role not in VALID_ROLES:
        return False, f"Invalid role. Must be one of: {', '.join(VALID_ROLES)}"

    # Validate password
    is_valid, errors = validate_password_policy(password, username)
    if not is_valid:
        return False, "; ".join(errors)

    # Hash password
    password_hash, salt = hash_password(password)
    now = datetime.now().isoformat()

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, salt, role, is_active,
                             created_at, updated_at, password_changed_at, description)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
        ''', (username, email, password_hash, salt, role, now, now, now, description))

        user_id = cursor.lastrowid

        # Add to password history
        cursor.execute('''
            INSERT INTO password_history (user_id, password_hash, salt, created_at)
            VALUES (?, ?, ?, ?)
        ''', (user_id, password_hash, salt, now))

        conn.commit()
        conn.close()

        log.info(f"User '{username}' created with role '{role}'")
        return True, user_id

    except sqlite3.IntegrityError as e:
        conn.close()
        if 'username' in str(e).lower():
            return False, "Username already exists"
        elif 'email' in str(e).lower():
            return False, "Email already exists"
        return False, str(e)


def authenticate_user(username, password, ip_address=None):
    """
    Authenticate a user.
    Returns (success, user_dict or error message).
    """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        log.warning(f"Failed login attempt for non-existent user '{username}' from {ip_address}")
        return False, "Invalid username or password"

    # Check if account is locked
    if user['locked_until']:
        locked_until = datetime.fromisoformat(user['locked_until'])
        if datetime.now() < locked_until:
            conn.close()
            remaining = (locked_until - datetime.now()).seconds // 60
            return False, f"Account is locked. Try again in {remaining} minutes"
        else:
            # Unlock the account
            cursor.execute('UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE id = ?',
                          (user['id'],))
            conn.commit()

    # Check if account is active
    if not user['is_active']:
        conn.close()
        log.warning(f"Login attempt for deactivated user '{username}' from {ip_address}")
        return False, "Account is deactivated"

    # Verify password
    if not verify_password(password, user['password_hash'], user['salt']):
        # Increment failed attempts
        failed_attempts = user['failed_login_attempts'] + 1

        if failed_attempts >= 5:
            # Lock account for 15 minutes
            locked_until = (datetime.now() + timedelta(minutes=15)).isoformat()
            cursor.execute('''
                UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?
            ''', (failed_attempts, locked_until, user['id']))
            conn.commit()
            conn.close()
            log.warning(f"Account '{username}' locked after {failed_attempts} failed attempts")
            return False, "Too many failed attempts. Account locked for 15 minutes"
        else:
            cursor.execute('UPDATE users SET failed_login_attempts = ? WHERE id = ?',
                          (failed_attempts, user['id']))
            conn.commit()
            conn.close()
            return False, "Invalid username or password"

    # Successful login - reset failed attempts and update last login
    now = datetime.now().isoformat()
    cursor.execute('''
        UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?
    ''', (now, user['id']))

    # Log the audit
    cursor.execute('''
        INSERT INTO audit_log (user_id, action, ip_address, created_at)
        VALUES (?, 'LOGIN', ?, ?)
    ''', (user['id'], ip_address, now))

    conn.commit()
    conn.close()

    # Check if password is expired
    password_changed = datetime.fromisoformat(user['password_changed_at'])
    if (datetime.now() - password_changed).days > PASSWORD_POLICY['max_age_days']:
        log.info(f"User '{username}' password has expired")
        return True, {
            'id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'must_change_password': True,
            'password_expired': True
        }

    log.info(f"User '{username}' logged in successfully from {ip_address}")
    return True, {
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'role': user['role'],
        'must_change_password': bool(user['must_change_password']),
        'password_expired': False
    }


def change_password(user_id, old_password, new_password):
    """
    Change user's password.
    Returns (success, message).
    """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return False, "User not found"

    # Verify old password
    if not verify_password(old_password, user['password_hash'], user['salt']):
        conn.close()
        return False, "Current password is incorrect"

    # Validate new password
    is_valid, errors = validate_password_policy(new_password, user['username'])
    if not is_valid:
        conn.close()
        return False, "; ".join(errors)

    # Check password history
    if not check_password_history(user_id, new_password):
        conn.close()
        return False, f"Cannot reuse one of your last {PASSWORD_POLICY['history_count']} passwords"

    # Hash new password
    password_hash, salt = hash_password(new_password)
    now = datetime.now().isoformat()

    cursor.execute('''
        UPDATE users SET password_hash = ?, salt = ?, password_changed_at = ?,
                        updated_at = ?, must_change_password = 0 WHERE id = ?
    ''', (password_hash, salt, now, now, user_id))

    conn.commit()

    # Add to password history
    add_to_password_history(user_id, password_hash, salt)

    conn.close()
    log.info(f"Password changed for user '{user['username']}'")
    return True, "Password changed successfully"


def reset_password(user_id, new_password, admin_user_id=None):
    """
    Admin reset of user password.
    Returns (success, message).
    """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return False, "User not found"

    # Validate new password
    is_valid, errors = validate_password_policy(new_password, user['username'])
    if not is_valid:
        conn.close()
        return False, "; ".join(errors)

    # Hash new password
    password_hash, salt = hash_password(new_password)
    now = datetime.now().isoformat()

    cursor.execute('''
        UPDATE users SET password_hash = ?, salt = ?, password_changed_at = ?,
                        updated_at = ?, must_change_password = 1,
                        failed_login_attempts = 0, locked_until = NULL WHERE id = ?
    ''', (password_hash, salt, now, now, user_id))

    # Log audit
    cursor.execute('''
        INSERT INTO audit_log (user_id, action, target_user_id, created_at)
        VALUES (?, 'PASSWORD_RESET', ?, ?)
    ''', (admin_user_id, user_id, now))

    conn.commit()

    # Clear password history for this user (reset allows reuse)
    cursor.execute('DELETE FROM password_history WHERE user_id = ?', (user_id,))

    # Add new password to history
    cursor.execute('''
        INSERT INTO password_history (user_id, password_hash, salt, created_at)
        VALUES (?, ?, ?, ?)
    ''', (user_id, password_hash, salt, now))

    conn.commit()
    conn.close()

    log.info(f"Password reset for user '{user['username']}' by admin {admin_user_id}")
    return True, "Password reset successfully. User must change password on next login."


def update_user(user_id, email=None, role=None, description=None, is_active=None, admin_user_id=None):
    """
    Update user details.
    Returns (success, message).
    """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return False, "User not found"

    updates = []
    params = []

    if email is not None:
        updates.append('email = ?')
        params.append(email)

    if role is not None:
        if role not in VALID_ROLES:
            conn.close()
            return False, f"Invalid role. Must be one of: {', '.join(VALID_ROLES)}"
        updates.append('role = ?')
        params.append(role)

    if description is not None:
        updates.append('description = ?')
        params.append(description)

    if is_active is not None:
        updates.append('is_active = ?')
        params.append(1 if is_active else 0)

    if not updates:
        conn.close()
        return False, "No updates provided"

    updates.append('updated_at = ?')
    params.append(datetime.now().isoformat())
    params.append(user_id)

    try:
        cursor.execute(f'''
            UPDATE users SET {', '.join(updates)} WHERE id = ?
        ''', params)

        # Log audit
        cursor.execute('''
            INSERT INTO audit_log (user_id, action, target_user_id, details, created_at)
            VALUES (?, 'USER_UPDATE', ?, ?, ?)
        ''', (admin_user_id, user_id, str(updates), datetime.now().isoformat()))

        conn.commit()
        conn.close()

        log.info(f"User '{user['username']}' updated")
        return True, "User updated successfully"

    except sqlite3.IntegrityError as e:
        conn.close()
        if 'email' in str(e).lower():
            return False, "Email already exists"
        return False, str(e)


def delete_user(user_id, admin_user_id=None):
    """
    Delete a user.
    Returns (success, message).
    """
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return False, "User not found"

    # Cannot delete yourself
    if user_id == admin_user_id:
        conn.close()
        return False, "Cannot delete your own account"

    # Cannot delete the last admin
    if user['role'] == ROLE_ADMIN:
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = ? AND is_active = 1', (ROLE_ADMIN,))
        if cursor.fetchone()[0] <= 1:
            conn.close()
            return False, "Cannot delete the last admin user"

    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))

    # Log audit
    cursor.execute('''
        INSERT INTO audit_log (user_id, action, details, created_at)
        VALUES (?, 'USER_DELETE', ?, ?)
    ''', (admin_user_id, f"Deleted user: {user['username']}", datetime.now().isoformat()))

    conn.commit()
    conn.close()

    log.info(f"User '{user['username']}' deleted by admin {admin_user_id}")
    return True, "User deleted successfully"


def get_user(user_id):
    """Get user by ID."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return dict(user)
    return None


def get_user_by_username(username):
    """Get user by username."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return dict(user)
    return None


def get_all_users():
    """Get all users."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, username, email, role, is_active, created_at,
               last_login, description, must_change_password,
               failed_login_attempts, locked_until
        FROM users ORDER BY username
    ''')

    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return users


def unlock_user(user_id, admin_user_id=None):
    """Unlock a locked user account."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE id = ?
    ''', (user_id,))

    # Log audit
    cursor.execute('''
        INSERT INTO audit_log (user_id, action, target_user_id, created_at)
        VALUES (?, 'USER_UNLOCK', ?, ?)
    ''', (admin_user_id, user_id, datetime.now().isoformat()))

    conn.commit()
    conn.close()

    log.info(f"User {user_id} unlocked by admin {admin_user_id}")
    return True, "User unlocked successfully"


def get_password_policy():
    """Get current password policy."""
    return PASSWORD_POLICY.copy()


def get_audit_log(limit=100, user_id=None):
    """Get audit log entries."""
    conn = get_db()
    cursor = conn.cursor()

    if user_id:
        cursor.execute('''
            SELECT a.*, u.username as actor_username, t.username as target_username
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN users t ON a.target_user_id = t.id
            WHERE a.user_id = ? OR a.target_user_id = ?
            ORDER BY a.created_at DESC LIMIT ?
        ''', (user_id, user_id, limit))
    else:
        cursor.execute('''
            SELECT a.*, u.username as actor_username, t.username as target_username
            FROM audit_log a
            LEFT JOIN users u ON a.user_id = u.id
            LEFT JOIN users t ON a.target_user_id = t.id
            ORDER BY a.created_at DESC LIMIT ?
        ''', (limit,))

    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs


# Decorator for requiring admin role
def require_admin(f):
    """Decorator to require admin role for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import session, redirect, url_for, flash
        if not session.get('logged_in'):
            return redirect(url_for('st_home_bp.index'))
        if session.get('user_role') != ROLE_ADMIN:
            flash('Admin access required')
            return redirect(url_for('st_home_bp.home'))
        return f(*args, **kwargs)
    return decorated_function


def require_login(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import session, redirect, url_for
        if not session.get('logged_in'):
            return redirect(url_for('st_home_bp.index'))
        return f(*args, **kwargs)
    return decorated_function
