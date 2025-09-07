import os
import sqlite3
import secrets
from contextlib import closing
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "bank.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")

def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(16)),
        DATABASE=DB_PATH
    )

    # ---- DB helpers ----
    def get_db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES)
            g.db.row_factory = sqlite3.Row
        return g.db

    def close_db(e=None):
        db = g.pop('db', None)
        if db is not None:
            db.close()

    app.teardown_appcontext(close_db)

    def init_db():
        db = get_db()
        with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
            db.executescript(f.read())
        db.commit()

    def query_one(sql, params=()):
        return get_db().execute(sql, params).fetchone()

    def query_all(sql, params=()):
        return get_db().execute(sql, params).fetchall()

    def execute(sql, params=()):
        db = get_db()
        cur = db.execute(sql, params)
        db.commit()
        return cur.lastrowid

    # ---- App bootstrap ----
    @app.before_request
    def ensure_db():
        # Initialize DB if missing
        if not os.path.exists(DB_PATH) or os.path.getsize(DB_PATH) == 0:
            init_db()

    # ---- Utilities ----
    def logged_in():
        return 'user_id' in session

    def current_user():
        if not logged_in():
            return None
        u = query_one("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        return u

    def require_login():
        if not logged_in():
            return redirect(url_for('login'))

    def require_admin():
        u = current_user()
        if not u or not u['is_admin']:
            abort(403, description="Admins only")

    def generate_account_number(user_id:int)->str:
        # Simple 12-digit pseudo account number: UID padded + random suffix
        suffix = secrets.token_hex(4)[:7].upper()
        return f"{user_id:05d}{suffix:>07}"[:12]

    # ---- Auth routes ----
    @app.route('/register', methods=['GET','POST'])
    def register():
        if request.method == 'POST':
            username = request.form.get('username','').strip()
            email = request.form.get('email','').strip().lower()
            password = request.form.get('password','')
            if not username or not email or not password:
                flash('All fields are required.', 'error')
                return render_template('register.html')
            if query_one("SELECT id FROM users WHERE username = ? OR email = ?", (username, email)):
                flash('Username or email already exists.', 'error')
                return render_template('register.html')
            pwd_hash = generate_password_hash(password)
            user_id = execute("INSERT INTO users (username, email, password_hash) VALUES (?,?,?)",
                              (username, email, pwd_hash))
            # Create a default account
            acct_no = generate_account_number(user_id)
            execute("INSERT INTO accounts (user_id, account_number, balance) VALUES (?,?,0.0)",
                    (user_id, acct_no))
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        return render_template('register.html')

    @app.route('/login', methods=['GET','POST'])
    def login():
        if request.method == 'POST':
            username = request.form.get('username','').strip()
            password = request.form.get('password','')
            user = query_one("SELECT * FROM users WHERE username = ?", (username,))
            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                flash('Logged in successfully.', 'success')
                return redirect(url_for('dashboard'))
            flash('Invalid credentials.', 'error')
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        session.clear()
        flash('Logged out.', 'info')
        return redirect(url_for('login'))

    # ---- Dashboard ----
    @app.route('/')
    def home():
        if logged_in():
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    @app.route('/dashboard')
    def dashboard():
        if not logged_in():
            return redirect(url_for('login'))
        user = current_user()
        accounts = query_all("SELECT * FROM accounts WHERE user_id = ? ORDER BY created_at DESC", (user['id'],))
        return render_template('dashboard.html', user=user, accounts=accounts)

    # ---- Account view & actions ----
    @app.route('/account/<int:account_id>')
    def view_account(account_id):
        if not logged_in():
            return redirect(url_for('login'))
        user = current_user()
        account = query_one("SELECT * FROM accounts WHERE id = ? AND user_id = ?", (account_id, user['id']))
        if not account:
            abort(404)
        txns = query_all("SELECT * FROM transactions WHERE account_id = ? ORDER BY created_at DESC LIMIT 50", (account_id,))
        return render_template('account.html', account=account, txns=txns)

    @app.route('/deposit/<int:account_id>', methods=['POST'])
    def deposit(account_id):
        if not logged_in():
            return redirect(url_for('login'))
        amount = float(request.form.get('amount','0') or 0)
        if amount <= 0:
            flash('Amount must be positive.', 'error')
            return redirect(url_for('view_account', account_id=account_id))
        user = current_user()
        account = query_one("SELECT * FROM accounts WHERE id = ? AND user_id = ?", (account_id, user['id']))
        if not account:
            abort(404)
        new_balance = account['balance'] + amount
        execute("UPDATE accounts SET balance = ? WHERE id = ?", (new_balance, account_id))
        execute("INSERT INTO transactions (account_id, kind, amount, description) VALUES (?,?,?,?)",
                (account_id, 'deposit', amount, 'Cash deposit'))
        flash('Deposit successful.', 'success')
        return redirect(url_for('view_account', account_id=account_id))

    @app.route('/withdraw/<int:account_id>', methods=['POST'])
    def withdraw(account_id):
        if not logged_in():
            return redirect(url_for('login'))
        amount = float(request.form.get('amount','0') or 0)
        if amount <= 0:
            flash('Amount must be positive.', 'error')
            return redirect(url_for('view_account', account_id=account_id))
        user = current_user()
        account = query_one("SELECT * FROM accounts WHERE id = ? AND user_id = ?", (account_id, user['id']))
        if not account:
            abort(404)
        if account['balance'] < amount:
            flash('Insufficient funds.', 'error')
            return redirect(url_for('view_account', account_id=account_id))
        new_balance = account['balance'] - amount
        execute("UPDATE accounts SET balance = ? WHERE id = ?", (new_balance, account_id))
        execute("INSERT INTO transactions (account_id, kind, amount, description) VALUES (?,?,?,?)",
                (account_id, 'withdraw', amount, 'Cash withdrawal'))
        flash('Withdrawal successful.', 'success')
        return redirect(url_for('view_account', account_id=account_id))

    @app.route('/transfer', methods=['GET','POST'])
    def transfer():
        if not logged_in():
            return redirect(url_for('login'))
        user = current_user()
        user_accounts = query_all("SELECT * FROM accounts WHERE user_id = ?", (user['id'],))
        if request.method == 'POST':
            from_id = int(request.form.get('from_account'))
            to_account_number = request.form.get('to_account','').strip()
            amount = float(request.form.get('amount','0') or 0)
            if amount <= 0:
                flash('Amount must be positive.', 'error')
                return render_template('transfer.html', accounts=user_accounts)
            from_acct = query_one("SELECT * FROM accounts WHERE id = ? AND user_id = ?", (from_id, user['id']))
            if not from_acct:
                flash('Invalid source account.', 'error')
                return render_template('transfer.html', accounts=user_accounts)
            to_acct = query_one("SELECT * FROM accounts WHERE account_number = ?", (to_account_number,))
            if not to_acct:
                flash('Destination account not found.', 'error')
                return render_template('transfer.html', accounts=user_accounts)
            if from_acct['balance'] < amount:
                flash('Insufficient funds.', 'error')
                return render_template('transfer.html', accounts=user_accounts)

            # Perform transfer atomically
            db = get_db()
            try:
                db.execute("BEGIN")
                # debit
                db.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?", (amount, from_acct['id']))
                db.execute("INSERT INTO transactions (account_id, kind, amount, description, related_account) VALUES (?,?,?,?,?)",
                           (from_acct['id'], 'transfer-out', amount, f'Transfer to {to_acct["account_number"]}', to_acct["account_number"]))
                # credit
                db.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?", (amount, to_acct['id']))
                db.execute("INSERT INTO transactions (account_id, kind, amount, description, related_account) VALUES (?,?,?,?,?)",
                           (to_acct['id'], 'transfer-in', amount, f'Transfer from {from_acct["account_number"]}', from_acct["account_number"]))
                db.commit()
            except Exception as e:
                db.rollback()
                flash('Transfer failed. Try again.', 'error')
                return render_template('transfer.html', accounts=user_accounts)

            flash('Transfer successful.', 'success')
            return redirect(url_for('dashboard'))
        return render_template('transfer.html', accounts=user_accounts)

    # ---- Admin ----
    @app.route('/admin')
    def admin_panel():
        if not logged_in():
            return redirect(url_for('login'))
        require_admin()
        users = query_all("SELECT id, username, email, is_admin, created_at FROM users ORDER BY created_at DESC")
        accounts = query_all("SELECT a.*, u.username FROM accounts a JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC")
        return render_template('admin.html', users=users, accounts=accounts)

    # ---- Create additional account ----
    @app.route('/account/create', methods=['POST'])
    def create_account():
        if not logged_in():
            return redirect(url_for('login'))
        user = current_user()
        acct_no = generate_account_number(user['id'])
        execute("INSERT INTO accounts (user_id, account_number, balance) VALUES (?,?,0.0)",
                (user['id'], acct_no))
        flash('New account created.', 'success')
        return redirect(url_for('dashboard'))

    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
