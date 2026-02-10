from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import os, hashlib, yara, math, datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyber_security_pro_secret_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyber_vault.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- DATABASE MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_biometric_enabled = db.Column(db.Boolean, default=False) # For the Fingerprint feature
    scans = db.relationship('ScanHistory', backref='owner', lazy=True)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    risk = db.Column(db.Integer)
    entropy = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- SCANNER LOGIC ---
try:
    rules = yara.compile(filepath='my_rules.yar')
except:
    rules = None

def calculate_entropy(data):
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

# --- ROUTES ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=request.form['username'], password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created! You can now login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Check username/password', 'danger')
    return render_template('login.html')

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    result = None
    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            data = file.read()
            entropy = round(calculate_entropy(data), 2)
            matches = [str(m) for m in rules.match(data=data)]
            
            risk = 10
            if entropy > 7.2: risk += 40
            if matches: risk += 50
            if risk > 100: risk = 100

            # Save to Database
            new_scan = ScanHistory(filename=file.filename, risk=risk, entropy=entropy, user_id=current_user.id)
            db.session.add(new_scan)
            db.session.commit()

            result = {
                "filename": file.filename,
                "sha256": hashlib.sha256(data).hexdigest(),
                "entropy": entropy,
                "matches": matches,
                "risk": risk
            }
    
    # Fetch history for this user
    history = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.timestamp.desc()).limit(10).all()
    return render_template('index.html', result=result, history=history)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)