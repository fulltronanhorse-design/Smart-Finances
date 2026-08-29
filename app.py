"""
Finance Tracker - Main Application
Features: Authentication, Bulk Editing, Budgets, Recurring Detection, Snapshots, Audit Logs
"""
from flask import Flask, render_template_string, request, jsonify, redirect, url_for, session, send_file, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
import json
import os
import io
import re
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///finance_tracker.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RECEIPT_FOLDER'] = 'receipts'

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RECEIPT_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define Models inline for simplicity
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    date = db.Column(db.DateTime, nullable=False, index=True)
    description = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False, default='Uncategorized')
    subcategory = db.Column(db.String(100), nullable=True)
    currency = db.Column(db.String(3), default='USD')
    original_amount = db.Column(db.Float, nullable=True)
    exchange_rate = db.Column(db.Float, default=1.0)
    account_type = db.Column(db.String(50), default='Checking')
    is_recurring = db.Column(db.Boolean, default=False)
    receipt_path = db.Column(db.String(255), nullable=True)
    file_import_id = db.Column(db.String(100), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Snapshot(db.Model):
    __tablename__ = 'snapshots'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    data_json = db.Column(db.Text, nullable=False)
    action_type = db.Column(db.String(50), nullable=False)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    transaction_id = db.Column(db.Integer, db.ForeignKey('transactions.id'), nullable=True, index=True)
    action = db.Column(db.String(50), nullable=False)
    old_value = db.Column(db.Text, nullable=True)
    new_value = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    details = db.Column(db.String(255), nullable=True)

class Budget(db.Model):
    __tablename__ = 'budgets'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    category = db.Column(db.String(100), nullable=False)
    amount_limit = db.Column(db.Float, nullable=False)
    period = db.Column(db.String(20), default='monthly')
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RecurringRule(db.Model):
    __tablename__ = 'recurring_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    merchant_pattern = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    expected_amount = db.Column(db.Float, nullable=True)
    frequency = db.Column(db.String(20), default='monthly')
    is_active = db.Column(db.Boolean, default=True)
    last_detected = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CategoryRule(db.Model):
    __tablename__ = 'category_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    keyword = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    priority = db.Column(db.Integer, default=0)
    is_regex = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper: Create audit log entry
def log_audit(action, old_value=None, new_value=None, transaction_id=None, details=None):
    audit = AuditLog(
        user_id=current_user.id,
        action=action,
        old_value=json.dumps(old_value) if old_value else None,
        new_value=json.dumps(new_value) if new_value else None,
        transaction_id=transaction_id,
        details=details,
        ip_address=request.remote_addr
    )
    db.session.add(audit)
    db.session.commit()

# Helper: Create snapshot for undo
def create_snapshot(name, action_type, transactions_data):
    snapshot = Snapshot(
        user_id=current_user.id,
        name=name,
        action_type=action_type,
        data_json=json.dumps(transactions_data)
    )
    db.session.add(snapshot)
    db.session.commit()
    return snapshot

# Auth Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            log_audit('LOGIN', details=f'User {username} logged in')
            return redirect(next_page or url_for('dashboard'))
        flash('Invalid username or password', 'error')
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Login - Finance Tracker</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
    <div class="bg-white p-8 rounded-lg shadow-md w-96">
        <h1 class="text-2xl font-bold mb-6 text-center text-gray-800">Finance Tracker</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="mb-4 p-3 rounded {% if category == 'error' %}bg-red-100 text-red-700{% else %}bg-blue-100 text-blue-700{% endif %}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST">
            <div class="mb-4">
                <label class="block text-gray-700 mb-2">Username</label>
                <input type="text" name="username" required class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            <div class="mb-6">
                <label class="block text-gray-700 mb-2">Password</label>
                <input type="password" name="password" required class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700">Login</button>
        </form>
        <p class="mt-4 text-center text-gray-600">
            Don't have an account? <a href="/signup" class="text-blue-600 hover:underline">Sign up</a>
        </p>
        <p class="mt-2 text-center text-xs text-gray-500">Default: admin / admin123</p>
    </div>
</body>
</html>
    ''')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))
            
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        log_audit('SIGNUP', new_value={'username': username, 'email': email}, details='New user registered')
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Sign Up - Finance Tracker</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center">
    <div class="bg-white p-8 rounded-lg shadow-md w-96">
        <h1 class="text-2xl font-bold mb-6 text-center text-gray-800">Create Account</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="mb-4 p-3 rounded {% if category == 'error' %}bg-red-100 text-red-700{% else %}bg-blue-100 text-blue-700{% endif %}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST">
            <div class="mb-4">
                <label class="block text-gray-700 mb-2">Username</label>
                <input type="text" name="username" required class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            <div class="mb-4">
                <label class="block text-gray-700 mb-2">Email</label>
                <input type="email" name="email" required class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            <div class="mb-6">
                <label class="block text-gray-700 mb-2">Password</label>
                <input type="password" name="password" required class="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700">Sign Up</button>
        </form>
        <p class="mt-4 text-center text-gray-600">
            Already have an account? <a href="/login" class="text-blue-600 hover:underline">Login</a>
        </p>
    </div>
</body>
</html>
    ''')

@app.route('/logout')
@login_required
def logout():
    log_audit('LOGOUT', details=f'User {current_user.username} logged out')
    logout_user()
    return redirect(url_for('login'))

# Dashboard
@app.route('/')
@login_required
def dashboard():
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).limit(50).all()
    
    total_income = db.session.query(db.func.sum(Transaction.amount)).filter(
        Transaction.user_id == current_user.id, Transaction.amount < 0
    ).scalar() or 0
    
    total_expenses = db.session.query(db.func.sum(Transaction.amount)).filter(
        Transaction.user_id == current_user.id, Transaction.amount > 0
    ).scalar() or 0
    
    budgets = Budget.query.filter_by(user_id=current_user.id).all()
    recurring = Transaction.query.filter_by(user_id=current_user.id, is_recurring=True).order_by(Transaction.date.desc()).limit(10).all()
    
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - Finance Tracker</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-gray-50">
    <nav class="bg-white shadow-sm">
        <div class="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
            <h1 class="text-xl font-bold text-gray-800">Finance Tracker</h1>
            <div class="flex items-center space-x-4">
                <span class="text-gray-600">Welcome, {{ current_user.username }}</span>
                <a href="/logout" class="text-red-600 hover:underline">Logout</a>
            </div>
        </div>
    </nav>
    
    <div class="max-w-7xl mx-auto px-4 py-8">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-white p-6 rounded-lg shadow">
                <h3 class="text-gray-600 text-sm">Total Income</h3>
                <p class="text-3xl font-bold text-green-600">${{ "%.2f"|format(total_income|abs) }}</p>
            </div>
            <div class="bg-white p-6 rounded-lg shadow">
                <h3 class="text-gray-600 text-sm">Total Expenses</h3>
                <p class="text-3xl font-bold text-red-600">${{ "%.2f"|format(total_expenses) }}</p>
            </div>
            <div class="bg-white p-6 rounded-lg shadow">
                <h3 class="text-gray-600 text-sm">Net Savings</h3>
                <p class="text-3xl font-bold {% if (total_income|abs - total_expenses) >= 0 %}text-green-600{% else %}text-red-600{% endif %}">${{ "%.2f"|format(total_income|abs - total_expenses) }}</p>
            </div>
        </div>
        
        <div class="bg-white rounded-lg shadow mb-8">
            <div class="p-6 border-b">
                <h2 class="text-lg font-semibold">Recent Transactions</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Date</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Category</th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Amount</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200">
                        {% for tx in transactions %}
                        <tr>
                            <td class="px-6 py-4 text-sm text-gray-900">{{ tx.date.strftime('%Y-%m-%d') }}</td>
                            <td class="px-6 py-4 text-sm text-gray-900">{{ tx.description }}</td>
                            <td class="px-6 py-4"><span class="px-2 py-1 text-xs rounded-full bg-blue-100 text-blue-800">{{ tx.category }}</span></td>
                            <td class="px-6 py-4 text-sm text-right {% if tx.amount > 0 %}text-red-600{% else %}text-green-600{% endif %}">${{ "%.2f"|format(tx.amount|abs) }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-white p-6 rounded-lg shadow">
                <h3 class="font-semibold mb-4">Budgets</h3>
                {% if budgets %}
                    {% for budget in budgets %}
                    <div class="mb-4">
                        <div class="flex justify-between text-sm mb-1">
                            <span>{{ budget.category }}</span>
                            <span>${{ "%.2f"|format(budget.amount_limit) }}</span>
                        </div>
                        <div class="w-full bg-gray-200 rounded-full h-2">
                            <div class="bg-blue-600 h-2 rounded-full" style="width: 50%"></div>
                        </div>
                    </div>
                    {% endfor %}
                {% else %}
                    <p class="text-gray-500 text-sm">No budgets set. <a href="/budgets" class="text-blue-600">Create one</a></p>
                {% endif %}
            </div>
            
            <div class="bg-white p-6 rounded-lg shadow">
                <h3 class="font-semibold mb-4">Quick Actions</h3>
                <div class="space-y-2">
                    <a href="/upload" class="block w-full bg-blue-600 text-white text-center py-2 rounded hover:bg-blue-700">Upload Statement</a>
                    <a href="/export" class="block w-full bg-green-600 text-white text-center py-2 rounded hover:bg-green-700">Export Data</a>
                    <a href="/budgets" class="block w-full bg-purple-600 text-white text-center py-2 rounded hover:bg-purple-700">Manage Budgets</a>
                    <a href="/audit" class="block w-full bg-gray-600 text-white text-center py-2 rounded hover:bg-gray-700">View Audit Log</a>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
    ''', total_income=total_income, total_expenses=total_expenses, transactions=transactions, budgets=budgets, recurring=recurring)

# Upload Route
@app.route('/upload')
@login_required
def upload():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Upload - Finance Tracker</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50">
    <nav class="bg-white shadow-sm">
        <div class="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
            <h1 class="text-xl font-bold text-gray-800">Finance Tracker</h1>
            <a href="/" class="text-blue-600 hover:underline">Back to Dashboard</a>
        </div>
    </nav>
    
    <div class="max-w-4xl mx-auto px-4 py-8">
        <div class="bg-white rounded-lg shadow p-8">
            <h2 class="text-2xl font-bold mb-6">Upload Bank Statement</h2>
            
            <div id="drop-zone" class="border-2 border-dashed border-gray-300 rounded-lg p-12 text-center hover:border-blue-500 transition-colors">
                <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m0-3v12"></path>
                </svg>
                <p class="mt-2 text-gray-600">Drag and drop your CSV or Excel file here</p>
                <p class="text-sm text-gray-500">or</p>
                <input type="file" id="file-input" accept=".csv,.xlsx,.xls" class="hidden">
                <button onclick="document.getElementById('file-input').click()" class="mt-4 bg-blue-600 text-white px-6 py-2 rounded hover:bg-blue-700">Select File</button>
            </div>
            
            <div id="preview" class="mt-8 hidden">
                <h3 class="font-semibold mb-4">Preview (First 10 rows)</h3>
                <div class="overflow-x-auto">
                    <table class="w-full text-sm">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-2 text-left">Date</th>
                                <th class="px-4 py-2 text-left">Description</th>
                                <th class="px-4 py-2 text-right">Amount</th>
                            </tr>
                        </thead>
                        <tbody id="preview-body"></tbody>
                    </table>
                </div>
                <button id="confirm-upload" class="mt-6 w-full bg-green-600 text-white py-3 rounded-lg hover:bg-green-700 font-semibold">Confirm & Process Full File</button>
            </div>
            
            <div id="status" class="mt-6 hidden">
                <div class="bg-blue-50 border border-blue-200 rounded p-4">
                    <p class="text-blue-800" id="status-text">Processing...</p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const dropZone = document.getElementById('drop-zone');
        const fileInput = document.getElementById('file-input');
        const preview = document.getElementById('preview');
        const previewBody = document.getElementById('preview-body');
        const confirmBtn = document.getElementById('confirm-upload');
        const statusDiv = document.getElementById('status');
        const statusText = document.getElementById('status-text');
        
        let currentFilename = null;
        
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('border-blue-500');
        });
        
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('border-blue-500');
        });
        
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('border-blue-500');
            const file = e.dataTransfer.files[0];
            handleFile(file);
        });
        
        fileInput.addEventListener('change', (e) => {
            handleFile(e.target.files[0]);
        });
        
        function handleFile(file) {
            const formData = new FormData();
            formData.append('file', file);
            
            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    currentFilename = data.filename;
                    showPreview(data.preview);
                } else {
                    alert('Error: ' + data.error);
                }
            });
        }
        
        function showPreview(rows) {
            previewBody.innerHTML = '';
            rows.forEach(row => {
                const tr = document.createElement('tr');
                tr.className = 'border-t';
                tr.innerHTML = `
                    <td class="px-4 py-2">${row.date}</td>
                    <td class="px-4 py-2">${row.description}</td>
                    <td class="px-4 py-2 text-right ${row.amount > 0 ? 'text-red-600' : 'text-green-600'}">$${Math.abs(row.amount).toFixed(2)}</td>
                `;
                previewBody.appendChild(tr);
            });
            preview.classList.remove('hidden');
        }
        
        confirmBtn.addEventListener('click', () => {
            if (!currentFilename) return;
            
            statusDiv.classList.remove('hidden');
            confirmBtn.disabled = true;
            
            fetch('/process/' + currentFilename, {
                method: 'POST'
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    statusText.textContent = `Success! Imported ${data.count} transactions. Redirecting...`;
                    statusText.parentElement.classList.replace('bg-blue-50', 'bg-green-50');
                    statusText.parentElement.classList.replace('border-blue-200', 'border-green-200');
                    statusText.classList.replace('text-blue-800', 'text-green-800');
                    setTimeout(() => window.location.href = '/', 2000);
                } else {
                    statusText.textContent = 'Error: ' + data.error;
                    confirmBtn.disabled = false;
                }
            });
        });
    </script>
</body>
</html>
    ''')

@app.route('/process/<filename>', methods=['POST'])
@login_required
def process_file(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
        
    try:
        if filename.endswith('.csv'):
            df = pd.read_csv(filepath)
        else:
            df = pd.read_excel(filepath)
            
        existing_transactions = Transaction.query.filter_by(user_id=current_user.id).all()
        create_snapshot(
            name=f"Before import {filename}",
            action_type="FILE_IMPORT",
            transactions_data=[{'id': t.id, 'category': t.category} for t in existing_transactions]
        )
        
        file_import_id = f"{current_user.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        imported_count = 0
        
        rules = CategoryRule.query.filter_by(user_id=current_user.id).order_by(CategoryRule.priority.desc()).all()
        
        for _, row in df.iterrows():
            date_str = str(row.iloc[0]) if len(row) > 0 else ''
            desc = str(row.iloc[1]) if len(row) > 1 else ''
            amount = float(row.iloc[2]) if len(row) > 2 else 0
            
            try:
                tx_date = pd.to_datetime(date_str)
            except:
                tx_date = datetime.utcnow()
                
            category = 'Uncategorized'
            for rule in rules:
                if rule.is_regex:
                    if re.search(rule.keyword, desc, re.IGNORECASE):
                        category = rule.category
                        break
                else:
                    if rule.keyword.lower() in desc.lower():
                        category = rule.category
                        break
            
            transaction = Transaction(
                user_id=current_user.id,
                date=tx_date,
                description=desc,
                amount=amount,
                category=category,
                account_type='Checking',
                file_import_id=file_import_id
            )
            db.session.add(transaction)
            imported_count += 1
            
        db.session.commit()
        
        log_audit('FILE_IMPORT', 
                 new_value={'filename': filename, 'count': imported_count},
                 details=f'Imported {imported_count} transactions from {filename}')
        
        return jsonify({'success': True, 'count': imported_count})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Processing error: {str(e)}'}), 500

@app.route('/bulk-edit', methods=['POST'])
@login_required
def bulk_edit():
    data = request.json
    transaction_ids = data.get('ids', [])
    new_category = data.get('category')
    
    if not transaction_ids or not new_category:
        return jsonify({'error': 'Missing data'}), 400
        
    transactions = Transaction.query.filter(
        Transaction.id.in_(transaction_ids),
        Transaction.user_id == current_user.id
    ).all()
    
    create_snapshot(
        name=f"Bulk edit to {new_category}",
        action_type="BULK_EDIT",
        transactions_data=[{'id': t.id, 'category': t.category} for t in transactions]
    )
    
    old_values = []
    for tx in transactions:
        old_values.append({'id': tx.id, 'category': tx.category})
        tx.category = new_category
        
    db.session.commit()
    
    log_audit('BULK_EDIT',
             old_value=old_values,
             new_value={'category': new_category, 'count': len(transactions)},
             details=f'Updated {len(transactions)} transactions to {new_category}')
    
    return jsonify({'success': True, 'updated': len(transactions)})

@app.route('/undo/<int:snapshot_id>', methods=['POST'])
@login_required
def undo_snapshot(snapshot_id):
    snapshot = Snapshot.query.filter_by(id=snapshot_id, user_id=current_user.id).first_or_404()
    
    data = json.loads(snapshot.data_json)
    
    for item in data:
        tx = Transaction.query.filter_by(id=item['id'], user_id=current_user.id).first()
        if tx:
            tx.category = item['category']
            
    db.session.commit()
    
    log_audit('RESTORE', old_value={'snapshot_id': snapshot_id}, details=f'Restored from snapshot: {snapshot.name}')
    
    return jsonify({'success': True})

@app.route('/budgets', methods=['GET', 'POST'])
@login_required
def manage_budgets():
    if request.method == 'POST':
        data = request.json
        budget = Budget(
            user_id=current_user.id,
            category=data['category'],
            amount_limit=float(data['limit']),
            period=data.get('period', 'monthly'),
            start_date=datetime.utcnow()
        )
        db.session.add(budget)
        db.session.commit()
        
        log_audit('BUDGET_CREATE', new_value={'category': budget.category, 'limit': budget.amount_limit})
        
        return jsonify({'success': True})
        
    budgets = Budget.query.filter_by(user_id=current_user.id).all()
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Budgets - Finance Tracker</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50">
    <nav class="bg-white shadow-sm">
        <div class="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
            <h1 class="text-xl font-bold text-gray-800">Finance Tracker</h1>
            <a href="/" class="text-blue-600 hover:underline">Back to Dashboard</a>
        </div>
    </nav>
    
    <div class="max-w-4xl mx-auto px-4 py-8">
        <div class="bg-white rounded-lg shadow p-8">
            <h2 class="text-2xl font-bold mb-6">Manage Budgets</h2>
            
            <form id="budget-form" class="mb-8 p-4 bg-gray-50 rounded">
                <div class="grid grid-cols-3 gap-4">
                    <input type="text" id="category" placeholder="Category (e.g., Food)" required class="px-3 py-2 border rounded">
                    <input type="number" id="limit" placeholder="Limit Amount" step="0.01" required class="px-3 py-2 border rounded">
                    <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">Add Budget</button>
                </div>
            </form>
            
            <div id="budgets-list">
                {% for budget in budgets %}
                <div class="flex justify-between items-center p-4 border-b">
                    <div>
                        <h3 class="font-semibold">{{ budget.category }}</h3>
                        <p class="text-sm text-gray-600">Limit: ${{ "%.2f"|format(budget.amount_limit) }} ({{ budget.period }})</p>
                    </div>
                    <span class="text-gray-500 text-sm">{{ budget.created_at.strftime('%Y-%m-%d') }}</span>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>
    
    <script>
        document.getElementById('budget-form').addEventListener('submit', (e) => {
            e.preventDefault();
            const category = document.getElementById('category').value;
            const limit = parseFloat(document.getElementById('limit').value);
            
            fetch('/budgets', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({category, limit})
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) location.reload();
            });
        });
    </script>
</body>
</html>
    ''', budgets=budgets)

@app.route('/export')
@login_required
def export_data():
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    
    data = [{
        'date': tx.date.strftime('%Y-%m-%d'),
        'description': tx.description,
        'amount': tx.amount,
        'category': tx.category,
        'currency': tx.currency
    } for tx in transactions]
    
    df = pd.DataFrame(data)
    
    output = io.BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    
    log_audit('EXPORT', details=f'Exported {len(transactions)} transactions')
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'finance_export_{datetime.utcnow().strftime("%Y%m%d")}.csv'
    )

@app.route('/audit')
@login_required
def view_audit():
    logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Audit Log - Finance Tracker</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50">
    <nav class="bg-white shadow-sm">
        <div class="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
            <h1 class="text-xl font-bold text-gray-800">Finance Tracker</h1>
            <a href="/" class="text-blue-600 hover:underline">Back to Dashboard</a>
        </div>
    </nav>
    
    <div class="max-w-6xl mx-auto px-4 py-8">
        <div class="bg-white rounded-lg shadow p-8">
            <h2 class="text-2xl font-bold mb-6">Audit Log</h2>
            
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-2 text-left">Timestamp</th>
                            <th class="px-4 py-2 text-left">Action</th>
                            <th class="px-4 py-2 text-left">Details</th>
                            <th class="px-4 py-2 text-left">IP Address</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for log in logs %}
                        <tr class="border-t">
                            <td class="px-4 py-2">{{ log.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                            <td class="px-4 py-2"><span class="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs">{{ log.action }}</span></td>
                            <td class="px-4 py-2">{{ log.details or '-' }}</td>
                            <td class="px-4 py-2 text-gray-500">{{ log.ip_address or '-' }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>
    ''', logs=logs)

# Initialize DB
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com')
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Default admin user created: admin / admin123")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
