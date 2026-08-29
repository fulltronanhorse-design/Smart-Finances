"""
Database Models for Finance Tracker
Includes: Users, Transactions, Snapshots, AuditLogs, Budgets, RecurringRules
"""
from datetime import datetime
import json
import os
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from werkzeug.security import generate_password_hash, check_password_hash

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    transactions = relationship('Transaction', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    snapshots = relationship('Snapshot', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    audit_logs = relationship('AuditLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    budgets = relationship('Budget', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    recurring_rules = relationship('RecurringRule', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Transaction(Base):
    __tablename__ = 'transactions'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    date = Column(DateTime, nullable=False, index=True)
    description = Column(String(255), nullable=False)
    amount = Column(Float, nullable=False)
    category = Column(String(100), nullable=False, default='Uncategorized')
    subcategory = Column(String(100), nullable=True)
    currency = Column(String(3), default='USD')
    original_amount = Column(Float, nullable=True)  # For multi-currency
    exchange_rate = Column(Float, default=1.0)
    account_type = Column(String(50), default='Checking')  # Checking, Credit, Investment
    is_recurring = Column(Boolean, default=False)
    recurring_rule_id = Column(Integer, ForeignKey('recurring_rules.id'), nullable=True)
    receipt_path = Column(String(255), nullable=True)  # Path to uploaded receipt image
    file_import_id = Column(String(100), nullable=True, index=True)  # Track which file import this came from
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    audit_logs = relationship('AuditLog', backref='transaction', lazy='dynamic')

class Snapshot(Base):
    """Point-in-time backup for Undo functionality"""
    __tablename__ = 'snapshots'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    name = Column(String(100), nullable=False)  # e.g., "Before Bulk Edit Food"
    created_at = Column(DateTime, default=datetime.utcnow)
    data_json = Column(Text, nullable=False)  # JSON dump of affected transactions
    action_type = Column(String(50), nullable=False)  # e.g., "BULK_EDIT", "FILE_IMPORT", "DELETE"
    
    def restore_data(self):
        return json.loads(self.data_json)

class AuditLog(Base):
    """Track all changes for compliance and debugging"""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    transaction_id = Column(Integer, ForeignKey('transactions.id'), nullable=True, index=True)
    action = Column(String(50), nullable=False)  # CREATE, UPDATE, DELETE, IMPORT, RESTORE
    old_value = Column(Text, nullable=True)  # JSON of old data
    new_value = Column(Text, nullable=True)  # JSON of new data
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip_address = Column(String(45), nullable=True)
    details = Column(String(255), nullable=True)

class Budget(Base):
    __tablename__ = 'budgets'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    category = Column(String(100), nullable=False)
    amount_limit = Column(Float, nullable=False)
    period = Column(String(20), default='monthly')  # monthly, weekly, yearly
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=True)  # Null for ongoing
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def get_current_spending(self, session, current_date=None):
        if current_date is None:
            current_date = datetime.utcnow()
        
        # Calculate spending in current period
        if self.period == 'monthly':
            start = current_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            if current_date.month == 12:
                end = current_date.replace(year=current_date.year+1, month=1, day=1)
            else:
                end = current_date.replace(month=current_date.month+1, day=1)
        elif self.period == 'weekly':
            start = current_date - timedelta(days=current_date.weekday())
            start = start.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=7)
        else: # yearly
            start = current_date.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
            end = current_date.replace(year=current_date.year+1, month=1, day=1)
            
        total = session.query(func.sum(Transaction.amount)).filter(
            Transaction.user_id == self.user_id,
            Transaction.category == self.category,
            Transaction.date >= start,
            Transaction.date < end,
            Transaction.amount > 0  # Only count expenses
        ).scalar() or 0
        
        return total

class RecurringRule(Base):
    __tablename__ = 'recurring_rules'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    merchant_pattern = Column(String(100), nullable=False)  # e.g., "Netflix", "Starbucks"
    category = Column(String(100), nullable=False)
    expected_amount = Column(Float, nullable=True)  # Approximate amount
    frequency = Column(String(20), default='monthly')  # daily, weekly, monthly, yearly
    is_active = Column(Boolean, default=True)
    last_detected = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class CategoryRule(Base):
    """Custom categorization rules defined by users"""
    __tablename__ = 'category_rules'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    keyword = Column(String(100), nullable=False)
    category = Column(String(100), nullable=False)
    priority = Column(Integer, default=0)  # Higher priority rules run first
    is_regex = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# Database initialization helper
def init_db(database_url='sqlite:///finance_tracker.db'):
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()

if __name__ == '__main__':
    # Initialize DB if run directly
    session = init_db()
    print("Database initialized successfully with all tables.")
