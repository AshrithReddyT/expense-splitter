from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from dotenv import load_dotenv
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_dance.consumer import oauth_authorized
from sqlalchemy.orm.exc import NoResultFound

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')  # Use environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expenses.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Google OAuth2 configuration
app.config['GOOGLE_OAUTH_CLIENT_ID'] = os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET')

db = SQLAlchemy(app)

# Create Google OAuth blueprint
google_bp = make_google_blueprint(
    client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
    client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
    scope=['profile', 'email']
)
app.register_blueprint(google_bp, url_prefix='/login')

# Models
class OAuth(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    provider = db.Column(db.String(50), nullable=False)
    provider_user_id = db.Column(db.String(256), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('oauth_accounts', lazy=True))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(120), nullable=True)  # Made nullable for OAuth users
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

group_members = db.Table('group_members',
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    members = db.relationship('User', secondary=group_members, backref='groups')
    expenses = db.relationship('Expense', backref='group', lazy=True)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    paid_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    split_type = db.Column(db.String(20), default='equal')  # 'equal' or 'unequal'
    
    payer = db.relationship('User', backref='paid_expenses')
    splits = db.relationship('ExpenseSplit', backref='expense', lazy=True, cascade='all, delete-orphan')

class ExpenseSplit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey('expense.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    
    user = db.relationship('User', backref='expense_splits')

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    groups = user.groups
    return render_template('index.html', user=user, groups=groups)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/groups')
def groups():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('groups.html', groups=user.groups)

@app.route('/create_group', methods=['GET', 'POST'])
def create_group():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        member_ids = request.form.getlist('members')
        
        group = Group(
            name=name,
            description=description,
            created_by=session['user_id']
        )
        
        # Add creator to group
        creator = User.query.get(session['user_id'])
        group.members.append(creator)
        
        # Add selected members
        for member_id in member_ids:
            if member_id != str(session['user_id']):  # Don't add creator twice
                member = User.query.get(int(member_id))
                if member:
                    group.members.append(member)
        
        db.session.add(group)
        db.session.commit()
        
        flash('Group created successfully!', 'success')
        return redirect(url_for('groups'))
    
    users = User.query.filter(User.id != session['user_id']).all()
    return render_template('create_group.html', users=users)

@app.route('/group/<int:group_id>')
def group_detail(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    group = Group.query.get_or_404(group_id)
    user = User.query.get(session['user_id'])
    
    # Check if user is member of group
    if user not in group.members:
        flash('You are not a member of this group!', 'error')
        return redirect(url_for('groups'))
    
    expenses = Expense.query.filter_by(group_id=group_id).order_by(Expense.created_at.desc()).all()
    balances = calculate_balances(group_id)
    
    return render_template('group_detail.html', group=group, expenses=expenses, balances=balances)

@app.route('/add_expense/<int:group_id>', methods=['GET', 'POST'])
def add_expense(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    group = Group.query.get_or_404(group_id)
    user = User.query.get(session['user_id'])
    
    if user not in group.members:
        flash('You are not a member of this group!', 'error')
        return redirect(url_for('groups'))
    
    if request.method == 'POST':
        title = request.form['title']
        amount = float(request.form['amount'])
        description = request.form.get('description', '')
        split_type = request.form['split_type']
        
        expense = Expense(
            title=title,
            amount=amount,
            description=description,
            paid_by=session['user_id'],
            group_id=group_id,
            split_type=split_type
        )
        
        db.session.add(expense)
        db.session.flush()  # Get expense.id
        
        if split_type == 'equal':
            # Split equally among all members
            split_amount = amount / len(group.members)
            for member in group.members:
                split = ExpenseSplit(
                    expense_id=expense.id,
                    user_id=member.id,
                    amount=split_amount
                )
                db.session.add(split)
        else:  # unequal
            # Get custom amounts from form
            total_split = 0
            for member in group.members:
                custom_amount = float(request.form.get(f'amount_{member.id}', 0))
                if custom_amount > 0:
                    split = ExpenseSplit(
                        expense_id=expense.id,
                        user_id=member.id,
                        amount=custom_amount
                    )
                    db.session.add(split)
                    total_split += custom_amount
            
            # Validate that splits add up to total amount
            if abs(total_split - amount) > 0.01:
                db.session.rollback()
                flash(f'Split amounts ({total_split:.2f}) must equal total amount ({amount:.2f})!', 'error')
                return render_template('add_expense.html', group=group)
        
        db.session.commit()
        flash('Expense added successfully!', 'success')
        return redirect(url_for('group_detail', group_id=group_id))
    
    return render_template('add_expense.html', group=group)

def calculate_balances(group_id):
    """Calculate who owes whom in a group"""
    group = Group.query.get(group_id)
    balances = {}
    
    # Initialize balances
    for member in group.members:
        balances[member.id] = {'user': member, 'balance': 0.0}
    
    # Calculate net balance for each user
    expenses = Expense.query.filter_by(group_id=group_id).all()
    
    for expense in expenses:
        # Person who paid gets credited
        balances[expense.paid_by]['balance'] += expense.amount
        
        # Each person who owes gets debited their share
        for split in expense.splits:
            balances[split.user_id]['balance'] -= split.amount
    
    return balances

@app.route('/settlements/<int:group_id>')
def settlements(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    group = Group.query.get_or_404(group_id)
    user = User.query.get(session['user_id'])
    
    if user not in group.members:
        flash('You are not a member of this group!', 'error')
        return redirect(url_for('groups'))
    
    balances = calculate_balances(group_id)
    settlements = calculate_settlements(balances)
    
    return render_template('settlements.html', group=group, settlements=settlements)

def calculate_settlements(balances):
    """Calculate optimal settlements to minimize transactions"""
    # Separate creditors (positive balance) and debtors (negative balance)
    creditors = []
    debtors = []
    
    for user_id, data in balances.items():
        balance = data['balance']
        if balance > 0.01:  # Creditor (someone owes them)
            creditors.append({'user': data['user'], 'amount': balance})
        elif balance < -0.01:  # Debtor (they owe someone)
            debtors.append({'user': data['user'], 'amount': -balance})
    
    settlements = []
    
    # Match debtors with creditors
    i, j = 0, 0
    while i < len(debtors) and j < len(creditors):
        debtor = debtors[i]
        creditor = creditors[j]
        
        # Settle the smaller amount
        settle_amount = min(debtor['amount'], creditor['amount'])
        
        settlements.append({
            'from_user': debtor['user'],
            'to_user': creditor['user'],
            'amount': settle_amount
        })
        
        # Update amounts
        debtor['amount'] -= settle_amount
        creditor['amount'] -= settle_amount
        
        # Move to next debtor or creditor if current one is settled
        if debtor['amount'] == 0:
            i += 1
        if creditor['amount'] == 0:
            j += 1
    
    return settlements

def init_db():
    """Initialize the database with all tables"""
    with app.app_context():
        db.create_all()
        print("Database initialized successfully!")

# Add OAuth callback handler
@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", category="error")
        return False

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", category="error")
        return False

    google_info = resp.json()
    google_user_id = google_info["id"]

    # Find this OAuth token in the database, or create it
    query = OAuth.query.filter_by(
        provider=blueprint.name,
        provider_user_id=google_user_id,
    )
    try:
        oauth = query.one()
    except NoResultFound:
        # See if the user exists
        user = User.query.filter_by(email=google_info["email"]).first()
        if not user:
            # Create new user
            user = User(
                username=google_info["email"].split('@')[0],
                email=google_info["email"]
            )
            db.session.add(user)
            db.session.flush()

        # Create OAuth token
        oauth = OAuth(
            provider=blueprint.name,
            provider_user_id=google_user_id,
            user_id=user.id,
        )
        db.session.add(oauth)
        db.session.commit()

    # Log in the user
    session['user_id'] = oauth.user.id
    flash("Successfully signed in with Google.")
    return False

if __name__ == '__main__':
    with app.app_context():
        init_db()  # Initialize database first
    app.run(debug=True)