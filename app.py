from flask import Flask, request, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime, timedelta
from email_validator import validate_email, EmailNotValidError
import secrets
from models import db, Admin, Opportunity, PasswordResetToken

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-to-a-random-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///qatar_admin.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# US-1.1 Admin Sign Up
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    full_name = data.get('full_name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    confirm_password = data.get('confirm_password', '')

    if not all([full_name, email, password, confirm_password]):
        return jsonify({'error': 'All fields are required'}), 400
    
    try:
        validate_email(email)
    except EmailNotValidError:
        return jsonify({'error': 'Invalid email format'}), 400
    
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400
    
    if Admin.query.filter_by(email=email).first():
        return jsonify({'error': 'Account already exists'}), 409
    
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_admin = Admin(full_name=full_name, email=email, password_hash=password_hash)
    db.session.add(new_admin)
    db.session.commit()
    
    return jsonify({'message': 'Account created successfully'}), 201

# US-1.2 Admin Login
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    remember = data.get('remember', False)

    admin = Admin.query.filter_by(email=email).first()
    
    if not admin or not bcrypt.check_password_hash(admin.password_hash, password):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    login_user(admin, remember=remember)
    return jsonify({'message': 'Logged in successfully', 'admin': {'id': admin.id, 'name': admin.full_name}}), 200

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out'}), 200

# US-1.3 Forgot Password
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    admin = Admin.query.filter_by(email=email).first()

    # Always show same message for privacy
    if admin:
        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + timedelta(hours=1)
        reset_token = PasswordResetToken(admin_id=admin.id, token=token, expires_at=expires)
        db.session.add(reset_token)
        db.session.commit()
        # Log internally instead of sending email
        print(f"Password reset link: /api/reset-password/{token}")
    
    return jsonify({'message': 'If that email exists, a reset link has been sent'}), 200

# US-2.1 View All Opportunities
@app.route('/api/opportunities', methods=['GET'])
@login_required
def get_opportunities():
    opps = Opportunity.query.filter_by(admin_id=current_user.id).order_by(Opportunity.created_at.desc()).all()
    return jsonify([{
        'id': o.id,
        'opportunity_name': o.opportunity_name,
        'category': o.category,
        'duration': o.duration,
        'start_date': o.start_date.isoformat(),
        'description': o.description
    } for o in opps]), 200

# US-2.2 Add a New Opportunity
@app.route('/api/opportunities', methods=['POST'])
@login_required
def create_opportunity():
    data = request.get_json()
    required = ['opportunity_name', 'duration', 'start_date', 'description', 'skills_to_gain', 'category', 'future_opportunities']
    
    if any(not data.get(f) for f in required):
        return jsonify({'error': 'All required fields must be filled'}), 400
    
    try:
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid start date format'}), 400

    opp = Opportunity(
        admin_id=current_user.id,
        opportunity_name=data['opportunity_name'],
        duration=data['duration'],
        start_date=start_date,
        description=data['description'],
        skills_to_gain=data['skills_to_gain'],
        category=data['category'],
        future_opportunities=data['future_opportunities'],
        max_applicants=data.get('max_applicants')
    )
    db.session.add(opp)
    db.session.commit()
    
    return jsonify({'message': 'Opportunity created', 'id': opp.id}), 201

# US-2.4 View Opportunity Details
@app.route('/api/opportunities/<int:opp_id>', methods=['GET'])
@login_required
def get_opportunity(opp_id):
    opp = Opportunity.query.filter_by(id=opp_id, admin_id=current_user.id).first()
    if not opp:
        return jsonify({'error': 'Not found'}), 404
    
    return jsonify({
        'id': opp.id,
        'opportunity_name': opp.opportunity_name,
        'duration': opp.duration,
        'start_date': opp.start_date.isoformat(),
        'description': opp.description,
        'skills_to_gain': opp.skills_to_gain,
        'category': opp.category,
        'future_opportunities': opp.future_opportunities,
        'max_applicants': opp.max_applicants
    }), 200

# US-2.5 Edit an Opportunity
@app.route('/api/opportunities/<int:opp_id>', methods=['PUT'])
@login_required
def update_opportunity(opp_id):
    opp = Opportunity.query.filter_by(id=opp_id, admin_id=current_user.id).first()
    if not opp:
        return jsonify({'error': 'Not found'}), 404
    
    data = request.get_json()
    required = ['opportunity_name', 'duration', 'start_date', 'description', 'skills_to_gain', 'category', 'future_opportunities']
    
    if any(not data.get(f) for f in required):
        return jsonify({'error': 'All required fields must be filled'}), 400
    
    try:
        opp.start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid start date format'}), 400

    opp.opportunity_name = data['opportunity_name']
    opp.duration = data['duration']
    opp.description = data['description']
    opp.skills_to_gain = data['skills_to_gain']
    opp.category = data['category']
    opp.future_opportunities = data['future_opportunities']
    opp.max_applicants = data.get('max_applicants')
    
    db.session.commit()
    return jsonify({'message': 'Opportunity updated'}), 200

# US-2.6 Delete an Opportunity
@app.route('/api/opportunities/<int:opp_id>', methods=['DELETE'])
@login_required
def delete_opportunity(opp_id):
    opp = Opportunity.query.filter_by(id=opp_id, admin_id=current_user.id).first()
    if not opp:
        return jsonify({'error': 'Not found'}), 404
    
    db.session.delete(opp)
    db.session.commit()
    return jsonify({'message': 'Opportunity deleted'}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
