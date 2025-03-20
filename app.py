from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
import smtplib
import os
from email.mime.text import MIMEText
from random import randint
import uuid
import qrcode  # For generating QR codes

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(16))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

GMAIL_USER = "kothiyal.official@gmail.com"
GMAIL_PASSWORD = "xetv zaze ckcp sfjk"

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Ensure the QR code folder exists
if not os.path.exists('static/qr_codes'):
    os.makedirs('static/qr_codes')

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    email_code = db.Column(db.String(6))
    is_admin = db.Column(db.Boolean, default=False)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    question_text = db.Column(db.String(500), nullable=False)
    option_a = db.Column(db.String(200), nullable=False)
    option_b = db.Column(db.String(200), nullable=False)
    option_c = db.Column(db.String(200), nullable=False)
    option_d = db.Column(db.String(200), nullable=False)
    correct_answer = db.Column(db.String(200), nullable=False)

class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    exam_type = db.Column(db.String(50), nullable=False)
    is_free = db.Column(db.Boolean, default=False)
    price = db.Column(db.Integer, nullable=True)  # Price in INR, nullable for free tests
    questions = db.relationship('Question', backref='test', lazy=True)

class UserTestAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    has_access = db.Column(db.Boolean, default=False)
    payment_proof = db.Column(db.String(200))
    payment_verified = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize the database and create sample data
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='anujkothiyal01@gmail.com').first():
        hashed_pw = bcrypt.hashpw('Kothiyal@123'.encode('utf-8'), bcrypt.gensalt())
        admin = User(email='anujkothiyal01@gmail.com', password=hashed_pw, email_verified=True, is_admin=True)
        db.session.add(admin)
        db.session.commit()

    if not Test.query.filter_by(exam_type='aws_cloud_practitioner').first():
        for i in range(1, 11):
            is_free = i <= 2
            price = None if is_free else 49 + (i - 3) * 10  # Free tests have no price, others start at ₹500 and increase by ₹50
            test = Test(name=f"Practice Test {i}", exam_type='aws_cloud_practitioner', is_free=is_free, price=price)
            db.session.add(test)
            db.session.commit()

            questions = [
                Question(test_id=test.id,
                         question_text=f"What is the primary benefit of cloud computing over traditional on-premises infrastructure? (Test {i})",
                         option_a='Higher upfront costs', option_b='Fixed capacity with no scalability',
                         option_c='On-demand scalability and flexibility',
                         option_d='Complete control over physical hardware',
                         correct_answer='On-demand scalability and flexibility'),
                Question(test_id=test.id,
                         question_text=f"Which AWS service is an example of Infrastructure as a Service (IaaS)? (Test {i})",
                         option_a='AWS Lambda', option_b='Amazon EC2', option_c='Amazon RDS', option_d='Amazon S3',
                         correct_answer='Amazon EC2'),
                Question(test_id=test.id,
                         question_text=f"What does the AWS Global Infrastructure consist of? (Test {i})",
                         option_a='Regions, Availability Zones, and Edge Locations',
                         option_b='Data centers, servers, and virtual machines',
                         option_c='S3 buckets, EC2 instances, and Lambda functions',
                         option_d='IAM users, groups, and policies',
                         correct_answer='Regions, Availability Zones, and Edge Locations'),
                Question(test_id=test.id, question_text=f"What is the purpose of an AWS Region? (Test {i})",
                         option_a='To provide low-latency content delivery',
                         option_b='To isolate resources in a geographic area',
                         option_c='To manage user access and permissions',
                         option_d='To automatically scale compute resources',
                         correct_answer='To isolate resources in a geographic area'),
                Question(test_id=test.id,
                         question_text=f"How many Availability Zones are typically in an AWS Region? (Test {i})",
                         option_a='One', option_b='Two', option_c='At least three', option_d='Ten',
                         correct_answer='At least three'),
                Question(test_id=test.id, question_text=f"What is the role of Edge Locations in AWS? (Test {i})",
                         option_a='To host EC2 instances', option_b='To cache content closer to users',
                         option_c='To store relational databases', option_d='To manage IAM policies',
                         correct_answer='To cache content closer to users'),
                Question(test_id=test.id,
                         question_text=f"Which AWS service aligns with the Platform as a Service (PaaS) model? (Test {i})",
                         option_a='Amazon EC2', option_b='AWS Elastic Beanstalk', option_c='Amazon S3',
                         option_d='AWS Lambda',
                         correct_answer='AWS Elastic Beanstalk'),
                Question(test_id=test.id,
                         question_text=f"What is a key benefit of the AWS Shared Responsibility Model? (Test {i})",
                         option_a='AWS manages all aspects of security',
                         option_b='Customers are responsible for physical hardware',
                         option_c='It clarifies security responsibilities between AWS and the customer',
                         option_d='Customers do not need to manage data encryption',
                         correct_answer='It clarifies security responsibilities between AWS and the customer'),
                Question(test_id=test.id,
                         question_text=f"Which of the following is a benefit of using AWS Cloud? (Test {i})",
                         option_a='Fixed costs with no flexibility', option_b='Pay-as-you-go pricing model',
                         option_c='Requires long-term hardware contracts', option_d='Limited scalability',
                         correct_answer='Pay-as-you-go pricing model'),
                Question(test_id=test.id,
                         question_text=f"What does the AWS Well-Architected Framework help with? (Test {i})",
                         option_a='Managing user access', option_b='Building secure, efficient, and reliable systems',
                         option_c='Calculating monthly AWS bills', option_d='Automating database backups',
                         correct_answer='Building secure, efficient, and reliable systems'),
                Question(test_id=test.id,
                         question_text=f"Which pillar of the AWS Well-Architected Framework focuses on recovering from disruptions? (Test {i})",
                         option_a='Security', option_b='Reliability', option_c='Performance Efficiency',
                         option_d='Cost Optimization',
                         correct_answer='Reliability'),
                Question(test_id=test.id, question_text=f"What is the main purpose of AWS CloudFormation? (Test {i})",
                         option_a='To monitor application performance',
                         option_b='To provision and manage infrastructure as code',
                         option_c='To store large amounts of data', option_d='To manage user authentication',
                         correct_answer='To provision and manage infrastructure as code'),
                Question(test_id=test.id,
                         question_text=f"Which AWS service is best for achieving global content delivery with low latency? (Test {i})",
                         option_a='Amazon S3', option_b='Amazon CloudFront', option_c='AWS Direct Connect',
                         option_d='Amazon EC2',
                         correct_answer='Amazon CloudFront'),
                Question(test_id=test.id,
                         question_text=f"In the AWS Shared Responsibility Model, what is the customer responsible for? (Test {i})",
                         option_a='Patching the hypervisor', option_b='Securing the physical data center',
                         option_c='Encrypting data at rest', option_d='Managing the AWS global infrastructure',
                         correct_answer='Encrypting data at rest'),
                Question(test_id=test.id,
                         question_text=f"Which AWS service is used to manage user access and permissions? (Test {i})",
                         option_a='AWS Shield', option_b='AWS IAM', option_c='Amazon CloudWatch', option_d='AWS Config',
                         correct_answer='AWS IAM'),
                Question(test_id=test.id, question_text=f"What does an IAM policy define? (Test {i})",
                         option_a='The physical location of AWS resources',
                         option_b='Permissions for AWS users, groups, or roles',
                         option_c='The cost of AWS services', option_d='The scaling rules for EC2 instances',
                         correct_answer='Permissions for AWS users, groups, or roles'),
                Question(test_id=test.id,
                         question_text=f"Which AWS service helps protect against Distributed Denial of Service (DDoS) attacks? (Test {i})",
                         option_a='AWS Shield', option_b='AWS Inspector', option_c='AWS Trusted Advisor',
                         option_d='AWS Config',
                         correct_answer='AWS Shield'),
                Question(test_id=test.id,
                         question_text=f"What is the purpose of AWS Key Management Service (KMS)? (Test {i})",
                         option_a='To monitor application logs', option_b='To manage encryption keys',
                         option_c='To scale compute resources', option_d='To track resource configurations',
                         correct_answer='To manage encryption keys'),
                Question(test_id=test.id,
                         question_text=f"Which AWS service provides a centralized way to manage SSL/TLS certificates? (Test {i})",
                         option_a='AWS Certificate Manager', option_b='AWS Secrets Manager',
                         option_c='AWS License Manager', option_d='AWS Data Lifecycle Manager',
                         correct_answer='AWS Certificate Manager'),
                Question(test_id=test.id, question_text=f"What is the purpose of AWS Artifact? (Test {i})",
                         option_a='To store application artifacts',
                         option_b='To provide on-demand access to compliance reports',
                         option_c='To manage user authentication', option_d='To monitor network traffic',
                         correct_answer='To provide on-demand access to compliance reports')
            ]
            db.session.bulk_save_objects(questions)
            db.session.commit()

# Email sending function
def send_email_otp(email, otp):
    try:
        if not GMAIL_USER or not GMAIL_PASSWORD:
            raise ValueError("Gmail credentials are not set. Please set GMAIL_USER and GMAIL_PASSWORD environment variables.")
        msg = MIMEText(f'Your CloudPrep OTP is: {otp}')
        msg['Subject'] = 'CloudPrep Email Verification'
        msg['From'] = GMAIL_USER
        msg['To'] = email
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(GMAIL_USER, GMAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        flash(f"Failed to send OTP email. Error: {str(e)}")
        return False

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.checkpw(password, user.password) and user.email_verified:
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login failed. Check credentials or verify email.')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        if User.query.filter_by(email=email).first():
            flash('Email already exists.')
            return render_template('signup.html')
        email_code = str(randint(100000, 999999))
        if not send_email_otp(email, email_code):
            flash('Failed to send OTP email. Check your email address.')
            return render_template('signup.html')
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        user = User(email=email, password=hashed_password, email_code=email_code)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('verify', user_id=user.id))
    return render_template('signup.html')

@app.route('/verify/<int:user_id>', methods=['GET', 'POST'])
def verify(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        email_code = request.form['email_code']
        if email_code == user.email_code:
            user.email_verified = True
            user.email_code = None
            db.session.commit()
            flash('Email verified successfully! Please log in.')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code.')
    return render_template('verify.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/tests/<exam_type>')
@login_required
def tests(exam_type):
    tests = Test.query.filter_by(exam_type=exam_type).all()
    user_access = {access.test_id: access for access in UserTestAccess.query.filter_by(user_id=current_user.id).all()}
    return render_template('tests.html', exam_type=exam_type, tests=tests, user_access=user_access)

@app.route('/checkout/<int:test_id>', methods=['GET', 'POST'])
@login_required
def checkout(test_id):
    test = Test.query.get_or_404(test_id)
    if test.is_free:
        access = UserTestAccess(user_id=current_user.id, test_id=test.id, has_access=True, payment_verified=True)
        db.session.add(access)
        db.session.commit()
        flash('Access granted to free test!')
        return redirect(url_for('tests', exam_type=test.exam_type))

    # Use the price from the Test model
    price = test.price

    # Generate UPI payment link
    upi_id = "9997305983@ptsbi"
    upi_link = f"upi://pay?pa={upi_id}&pn=CloudPrep&am={price}&cu=INR"

    # Generate QR code for the UPI link
    qr_code_path = f"static/qr_codes/test_{test_id}_qr.png"
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(upi_link)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img.save(qr_code_path)

    if request.method == 'POST':
        if 'payment_proof' not in request.files:
            flash('No file uploaded.')
            return redirect(request.url)
        file = request.files['payment_proof']
        if file.filename == '':
            flash('No file selected.')
            return redirect(request.url)
        if file:
            filename = f"{uuid.uuid4()}_{file.filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            access = UserTestAccess.query.filter_by(user_id=current_user.id, test_id=test.id).first()
            if not access:
                access = UserTestAccess(user_id=current_user.id, test_id=test.id, payment_proof=file_path)
                db.session.add(access)
            else:
                access.payment_proof = file_path
            db.session.commit()
            flash('Payment proof uploaded! Awaiting admin verification.')
            return redirect(url_for('tests', exam_type=test.exam_type))

    return render_template('checkout.html', test=test, price=price, qr_code_path=qr_code_path)

@app.route('/test/<int:test_id>', methods=['GET', 'POST'])
@login_required
def take_test(test_id):
    test = Test.query.get_or_404(test_id)
    access = UserTestAccess.query.filter_by(user_id=current_user.id, test_id=test.id).first()

    if not test.is_free and (not access or not access.has_access or not access.payment_verified):
        flash('You need to purchase access to this test and have it verified.')
        return redirect(url_for('tests', exam_type=test.exam_type))

    questions = Question.query.filter_by(test_id=test.id).all()
    if not questions:
        flash('No questions available for this test yet.')
        return redirect(url_for('tests', exam_type=test.exam_type))

    exam_duration = 1800

    if request.method == 'POST':
        score = 0
        total = len(questions)
        user_answers = []

        for q in questions:
            user_answer = request.form.get(f'question_{q.id}')
            is_correct = user_answer == q.correct_answer
            if is_correct:
                score += 1
            user_answers.append({
                'question_text': q.question_text,
                'user_answer': user_answer,
                'correct_answer': q.correct_answer,
                'is_correct': is_correct
            })

        return render_template('results.html', score=score, total=total, user_answers=user_answers, exam_type=test.exam_type)

    return render_template('test.html', questions=questions, exam_type=test.exam_type, exam_duration=exam_duration, test_name=test.name)

@app.route('/admin/verify_payments', methods=['GET', 'POST'])
@login_required
def verify_payments():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home'))

    if request.method == 'POST':
        access_id = request.form['access_id']
        action = request.form['action']
        access = UserTestAccess.query.get_or_404(access_id)
        if action == 'approve':
            access.has_access = True
            access.payment_verified = True
            flash('Payment verified! User granted access.')
        elif action == 'reject':
            access.has_access = False
            access.payment_verified = False
            if access.payment_proof and os.path.exists(access.payment_proof):
                os.remove(access.payment_proof)
            access.payment_proof = None
            flash('Payment rejected.')
        db.session.commit()
        return redirect(url_for('verify_payments'))

    pending_access = UserTestAccess.query.filter_by(payment_verified=False).all()
    access_data = []
    for access in pending_access:
        user = User.query.get(access.user_id)
        test = Test.query.get(access.test_id)
        access_data.append({
            'access': access,
            'user_email': user.email if user else 'Unknown User',
            'test_name': test.name if test else 'Unknown Test'
        })

    return render_template('verify_payments.html', access_data=access_data)

@app.route('/admin/add_question', methods=['GET', 'POST'])
@login_required
def add_question():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home'))
    if request.method == 'POST':
        test_id = request.form['test_id']
        question_text = request.form['question_text']
        option_a = request.form['option_a']
        option_b = request.form['option_b']
        option_c = request.form['option_c']
        option_d = request.form['option_d']
        correct_answer = request.form['correct_answer']
        new_question = Question(
            test_id=test_id,
            question_text=question_text,
            option_a=option_a,
            option_b=option_b,
            option_c=option_c,
            option_d=option_d,
            correct_answer=correct_answer
        )
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully!')
        return redirect(url_for('add_question'))
    tests = Test.query.all()
    return render_template('add_question.html', tests=tests)

@app.route('/admin/manage_questions', methods=['GET', 'POST'])
@login_required
def manage_questions():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home'))
    if request.method == 'POST':
        question_id = request.form['question_id']
        question = Question.query.get_or_404(question_id)
        db.session.delete(question)
        db.session.commit()
        flash('Question deleted successfully!')
        return redirect(url_for('manage_questions'))
    questions = Question.query.all()
    return render_template('manage_questions.html', questions=questions)

@app.route('/admin/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.is_authenticated or not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home'))
    if request.method == 'POST':
        user_id = request.form['user_id']
        user = User.query.get_or_404(user_id)
        if user.is_admin:
            flash('Cannot delete an admin user.')
        else:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully!')
        return redirect(url_for('manage_users'))
    users = User.query.all()
    return render_template('manage_users.html', users=users)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)