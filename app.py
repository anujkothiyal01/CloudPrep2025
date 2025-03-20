from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt
import smtplib
import os
from email.mime.text import MIMEText
from random import randint

app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

GMAIL_USER = 'kothiyal.official@gmail.com'
GMAIL_PASSWORD = 'xetv zaze ckcp sfjk'


# User Model (Added is_admin)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    email_code = db.Column(db.String(6))
    is_admin = db.Column(db.Boolean, default=False)


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    exam_type = db.Column(db.String(50), nullable=False)
    question_text = db.Column(db.String(500), nullable=False)
    option_a = db.Column(db.String(200), nullable=False)
    option_b = db.Column(db.String(200), nullable=False)
    option_c = db.Column(db.String(200), nullable=False)
    option_d = db.Column(db.String(200), nullable=False)
    correct_answer = db.Column(db.String(200), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='anujkothiyal01@gmail.com').first():
        hashed_pw = bcrypt.hashpw('Kothiyal@123'.encode('utf-8'), bcrypt.gensalt())
        admin = User(email='anujkothiyal01@gmail.com', password=hashed_pw, email_verified=True, is_admin=True)
        db.session.add(admin)
        db.session.commit()
    if not Question.query.first():
        sample_questions = [
            Question(exam_type='aws_cloud_practitioner', question_text='What is the primary use of AWS S3?',
                     option_a='Compute', option_b='Storage', option_c='Networking', option_d='Database',
                     correct_answer='Storage'),
            Question(exam_type='aws_cloud_practitioner', question_text='Which AWS service is used for virtual servers?',
                     option_a='S3', option_b='EC2', option_c='RDS', option_d='Lambda', correct_answer='EC2'),
            Question(exam_type='azure_fundamentals', question_text='What is Azure Blob Storage used for?',
                     option_a='Virtual Machines', option_b='Unstructured Data', option_c='SQL Databases',
                     option_d='Networking',
                     correct_answer='Unstructured Data')
        ]
        db.session.bulk_save_objects(sample_questions)
        db.session.commit()


def send_email_otp(email, otp):
    try:
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
        return False


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
        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
        user = User(email=email, password=hashed_pw, email_code=email_code)
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


@app.route('/test/<exam_type>', methods=['GET', 'POST'])
@login_required
def test(exam_type):
    questions = Question.query.filter_by(exam_type=exam_type).all()
    if not questions:
        flash('No questions available for this exam yet.')
        return redirect(url_for('home'))
    if request.method == 'POST':
        score = 0
        total = len(questions)
        for q in questions:
            user_answer = request.form.get(f'question_{q.id}')
            if user_answer == q.correct_answer:
                score += 1
        flash(f'You scored {score} out of {total}!')
        return redirect(url_for('home'))
    return render_template('test.html', questions=questions, exam_type=exam_type)


@app.route('/admin/add_question', methods=['GET', 'POST'])
@login_required
def add_question():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('home'))
    if request.method == 'POST':
        exam_type = request.form['exam_type']
        question_text = request.form['question_text']
        option_a = request.form['option_a']
        option_b = request.form['option_b']
        option_c = request.form['option_c']
        option_d = request.form['option_d']
        correct_answer = request.form['correct_answer']

        new_question = Question(
            exam_type=exam_type, question_text=question_text,
            option_a=option_a, option_b=option_b, option_c=option_c, option_d=option_d,
            correct_answer=correct_answer
        )
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully!')
        return redirect(url_for('add_question'))

    exam_types = [
        'aws_cloud_practitioner', 'aws_solutions_architect', 'aws_data_engineer',
        'azure_fundamentals', 'snowpro_core', 'snowpro_advanced', 'databricks_data_engineer'
    ]
    return render_template('add_question.html', exam_types=exam_types)


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
    if not current_user.is_admin:
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
    app.run(debug=True)
