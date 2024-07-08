from flask import Flask, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, TextAreaField, BooleanField
from wtforms.validators import InputRequired, Length
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap4
import os


app = Flask(__name__)
load_dotenv()

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1234@127.0.0.1/tododb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = os.getenv("MY_SECRET")

db = SQLAlchemy(app)
bootstrap = Bootstrap4(app)

login_manager = LoginManager()
login_manager.init_app(app)

input_required = InputRequired()

# DB user Modal
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)

# TODO Model
class Todo(db.Model):
    __tablename__ = 'todo'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String, nullable=False)
    is_completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# WT Registartion Form Class
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[input_required, Length(min=4, max=15)])
    email = EmailField('Email', validators=[input_required, Length(min=4, max=15)])
    password = PasswordField('Password', validators=[input_required, Length(min=4, max=24)])

# WT Login Form Class
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[input_required, Length(min=4, max=15)])
    password = PasswordField('Password', validators=[input_required, Length(min=4, max=24)])

# Todo WTForm
class TodoForm(FlaskForm):
    title = StringField('Title', validators=[input_required, Length(max=100)])
    description = TextAreaField('Description', validators=[input_required])
    is_completed = BooleanField('Is Completed')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# Register User Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        print(form)
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        try:
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in', 'success')

            return redirect(url_for('login'))
        except :
            # Handle email already exists error (example using SQLAlchemy)
            db.session.rollback()
            form.email.errors.append('Email address already exists.')  # Add error message to the email field
    return render_template('/register.html', form= form)


# Login user Route
@app.route('/login', methods= ['GET','POST'])
def login():
    form = LoginForm()
    # check if it's already authenticated
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email = form.email.data).first()
            if not user:
                form.email.errors.append('Email not exists.')  

            if user and check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('Logged in Succesfully')
                return redirect('/dashboard')
            else :
                flash('Logged in Failed')
                form.password.errors.append('Password is incorrect.')  # Add error message to the email field
        except:
            flash('Logged in Failed')
            form.password.errors.append('Password is incorrect.') 
    return render_template('/login.html', form= form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# Dashboard
@app.route("/")
@app.route('/dashboard')
@login_required
def dashboard():
    todos = Todo.query.filter_by(user_id=current_user.id).all()
    return render_template('/dashboard.html', name = current_user.username, todos= todos)

# All unauthorised return to login
@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('login'))


#Create Todo
@app.route('/dashboard/add-todo', methods= ['GET', 'POST'])
@login_required
def add_todo():
    form = TodoForm()
    if form.validate_on_submit():
        new_todo = Todo(title=form.title.data, description = form.description.data, is_completed=False, user_id = current_user.id)

        db.session.add(new_todo)
        db.session.commit()
        flash('New TODO is created', 'success')
        return redirect(url_for('dashboard'))

    return render_template('/add_todo.html', form=form)

# Edit Todo
@app.route('/dashboard/edit/<todo_id>', methods=['GET', 'POST'])
@login_required
def edit_todo(todo_id):
    form = TodoForm()
    get_todo = Todo.query.filter_by(id=todo_id).first()
    if form.validate_on_submit():
        get_todo.title = form.title.data
        get_todo.description = form.description.data
        get_todo.is_completed = form.is_completed.data

        db.session.add(get_todo)
        db.session.commit()
        flash('TODO is updated', 'success')
        return redirect(url_for('dashboard'))
    form.description.data = get_todo.description
    form.is_completed.data = get_todo.is_completed

    return render_template('/edit_todo.html', form=form, todo=get_todo)

#  Delete Todo   
@app.route('/dashboard/delete/<todo_id>', methods=['GET', 'POST'])
@login_required
def delete_todo(todo_id):
        form = TodoForm()
        get_todo = Todo.query.filter_by(id=todo_id).first()

        if form.validate_on_submit():
            db.session.delete(get_todo)
            db.session.commit()
            return redirect(url_for('dashboard'))
        form.description.data = get_todo.description
        form.is_completed.data = get_todo.is_completed

        return render_template('delete_todo.html', form=form, todo=get_todo)



if '__name__' == '__main__':
    app.run(debug=True)