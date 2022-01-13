from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)



##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        else:
            hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
            user = User(email=request.form.get("email"), password=hash, name=request.form.get("name"))
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('secrets'))
    else:
        return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST', 'GET'])
def login():
    error=None
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get("email")).first()
        # hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        if user:
            if check_password_hash(user.password, request.form.get("password")):
                login_user(user)
                return redirect(url_for('secrets'))
            else:
                flash('Password incorrect, please try again.')
                return redirect(url_for('login'))
        else:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
    else:
        return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template('secrets.html', name=current_user.name,  logged_in=True)


@app.route('/download')
@login_required
def download():
    try:
        return send_from_directory(app.static_folder, filename='files/cheat_sheet.pdf')
    except FileNotFoundError:
        print("File not found")


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))



if __name__ == "__main__":
    app.run(debug=True)
