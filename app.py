from datetime import datetime

from flask import Flask, render_template, request, redirect, abort, flash, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_login import LoginManager, UserMixin, login_required, logout_user, login_user

from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nowevnoewijcopwencpemcpoempwjoepwfpowemvweopjfmpwe'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project_flask.db"
db = SQLAlchemy(app)

manager = LoginManager(app)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    text = db.Column(db.Text, nullable=False)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.now())


@manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)



@app.route('/')
def index():
    return render_template('index.html')


@app.route('/posts')
def posts():
    posts = Post.query.order_by(desc(Post.id)).all()
    content = {
        'posts': posts,
    }
    return render_template('posts.html', content=content)


@app.route('/posts/<int:post_id>')
def post_detail(post_id):
    post = Post.query.get(post_id)
    if post is None:
        abort(404)
    return render_template('post_detail.html', post=post)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route("/create", methods=['POST', 'GET'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        text = request.form['text']
        if title == '':
            flash('Поле заголовка должно быть заполнено', category='danger')
        else:
            flash('Пост добавлен', category='success ')
            post = Post(title=title, text=text)
            try:
                db.session.add(post)
                db.session.commit()

            except:
                return 'Ошибка'

    return render_template('create.html')


@app.route('/login_page', methods=['POST', 'GET'])
def login_page():
    email = request.form.get('email')
    password = request.form.get('password')
    if email and password:
        user = db.session.query(User).filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            print('ТУТ')
            login_user(user)
            # next_page = request.args.get('next')
            # return redirect(next_page)
            return render_template('index.html', email=email)
        else:
            flash('email или пароль не верные', category='danger')
    else:
        flash('Ошибка авторизации', category='danger')
    return render_template('login_page.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    password2 = request.form.get('password2')
    if request.method == "POST":
        if not (name or email or password or password2):
            flash('Заполните все поля', category='danger')
        elif password2 != password:
            flash('Пароли не равны', category='danger')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(name=name, email=email, password=hash_pwd)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login_page'))

    return render_template('register.html')


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('about'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)
    return response


# @app.route('/login', methods=['POST', 'GET'])
# def login():
#     if 'userLogger' in session:
#         return redirect(url_for('profile', username=session['userLogger']))
#     elif request.method == 'POST' and request.form['username'] == 'selfedu' and request.form['psw'] == '123':
#         session['userLogger'] = request.form['username']
#         return redirect(url_for('profile', username=session['userLogger']))
#
#     return render_template('login_page.html')
#
#
# @app.route("/profile/<username>")
# def profile(username):
#     if 'userLogger' not in session or session['userLogger'] !=username:
#         abort(401)
#     return f"Профиль пользователя {username}"


if __name__ == "__main__":
    app.run(debug=True)
