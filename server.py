from flask import Flask, render_template, redirect, request, make_response, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from form.user import RegisterForm, LoginForm
from data.users import User
from data import db_session
from PIL import Image, ImageOps
import numpy as np


def files_to_hex_colors(rgb):
    return '%02x%02x%02x' % rgb


def files_to_rgb_colors(files, code):
    kartinka = Image.open(files).convert('RGB')
    kartinka = ImageOps.posterize(kartinka, 2)
    kartinka_razbiv = np.array(kartinka)

    colors = {}

    for kolonka in kartinka_razbiv:
        for rgb in kolonka:
            tochka_rgb = tuple(rgb)
            if tochka_rgb in colors:
                colors[tochka_rgb] += 1
            else:
                colors[tochka_rgb] = 1

    sorted_colors = sorted(colors.items(), key=lambda x: x[1], reverse=True)
    obrat_to_dict = dict(sorted_colors)
    val = list(obrat_to_dict.keys())
    top = val[0:10]

    if code == 'hex':
        hexes = []
        for rgbs in top:
            hex = files_to_hex_colors(rgbs)
            hexes.append(hex)
        return hexes
    else:
        return top


app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
login_manager = LoginManager()
login_manager.init_app(app)


# api = Api(app)


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        csvet_code = request.form['csvet_code']
        files = request.files['file']
        csveta = files_to_rgb_colors(files.stream, csvet_code)
        return render_template('index.html', colors=csveta, code=csvet_code)
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Такой пользователь уже есть")
        user = User(name=form.name.data,
                    email=form.email.data,
                    about=form.about.data)
        user.set_password(form.password.data)
        db_sess.add(user)
        db_sess.commit()
        return redirect('/login')
    return render_template('register.html', title='Регистрация', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/")
        return render_template('login.html',
                               message="Неправильный логин или пароль",
                               form=form)
    return render_template('login.html', title='Авторизация', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


def main():
    db_session.global_init("db/blogs.db")
    app.run()


if __name__ == '__main__':
    main()
