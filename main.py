from flask import make_response, jsonify

from wtforms import EmailField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired
from wtforms.fields.simple import StringField

from flask import Flask
from flask import render_template, redirect
from flask_wtf import FlaskForm
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_restful import Api

from data import db_session
from data.games import Games
from data.users import User

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
api = Api(app)

login_manager = LoginManager()
login_manager.init_app(app)

db_session.global_init("db/stearn_users.db")


def main():
    db_session.global_init("db/stearn_users.db")
    app.run(host='127.0.0.1', port=5000)


class RegisterForm(FlaskForm):
    email = EmailField('Почта:', validators=[DataRequired()])
    password = PasswordField('Пароль:', validators=[DataRequired()])
    password_again = PasswordField('Повторите пароль:', validators=[DataRequired()])
    name = StringField('Имя пользователя:', validators=[DataRequired()])
    submit = SubmitField('Войти:')


class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


class AddFundsForm(FlaskForm):
    card_num = StringField('Номер карты', validators=[DataRequired()])
    validity = StringField('Срок действия', validators=[DataRequired()])
    cvc = PasswordField('CVV/CVC', validators=[DataRequired()])
    submit = SubmitField('Подтвердить')


@app.route('/')
@app.route('/index')
def index():
    db_sess = db_session.create_session()
    games = db_sess.query(Games)
    return render_template('index.html', path='/index', games=games)


@app.route('/community')
def community():
    return render_template('community.html', path='/community')


@app.route('/info')
def info():
    return render_template('information.html', path='/info')


@app.route('/help')
def help():
    return render_template('help.html', path='/help')


@app.route('/account')
def account():
    return render_template('account.html', path='/account')


@app.route('/chat')
def chat():
    return render_template('chat.html', path='/chat')


@app.route('/wallet')
def wallet():
    return render_template('wallet.html', path='/wallet')


@app.route('/addfunds/<int:money>', methods=['GET', 'POST'])
def addfunds(money):
    form = AddFundsForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.id == current_user.id).first()
        user.wallet += money
        db_sess.commit()
        return redirect('/')
    return render_template('addfunds.html', path='/addfunds', form=form)


@app.route('/games/<int:id>', methods=['GET', 'POST'])
def games(id):
    db_sess = db_session.create_session()
    game = db_sess.query(Games).filter(Games.id == id).first()
    return render_template('games.html', path='/addfunds', game=game)


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


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
        user = User(
            email=form.email.data,
            nickname=form.name.data,
            wallet=0,
            currency=' руб.',
            steam_level=0
        )
        user.set_password(form.password.data)
        db_sess.add(user)
        db_sess.commit()
        return redirect('/login')
    return render_template('register.html', title='Регистрация', form=form)


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


@app.errorhandler(400)
def bad_request(_):
    return make_response(jsonify({'error': 'Bad Request'}), 400)


if __name__ == '__main__':
    main()
