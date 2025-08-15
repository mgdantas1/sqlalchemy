from flask import Flask, render_template
from flask import request, session, redirect, url_for
from flask import flash

from flask_login import LoginManager, UserMixin, logout_user
from flask_login import login_required, login_user, current_user

from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker



login_manager = LoginManager()

app = Flask(__name__)


login_manager.__init__(app)

app.secret_key = 'chave_secreta'

engine = create_engine('sqlite:///banco.db')
Session = sessionmaker(bind=engine)
Base = declarative_base()

class User(UserMixin, Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    nome = Column(String(150), nullable=False)
    senha = Column(String(150), nullable=False)

    def get_id(self):
        return str(self.id)

with engine.begin() as conn:
    Base.metadata.create_all(bind=engine)

@login_manager.user_loader
def load_user(user_id):
    session = Session()
    user = session.query(User).get(int(user_id))
    session.close()
    return user


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':
        nome = request.form['name']
        senha= request.form['password']
        senha_h = generate_password_hash(senha)
    
        session = Session()        
        usuario = session.query(User).filter(User.nome == nome).first()


        if not usuario:
            user = User(nome=nome, senha=senha_h)
            session.add(user)
            session.commit()
            login_user(user)
            session.close()
            return redirect(url_for('dash'))
        
        flash('Problema no cadastro', category='error')
        return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        nome = request.form['name']
        senha= request.form['password']

        session = Session()

        usuario = session.query(User).filter(User.nome == nome).first()
        if usuario and check_password_hash(usuario.senha, senha):
            login_user(usuario)
            session.close()
            return redirect(url_for('dash'))

        flash('Dados incorretos', category='error')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dash():
    return render_template('dash.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))