import os

from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from dotenv import load_dotenv
import bcrypt

"""
Flask: cria a aplicação.
request: pega os dados enviados pelo cliente.
jsonify: retorna JSON.
User: modelo da tabela user.
db: objeto do SQLAlchemy.
LoginManager: gerencia autenticação.
login_user(): faz login do usuário.
current_user: representa o usuário logado.
"""

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key" #chave
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL") #caminho do banco

login_manager = LoginManager()
db.init_app(app) #conexao db
login_manager.init_app(app)

#Se uma rota protegida exigir autenticação e o usuário não estiver logado, ele será redirecionado para login
login_manager.login_view = 'login'
#view de login -> para enviar as info

@login_manager.user_loader #Serve para registrar a função que recupera usuários.
def load_user(user_id): #Recebe o id do usuário.
    return User.query.get(user_id) #Busca o usuário no banco.
@app.route('/login', methods=["POST"])
def login():
    data = request.json #Pega o JSON enviado.
    username = data.get("username")
    password = data.get("password")

    if username and password:
        #login
        user = User.query.filter_by(username=username).first() #Busca usuário pelo nome.

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated) #Mostra no terminal se o usuário está autenticado.
            return jsonify({"message": "Autenticação realizada com sucesso"})
    return  jsonify({"message": "Credenciais inválidas"}), 400

@app.route('/logout', methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso!"})

@app.route("/user", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        senha_hash = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User(username=username, password=senha_hash, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuário cadastrado com sucesso"})

    return jsonify({"message": "Dados inválidos"}), 400

@app.route("/user/<int:id_user>", methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)

    if user:
        return {"username": user.username,
                "role": user.role}

    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route("/user/<int:id_user>", methods=["PUT"])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)

    if id_user != current_user.id and current_user.role == "user":
        return jsonify({"message": "Operação não permitida"}), 403

    if user and data.get("password"):
        user.password = data.get("password")
        db.session.commit()
        return jsonify({"message": f"Usuario {id_user} atualizado com sucesso!"})

    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route("/user/<int:id_user>", methods=["DELETE"])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)

    if current_user.role != 'admin':
        return jsonify({"message": "Acesso não permitido"}), 403

    if id_user == current_user.id:
        return jsonify({"message": "Deleção não permitido"}), 403

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuario {id_user} deletado com sucesso!"})

    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route("/hello-world", methods=["GET"])
def helloWorld():
    return "Hello World"

if __name__ == '__main__':
    app.run(debug=True)