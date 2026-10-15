from flask import Flask, render_template, request, flash, redirect, url_for, session
import fdb
from flask_bcrypt import Bcrypt
from datetime import date


# Inicia a aplicação
app = Flask(__name__)
app.secret_key = 'automatic_fit_teste'
bcrypt = Bcrypt(app)


# Conecta ao banco Firebird
def conectar():
    return fdb.connect(
        host='localhost',
        database=r'C:\Users\Aluno\Desktop\banco\BANCO.FDB',
        user='SYSDBA',
        password='sysdba'
    )


# Confere se a senha é forte
def senha_forte(senha):
    if len(senha) < 8:
        return False

    maiuscula = False
    minuscula = False
    numero = False
    especial = False

    for letra in senha:
        if letra.isupper():
            maiuscula = True
        if letra.islower():
            minuscula = True
        if letra.isdigit():
            numero = True
        if not letra.isalnum() and not letra.isspace():
            especial = True

    return maiuscula and minuscula and numero and especial


# Abre a página inicial do site
@app.route('/')
def index():
    return render_template('landing.html')


# Cadastra novos alunos
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        nome = request.form.get('nome', '').strip()
        telefone = request.form.get('telefone', '').strip()
        cpf = request.form.get('cpf', '').strip().replace('.', '').replace('-', '')
        data_nascimento = request.form.get('data_nascimento', '')
        senha = request.form.get('senha', '')
        confirmar = request.form.get('confirmar_senha', '')

        # Confere os dados informados
        if not nome or not email or not cpf or not data_nascimento or not senha:
            flash('Preencha todos os campos obrigatórios.')
            return redirect(url_for('cadastro'))

        if '@' not in email or '.' not in email.split('@')[-1]:
            flash('Digite um e-mail válido.')
            return redirect(url_for('cadastro'))

        if len(cpf) != 11 or not cpf.isdigit():
            flash('O CPF deve conter 11 números.')
            return redirect(url_for('cadastro'))

        # Confere a data de nascimento
        try:
            nascimento = date.fromisoformat(data_nascimento)
        except ValueError:
            flash('Data de nascimento inválida.')
            return redirect(url_for('cadastro'))

        if nascimento > date.today():
            flash('A data de nascimento não pode ser futura.')
            return redirect(url_for('cadastro'))

        # Calcula a idade do aluno
        hoje = date.today()
        idade = hoje.year - nascimento.year

        # Verifica se já fez aniversário neste ano
        if (hoje.month, hoje.day) < (nascimento.month, nascimento.day):
            idade = idade - 1

        # Impede o cadastro de menores de 18 anos
        if idade < 18:
            flash('Você precisa ter pelo menos 18 anos para se cadastrar.')
            return redirect(url_for('cadastro'))


        if senha != confirmar:
            flash('As senhas não coincidem.')
            return redirect(url_for('cadastro'))

        if not senha_forte(senha):
            flash('A senha deve ter 8 caracteres, maiúscula, minúscula, número e especial.')
            return redirect(url_for('cadastro'))

        con = None
        try:
            con = conectar()
            cursor = con.cursor()

            # Verifica se o e-mail já existe
            cursor.execute('SELECT ID_USUARIO FROM USUARIOS WHERE EMAIL = ?', (email,))
            if cursor.fetchone() is not None:
                flash('Este e-mail já está cadastrado.')
                return redirect(url_for('cadastro'))

            senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

            # Grava o aluno
            cursor.execute('''
                INSERT INTO USUARIOS
                (NOME, EMAIL, SENHA, TIPO_USUARIO, TELEFONE, CPF, DATA_NASCIMENTO)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                RETURNING ID_USUARIO
            ''', (nome, email, senha_hash, 'ALUNO', telefone, cpf, nascimento))
            id_usuario = cursor.fetchone()[0]

            # Grava a primeira senha no histórico
            cursor.execute('''
                INSERT INTO HISTORICO_SENHAS (ID_USUARIO, SENHA)
                VALUES (?, ?)
            ''', (id_usuario, senha_hash))
            con.commit()

            flash('Cadastro realizado com sucesso! Faça seu login.', 'sucesso')
            return redirect(url_for('login'))

        except Exception as erro:
            if con is not None:
                con.rollback()
            print('Erro no cadastro:', erro)
            flash('Não foi possível realizar o cadastro.')

        finally:
            if con is not None:
                con.close()

        return redirect(url_for('cadastro'))

    return render_template('cadastro.html')


# Faz o login dos três perfis
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        senha = request.form.get('senha', '')

        if not email or not senha:
            flash('Preencha o e-mail e a senha.')
            return redirect(url_for('login'))

        con = None
        try:
            con = conectar()
            cursor = con.cursor()

            # Busca o usuário no banco
            cursor.execute('''
                SELECT ID_USUARIO, NOME, SENHA, TIPO_USUARIO,
                       TENTATIVAS_LOGIN, BLOQUEADO, ATIVO
                FROM USUARIOS WHERE EMAIL = ?
            ''', (email,))
            usuario = cursor.fetchone()

            if usuario is None:
                flash('E-mail ou senha incorretos.')
                return redirect(url_for('login'))

            id_usuario, nome, senha_hash, tipo, tentativas, bloqueado, ativo = usuario

            if ativo == 0:
                flash('Usuário inativo.')
                return redirect(url_for('login'))

            if bloqueado == 1:
                flash('Usuário bloqueado. Procure o administrador.')
                return redirect(url_for('login'))

            # Confere a senha protegida
            if bcrypt.check_password_hash(senha_hash, senha):
                rotas = {
                    'ALUNO': 'aluno',
                    'PERSONAL': 'personal',
                    'ADMINISTRADOR': 'administrador'
                }

                if tipo not in rotas:
                    flash('Perfil de usuário inválido.')
                    return redirect(url_for('login'))

                cursor.execute('''
                    UPDATE USUARIOS SET TENTATIVAS_LOGIN = 0
                    WHERE ID_USUARIO = ?
                ''', (id_usuario,))
                con.commit()

                session.clear()
                session['id_usuario'] = id_usuario
                session['nome_usuario'] = nome
                session['tipo_usuario'] = tipo
                return redirect(url_for(rotas[tipo]))

            # Bloqueia após três erros
            tentativas += 1
            bloqueado = 1 if tentativas >= 3 else 0
            cursor.execute('''
                UPDATE USUARIOS
                SET TENTATIVAS_LOGIN = ?, BLOQUEADO = ?
                WHERE ID_USUARIO = ?
            ''', (tentativas, bloqueado, id_usuario))
            con.commit()

            if bloqueado:
                flash('Usuário bloqueado após 3 tentativas erradas.')
            else:
                flash('Senha incorreta. Tentativas restantes: ' + str(3 - tentativas))

        except Exception as erro:
            if con is not None:
                con.rollback()
            print('Erro no login:', erro)
            flash('Não foi possível realizar o login.')

        finally:
            if con is not None:
                con.close()

        return redirect(url_for('login'))

    return render_template('login.html')


# Procura a conta da pessoa que está conectada
def usuario_logado():
    if 'id_usuario' not in session:
        return None

    con = None
    try:
        con = conectar()
        cursor = con.cursor()
        cursor.execute('''
            SELECT ID_USUARIO, NOME, EMAIL, SENHA, TIPO_USUARIO,
                   TELEFONE, CPF, DATA_NASCIMENTO, BLOQUEADO, ATIVO
            FROM USUARIOS WHERE ID_USUARIO = ?
        ''', (session['id_usuario'],))
        usuario = cursor.fetchone()

        if (usuario is None or usuario[8] == 1 or usuario[9] == 0
                or usuario[4] != session.get('tipo_usuario')):
            session.clear()
            return None

        return usuario

    except Exception as erro:
        print('Erro ao verificar usuário:', erro)
        return None

    finally:
        if con is not None:
            con.close()


# Usa a mesma Home para os três perfis
def abrir_home(tipo):
    usuario = usuario_logado()

    if usuario is None or usuario[4] != tipo:
        flash('Faça login com o perfil correto para acessar.')
        return redirect(url_for('login'))

    return render_template('home.html',
                           nome=usuario[1],
                           email=usuario[2],
                           perfil=usuario[4])


# Home do aluno
@app.route('/aluno')
def aluno():
    return abrir_home('ALUNO')


# Home do professor
@app.route('/personal')
def personal():
    return abrir_home('PERSONAL')


# Home do administrador
@app.route('/administrador')
def administrador():
    return abrir_home('ADMINISTRADOR')


# Volta para a Home do perfil conectado
@app.route('/minha-home')
def voltar_home():
    rotas = {
        'ALUNO': 'aluno',
        'PERSONAL': 'personal',
        'ADMINISTRADOR': 'administrador'
    }
    tipo = session.get('tipo_usuario')
    if tipo not in rotas:
        return redirect(url_for('login'))
    return redirect(url_for(rotas[tipo]))


# Altera os dados da própria conta
@app.route('/editar-dados', methods=['GET', 'POST'])
def editar_dados():
    usuario = usuario_logado()
    if usuario is None:
        flash('Faça login para continuar.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip().lower()
        telefone = request.form.get('telefone', '').strip()
        cpf = request.form.get('cpf', '').strip().replace('.', '').replace('-', '')
        data_nascimento = request.form.get('data_nascimento', '')

        if not nome or not email:
            flash('Preencha o nome e o e-mail.')
            return redirect(url_for('editar_dados'))

        if '@' not in email or '.' not in email.split('@')[-1]:
            flash('Digite um e-mail válido.')
            return redirect(url_for('editar_dados'))

        # CPF e nascimento podem ficar em branco
        if cpf and (len(cpf) != 11 or not cpf.isdigit()):
            flash('O CPF deve conter 11 números.')
            return redirect(url_for('editar_dados'))

        nascimento = None
        if data_nascimento:
            try:
                nascimento = date.fromisoformat(data_nascimento)
            except ValueError:
                flash('Data de nascimento inválida.')
                return redirect(url_for('editar_dados'))

            if nascimento > date.today():
                flash('A data de nascimento não pode ser futura.')
                return redirect(url_for('editar_dados'))

        con = None
        try:
            con = conectar()
            cursor = con.cursor()

            # Impede usar o e-mail de outra pessoa
            cursor.execute('''
                SELECT ID_USUARIO FROM USUARIOS
                WHERE EMAIL = ? AND ID_USUARIO <> ?
            ''', (email, usuario[0]))

            if cursor.fetchone() is not None:
                flash('Este e-mail já está cadastrado.')
                return redirect(url_for('editar_dados'))

            # Atualiza somente os dados do próprio usuário
            cursor.execute('''
                UPDATE USUARIOS
                SET NOME = ?, EMAIL = ?, TELEFONE = ?,
                    CPF = ?, DATA_NASCIMENTO = ?
                WHERE ID_USUARIO = ?
            ''', (nome, email, telefone, cpf, nascimento, usuario[0]))
            con.commit()
            session['nome_usuario'] = nome

            flash('Dados atualizados com sucesso!', 'sucesso')
            return redirect(url_for('editar_dados'))

        except Exception as erro:
            if con is not None:
                con.rollback()
            print('Erro ao editar dados:', erro)
            flash('Não foi possível atualizar seus dados.')

        finally:
            if con is not None:
                con.close()

        return redirect(url_for('editar_dados'))

    return render_template('editar_dados.html', dados=usuario)


# Altera a senha da própria conta
@app.route('/alterar-senha', methods=['GET', 'POST'])
def alterar_senha():
    usuario = usuario_logado()
    if usuario is None:
        flash('Faça login para continuar.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        senha_atual = request.form.get('senha_atual', '')
        nova_senha = request.form.get('nova_senha', '')
        confirmar = request.form.get('confirmar', '')

        if not bcrypt.check_password_hash(usuario[3], senha_atual):
            flash('A senha atual está incorreta.')
            return redirect(url_for('alterar_senha'))

        if nova_senha != confirmar:
            flash('As novas senhas não coincidem.')
            return redirect(url_for('alterar_senha'))

        if not senha_forte(nova_senha):
            flash('A nova senha deve ter 8 caracteres, maiúscula, minúscula, número e especial.')
            return redirect(url_for('alterar_senha'))

        # Impede repetir a senha que está em uso
        if bcrypt.check_password_hash(usuario[3], nova_senha):
            flash('A nova senha deve ser diferente da senha atual.')
            return redirect(url_for('alterar_senha'))

        con = None
        try:
            con = conectar()
            cursor = con.cursor()

            # Consulta as três últimas senhas
            cursor.execute('''
                SELECT FIRST 3 SENHA FROM HISTORICO_SENHAS
                WHERE ID_USUARIO = ? ORDER BY ID_HISTORICO DESC
            ''', (usuario[0],))

            for registro in cursor.fetchall():
                if bcrypt.check_password_hash(registro[0], nova_senha):
                    flash('Você não pode repetir as três últimas senhas.')
                    return redirect(url_for('alterar_senha'))

            # Se a conta não tiver histórico, salva a senha atual
            cursor.execute('''
                SELECT FIRST 1 ID_HISTORICO FROM HISTORICO_SENHAS
                WHERE ID_USUARIO = ?
            ''', (usuario[0],))
            if cursor.fetchone() is None:
                cursor.execute('''
                    INSERT INTO HISTORICO_SENHAS (ID_USUARIO, SENHA)
                    VALUES (?, ?)
                ''', (usuario[0], usuario[3]))

            # Protege e grava a nova senha
            senha_hash = bcrypt.generate_password_hash(nova_senha).decode('utf-8')
            cursor.execute('''
                UPDATE USUARIOS SET SENHA = ? WHERE ID_USUARIO = ?
            ''', (senha_hash, usuario[0]))
            cursor.execute('''
                INSERT INTO HISTORICO_SENHAS (ID_USUARIO, SENHA)
                VALUES (?, ?)
            ''', (usuario[0], senha_hash))
            con.commit()

            flash('Senha alterada com sucesso!', 'sucesso')
            return redirect(url_for('alterar_senha'))

        except Exception as erro:
            if con is not None:
                con.rollback()
            print('Erro ao alterar senha:', erro)
            flash('Não foi possível alterar a senha.')

        finally:
            if con is not None:
                con.close()

        return redirect(url_for('alterar_senha'))

    return render_template('alterar_senha.html', nome=usuario[1])


# Encerra a sessão
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Você saiu da sua conta.')
    return redirect(url_for('login'))





# Inicia o sistema
if __name__ == '__main__':
    app.run(debug=True)

