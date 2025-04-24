from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, SelectField
from wtforms.validators import DataRequired, IPAddress, Regexp, ValidationError, Length
from flask_sqlalchemy import SQLAlchemy
from flask_paginate import Pagination, get_page_parameter
from sqlalchemy.exc import IntegrityError
import os
import csv
import time
import io
from datetime import datetime
from io import StringIO
import logging
from logging.handlers import RotatingFileHandler
import pymysql
from dotenv import load_dotenv
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import timedelta

# Carrega as variáveis de ambiente
load_dotenv()

# Configuração do aplicativo
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15) #tempo máximo de conexão
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Nome da função de rota que vai ser a tela de login


# Configuração do banco de dados MariaDB
MYSQL_HOST = os.getenv('MYSQL_HOST')
MYSQL_PORT = int(os.getenv('MYSQL_PORT', '3306'))
MYSQL_USER = os.getenv('MYSQL_USER')
MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD')
MYSQL_DB = os.getenv('MYSQL_DB')

# Correção na string de conexão para evitar problemas de caracteres especiais
from urllib.parse import quote_plus
escaped_password = quote_plus(MYSQL_PASSWORD)

# Configuração da URI de conexão para MariaDB
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{MYSQL_USER}:{escaped_password}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PAGINATION_PER_PAGE'] = 10

# Registrar o driver PyMySQL
pymysql.install_as_MySQLdb()

# ------------------------------ COMEÇO: Configuração de logs --------------------------------------------
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/service.log', maxBytes=10240, backupCount=10) #alterar nome da arquivo dentro de 'logs/'
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Portal TI Manager - Iniciando aplicacao') 

db = SQLAlchemy(app)

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))
# ------------------------------ TÉRMINO: Configuração de logs --------------------------------------------
#
# ------------------------------ COMEÇO: Modelos de dados (classes) ---------------------------------------
class Registro(db.Model):
    __tablename__ = 'registros'
    
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False, index=True)
    departamento = db.Column(db.String(100), nullable=False, index=True)
    endereco_ip = db.Column(db.String(20), nullable=False, unique=True, index=True)
    mac_adress = db.Column(db.String(20), nullable=False, unique=True, index=True)
    hostname = db.Column(db.String(100), nullable=False, index=True)
    memoria_ram = db.Column(db.Integer, nullable=False)
    ssd = db.Column(db.Integer, nullable=False) #substituir pelo campo anydesk
    ramal = db.Column(db.Integer, nullable=False) #campo ramal
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)
    ultima_atualizacao = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Registro {self.nome} - {self.endereco_ip}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'nome': self.nome,
            'departamento': self.departamento,
            'endereco_ip': self.endereco_ip,
            'mac_adress': self.mac_adress,
            'hostname': self.hostname,
            'memoria_ram': self.memoria_ram,
            'ssd': self.ssd,
            'ramal': self.ramal, #campo ramal 
            'data_cadastro': self.data_cadastro.strftime('%d/%m/%Y %H:%M'),
            'ultima_atualizacao': self.ultima_atualizacao.strftime('%d/%m/%Y %H:%M')
        }

class Usuario(db.Model, UserMixin):
    __tablename__ = 'usuarios'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)  # Nome de usuário (login)
    password_hash = db.Column(db.String(128), nullable=False)
    
    nome = db.Column(db.String(100), nullable=False)                  # Nome completo
    email = db.Column(db.String(120), nullable=False, unique=True)
    setor = db.Column(db.String(100))
    cargo = db.Column(db.String(100))
    apelido = db.Column(db.String(50))                                 # Nome que aparece no navbar
    avatar = db.Column(db.String(200), default='img/default-avatar.png') # Caminho da imagem de perfil
    
    data_registro = db.Column(db.DateTime, default=datetime.utcnow)    # Data de criação do usuário
    is_admin = db.Column(db.Boolean, default=False)
    trocar_senha = db.Column(db.Boolean, default=False) #verifica se o usuario tem a credencial igual ao login

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

# Modelo de Auditoria
class LogAuditoria(db.Model):
    __tablename__ = 'logs_auditoria'
    
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), nullable=True)
    acao = db.Column(db.String(255), nullable=False)
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)
    ip_origem = db.Column(db.String(45))
    detalhes = db.Column(db.Text)

    usuario = db.relationship('Usuario', backref=db.backref('logs_auditoria', lazy=True))

    def __repr__(self):
        return f"<LogAuditoria {self.acao} - {self.data_hora}>"
# ------------------------------ TÉRMINO: Modelos de dados (classes) ---------------------------------------
#
# ------------------------------ COMEÇO: Função para registrar logs de auditoria  --------------------------
def registrar_log(acao, detalhes=None):
    ip_origem = request.remote_addr if request else 'Desconhecido'
    log = LogAuditoria(
        usuario_id=current_user.id if current_user.is_authenticated else None,
        acao=acao,
        ip_origem=ip_origem,
        detalhes=detalhes
    )
    db.session.add(log)
    db.session.commit()
# ------------------------------ TÉRMINO: Função para registrar logs de auditoria  -------------------------
#
# ------------------------------ COMEÇO: Validadores personalizados  ---------------------------------------
def validate_hostname(form, field):
    if len(field.data) < 3:
        raise ValidationError('O hostname deve ter pelo menos 3 caracteres.')
    
    if Registro.query.filter(Registro.hostname == field.data, Registro.id != getattr(form, 'id', None)).first():
        raise ValidationError('Este hostname já está em uso.')

def validate_ip_existente(form, field):
    if Registro.query.filter(Registro.endereco_ip == field.data, Registro.id != getattr(form, 'id', None)).first():
        raise ValidationError('Este endereço IP já está em uso.')

def validate_mac_existente(form, field):
    if Registro.query.filter(Registro.mac_adress == field.data, Registro.id != getattr(form, 'id', None)).first():
        raise ValidationError('Este MAC Address já está em uso.')
# ------------------------------ TÉRMINO: Validadores personalizados  --------------------------------------
#
#  ------------------------------ COMEÇO: Formulário de cadastro/edição ------------------------------------
class MaquinaForm(FlaskForm):
    nome = StringField('Nome da Máquina', validators=[
        DataRequired(message="Nome é obrigatório"),
        Length(min=2, max=100, message="Nome deve ter entre 2 e 100 caracteres")
    ])
    departamento = SelectField('Departamento', validators=[DataRequired(message="Departamento é obrigatório")], 
                             choices=[
                                 ('TI', 'Tecnologia da Informação'),
                                 ('Operações', 'Operações'),
                                 ('Administração', 'Administração'),
                                 ('Controladoria', 'Controladoria'),
                                 ('Fiscal', 'Fiscal'),
                                 ('RH', 'Recursos Humanos'),
                                 ('Marketing', 'Marketing'),
                                 ('Vendas', 'Vendas'),
                                 ('Diretoria', 'Diretoria'),
                                 ('Engenharia', 'Engenharia'),
                                 ('Manutenção', 'Manutenção')
                             ])
    endereco_ip = StringField('Endereço IP', validators=[
        DataRequired(message="Endereço IP é obrigatório"),
        IPAddress(message="Endereço IP inválido"),
        validate_ip_existente
    ])
    mac_adress = StringField('MAC Address', validators=[
        DataRequired(message="MAC Address é obrigatório"),
        Regexp(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', message="Formato de MAC Address inválido. Use o formato XX:XX:XX:XX:XX:XX"),
        validate_mac_existente
    ])
    hostname = StringField('Hostname', validators=[
        DataRequired(message="Hostname é obrigatório"),
        validate_hostname
    ])
    memoria_ram = IntegerField('Memória RAM (GB)', validators=[
        DataRequired(message="Memória RAM é obrigatória")
    ])
    ssd = IntegerField('SSD (GB)', validators=[
        DataRequired(message="Capacidade do SSD é obrigatória")
    ])
    ramal = IntegerField('Ramal', validators=[
        DataRequired(message="O ramal é obrigatório")
    ])
    
    def __init__(self, *args, registro_id=None, **kwargs):
        super(MaquinaForm, self).__init__(*args, **kwargs)
        self.id = registro_id
#  ------------------------------ TÉRMINO: Formulário de cadastro/edição ------------------------------------
#
# ------------------------------ COMEÇO: Rotas (protegidas com loginRequired) ------------------------------
@app.route('/', methods=['GET', 'POST']) # rota de cadastro + logs atribuidas
@login_required
def index():
    form = MaquinaForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        try:
            novo_registro = Registro(
                nome=form.nome.data,
                departamento=form.departamento.data,
                endereco_ip=form.endereco_ip.data,
                mac_adress=form.mac_adress.data,
                hostname=form.hostname.data,
                memoria_ram=form.memoria_ram.data,
                ssd=form.ssd.data,
                ramal=form.ramal.data
            )
            db.session.add(novo_registro)
            db.session.commit()
            registrar_log('Cadastro de máquina', detalhes=f'Máquina: {form.nome.data}, IP: {form.endereco_ip.data}') #função de captura de logs
            flash('Máquina cadastrada com sucesso!', 'success')
            app.logger.info(f'Nova máquina cadastrada: {form.nome.data} ({form.endereco_ip.data})')
            return redirect(url_for('relatorio'))
        except IntegrityError as e:
            db.session.rollback()
            app.logger.error(f'Erro ao cadastrar máquina: {str(e)}')
            flash('Erro ao cadastrar: IP ou MAC Address já existentes no sistema.', 'danger')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Erro ao cadastrar máquina: {str(e)}')
            flash(f'Erro ao cadastrar: {str(e)}', 'danger')
    
    return render_template('index.html', form=form, titulo='Cadastro de Máquinas')

@app.route('/relatorio')
@login_required
def relatorio():
    page = request.args.get(get_page_parameter(), type=int, default=1)
    search = request.args.get('search', '')
    per_page = app.config['PAGINATION_PER_PAGE']
    
    query = Registro.query
    
    # Aplicar busca se informada
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                Registro.nome.ilike(search_term),
                Registro.departamento.ilike(search_term),
                Registro.endereco_ip.ilike(search_term),
                Registro.mac_adress.ilike(search_term),
                Registro.hostname.ilike(search_term)
            )
        )
    
    # Ordenação
    sort_by = request.args.get('sort', 'nome')
    order = request.args.get('order', 'asc')
    
    if sort_by == 'nome':
        if order == 'asc':
            query = query.order_by(Registro.nome)
        else:
            query = query.order_by(Registro.nome.desc())
    elif sort_by == 'departamento':
        if order == 'asc':
            query = query.order_by(Registro.departamento)
        else:
            query = query.order_by(Registro.departamento.desc())
    elif sort_by == 'data':
        if order == 'asc':
            query = query.order_by(Registro.data_cadastro)
        else:
            query = query.order_by(Registro.data_cadastro.desc())
    
    # Paginação
    registros = query.paginate(page=page, per_page=per_page)
    pagination = Pagination(
        page=page, 
        per_page=per_page, 
        total=registros.total, 
        css_framework='bootstrap5',
        search=search,
        record_name='registros'
    )
    
    return render_template('relatorio.html', 
                           registros=registros, 
                           pagination=pagination,
                           search=search,
                           sort_by=sort_by,
                           order=order,
                           titulo='Relatório de Máquinas')

@app.route('/editar/<int:id>', methods=['GET', 'POST']) # rota de edição de cadstro + logs atribuidas
@login_required
def editar(id):
    registro = Registro.query.get_or_404(id)
    form = MaquinaForm(registro_id=id)
    
    if request.method == 'GET':
        form.nome.data = registro.nome
        form.departamento.data = registro.departamento
        form.endereco_ip.data = registro.endereco_ip
        form.mac_adress.data = registro.mac_adress
        form.hostname.data = registro.hostname
        form.memoria_ram.data = registro.memoria_ram
        form.ssd.data = registro.ssd
        form.ramal.data = registro.ramal
    
    if form.validate_on_submit():
        try:
            registro.nome = form.nome.data
            registro.departamento = form.departamento.data
            registro.endereco_ip = form.endereco_ip.data
            registro.mac_adress = form.mac_adress.data
            registro.hostname = form.hostname.data
            registro.memoria_ram = form.memoria_ram.data
            registro.ssd = form.ssd.data
            registro.ramal = form.ramal.data
            
            db.session.commit()
            registrar_log('Edição de máquina', detalhes=f'Máquina: {registro.nome}, IP: {registro.endereco_ip}') #logs
            app.logger.info(f'Máquina atualizada: {registro.nome} ({registro.endereco_ip})')
            flash('Máquina atualizada com sucesso!', 'success')
            return redirect(url_for('relatorio'))
        except IntegrityError as e:
            db.session.rollback()
            app.logger.error(f'Erro ao atualizar máquina: {str(e)}')
            flash('Erro ao atualizar: IP ou MAC Address já existentes no sistema.', 'danger')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Erro ao atualizar máquina: {str(e)}')
            flash(f'Erro ao atualizar: {str(e)}', 'danger')
    
    return render_template('editar.html', form=form, registro=registro, titulo='Editar Máquina')

@app.route('/excluir/<int:id>') # rota de exclusão de cadastro + logs atribuidas 
@login_required
def excluir(id):
    registro = Registro.query.get_or_404(id)
    try:
        nome = registro.nome
        db.session.delete(registro)
        db.session.commit()
        registrar_log('Exclusão de máquina', detalhes=f'Máquina: {nome}') #logs
        flash(f'Máquina "{nome}" removida com sucesso!', 'success')
        app.logger.info(f'Máquina excluída: ID {id} - {nome}')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir registro: {str(e)}', 'danger')
    
    return redirect(url_for('relatorio'))

@app.route('/exportar_csv') #função para exportar em csv + logs atribuidas
@login_required
def exportar_csv():
    try:
        # Filtrar resultados para exportação (similar ao relatório)
        search = request.args.get('search', '')
        
        query = Registro.query
        
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                db.or_(
                    Registro.nome.ilike(search_term),
                    Registro.departamento.ilike(search_term),
                    Registro.endereco_ip.ilike(search_term),
                    Registro.mac_adress.ilike(search_term),
                    Registro.hostname.ilike(search_term)
                )
            )
        
        registros = query.all()
        
        # Criar CSV na memória
        si = StringIO()
        cw = csv.writer(si)
        
        # Cabeçalhos
        cw.writerow(['Nome', 'Departamento', 'Endereço IP', 'MAC Address', 
                     'Hostname', 'Memória RAM (GB)', 'SSD (GB)', 
                     'Data de Cadastro', 'Ultima Atualizacao'])
        
        # Dados
        for registro in registros:
            cw.writerow([
                registro.nome,
                registro.departamento,
                registro.endereco_ip,
                registro.mac_adress,
                registro.hostname,
                registro.memoria_ram,
                registro.ssd,
                registro.ramal,
                registro.data_cadastro.strftime('%d/%m/%Y %H:%M'),
                registro.ultima_atualizacao.strftime('%d/%m/%Y %H:%M')
            ])
        
        data_atual = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"maquinas_Portal_{data_atual}.csv" #alterar nome 'portal' para o da empresa
        
        # Criar resposta com o arquivo CSV
        response = app.response_class(
            si.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
        
        app.logger.info(f'Exportação de CSV gerada: {filename}')
        registrar_log('Exportação de CSV', detalhes=f'Arquivo: {filename}') #logs
        return response
    
    except Exception as e:
        app.logger.error(f'Erro na exportação de CSV: {str(e)}')
        flash(f'Erro ao exportar dados: {str(e)}', 'danger')
        return redirect(url_for('relatorio'))

@app.route('/api/maquinas')
@login_required
def api_maquinas():
    """API simples para obter dados das máquinas em formato JSON."""
    try:
        registros = Registro.query.all()
        return jsonify([registro.to_dict() for registro in registros])
    except Exception as e:
        app.logger.error(f'Erro na API de máquinas: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/estatisticas')
@login_required
def estatisticas():
    # Total de máquinas
    total_maquinas = Registro.query.count()
    
    # Total de departamentos únicos
    total_departamentos = db.session.query(Registro.departamento).distinct().count()
    
    # Média de RAM e SSD
    media_ram = db.session.query(db.func.avg(Registro.memoria_ram)).scalar() or 0
    media_ssd = db.session.query(db.func.avg(Registro.ssd)).scalar() or 0
    
    # Distribuição por departamento
    departamentos_query = db.session.query(
        Registro.departamento,
        db.func.count(Registro.id).label('quantidade')
    ).group_by(Registro.departamento).all()
    
    departamentos = []
    for dept, quantidade in departamentos_query:
        porcentagem = (quantidade / total_maquinas) * 100 if total_maquinas > 0 else 0
        departamentos.append({
            'nome': dept,
            'quantidade': quantidade,
            'porcentagem': porcentagem
        })
    
    # Distribuição de RAM
    ram_query = db.session.query(
        Registro.memoria_ram,
        db.func.count(Registro.id).label('quantidade')
    ).group_by(Registro.memoria_ram).all()
    
    distribuicao_ram = []
    for ram, quantidade in ram_query:
        porcentagem = (quantidade / total_maquinas) * 100 if total_maquinas > 0 else 0
        distribuicao_ram.append({
            'tamanho': ram,
            'quantidade': quantidade,
            'porcentagem': porcentagem
        })
    
    # Distribuição de SSD
    ssd_query = db.session.query(
        Registro.ssd,
        db.func.count(Registro.id).label('quantidade')
    ).group_by(Registro.ssd).all()
    
    distribuicao_ssd = []
    for ssd, quantidade in ssd_query:
        porcentagem = (quantidade / total_maquinas) * 100 if total_maquinas > 0 else 0
        distribuicao_ssd.append({
            'tamanho': ssd,
            'quantidade': quantidade,
            'porcentagem': porcentagem
        })
    
    return render_template('estatisticas.html',
                         titulo='Estatísticas',
                         total_maquinas=total_maquinas,
                         total_departamentos=total_departamentos,
                         media_ram=round(media_ram, 1),
                         media_ssd=round(media_ssd, 1),
                         departamentos=sorted(departamentos, key=lambda x: x['quantidade'], reverse=True),
                         distribuicao_ram=sorted(distribuicao_ram, key=lambda x: x['tamanho']),
                         distribuicao_ssd=sorted(distribuicao_ssd, key=lambda x: x['tamanho']))

@app.route('/login', methods=['GET', 'POST']) #rota de login + logs atribuidas
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if 'tentativas' not in session:
        session['tentativas'] = 0

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Usuario.query.filter_by(username=username).first()

        if session['tentativas'] >= 5:
            flash('Muitas tentativas de login! Aguarde 30 segundos.', 'danger')
            time.sleep(30)
            session['tentativas'] = 0
            return redirect(url_for('login'))

        if user and user.check_password(password):
            login_user(user)
            registrar_log('Login no sistema', detalhes=f'Usuário: {user.username}') #logs
            session.permanent = True
            session.pop('tentativas', None)

            if user.trocar_senha:
                return redirect(url_for('trocar_senha_obrigatorio'))
            else:
                return redirect(url_for('index'))
        else:
            session['tentativas'] += 1
            flash('Usuário ou senha inválidos.', 'danger')

    return render_template('login.html', titulo='Login')

@app.route('/logout') #rota de logout + logs atribuidas
@login_required
def logout():
    logout_user()
    registrar_log('Logout do sistema', detalhes=f'Usuário: {current_user.username}')
    return redirect(url_for('login'))

@app.route('/usuarios', methods=['GET', 'POST']) #cadastro de usuario + logs atribuidas
@login_required
def usuarios():
    if not current_user.is_admin:
        flash('Acesso negado: você não tem permissão para acessar esta página.', 'danger')
        logout_user()
        return redirect(url_for('index'))

    busca = request.args.get('busca')

    if busca:
        usuarios = Usuario.query.filter(
            (Usuario.nome.like(f'%{busca}%')) | 
            (Usuario.email.like(f'%{busca}%'))
        ).all()
    else:
        usuarios = Usuario.query.all()

    if request.method == 'POST':
        username = request.form['username']
        nome = request.form['nome']
        email = request.form['email']
        setor = request.form['setor']
        cargo = request.form['cargo']
        apelido = request.form['apelido']
        password = request.form['password']
        is_admin = bool(int(request.form['is_admin']))

        if Usuario.query.filter_by(username=username).first():
            flash('Usuário já existe.', 'warning')
        else:
            novo_usuario = Usuario(
                username=username,
                nome=nome,
                email=email,
                setor=setor,
                cargo=cargo,
                apelido=apelido,
                avatar='img/default-avatar.png',
                is_admin=is_admin
            )
            novo_usuario.set_password(password)
            db.session.add(novo_usuario)
            db.session.commit()
            registrar_log('Cadastro de usuário', detalhes=f'Usuário: {novo_usuario.username}') #logs
            flash('Usuário criado com sucesso!', 'success')
        return redirect(url_for('usuarios'))

    return render_template('usuarios.html', titulo='Gerenciar Usuários', usuarios=usuarios)

#@app.route('/perfil') #rota de perfil (descontinuado)
#@login_required
#def perfil():
#   return render_template('perfil.html', titulo='Meu Perfil')

@app.route('/meu_perfil')
@login_required
def perfil():
    return render_template('meu_perfil.html', titulo='Meu Perfil')

# Rota para editar o perfil
@app.route('/editar_perfil', methods=['GET', 'POST'])
@login_required
def editar_perfil():
    if request.method == 'POST':
        apelido = request.form['apelido']
        email = request.form['email']
        setor = request.form['setor']
        cargo = request.form['cargo']

        # Atualiza os dados do usuário
        current_user.apelido = apelido
        current_user.email = email
        current_user.setor = setor
        current_user.cargo = cargo

        # Se o usuário enviou um novo avatar
        if 'avatar' in request.files:
            avatar = request.files['avatar']
            if avatar and avatar.filename != '':
                filename = secure_filename(avatar.filename)
                avatar_path = os.path.join('static', 'img', 'avatars', filename)
                avatar.save(avatar_path)
                current_user.avatar = f'img/avatars/{filename}'

        # Salva as alterações no banco
        db.session.commit()

        flash('Perfil atualizado com sucesso!', 'success')
        return redirect(url_for('perfil'))

    return render_template('editar_perfil.html', titulo='Editar Perfil')

@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST']) #editar usuario + logs atribuidas
@login_required 
def editar_usuario(id):
    if not current_user.is_admin:
        flash('Acesso negado: você não tem permissão para acessar esta página.', 'danger')
        return redirect(url_for('index'))

    usuario = Usuario.query.get_or_404(id)

    if request.method == 'POST':
        usuario.username = request.form['username']
        usuario.nome = request.form['nome']
        usuario.email = request.form['email']
        usuario.setor = request.form['setor']
        usuario.cargo = request.form['cargo']
        usuario.apelido = request.form['apelido']
        is_admin = request.form.get('is_admin')
        usuario.is_admin = True if is_admin == 'on' else False

        db.session.commit()
        registrar_log('Edição de usuário', detalhes=f'Usuário: {usuario.username}')
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('usuarios'))

    return render_template('editar_usuario.html', usuario=usuario, titulo='Editar Usuário')

@app.route('/trocar_senha_perfil', methods=['GET', 'POST']) #trocar senha voluntaria
@login_required
def trocar_senha_perfil():
    if request.method == 'POST':
        senha_atual = request.form['senha_atual']
        nova_senha = request.form['nova_senha']
        confirmar_senha = request.form['confirmar_senha']

        if not current_user.check_password(senha_atual):
            flash('Senha atual incorreta.', 'danger')
            return redirect(url_for('trocar_senha_perfil'))

        if nova_senha != confirmar_senha:
            flash('As novas senhas não conferem.', 'warning')
            return redirect(url_for('trocar_senha_perfil'))

        current_user.set_password(nova_senha)
        db.session.commit()
        registrar_log('Troca de senha voluntária', detalhes=f'Usuário: {current_user.username}')

        flash('Senha atualizada com sucesso!', 'success')
        return redirect(url_for('perfil'))

    return render_template('trocar_senha.html', titulo='Trocar Senha')

@app.route('/excluir_usuario/<int:id>') #excluir usuario + logs atribuidas
@login_required
def excluir_usuario(id):
    if not current_user.is_admin:
        flash('Acesso negado: você não tem permissão para excluir usuários.', 'danger')
        return redirect(url_for('usuarios'))
    
    usuario = Usuario.query.get_or_404(id)
    
    if usuario.id == current_user.id:
        flash('Você não pode excluir a si mesmo.', 'danger')
        return redirect(url_for('usuarios'))
    
    db.session.delete(usuario)
    db.session.commit()
    registrar_log('Exclusão de usuário', detalhes=f'Usuário: {usuario.username}')
    flash('Usuário excluído com sucesso!', 'success')
    return redirect(url_for('usuarios'))

@app.route('/trocar_senha_obrigatorio', methods=['GET', 'POST']) #editar senha obrigatoria
@login_required
def trocar_senha_obrigatorio():
    if request.method == 'POST':
        senha_atual = request.form['senha_atual']
        nova_senha = request.form['nova_senha']
        confirmar_senha = request.form['confirmar_senha']

        if not current_user.check_password(senha_atual):
            flash('Senha atual incorreta.', 'danger')
            return redirect(url_for('trocar_senha_obrigatorio'))

        if nova_senha != confirmar_senha:
            flash('A nova senha e a confirmação não coincidem.', 'danger')
            return redirect(url_for('trocar_senha_obrigatorio'))

        current_user.set_password(nova_senha)
        current_user.trocar_senha = False
        db.session.commit()
        registrar_log('Troca de senha obrigatória', detalhes=f'Usuário: {current_user.username}')
        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('index'))

    return render_template('trocar_senha_obrigatorio.html', titulo='Trocar Senha')


@app.route('/resetar_senha_usuario/<int:id>', methods=['GET']) #resetar senha
@login_required 
def resetar_senha_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    usuario.set_password(usuario.username)  # senha = username
    usuario.trocar_senha = True
    db.session.commit()
    registrar_log('Reset de senha de usuário', detalhes=f'Usuário: {usuario.username}')
    flash('Senha resetada para o login do usuário. Ele deverá alterá-la no próximo acesso.', 'success')
    return redirect(url_for('usuarios'))

@app.route('/logs_auditoria')
@login_required
def logs_auditoria():
    if not current_user.is_admin:
        flash('Acesso negado: apenas administradores podem ver os logs.', 'danger')
        return redirect(url_for('index'))

    usuario = request.args.get('usuario')
    acao = request.args.get('acao')
    data_inicio = request.args.get('data_inicio')
    data_fim = request.args.get('data_fim')

    query = LogAuditoria.query

    if usuario:
        query = query.join(Usuario).filter(Usuario.username.ilike(f'%{usuario}%'))
    if acao:
        query = query.filter(LogAuditoria.acao.ilike(f'%{acao}%'))
    if data_inicio:
        query = query.filter(LogAuditoria.data_hora >= data_inicio)
    if data_fim:
        query = query.filter(LogAuditoria.data_hora <= data_fim)

    logs = query.order_by(LogAuditoria.data_hora.desc()).all()

    return render_template('logs_auditoria.html', logs=logs, titulo='Auditoria do Sistema')


@app.route('/exportar_logs')
@login_required
def exportar_logs():
    if not current_user.is_admin:
        flash('Acesso negado: apenas administradores podem exportar logs.', 'danger')
        return redirect(url_for('index'))

    # Pegando os mesmos filtros que estão em /logs_auditoria
    usuario = request.args.get('usuario')
    acao = request.args.get('acao')
    data_inicio = request.args.get('data_inicio')
    data_fim = request.args.get('data_fim')

    query = LogAuditoria.query

    if usuario:
        query = query.join(Usuario).filter(Usuario.username.ilike(f'%{usuario}%'))
    if acao:
        query = query.filter(LogAuditoria.acao.ilike(f'%{acao}%'))
    if data_inicio:
        query = query.filter(LogAuditoria.data_hora >= data_inicio)
    if data_fim:
        query = query.filter(LogAuditoria.data_hora <= data_fim)

    logs = query.order_by(LogAuditoria.data_hora.desc()).all()

    # Gerar CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Cabeçalho
    writer.writerow(['Data/Hora', 'Usuario', 'Acao', 'IP de Origem', 'Detalhes'])

    for log in logs:
        writer.writerow([
            log.data_hora.strftime('%d/%m/%Y %H:%M:%S'),
            log.usuario.username if log.usuario else 'Desconhecido',
            log.acao,
            log.ip_origem or '',
            log.detalhes or ''
        ])

    output.seek(0)

    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=logs_auditoria.csv"})



# ------------------------------ TÉRMINO: Rotas (protegidas com loginRequired) ------------------------------
#
# ------------------------------ COMEÇO: Tratamento de erros ------------------------------------------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, message="Página não encontrada"), 404

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f'Erro 500: {str(e)}')
    return render_template('error.html', error_code=500, message="Erro interno do servidor"), 500
# ------------------------------ TÉRMINO: Tratamento de erros -----------------------------------------------
#
# ------------------------------ COMEÇO: Criar todas as tabelas do banco de dados ---------------------------
with app.app_context():
    db.create_all()
    app.logger.info('Banco de dados inicializado')
# ------------------------------ TÉRMINO: Criar todas as tabelas do banco de dados --------------------------
#
# ------------------------------ COMEÇO: Aplicação principal -----------------------------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=True)
# ------------------------------ TÉRMINO: Aplicação principal -----------------------------------------------