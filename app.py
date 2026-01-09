from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response
from flask_wtf import FlaskForm
# from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, IntegerField, SubmitField, SelectField, PasswordField, DecimalField, DateField
from wtforms.validators import DataRequired, IPAddress, Regexp, ValidationError, Length, Optional, NumberRange
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_paginate import Pagination, get_page_parameter
from sqlalchemy.exc import IntegrityError, OperationalError, DisconnectionError
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
from datetime import timedelta, timezone

# Carrega as variáveis de ambiente
load_dotenv()

#Verificação .env
required_env_vars = ['SECRET_KEY', 'MYSQL_HOST', 'MYSQL_PORT', 'MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_DB']
for var in required_env_vars:
    if not os.getenv(var):
        raise EnvironmentError(f"Variável de ambiente obrigatória não encontrada: {var}")

# Configuração do aplicativo
app = Flask(__name__)
# csrf = CSRFProtect(app)
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

# Configurações avançadas do SQLAlchemy para produção
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 3600,          # Recicla conexões a cada 1 hora
    'pool_pre_ping': True,         # Testa conexões antes de usar
    'pool_timeout': 20,            # Timeout para obter conexão do pool
    'pool_size': 10,               # Número de conexões no pool
    'max_overflow': 20,            # Conexões extras se pool lotado
    'connect_args': {
        'connect_timeout': 30,     # Timeout para conectar
        'read_timeout': 30,        # Timeout para leitura
        'write_timeout': 30,       # Timeout para escrita
        'charset': 'utf8mb4',      # Charset para emojis e caracteres especiais
        'autocommit': False        # Desabilitado para controle manual de transações
    }
}

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

# Configuração de timezone - Brasília (UTC-3)
BRASIL_TZ = timezone(timedelta(hours=-3))

def to_local_time(utc_dt):
    """Converte datetime UTC para horário de Brasília (UTC-3)"""
    if utc_dt is None:
        return None
    if utc_dt.tzinfo is None:
        # Se não tem timezone, assume que é UTC
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    # Converte para horário de Brasília
    local_dt = utc_dt.astimezone(BRASIL_TZ)
    return local_dt

def retry_db_operation(operation, max_retries=3, delay=1):
    """
    Executa uma operação de banco com retry em caso de erro de conexão
    """
    for attempt in range(max_retries):
        try:
            return operation()
        except (OperationalError, DisconnectionError) as e:
            app.logger.warning(f'Tentativa {attempt + 1} falhou: {str(e)}')
            if attempt == max_retries - 1:
                # Última tentativa falhou, relança a exceção
                raise e
            # Aguarda antes da próxima tentativa
            time.sleep(delay * (attempt + 1))
            # Limpa a sessão antes de tentar novamente
            db.session.rollback()
            db.session.close()
        except Exception as e:
            # Para outros tipos de erro, não tenta novamente
            app.logger.error(f'Erro não relacionado à conexão: {str(e)}')
            raise e

@login_manager.user_loader
def load_user(user_id):
    try:
        return retry_db_operation(lambda: db.session.get(Usuario, int(user_id)))
    except (OperationalError, DisconnectionError) as e:
        app.logger.error(f'Erro de conexão ao carregar usuário {user_id}: {str(e)}')
        return None
    except Exception as e:
        app.logger.error(f'Erro ao carregar usuário {user_id}: {str(e)}')
        return None
# ------------------------------ TÉRMINO: Configuração de logs --------------------------------------------
#
# ------------------------------ COMEÇO: Modelos de dados (classes) ---------------------------------------
class Registro(db.Model):
    __tablename__ = 'registros'
    
    id = db.Column(db.Integer, primary_key=True)
    base = db.Column(db.String(100), nullable=False, index=True) #dados das bases 06.05
    nome = db.Column(db.String(100), nullable=False, index=True)
    departamento = db.Column(db.String(100), nullable=False, index=True)
    tipo_dispositivo = db.Column(db.String(50), nullable=False, index=True) #tipo de dispositivo
    endereco_ip = db.Column(db.String(20), nullable=False, unique=True, index=True)
    mac_adress = db.Column(db.String(20), nullable=False, unique=True, index=True)
    hostname = db.Column(db.String(100), nullable=False, index=True)
    serial_number = db.Column(db.String(50), nullable=False, unique=True, index=True) #serial number da máquina
    memoria_ram = db.Column(db.Integer, nullable=False)
    ssd = db.Column(db.Integer, nullable=False) 
    ramal = db.Column(db.Integer, nullable=False, unique=True) #dados de ramal
    anydesk  = db.Column(db.String(20), nullable=False, unique=True, index=True) #dados de anydesk! 06.05
    id_organizacao = db.Column(db.Integer, db.ForeignKey('organizacao.id_organizacao'), nullable=False, index=True) #dados de organizacao
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)
    ultima_atualizacao = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    one_drive_pessoal = db.Column(db.Boolean, default=False, comment="Confirmação do One Drive Pessoal") #campo para confirmação do one drive pessoal! 09.01
    
    # Campos financeiros para gestão patrimonial
    valor_aquisicao = db.Column(db.Numeric(10, 2), nullable=True, comment="Valor de aquisição do dispositivo")
    data_aquisicao = db.Column(db.Date, nullable=True, comment="Data de aquisição")
    vida_util_anos = db.Column(db.Integer, nullable=True, default=5, comment="Vida útil em anos")
    taxa_depreciacao = db.Column(db.Numeric(5, 2), nullable=True, default=20.0, comment="Taxa de depreciação anual %")
    fornecedor = db.Column(db.String(100), nullable=True, comment="Fornecedor do dispositivo")
    numero_nota_fiscal = db.Column(db.String(50), nullable=True, comment="Número da nota fiscal")
    status_ativo = db.Column(db.String(20), nullable=False, default='ATIVO', comment="Status do ativo", index=True)
    categoria_financeira = db.Column(db.String(50), nullable=True, comment="Categoria para análise financeira")
    centro_custo = db.Column(db.String(50), nullable=True, comment="Centro de custo")
    
    # Relacionamento com Organizacao
    organizacao = db.relationship('Organizacao', backref='registros')
    
    def __repr__(self):
        return f'<Registro {self.nome} - {self.endereco_ip}>'
    
    def calcular_depreciacao(self):
        """Calcula a depreciação acumulada e valor residual do ativo"""
        if not self.valor_aquisicao or not self.data_aquisicao:
            return {'valor_residual': 0, 'depreciacao_acumulada': 0, 'idade_anos': 0, 'obsoleto': False}
        
        hoje = datetime.now().date()
        idade_dias = (hoje - self.data_aquisicao).days
        idade_anos = idade_dias / 365.25
        
        # Calcula depreciação linear
        taxa_anual = float(self.taxa_depreciacao or 20.0) / 100
        depreciacao_acumulada = float(self.valor_aquisicao) * taxa_anual * min(idade_anos, self.vida_util_anos or 5)
        valor_residual = max(float(self.valor_aquisicao) - depreciacao_acumulada, 0)
        
        # Se passou da vida útil, considerar valor residual mínimo (10% do valor original)
        if idade_anos > (self.vida_util_anos or 5):
            valor_residual = float(self.valor_aquisicao) * 0.1
            
        return {
            'valor_residual': round(valor_residual, 2),
            'depreciacao_acumulada': round(depreciacao_acumulada, 2),
            'idade_anos': round(idade_anos, 1),
            'obsoleto': idade_anos > (self.vida_util_anos or 5)
        }
    
    def to_dict(self):
        return {
            'id': self.id,
            'base': self.base, #dados das bases
            'nome': self.nome,
            'departamento': self.departamento,
            'tipo_dispositivo': self.tipo_dispositivo, #tipo de dispositivo
            'endereco_ip': self.endereco_ip,
            'mac_adress': self.mac_adress,
            'hostname': self.hostname,
            'serial_number': self.serial_number, #serial number da máquina
            'memoria_ram': self.memoria_ram,
            'ssd': self.ssd,
            'ramal': self.ramal, #dados de ramal 
            'anydesk': self.anydesk, #dados de anydesk
            'organizacao': self.organizacao.nome_organizacao if self.organizacao else 'N/A', #dados de organizacao
            'data_cadastro': to_local_time(self.data_cadastro).strftime('%d/%m/%Y %H:%M') if self.data_cadastro else '',
            'ultima_atualizacao': to_local_time(self.ultima_atualizacao).strftime('%d/%m/%Y %H:%M') if self.ultima_atualizacao else '',
            'one_drive_pessoal': self.one_drive_pessoal, #confirmação do one drive pessoal 09.01
            # Campos financeiros
            'valor_aquisicao': float(self.valor_aquisicao) if self.valor_aquisicao else 0.0,
            'data_aquisicao': self.data_aquisicao.strftime('%d/%m/%Y') if self.data_aquisicao else '',
            'vida_util_anos': self.vida_util_anos or 5,
            'taxa_depreciacao': float(self.taxa_depreciacao) if self.taxa_depreciacao else 20.0,
            'fornecedor': self.fornecedor or '',
            'numero_nota_fiscal': self.numero_nota_fiscal or '',
            'status_ativo': self.status_ativo,
            'categoria_financeira': self.categoria_financeira or '',
            'centro_custo': self.centro_custo or '',
            # Cálculos de depreciação
            'depreciacao_info': self.calcular_depreciacao()
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
    
class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class Base(db.Model): #class base inclusa 29/05
    __tablename__ = 'bases'
    id = db.Column(db.String(10), primary_key=True)
    nome = db.Column(db.String(100), nullable=False, unique=True)

    def __repr__(self):
        return f'<Base {self.nome}>'

class Departamento(db.Model): #class departamentos 29/05 
    __tablename__ = 'departamentos'
    id = db.Column(db.String(20), primary_key=True)
    nome = db.Column(db.String(100), nullable=False, unique=True)

    def __repr__(self):
        return f'<Departamento {self.nome}>'

class Organizacao(db.Model): #class organizacao
    __tablename__ = 'organizacao'
    id_organizacao = db.Column(db.Integer, primary_key=True)
    nome_organizacao = db.Column(db.String(100), nullable=False, unique=True)

    def __repr__(self):
        return f'<Organizacao {self.nome_organizacao}>'

class DispositivoMovel(db.Model): #class para tablets e celulares
    __tablename__ = 'dispositivos_moveis'
    
    id = db.Column(db.Integer, primary_key=True)
    base = db.Column(db.String(100), nullable=False, index=True)
    nome = db.Column(db.String(100), nullable=False, index=True)  # Nome do usuário/responsável
    departamento = db.Column(db.String(100), nullable=False, index=True)
    tipo_dispositivo = db.Column(db.String(50), nullable=False, index=True)  # tablet ou celular
    one_drive_pessoal = db.Column(db.Boolean, default=False, comment="Confirmação do One Drive Pessoal") #campo para confirmação do one drive pessoal! 09.01
    
    # Campos específicos para dispositivos móveis
    numero_telefone = db.Column(db.String(20), nullable=False, unique=True, index=True)
    imei = db.Column(db.String(20), nullable=False, unique=True, index=True)
    modelo_dispositivo = db.Column(db.String(100), nullable=False, index=True)
    sistema_operacional = db.Column(db.String(50), nullable=False)  # iOS, Android
    versao_so = db.Column(db.String(20), nullable=False)
    numero_chip = db.Column(db.String(20), nullable=True, index=True)  # Número da linha/chip
    plano_dados = db.Column(db.String(100), nullable=True)  # Plano de dados contratado
    operadora = db.Column(db.String(50), nullable=True)  # Vivo, Claro, TIM, etc
    
    id_organizacao = db.Column(db.Integer, db.ForeignKey('organizacao.id_organizacao'), nullable=False, index=True)
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)
    ultima_atualizacao = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Campos financeiros para gestão patrimonial
    valor_aquisicao = db.Column(db.Numeric(10, 2), nullable=True, comment="Valor de aquisição do dispositivo")
    data_aquisicao = db.Column(db.Date, nullable=True, comment="Data de aquisição")
    vida_util_anos = db.Column(db.Integer, nullable=True, default=3, comment="Vida útil em anos (menor para móveis)")
    taxa_depreciacao = db.Column(db.Numeric(5, 2), nullable=True, default=33.33, comment="Taxa de depreciação anual %")
    fornecedor = db.Column(db.String(100), nullable=True, comment="Fornecedor do dispositivo")
    numero_nota_fiscal = db.Column(db.String(50), nullable=True, comment="Número da nota fiscal")
    status_ativo = db.Column(db.String(20), nullable=False, default='ATIVO', comment="Status do ativo", index=True)
    categoria_financeira = db.Column(db.String(50), nullable=True, comment="Categoria para análise financeira")
    centro_custo = db.Column(db.String(50), nullable=True, comment="Centro de custo")
    
    # Relacionamento com Organizacao
    organizacao = db.relationship('Organizacao', backref='dispositivos_moveis')
    
    def __repr__(self):
        return f'<DispositivoMovel {self.nome} - {self.numero_telefone}>'
    
    def calcular_depreciacao(self):
        """Calcula a depreciação acumulada e valor residual do dispositivo móvel"""
        if not self.valor_aquisicao or not self.data_aquisicao:
            return {'valor_residual': 0, 'depreciacao_acumulada': 0, 'idade_anos': 0, 'obsoleto': False}
        
        hoje = datetime.now().date()
        idade_dias = (hoje - self.data_aquisicao).days
        idade_anos = idade_dias / 365.25
        
        # Calcula depreciação linear (móveis depreciam mais rápido)
        taxa_anual = float(self.taxa_depreciacao or 33.33) / 100
        depreciacao_acumulada = float(self.valor_aquisicao) * taxa_anual * min(idade_anos, self.vida_util_anos or 3)
        valor_residual = max(float(self.valor_aquisicao) - depreciacao_acumulada, 0)
        
        # Se passou da vida útil, considerar valor residual mínimo (5% para móveis)
        if idade_anos > (self.vida_util_anos or 3):
            valor_residual = float(self.valor_aquisicao) * 0.05
            
        return {
            'valor_residual': round(valor_residual, 2),
            'depreciacao_acumulada': round(depreciacao_acumulada, 2),
            'idade_anos': round(idade_anos, 1),
            'obsoleto': idade_anos > (self.vida_util_anos or 3)
        }
    
    def to_dict(self):
        return {
            'id': self.id,
            'base': self.base,
            'nome': self.nome,
            'departamento': self.departamento,
            'tipo_dispositivo': self.tipo_dispositivo,
            'numero_telefone': self.numero_telefone,
            'imei': self.imei,
            'modelo_dispositivo': self.modelo_dispositivo,
            'sistema_operacional': self.sistema_operacional,
            'versao_so': self.versao_so,
            'numero_chip': self.numero_chip,
            'plano_dados': self.plano_dados,
            'operadora': self.operadora,
            'organizacao': self.organizacao.nome_organizacao if self.organizacao else 'N/A',
            'data_cadastro': to_local_time(self.data_cadastro).strftime('%d/%m/%Y %H:%M') if self.data_cadastro else '',
            'ultima_atualizacao': to_local_time(self.ultima_atualizacao).strftime('%d/%m/%Y %H:%M') if self.ultima_atualizacao else '',
            'one_drive_pessoal': self.one_drive_pessoal, #confirmação do one drive pessoal 09.01
            # Campos financeiros
            'valor_aquisicao': float(self.valor_aquisicao) if self.valor_aquisicao else 0.0,
            'data_aquisicao': self.data_aquisicao.strftime('%d/%m/%Y') if self.data_aquisicao else '',
            'vida_util_anos': self.vida_util_anos or 3,
            'taxa_depreciacao': float(self.taxa_depreciacao) if self.taxa_depreciacao else 33.33,
            'fornecedor': self.fornecedor or '',
            'numero_nota_fiscal': self.numero_nota_fiscal or '',
            'status_ativo': self.status_ativo,
            'categoria_financeira': self.categoria_financeira or '',
            'centro_custo': self.centro_custo or '',
            # Cálculos de depreciação
            'depreciacao_info': self.calcular_depreciacao()
        }
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
    # Commit apenas do log, sem afetar outras transações
    try:
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Erro ao registrar log de auditoria: {e}")
        db.session.rollback()
        # Não propagar o erro para não afetar a operação principal
# ------------------------------ TÉRMINO: Função para registrar logs de auditoria  -------------------------
#
# ------------------------------ COMEÇO: Validadores personalizados  ---------------------------------------

def validate_hostname_existente(form, field):
    if len(field.data) < 3:
        raise ValidationError('O hostname deve ter pelo menos 3 caracteres.')
    
    if Registro.query.filter(Registro.hostname == field.data, Registro.id != getattr(form, 'id', None)).first():
        raise ValidationError('Este hostname já está em uso.')

def validate_serial_existente(form, field):
    if Registro.query.filter(Registro.serial_number == field.data, Registro.id != getattr(form, 'id', None)).first():
        raise ValidationError('Este Serial Number já está em uso.')

def validate_ip_existente(form, field):
    registro_id = form.id if hasattr(form, 'id') else None
    if Registro.query.filter(Registro.endereco_ip == field.data, Registro.id != registro_id).first():
        raise ValidationError('Este endereço IP já está em uso.')

def validate_mac_existente(form, field):
    # Padronizar MAC antes de verificar duplicidade
    mac_padronizado = field.data.upper().replace('-', ':').strip()
    registro_id = getattr(form, 'id', None)
    if Registro.query.filter(Registro.mac_adress == mac_padronizado, Registro.id != registro_id).first():
        raise ValidationError('Este MAC Address já está em uso.')

def validate_anydesk_existente(form, field):
    registro_id = getattr(form, 'id', None)
    if Registro.query.filter(Registro.anydesk == field.data, Registro.id != registro_id).first():
        raise ValidationError('Este código AnyDesk já está em uso.')

# Ramal pode ser duplicado, então não há validação específica

# Validadores para dispositivos móveis (tablet/celular)
def validate_telefone_existente(form, field):
    dispositivo_id = getattr(form, 'id', None)
    if DispositivoMovel.query.filter(DispositivoMovel.numero_telefone == field.data, DispositivoMovel.id != dispositivo_id).first():
        raise ValidationError('Este número de telefone já está em uso.')

def validate_imei_existente(form, field):
    # Padronizar IMEI (apenas números)
    imei_padronizado = ''.join(filter(str.isdigit, field.data))
    dispositivo_id = getattr(form, 'id', None)
    if DispositivoMovel.query.filter(DispositivoMovel.imei == imei_padronizado, DispositivoMovel.id != dispositivo_id).first():
        raise ValidationError('Este IMEI já está em uso.')
                             
# ------------------------------ TÉRMINO: Validadores personalizados  --------------------------------------
#
#  ------------------------------ COMEÇO: Formulário de cadastro/edição ------------------------------------

class MaquinaForm(FlaskForm):
    base = SelectField('Base', validators=[DataRequired(message="Escolha a base...")], choices=[])
    nome = StringField('Nome da Máquina', validators=[
        DataRequired(message="Nome é obrigatório"),
        Length(min=2, max=100, message="Nome deve ter entre 2 e 100 caracteres")
    ])
    departamento = SelectField('Departamento', validators=[DataRequired(message="Departamento é obrigatório")], choices=[])
    organizacao = SelectField('Organização', validators=[DataRequired(message="Organização é obrigatória")], choices=[])
    onedrive_pessoal = SelectField('OneDrive Pessoal Configurado?', validators=[DataRequired(message="Informe se o OneDrive pessoal está configurado")], choices=[
        ('', 'Selecione...'),
        ('sim', 'Sim'),
        ('nao', 'Não')
    ])
    endereco_ip = StringField('Endereço IP', validators=[
        DataRequired(message="Endereço IP é obrigatório"),
        IPAddress(message="Endereço IP inválido"),
        validate_ip_existente
    ])
    mac_adress = StringField('MAC Address', validators=[
        DataRequired(message="MAC Address é obrigatório"),
        Regexp(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', message="Formato de MAC Address inválido"),
        validate_mac_existente
    ])
    hostname = StringField('Hostname', validators=[
        DataRequired(),
        Length(min=3, message="Hostname deve ter pelo menos 3 caracteres.")
    ])
    serial_number = StringField('Serial Number', validators=[
        DataRequired(message="Serial Number é obrigatório"),
        Length(min=3, max=50, message="Serial Number deve ter entre 3 e 50 caracteres"),
        validate_serial_existente
    ])
    memoria_ram = IntegerField('Memória RAM (GB)', validators=[DataRequired()])
    ssd = IntegerField('SSD (GB)', validators=[DataRequired()])
    ramal = IntegerField('Ramal', validators=[DataRequired()])
    anydesk = StringField('Anydesk', validators=[
        DataRequired(message="Anydesk é obrigatório"),
        validate_anydesk_existente
    ])
    
    # Campos financeiros para gestão patrimonial
    valor_aquisicao = DecimalField('Valor de Aquisição (R$)', places=2, validators=[
        Optional(),
        NumberRange(min=0, message="Valor deve ser positivo")
    ])
    data_aquisicao = DateField('Data de Aquisição', validators=[Optional()])
    vida_util_anos = IntegerField('Vida Útil (anos)', validators=[
        Optional(),
        NumberRange(min=1, max=10, message="Vida útil deve estar entre 1 e 10 anos")
    ], default=5)
    taxa_depreciacao = DecimalField('Taxa de Depreciação Anual (%)', places=2, validators=[
        Optional(),
        NumberRange(min=0, max=100, message="Taxa deve estar entre 0 e 100%")
    ], default=20.0)
    fornecedor = StringField('Fornecedor', validators=[
        Optional(),
        Length(max=100, message="Fornecedor deve ter no máximo 100 caracteres")
    ])
    numero_nota_fiscal = StringField('Número da Nota Fiscal', validators=[
        Optional(),
        Length(max=50, message="Número da NF deve ter no máximo 50 caracteres")
    ])
    status_ativo = SelectField('Status do Ativo', validators=[DataRequired()], choices=[
        ('ATIVO', 'Ativo'),
        ('INATIVO', 'Inativo'),
        ('MANUTENCAO', 'Em Manutenção'),
        ('DESCARTADO', 'Descartado')
    ], default='ATIVO')
    categoria_financeira = SelectField('Categoria Financeira', validators=[Optional()], choices=[
        ('', 'Selecione...'),
        ('TI_ESCRITORIO', 'TI - Escritório'),
        ('TI_SERVIDOR', 'TI - Servidor'),
        ('TI_REDE', 'TI - Rede'),
        ('TI_MOBILE', 'TI - Mobile')
    ])
    centro_custo = SelectField('Centro de Custo', validators=[Optional()], choices=[])

    def __init__(self, *args, registro_id=None, **kwargs):
        super(MaquinaForm, self).__init__(*args, **kwargs)
        self.id = registro_id
        self.base.choices = [(b.id, b.nome) for b in Base.query.order_by(Base.nome).all()]
        self.departamento.choices = [(d.id, d.nome) for d in Departamento.query.order_by(Departamento.nome).all()]
        self.organizacao.choices = [(o.id_organizacao, o.nome_organizacao) for o in Organizacao.query.order_by(Organizacao.nome_organizacao).all()]
        # Centro de custos baseado nos departamentos
        self.centro_custo.choices = [('', 'Selecione...')] + [(d.nome, d.nome) for d in Departamento.query.order_by(Departamento.nome).all()]

class DispositivoMovelForm(FlaskForm):
    base = SelectField('Base', validators=[DataRequired(message="Escolha a base...")], choices=[])
    nome = StringField('Nome do Responsável', validators=[
        DataRequired(message="Nome é obrigatório"),
        Length(min=2, max=100, message="Nome deve ter entre 2 e 100 caracteres")
    ])
    departamento = SelectField('Departamento', validators=[DataRequired(message="Departamento é obrigatório")], choices=[])
    organizacao = SelectField('Organização', validators=[DataRequired(message="Organização é obrigatória")], choices=[])
    onedrive_pessoal = SelectField('OneDrive Pessoal Configurado?', validators=[DataRequired(message="Informe se o OneDrive pessoal está configurado")], choices=[
        ('', 'Selecione...'),
        ('sim', 'Sim'),
        ('nao', 'Não')
    ])
    
    # Campos específicos para dispositivos móveis
    numero_telefone = StringField('Número de Telefone', validators=[
        DataRequired(message="Número de telefone é obrigatório"),
        Regexp(r'^\(\d{2}\)\s\d{4,5}-\d{4}$', message="Formato: (11) 99999-9999"),
        validate_telefone_existente
    ])
    imei = StringField('IMEI', validators=[
        DataRequired(message="IMEI é obrigatório"),
        Length(min=15, max=15, message="IMEI deve ter 15 dígitos"),
        Regexp(r'^\d{15}$', message="IMEI deve conter apenas 15 números"),
        validate_imei_existente
    ])
    modelo_dispositivo = StringField('Modelo do Dispositivo', validators=[
        DataRequired(message="Modelo é obrigatório"),
        Length(min=2, max=100, message="Modelo deve ter entre 2 e 100 caracteres")
    ])
    sistema_operacional = SelectField('Sistema Operacional', validators=[DataRequired()], choices=[
        ('', 'Selecione o SO...'),
        ('iOS', 'iOS'),
        ('Android', 'Android'),
        ('iPadOS', 'iPadOS'),
        ('Windows', 'Windows Mobile'),
        ('Outro', 'Outro')
    ])
    versao_so = StringField('Versão do SO', validators=[
        DataRequired(message="Versão do SO é obrigatória"),
        Length(min=1, max=20, message="Versão deve ter entre 1 e 20 caracteres")
    ])
    numero_chip = StringField('Número do Chip/Linha', validators=[
        Length(max=20, message="Número do chip deve ter até 20 caracteres")
    ])
    plano_dados = StringField('Plano de Dados', validators=[
        Length(max=100, message="Plano deve ter até 100 caracteres")
    ])
    operadora = SelectField('Operadora', choices=[
        ('', 'Selecione a operadora...'),
        ('Vivo', 'Vivo'),
        ('Claro', 'Claro'),
        ('TIM', 'TIM'),
        ('Oi', 'Oi'),
        ('Algar', 'Algar'),
        ('Outra', 'Outra')
    ])
    
    # Campos financeiros para gestão patrimonial
    valor_aquisicao = DecimalField('Valor de Aquisição (R$)', places=2, validators=[
        Optional(),
        NumberRange(min=0, message="Valor deve ser positivo")
    ])
    data_aquisicao = DateField('Data de Aquisição', validators=[Optional()])
    vida_util_anos = IntegerField('Vida Útil (anos)', validators=[
        Optional(),
        NumberRange(min=1, max=5, message="Vida útil deve estar entre 1 e 5 anos")
    ], default=3)
    taxa_depreciacao = DecimalField('Taxa de Depreciação Anual (%)', places=2, validators=[
        Optional(),
        NumberRange(min=0, max=100, message="Taxa deve estar entre 0 e 100%")
    ], default=33.33)
    fornecedor = StringField('Fornecedor', validators=[
        Optional(),
        Length(max=100, message="Fornecedor deve ter no máximo 100 caracteres")
    ])
    numero_nota_fiscal = StringField('Número da Nota Fiscal', validators=[
        Optional(),
        Length(max=50, message="Número da NF deve ter no máximo 50 caracteres")
    ])
    status_ativo = SelectField('Status do Ativo', validators=[DataRequired()], choices=[
        ('ATIVO', 'Ativo'),
        ('INATIVO', 'Inativo'),
        ('MANUTENCAO', 'Em Manutenção'),
        ('DESCARTADO', 'Descartado')
    ], default='ATIVO')
    categoria_financeira = SelectField('Categoria Financeira', validators=[Optional()], choices=[
        ('', 'Selecione...'),
        ('TI_MOBILE_CELULAR', 'TI - Celular'),
        ('TI_MOBILE_TABLET', 'TI - Tablet')
    ])
    centro_custo = SelectField('Centro de Custo', validators=[Optional()], choices=[])

    def __init__(self, *args, dispositivo_id=None, **kwargs):
        super(DispositivoMovelForm, self).__init__(*args, **kwargs)
        self.id = dispositivo_id
        self.base.choices = [(b.id, b.nome) for b in Base.query.order_by(Base.nome).all()]
        self.departamento.choices = [(d.id, d.nome) for d in Departamento.query.order_by(Departamento.nome).all()]
        self.organizacao.choices = [(o.id_organizacao, o.nome_organizacao) for o in Organizacao.query.order_by(Organizacao.nome_organizacao).all()]
        # Centro de custos baseado nos departamentos
        self.centro_custo.choices = [('', 'Selecione...')] + [(d.nome, d.nome) for d in Departamento.query.order_by(Departamento.nome).all()]


# Formulário para edição de máquinas (inclui tipo_dispositivo)
class MaquinaEditForm(MaquinaForm):
    tipo_dispositivo = SelectField('Tipo de Dispositivo', validators=[DataRequired()], choices=[
        ('desktop', 'Desktop'),
        ('notebook', 'Notebook')
    ])

#  ------------------------------ TÉRMINO: Formulário de cadastro/edição ------------------------------------
#
# ------------------------------ COMEÇO: Funções de Análise Financeira e Patrimonial ----------------------

def calcular_estatisticas_financeiras():
    """Calcula estatísticas financeiras completas para análise patrimonial"""
    try:
        # Estatísticas Desktop/Notebook
        desktop_notebook_stats = db.session.query(
            db.func.count(Registro.id).label('total'),
            db.func.sum(Registro.valor_aquisicao).label('valor_total'),
            db.func.avg(Registro.valor_aquisicao).label('valor_medio'),
            db.func.count(db.case((Registro.status_ativo == 'ATIVO', 1))).label('ativos'),
            db.func.count(db.case((Registro.status_ativo == 'INATIVO', 1))).label('inativos'),
            db.func.count(db.case((Registro.status_ativo == 'MANUTENCAO', 1))).label('manutencao'),
            db.func.count(db.case((Registro.status_ativo == 'DESCARTADO', 1))).label('descartados')
        ).filter(Registro.valor_aquisicao.isnot(None)).first()
        
        # Estatísticas Dispositivos Móveis
        movel_stats = db.session.query(
            db.func.count(DispositivoMovel.id).label('total'),
            db.func.sum(DispositivoMovel.valor_aquisicao).label('valor_total'),
            db.func.avg(DispositivoMovel.valor_aquisicao).label('valor_medio'),
            db.func.count(db.case((DispositivoMovel.status_ativo == 'ATIVO', 1))).label('ativos'),
            db.func.count(db.case((DispositivoMovel.status_ativo == 'INATIVO', 1))).label('inativos'),
            db.func.count(db.case((DispositivoMovel.status_ativo == 'MANUTENCAO', 1))).label('manutencao'),
            db.func.count(db.case((DispositivoMovel.status_ativo == 'DESCARTADO', 1))).label('descartados')
        ).filter(DispositivoMovel.valor_aquisicao.isnot(None)).first()
        
        # Calcular depreciação total
        depreciacao_desktop = 0
        valor_residual_desktop = 0
        obsoletos_desktop = 0
        
        for registro in Registro.query.filter(Registro.valor_aquisicao.isnot(None)).all():
            info = registro.calcular_depreciacao()
            depreciacao_desktop += info['depreciacao_acumulada']
            valor_residual_desktop += info['valor_residual']
            if info.get('obsoleto'):
                obsoletos_desktop += 1
                
        depreciacao_movel = 0
        valor_residual_movel = 0
        obsoletos_movel = 0
        
        for dispositivo in DispositivoMovel.query.filter(DispositivoMovel.valor_aquisicao.isnot(None)).all():
            info = dispositivo.calcular_depreciacao()
            depreciacao_movel += info['depreciacao_acumulada']
            valor_residual_movel += info['valor_residual']
            if info.get('obsoleto'):
                obsoletos_movel += 1
        
        # Estatísticas por tipo de dispositivo
        tipo_stats = db.session.query(
            Registro.tipo_dispositivo,
            db.func.count(Registro.id).label('quantidade'),
            db.func.sum(Registro.valor_aquisicao).label('valor_total'),
            db.func.avg(Registro.valor_aquisicao).label('valor_medio')
        ).filter(Registro.valor_aquisicao.isnot(None)).group_by(Registro.tipo_dispositivo).all()
        
        # Adicionar tablets e celulares
        for tipo in ['tablet', 'celular']:
            tipo_movel_stats = db.session.query(
                db.func.count(DispositivoMovel.id).label('quantidade'),
                db.func.sum(DispositivoMovel.valor_aquisicao).label('valor_total'),
                db.func.avg(DispositivoMovel.valor_aquisicao).label('valor_medio')
            ).filter(
                DispositivoMovel.tipo_dispositivo == tipo,
                DispositivoMovel.valor_aquisicao.isnot(None)
            ).first()
            
            if tipo_movel_stats and tipo_movel_stats.quantidade > 0:
                tipo_stats.append(type('TipoStat', (), {
                    'tipo_dispositivo': tipo,
                    'quantidade': tipo_movel_stats.quantidade,
                    'valor_total': tipo_movel_stats.valor_total,
                    'valor_medio': tipo_movel_stats.valor_medio
                })())
        
        # Estatísticas por departamento
        dept_stats = db.session.query(
            Registro.departamento,
            db.func.count(Registro.id).label('quantidade'),
            db.func.sum(Registro.valor_aquisicao).label('valor_investido')
        ).filter(Registro.valor_aquisicao.isnot(None)).group_by(Registro.departamento).all()
        
        # Adicionar dispositivos móveis por departamento
        dept_movel_stats = db.session.query(
            DispositivoMovel.departamento,
            db.func.count(DispositivoMovel.id).label('quantidade'),
            db.func.sum(DispositivoMovel.valor_aquisicao).label('valor_investido')
        ).filter(DispositivoMovel.valor_aquisicao.isnot(None)).group_by(DispositivoMovel.departamento).all()
        
        # Consolidar departamentos
        dept_dict = {}
        for stat in dept_stats:
            dept_dict[stat.departamento] = {
                'quantidade': stat.quantidade,
                'valor_investido': float(stat.valor_investido or 0)
            }
        
        for stat in dept_movel_stats:
            if stat.departamento in dept_dict:
                dept_dict[stat.departamento]['quantidade'] += stat.quantidade
                dept_dict[stat.departamento]['valor_investido'] += float(stat.valor_investido or 0)
            else:
                dept_dict[stat.departamento] = {
                    'quantidade': stat.quantidade,
                    'valor_investido': float(stat.valor_investido or 0)
                }
        
        return {
            'desktop_notebook': {
                'total': desktop_notebook_stats.total or 0,
                'valor_total': float(desktop_notebook_stats.valor_total or 0),
                'valor_medio': float(desktop_notebook_stats.valor_medio or 0),
                'depreciacao_acumulada': depreciacao_desktop,
                'valor_residual_total': valor_residual_desktop,
                'obsoletos': obsoletos_desktop,
                'status': {
                    'ativos': desktop_notebook_stats.ativos or 0,
                    'inativos': desktop_notebook_stats.inativos or 0,
                    'manutencao': desktop_notebook_stats.manutencao or 0,
                    'descartados': desktop_notebook_stats.descartados or 0
                }
            },
            'dispositivos_moveis': {
                'total': movel_stats.total or 0,
                'valor_total': float(movel_stats.valor_total or 0),
                'valor_medio': float(movel_stats.valor_medio or 0),
                'depreciacao_acumulada': depreciacao_movel,
                'valor_residual_total': valor_residual_movel,
                'obsoletos': obsoletos_movel,
                'status': {
                    'ativos': movel_stats.ativos or 0,
                    'inativos': movel_stats.inativos or 0,
                    'manutencao': movel_stats.manutencao or 0,
                    'descartados': movel_stats.descartados or 0
                }
            },
            'por_tipo': [
                {
                    'tipo': stat.tipo_dispositivo.title(),
                    'quantidade': stat.quantidade,
                    'valor_total': float(stat.valor_total or 0),
                    'valor_medio': float(stat.valor_medio or 0)
                } for stat in tipo_stats
            ],
            'por_departamento': [
                {
                    'departamento': dept,
                    'quantidade': info['quantidade'],
                    'valor_investido': info['valor_investido']
                } for dept, info in dept_dict.items()
            ],
            'totais': {
                'dispositivos': (desktop_notebook_stats.total or 0) + (movel_stats.total or 0),
                'valor_aquisicao': float((desktop_notebook_stats.valor_total or 0) + (movel_stats.valor_total or 0)),
                'depreciacao_total': depreciacao_desktop + depreciacao_movel,
                'valor_residual': valor_residual_desktop + valor_residual_movel,
                'obsoletos_total': obsoletos_desktop + obsoletos_movel
            }
        }
    except Exception as e:
        app.logger.error(f'Erro ao calcular estatísticas financeiras: {str(e)}')
        return None

def formatar_moeda(valor):
    """Formata valor para moeda brasileira"""
    return f"R$ {valor:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.')

def gerar_insights_inteligentes(total_maquinas, departamentos, distribuicao_ram, distribuicao_ssd, media_ram, media_ssd):
    """Gera insights inteligentes baseados nos dados do sistema"""
    insights = []
    
    # 1. Análise de RAM
    maquinas_ram_baixa = sum(item['quantidade'] for item in distribuicao_ram if item['tamanho'] < 8)
    if maquinas_ram_baixa > 0:
        porcentagem_ram_baixa = (maquinas_ram_baixa / total_maquinas * 100)
        if porcentagem_ram_baixa > 30:
            insights.append({
                'tipo': 'danger',
                'icone': 'fas fa-exclamation-circle',
                'titulo': 'Atualização Urgente de RAM',
                'mensagem': f'{maquinas_ram_baixa} dispositivos ({porcentagem_ram_baixa:.0f}%) possuem menos de 8GB de RAM. Considere um plano de upgrade.',
                'prioridade': 1
            })
        else:
            insights.append({
                'tipo': 'warning',
                'icone': 'fas fa-exclamation-triangle',
                'titulo': 'Monitorar Dispositivos com Pouca RAM',
                'mensagem': f'{maquinas_ram_baixa} dispositivos com menos de 8GB de RAM podem apresentar lentidão em tarefas pesadas.',
                'prioridade': 2
            })
    
    # 2. Análise de SSD
    maquinas_ssd_pequeno = sum(item['quantidade'] for item in distribuicao_ssd if item['tamanho'] < 240)
    if maquinas_ssd_pequeno > 0:
        porcentagem_ssd_pequeno = (maquinas_ssd_pequeno / total_maquinas * 100)
        if porcentagem_ssd_pequeno > 20:
            insights.append({
                'tipo': 'warning',
                'icone': 'fas fa-hdd',
                'titulo': 'Armazenamento Limitado',
                'mensagem': f'{maquinas_ssd_pequeno} dispositivos ({porcentagem_ssd_pequeno:.0f}%) têm menos de 240GB. Pode ser necessário expansão.',
                'prioridade': 2
            })
    
    # 3. Análise de distribuição por departamento
    if departamentos:
        maior_dept = max(departamentos, key=lambda x: x['quantidade'])
        menor_dept = min(departamentos, key=lambda x: x['quantidade'])
        
        if maior_dept['quantidade'] > (total_maquinas * 0.4):
            insights.append({
                'tipo': 'info',
                'icone': 'fas fa-chart-pie',
                'titulo': 'Concentração de Dispositivos',
                'mensagem': f'O departamento {maior_dept["nome"]} concentra {maior_dept["porcentagem"]:.0f}% dos dispositivos. Avalie a distribuição.',
                'prioridade': 3
            })
    
    # 4. Análise financeira (buscar dados financeiros)
    try:
        # Calcular valor total de ativos
        valor_total = db.session.query(db.func.sum(Registro.valor_aquisicao)).scalar() or 0
        valor_total_movel = db.session.query(db.func.sum(DispositivoMovel.valor_aquisicao)).scalar() or 0
        valor_total_geral = float(valor_total or 0) + float(valor_total_movel or 0)
        
        if valor_total_geral > 0:
            # Calcular depreciação média
            registros_com_valor = Registro.query.filter(Registro.valor_aquisicao > 0).all()
            moveis_com_valor = DispositivoMovel.query.filter(DispositivoMovel.valor_aquisicao > 0).all()
            
            total_depreciacao = 0
            equipamentos_obsoletos = 0
            equipamentos_proximos_troca = 0
            
            for reg in registros_com_valor + moveis_com_valor:
                info = reg.calcular_depreciacao()
                if info:
                    total_depreciacao += info['depreciacao_acumulada']
                    if info['obsoleto']:
                        equipamentos_obsoletos += 1
                    elif info['idade_anos'] >= (reg.vida_util_anos * 0.8):
                        equipamentos_proximos_troca += 1
            
            # Insight sobre valor patrimonial
            insights.append({
                'tipo': 'success',
                'icone': 'fas fa-dollar-sign',
                'titulo': 'Valor Patrimonial',
                'mensagem': f'Valor total de ativos: {formatar_moeda(valor_total_geral)}. Depreciação acumulada: {formatar_moeda(total_depreciacao)}.',
                'prioridade': 4
            })
            
            # Insight sobre obsolescência
            if equipamentos_obsoletos > 0:
                insights.append({
                    'tipo': 'danger',
                    'icone': 'fas fa-clock',
                    'titulo': 'Equipamentos Obsoletos',
                    'mensagem': f'{equipamentos_obsoletos} equipamentos já ultrapassaram a vida útil e precisam ser substituídos.',
                    'prioridade': 1
                })
            
            if equipamentos_proximos_troca > 0:
                insights.append({
                    'tipo': 'warning',
                    'icone': 'fas fa-calendar-alt',
                    'titulo': 'Renovação Próxima',
                    'mensagem': f'{equipamentos_proximos_troca} equipamentos estão próximos do fim da vida útil (próximos 12 meses).',
                    'prioridade': 2
                })
    except:
        pass  # Se houver erro ao buscar dados financeiros, continua sem esses insights
    
    # 5. Análise de padrões
    if media_ram < 8:
        insights.append({
            'tipo': 'warning',
            'icone': 'fas fa-memory',
            'titulo': 'Média de RAM Baixa',
            'mensagem': f'A média de RAM ({media_ram:.1f}GB) está abaixo do recomendado (8GB) para ambientes corporativos modernos.',
            'prioridade': 2
        })
    elif media_ram >= 12:
        insights.append({
            'tipo': 'success',
            'icone': 'fas fa-check-circle',
            'titulo': 'Boa Capacidade de RAM',
            'mensagem': f'A média de RAM ({media_ram:.1f}GB) está adequada para aplicações exigentes.',
            'prioridade': 5
        })
    
    # 6. Recomendações baseadas em dados
    if total_maquinas > 100:
        insights.append({
            'tipo': 'info',
            'icone': 'fas fa-lightbulb',
            'titulo': 'Gestão de Ativos',
            'mensagem': f'Com {total_maquinas} dispositivos, considere implementar um sistema de rotação e upgrade programado.',
            'prioridade': 4
        })
    
    # Ordenar insights por prioridade
    insights.sort(key=lambda x: x['prioridade'])
    
    # Limitar a 6 insights mais importantes
    return insights[:6]

def calcular_previsao_substituicao():
    """Calcula previsão de substituição de equipamentos obsoletos"""
    previsoes = []
    
    # Desktop/Notebook
    for registro in Registro.query.filter(
        Registro.valor_aquisicao.isnot(None),
        Registro.data_aquisicao.isnot(None),
        Registro.status_ativo == 'ATIVO'
    ).all():
        info = registro.calcular_depreciacao()
        if info and info['idade_anos'] > (registro.vida_util_anos or 5) * 0.8:  # 80% da vida útil
            data_substituicao = registro.data_aquisicao + timedelta(days=(registro.vida_util_anos or 5) * 365)
            previsoes.append({
                'tipo': 'Desktop/Notebook',
                'dispositivo': f"{registro.hostname} - {registro.nome}",
                'departamento': registro.departamento,
                'idade_anos': info['idade_anos'],
                'data_aquisicao': registro.data_aquisicao,
                'data_substituicao_prevista': data_substituicao,
                'valor_estimado': float(registro.valor_aquisicao or 0) * 1.15,  # 15% de inflação
                'urgencia': 'ALTA' if info['obsoleto'] else 'MÉDIA'
            })
    
    # Dispositivos móveis
    for dispositivo in DispositivoMovel.query.filter(
        DispositivoMovel.valor_aquisicao.isnot(None),
        DispositivoMovel.data_aquisicao.isnot(None),
        DispositivoMovel.status_ativo == 'ATIVO'
    ).all():
        info = dispositivo.calcular_depreciacao()
        if info and info['idade_anos'] > (dispositivo.vida_util_anos or 3) * 0.8:
            data_substituicao = dispositivo.data_aquisicao + timedelta(days=(dispositivo.vida_util_anos or 3) * 365)
            previsoes.append({
                'tipo': 'Dispositivo Móvel',
                'dispositivo': f"{dispositivo.modelo_dispositivo} - {dispositivo.nome}",
                'departamento': dispositivo.departamento,
                'idade_anos': info['idade_anos'],
                'data_aquisicao': dispositivo.data_aquisicao,
                'data_substituicao_prevista': data_substituicao,
                'valor_estimado': float(dispositivo.valor_aquisicao or 0) * 1.20,  # 20% de inflação para móveis
                'urgencia': 'ALTA' if info['obsoleto'] else 'MÉDIA'
            })
    
    # Ordenar por urgência e data
    previsoes.sort(key=lambda x: (x['urgencia'] == 'ALTA', x['data_substituicao_prevista']), reverse=True)
    
    return previsoes

# ------------------------------ TÉRMINO: Funções de Análise Financeira e Patrimonial ---------------------
#
# ------------------------------ COMEÇO: Rotas (protegidas com loginRequired) ------------------------------

@app.route('/')
@login_required
def home():
    """Redireciona para a seleção de tipo de dispositivo"""
    return redirect(url_for('selecionar_tipo_dispositivo'))

@app.route('/selecionar_tipo_dispositivo')
@login_required
def selecionar_tipo_dispositivo():
    """Tela para seleção do tipo de dispositivo antes do cadastro"""
    return render_template('selecionar_tipo_dispositivo.html', titulo='Selecionar Tipo de Dispositivo')

@app.route('/cadastro/<tipo_dispositivo>', methods=['GET', 'POST'], endpoint='cadastro_tipo')
@login_required
def cadastro(tipo_dispositivo):
    app.logger.info(f"=== INÍCIO CADASTRO === Método: {request.method}, Tipo: {tipo_dispositivo}")
    app.logger.info(f"Headers: {dict(request.headers)}")
    
    # Validar tipo de dispositivo
    tipos_permitidos = ['desktop', 'notebook', 'tablet', 'celular']
    if tipo_dispositivo not in tipos_permitidos:
        flash('Tipo de dispositivo inválido.', 'danger')
        return redirect(url_for('selecionar_tipo_dispositivo'))
    
    # Dispositivos móveis (tablet/celular) usam formulário e tabela diferentes
    if tipo_dispositivo in ['tablet', 'celular']:
        return cadastro_dispositivo_movel(tipo_dispositivo)
    
    # Desktop/Notebook usam o formulário original
    form = MaquinaForm()
    
    if request.method == 'POST':
        app.logger.info("=== POST RECEBIDO ===")
        app.logger.info(f"Form data: {request.form.to_dict()}")
        
        if form.validate_on_submit():
            app.logger.info("=== FORMULÁRIO VÁLIDO ===")
            campos_obrigatorios = [form.nome.data, form.endereco_ip.data, form.mac_adress.data, form.serial_number.data]
            if not all(campos_obrigatorios):
                app.logger.warning("Campos obrigatórios faltando")
                flash('Preencha todos os campos obrigatórios.', 'Warning')
                return redirect(url_for('cadastro_tipo', tipo_dispositivo=tipo_dispositivo))
            try:
                novo_registro = Registro(
                base=form.base.data, 
                nome=form.nome.data,
                departamento=form.departamento.data,
                tipo_dispositivo=tipo_dispositivo,
                id_organizacao=form.organizacao.data,
                one_drive_pessoal=form.onedrive_pessoal.data == 'sim',
                endereco_ip=form.endereco_ip.data.strip(),  # Remove espaços
                mac_adress=form.mac_adress.data.upper().replace('-', ':').strip(),  # Padroniza e remove espaços
                hostname=form.hostname.data.strip(),
                serial_number=form.serial_number.data.strip().upper(),  # Serial em maiúsculo
                memoria_ram=form.memoria_ram.data,
                ssd=form.ssd.data,
                ramal=form.ramal.data,
                anydesk=form.anydesk.data,
                # Campos financeiros
                valor_aquisicao=form.valor_aquisicao.data,
                data_aquisicao=form.data_aquisicao.data,
                vida_util_anos=form.vida_util_anos.data or 5,
                taxa_depreciacao=form.taxa_depreciacao.data or 20.0,
                fornecedor=form.fornecedor.data.strip() if form.fornecedor.data else None,
                numero_nota_fiscal=form.numero_nota_fiscal.data.strip() if form.numero_nota_fiscal.data else None,
                status_ativo=form.status_ativo.data,
                categoria_financeira=form.categoria_financeira.data if form.categoria_financeira.data else None,
                centro_custo=form.centro_custo.data if form.centro_custo.data else None
            )
                app.logger.debug(f"Salvando IP: '{novo_registro.endereco_ip}', MAC: '{novo_registro.mac_adress}'") # Log de debug
                app.logger.debug(f"Tipo dispositivo: '{novo_registro.tipo_dispositivo}', Base: '{novo_registro.base}'")
                db.session.add(novo_registro)
                app.logger.debug("Registro adicionado à sessão")
                
                # Primeiro faz o commit do registro principal
                try:
                    db.session.commit()
                    app.logger.info(f'Nova máquina cadastrada: {form.nome.data} ({form.endereco_ip.data})')
                    flash('Máquina cadastrada com sucesso!', 'success')
                    
                    # Depois registra o log (tem seu próprio commit)
                    registrar_log('Cadastro de máquina', detalhes=f'Máquina: {form.nome.data}, IP: {form.endereco_ip.data}')
                    
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f'Erro ao salvar no banco: {str(e)}')
                    raise  # Re-lança a exceção para ser tratada pelo bloco except externo
                    
                return redirect(url_for('relatorio'))
            except IntegrityError as e:
                db.session.rollback()
                app.logger.error(f'Erro ao cadastrar máquina: {str(e)}')
                flash('Erro ao cadastrar: IP ou MAC Address já existentes no sistema.', 'danger')
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Erro ao cadastrar máquina: {str(e)}')
                flash(f'Erro ao cadastrar: {str(e)}', 'danger')
        else:
            # Formulário não é válido
            app.logger.warning("=== FORMULÁRIO INVÁLIDO ===")
            app.logger.warning(f"Erros de validação: {form.errors}")
            for field, errors in form.errors.items():
                app.logger.warning(f"Campo {field}: {errors}")
    
    return render_template('index.html', form=form, titulo=f'Cadastro de {tipo_dispositivo.title()}', tipo_dispositivo=tipo_dispositivo)

def cadastro_dispositivo_movel(tipo_dispositivo):
    """Função auxiliar para cadastro de tablets e celulares"""
    form = DispositivoMovelForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        campos_obrigatorios = [form.nome.data, form.numero_telefone.data, form.imei.data]
        if not all(campos_obrigatorios):
            flash('Preencha todos os campos obrigatórios.', 'Warning')
            return redirect(url_for('cadastro_tipo', tipo_dispositivo=tipo_dispositivo))
        try:
            # Padronizar IMEI para apenas números
            imei_padronizado = ''.join(filter(str.isdigit, form.imei.data))
            
            novo_dispositivo = DispositivoMovel(
                base=form.base.data,
                nome=form.nome.data,
                departamento=form.departamento.data,
                tipo_dispositivo=tipo_dispositivo,
                id_organizacao=form.organizacao.data,
                numero_telefone=form.numero_telefone.data.strip(),
                imei=imei_padronizado,
                modelo_dispositivo=form.modelo_dispositivo.data.strip(),
                sistema_operacional=form.sistema_operacional.data,
                versao_so=form.versao_so.data.strip(),
                numero_chip=form.numero_chip.data.strip() if form.numero_chip.data else None,
                plano_dados=form.plano_dados.data.strip() if form.plano_dados.data else None,
                operadora=form.operadora.data if form.operadora.data else None,
                one_drive_pessoal=form.onedrive_pessoal.data == 'sim',
                # Campos financeiros
                valor_aquisicao=form.valor_aquisicao.data,
                data_aquisicao=form.data_aquisicao.data,
                vida_util_anos=form.vida_util_anos.data or 3,
                taxa_depreciacao=form.taxa_depreciacao.data or 33.33,
                fornecedor=form.fornecedor.data.strip() if form.fornecedor.data else None,
                numero_nota_fiscal=form.numero_nota_fiscal.data.strip() if form.numero_nota_fiscal.data else None,
                status_ativo=form.status_ativo.data,
                categoria_financeira=form.categoria_financeira.data if form.categoria_financeira.data else None,
                centro_custo=form.centro_custo.data if form.centro_custo.data else None
            )
            db.session.add(novo_dispositivo)
            
            # Primeiro faz o commit do registro principal
            try:
                db.session.commit()
                app.logger.info(f'Novo dispositivo móvel cadastrado: {form.nome.data} ({form.numero_telefone.data})')
                flash('Dispositivo móvel cadastrado com sucesso!', 'success')
                
                # Depois registra o log (tem seu próprio commit)
                registrar_log('Cadastro de dispositivo móvel', detalhes=f'Dispositivo: {form.nome.data}, Telefone: {form.numero_telefone.data}')
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Erro ao salvar dispositivo móvel no banco: {str(e)}')
                raise  # Re-lança a exceção para ser tratada pelo bloco except externo
            return redirect(url_for('relatorio'))
        except IntegrityError as e:
            db.session.rollback()
            app.logger.error(f'Erro ao cadastrar dispositivo móvel: {str(e)}')
            if 'numero_telefone' in str(e):
                flash('Erro: Este número de telefone já está cadastrado no sistema.', 'danger')
            elif 'imei' in str(e):
                flash('Erro: Este IMEI já está cadastrado no sistema.', 'danger')
            else:
                flash('Erro ao cadastrar: Telefone ou IMEI já existentes no sistema.', 'danger')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Erro ao cadastrar dispositivo móvel: {str(e)}')
            flash(f'Erro ao cadastrar: {str(e)}', 'danger')
    
    return render_template('cadastro_movel.html', form=form, titulo=f'Cadastro de {tipo_dispositivo.title()}', tipo_dispositivo=tipo_dispositivo)

@app.route('/cadastro')
@login_required
def index():
    """Redireciona para seleção de tipo se acessado sem parâmetro"""
    return redirect(url_for('selecionar_tipo_dispositivo'))

@app.route('/relatorio')
@login_required
def relatorio():
    page = request.args.get(get_page_parameter(), type=int, default=1)
    search = request.args.get('search', '').strip()
    
    # Parâmetros de filtros específicos
    filter_base = request.args.get('filter_base', '').strip()
    filter_nome = request.args.get('filter_nome', '').strip()
    filter_departamento = request.args.get('filter_departamento', '').strip()
    filter_organizacao = request.args.get('filter_organizacao', '').strip()
    filter_ip = request.args.get('filter_ip', '').strip()
    filter_mac = request.args.get('filter_mac', '').strip()
    filter_hostname = request.args.get('filter_hostname', '').strip()
    filter_ramal = request.args.get('filter_ramal', '').strip()
    filter_anydesk = request.args.get('filter_anydesk', '').strip()
    filter_status = request.args.get('filter_status', '').strip()
    filter_tipo = request.args.get('filter_tipo', '').strip()
    
    # Parâmetros de paginação
    per_page_options = [10, 25, 50, 100]
    per_page = request.args.get('per_page', type=int, default=10)
    if per_page not in per_page_options:
        per_page = 10
    
    # Parâmetros de ordenação
    sort_by = request.args.get('sort', 'nome')
    if sort_by not in ['nome', 'departamento', 'organizacao', 'endereco_ip', 'data_cadastro']:
        sort_by = 'nome'
    
    order = request.args.get('order', 'asc')
    if order not in ['asc', 'desc']:
        order = 'asc'
    
    # Query com join para organização
    query = Registro.query.join(Organizacao, Registro.id_organizacao == Organizacao.id_organizacao)
    
    # Aplicar busca geral se informada
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                Registro.nome.ilike(search_term),
                Registro.departamento.ilike(search_term),
                Registro.endereco_ip.ilike(search_term),
                Registro.mac_adress.ilike(search_term),
                Registro.hostname.ilike(search_term),
                Organizacao.nome_organizacao.ilike(search_term)
            )
        )
    
    # Aplicar filtros específicos
    if filter_base:
        query = query.filter(Registro.base.ilike(f"%{filter_base}%"))
    if filter_nome:
        query = query.filter(Registro.nome.ilike(f"%{filter_nome}%"))
    if filter_departamento:
        query = query.filter(Registro.departamento.ilike(f"%{filter_departamento}%"))
    if filter_organizacao:
        query = query.filter(Organizacao.nome_organizacao.ilike(f"%{filter_organizacao}%"))
    if filter_ip:
        query = query.filter(Registro.endereco_ip.ilike(f"%{filter_ip}%"))
    if filter_mac:
        query = query.filter(Registro.mac_adress.ilike(f"%{filter_mac}%"))
    if filter_hostname:
        query = query.filter(Registro.hostname.ilike(f"%{filter_hostname}%"))
    if filter_ramal:
        query = query.filter(Registro.ramal.like(f"%{filter_ramal}%"))
    if filter_anydesk:
        query = query.filter(Registro.anydesk.ilike(f"%{filter_anydesk}%"))
    
    if filter_status:
        query = query.filter(Registro.status_ativo == filter_status)
    
    if filter_tipo:
        query = query.filter(Registro.tipo_dispositivo == filter_tipo)
    
    # Aplicar ordenação
    if sort_by == 'organizacao':
        query = query.order_by(getattr(Organizacao, 'nome_organizacao').asc() if order == 'asc' else getattr(Organizacao, 'nome_organizacao').desc())
    else:
        query = query.order_by(getattr(Registro, sort_by).asc() if order == 'asc' else getattr(Registro, sort_by).desc())
    
    # Configurar parâmetros de paginação
    pagination_params = {}
    if search:
        pagination_params['search'] = search
    if filter_base:
        pagination_params['filter_base'] = filter_base
    if filter_nome:
        pagination_params['filter_nome'] = filter_nome
    if filter_departamento:
        pagination_params['filter_departamento'] = filter_departamento
    if filter_organizacao:
        pagination_params['filter_organizacao'] = filter_organizacao
    if filter_ip:
        pagination_params['filter_ip'] = filter_ip
    if filter_mac:
        pagination_params['filter_mac'] = filter_mac
    if filter_hostname:
        pagination_params['filter_hostname'] = filter_hostname
    if filter_ramal:
        pagination_params['filter_ramal'] = filter_ramal
    if filter_anydesk:
        pagination_params['filter_anydesk'] = filter_anydesk
    if sort_by != 'nome':
        pagination_params['sort'] = sort_by
    if order != 'asc':
        pagination_params['order'] = order
    
    # Sempre adicionar per_page aos parâmetros
    pagination_params['per_page'] = per_page
    
    # Executar query com paginação
    registros = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Criar objeto de paginação
    pagination = Pagination(
        page=page, 
        total=registros.total, 
        css_framework='bootstrap5',
        record_name='registros',
        **pagination_params
    )
    # Obter listas únicas para os filtros
    bases = db.session.query(Registro.base).distinct().order_by(Registro.base).all()
    bases = [b[0] for b in bases if b[0]]
    
    departamentos = db.session.query(Registro.departamento).distinct().order_by(Registro.departamento).all()
    departamentos = [d[0] for d in departamentos if d[0]]
    
    organizacoes = db.session.query(Organizacao.nome_organizacao).distinct().order_by(Organizacao.nome_organizacao).all()
    organizacoes = [o[0] for o in organizacoes if o[0]]
    
    return render_template('relatorio.html', 
                           registros=registros, 
                           pagination=pagination,
                           search=search,
                           page=page,
                           filter_base=filter_base,
                           filter_nome=filter_nome,
                           filter_departamento=filter_departamento,
                           filter_organizacao=filter_organizacao,
                           filter_ip=filter_ip,
                           filter_mac=filter_mac,
                           filter_hostname=filter_hostname,
                           filter_ramal=filter_ramal,
                           filter_anydesk=filter_anydesk,
                           filter_status=filter_status,
                           filter_tipo=filter_tipo,
                           sort_by=sort_by,
                           order=order,
                           per_page=per_page,
                           per_page_options=per_page_options,
                           bases=bases,
                           departamentos=departamentos,
                           organizacoes=organizacoes,
                           titulo='Relatório de Máquinas')


@app.route('/api/dispositivo/<int:id>')
@login_required
def api_dispositivo_detalhes(id):
    """API para retornar detalhes do dispositivo em JSON"""
    registro = Registro.query.get_or_404(id)
    return jsonify(registro.to_dict())

@app.route('/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar(id):
    registro = Registro.query.get_or_404(id)
    form = MaquinaEditForm(registro_id=id)
    
    if request.method == 'GET':
        form.base.data = registro.base
        form.nome.data = registro.nome
        form.departamento.data = registro.departamento
        form.organizacao.data = registro.id_organizacao
        form.onedrive_pessoal.data = 'sim' if registro.one_drive_pessoal else 'nao'
        form.tipo_dispositivo.data = registro.tipo_dispositivo
        form.endereco_ip.data = registro.endereco_ip
        form.mac_adress.data = registro.mac_adress
        form.hostname.data = registro.hostname
        form.serial_number.data = registro.serial_number
        form.memoria_ram.data = registro.memoria_ram
        form.ssd.data = registro.ssd
        form.ramal.data = registro.ramal
        form.anydesk.data =  registro.anydesk
        # Carregar dados financeiros se existirem
        if registro.valor_aquisicao:
            form.valor_aquisicao.data = registro.valor_aquisicao
        if registro.data_aquisicao:
            form.data_aquisicao.data = registro.data_aquisicao
        if registro.vida_util_anos:
            form.vida_util_anos.data = registro.vida_util_anos
        if registro.taxa_depreciacao:
            form.taxa_depreciacao.data = registro.taxa_depreciacao
        if registro.fornecedor:
            form.fornecedor.data = registro.fornecedor
        if registro.numero_nota_fiscal:
            form.numero_nota_fiscal.data = registro.numero_nota_fiscal
        if registro.status_ativo:
            form.status_ativo.data = registro.status_ativo
        if registro.categoria_financeira:
            form.categoria_financeira.data = registro.categoria_financeira
        if registro.centro_custo:
            form.centro_custo.data = registro.centro_custo

    if form.validate_on_submit():
        try:
            registro.base = form.base.data
            registro.nome = form.nome.data
            registro.departamento = form.departamento.data
            registro.tipo_dispositivo = form.tipo_dispositivo.data
            registro.id_organizacao = form.organizacao.data
            registro.one_drive_pessoal = form.onedrive_pessoal.data == 'sim'
            registro.endereco_ip = form.endereco_ip.data.strip() # Remove espaços
            registro.mac_adress = form.mac_adress.data.upper().replace('-', ':').strip()
            registro.hostname = form.hostname.data.strip()
            registro.serial_number = form.serial_number.data.strip().upper()  # Serial em maiúsculo
            registro.memoria_ram = form.memoria_ram.data
            registro.ssd = form.ssd.data
            registro.ramal = form.ramal.data
            registro.anydesk = form.anydesk.data
            
            # Atualizar campos financeiros
            registro.valor_aquisicao = form.valor_aquisicao.data
            registro.data_aquisicao = form.data_aquisicao.data
            registro.vida_util_anos = form.vida_util_anos.data or 5
            registro.taxa_depreciacao = form.taxa_depreciacao.data or 20.0
            registro.fornecedor = form.fornecedor.data.strip() if form.fornecedor.data else None
            registro.numero_nota_fiscal = form.numero_nota_fiscal.data.strip() if form.numero_nota_fiscal.data else None
            registro.status_ativo = form.status_ativo.data
            registro.categoria_financeira = form.categoria_financeira.data if form.categoria_financeira.data else None
            registro.centro_custo = form.centro_custo.data if form.centro_custo.data else None

            app.logger.debug(f"Atualizando IP: '{registro.endereco_ip}', MAC: '{registro.mac_adress}'") # Log de debug
            db.session.commit()
            registrar_log('Edição de máquina', detalhes=f'Máquina: {registro.nome}, IP: {registro.endereco_ip}') 
            flash('Máquina atualizada com sucesso!', 'success')
            app.logger.info(f'Máquina atualizada: {registro.nome} ({registro.endereco_ip})')
            return redirect(url_for('relatorio'))

        except IntegrityError as e:
            db.session.rollback()
            app.logger.error(f'Erro ao atualizar máquina: {str(e)}')
            flash('Erro ao atualizar: IP ou MAC Address já existentes no sistema.', 'danger')
            return redirect(url_for('editar', id=id))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Erro ao atualizar máquina: {str(e)}')
            flash(f'Erro ao atualizar: {str(e)}', 'danger')
            return redirect(url_for('editar', id=id))
    
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
        flash('Erro ao excluir máquina.', 'danger')
        app.logger.error(f'Erro ao excluir máquina: {e}')
    
    return redirect(url_for('relatorio'))

@app.route('/exportar_csv') #função para exportar em csv + logs atribuidas
@login_required
def exportar_csv():
    try:
        # Filtrar resultados para exportação (similar ao relatório)
        search = request.args.get('search', '')
        
        query = Registro.query.join(Organizacao, Registro.id_organizacao == Organizacao.id_organizacao)
        
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    Registro.nome.ilike(search_term),
                    Registro.departamento.ilike(search_term),
                    Registro.endereco_ip.ilike(search_term),
                    Registro.mac_adress.ilike(search_term),
                    Registro.hostname.ilike(search_term),
                    Organizacao.nome_organizacao.ilike(search_term)
                )
            )
        
        registros = query.all()
        
        # Criar CSV na memória
        si = StringIO()
        cw = csv.writer(si)
        
        # Cabeçalhos
        cw.writerow(['Base', 'Nome', 'Departamento', 'Tipo Dispositivo', 'Organização', 'Endereço IP', 'MAC Address', 
                     'Hostname', 'Serial Number', 'Memória RAM (GB)', 'SSD (GB)', 'Ramal', 'Anydesk',
                     'Data de Cadastro', 'Ultima Atualizacao'])
        
        # Dados
        for registro in registros:
            cw.writerow([
                registro.base, 
                registro.nome,
                registro.departamento,
                registro.tipo_dispositivo,
                registro.organizacao.nome_organizacao if registro.organizacao else 'N/A',
                registro.endereco_ip,
                registro.mac_adress,
                registro.hostname,
                registro.serial_number,
                registro.memoria_ram,
                registro.ssd,
                registro.ramal,
                registro.anydesk,
                to_local_time(registro.data_cadastro).strftime('%d/%m/%Y %H:%M') if registro.data_cadastro else '',
                to_local_time(registro.ultima_atualizacao).strftime('%d/%m/%Y %H:%M') if registro.ultima_atualizacao else ''
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
    
    # Gerar insights inteligentes
    insights = gerar_insights_inteligentes(
        total_maquinas=total_maquinas,
        departamentos=departamentos,
        distribuicao_ram=distribuicao_ram,
        distribuicao_ssd=distribuicao_ssd,
        media_ram=round(media_ram, 1),
        media_ssd=round(media_ssd, 1)
    )
    
    return render_template('estatisticas.html',
                         titulo='Estatísticas',
                         total_maquinas=total_maquinas,
                         total_departamentos=total_departamentos,
                         media_ram=round(media_ram, 1),
                         media_ssd=round(media_ssd, 1),
                         departamentos=sorted(departamentos, key=lambda x: x['quantidade'], reverse=True),
                         distribuicao_ram=sorted(distribuicao_ram, key=lambda x: x['tamanho']),
                         distribuicao_ssd=sorted(distribuicao_ssd, key=lambda x: x['tamanho']),
                         insights=insights)

# Nova rota para o dashboard financeiro
@app.route('/dashboard_financeiro')
@login_required
def dashboard_financeiro():
    """Dashboard completo de análise financeira e patrimonial"""
    try:
        # Calcular todas as estatísticas financeiras
        stats = calcular_estatisticas_financeiras()
        if not stats:
            flash('Erro ao carregar estatísticas financeiras.', 'warning')
            return redirect(url_for('relatorio'))
        
        # Calcular previsões de substituição
        previsoes = calcular_previsao_substituicao()
        
        # Calcular valor total de substituição prevista
        valor_substituicao_total = sum(p['valor_estimado'] for p in previsoes)
        
        # Preparar dados para gráficos
        graficos = {
            'tipos': {
                'labels': [t['tipo'] for t in stats['por_tipo']],
                'valores': [t['valor_total'] for t in stats['por_tipo']]
            },
            'departamentos': {
                'labels': [d['departamento'] for d in stats['por_departamento']],
                'valores': [d['valor_investido'] for d in stats['por_departamento']]
            },
            'status': {
                'labels': ['Ativos', 'Inativos', 'Manutenção', 'Descartados'],
                'desktop': [
                    stats['desktop_notebook']['status']['ativos'],
                    stats['desktop_notebook']['status']['inativos'],
                    stats['desktop_notebook']['status']['manutencao'],
                    stats['desktop_notebook']['status']['descartados']
                ],
                'movel': [
                    stats['dispositivos_moveis']['status']['ativos'],
                    stats['dispositivos_moveis']['status']['inativos'],
                    stats['dispositivos_moveis']['status']['manutencao'],
                    stats['dispositivos_moveis']['status']['descartados']
                ]
            }
        }
        
        return render_template('dashboard_financeiro.html',
                             titulo='Dashboard Financeiro e Patrimonial',
                             stats=stats,
                             previsoes=previsoes[:10],  # Top 10 previsões
                             valor_substituicao_total=valor_substituicao_total,
                             graficos=graficos,
                             formatar_moeda=formatar_moeda)
                             
    except Exception as e:
        app.logger.error(f'Erro no dashboard financeiro: {str(e)}')
        flash('Erro ao carregar dashboard financeiro.', 'danger')
        return redirect(url_for('relatorio'))

# Rota de login
@app.route('/login', methods=['GET', 'POST'])  # rota de login + logs atribuídas
def login():
    if current_user.is_authenticated:
        return redirect(url_for('relatorio'))

    form = LoginForm()

    if 'tentativas' not in session:
        session['tentativas'] = 0

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Tratamento específico para problemas de conexão com o banco usando retry
        try:
            user = retry_db_operation(lambda: Usuario.query.filter_by(username=username).first())
        except (OperationalError, DisconnectionError) as e:
            app.logger.error(f'Erro de conexão com banco após múltiplas tentativas: {str(e)}')
            flash('Erro de conexão com o banco de dados. Tente novamente em alguns momentos.', 'warning')
            return render_template('login.html', form=form, titulo='Login')
        except Exception as e:
            db.session.rollback()
            db.session.close()
            app.logger.error(f'Erro inesperado durante login: {str(e)}')
            flash('Erro interno do sistema. Contate o administrador.', 'danger')
            return render_template('login.html', form=form, titulo='Login')

        if session['tentativas'] >= 5:
            flash('Muitas tentativas de login! Aguarde 30 segundos.', 'danger')
            time.sleep(30)
            session['tentativas'] = 0
            return redirect(url_for('login'))

        if user and user.check_password(password):
            try:
                login_user(user)
                registrar_log('Login no sistema', detalhes=f'Usuário: {user.username}')
                session.permanent = True
                session.pop('tentativas', None)

                if user.trocar_senha:
                    return redirect(url_for('trocar_senha_obrigatorio'))
                else:
                    return redirect(url_for('relatorio'))
            except Exception as e:
                app.logger.error(f'Erro durante processo de login: {str(e)}')
                flash('Erro durante o login. Tente novamente.', 'warning')
                return render_template('login.html', form=form, titulo='Login')
        else:
            session['tentativas'] += 1
            flash('Usuário ou senha inválidos.', 'danger')

    return render_template('login.html', form=form, titulo='Login')

@app.route('/logout') #rota de logout + logs atribuidas
@login_required
def logout():
    registrar_log('Logout do sistema', detalhes=f'Usuário: {current_user.username}')
    logout_user()
    return redirect(url_for('login'))

@app.route('/usuarios', methods=['GET', 'POST']) #cadastro de usuario + logs atribuidas
@login_required
def usuarios():
    if not current_user.is_admin:
        flash('Acesso negado: você não tem permissão para acessar esta página.', 'danger')
        logout_user()
        return redirect(url_for('relatorio'))

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
                is_admin=is_admin,
                trocar_senha=True #força troca no primeiro login
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
        current_user.apelido = apelido
        current_user.email = email
        current_user.setor = setor
        current_user.cargo = cargo

        if 'avatar' in request.files:
            avatar = request.files['avatar']
            if avatar and avatar.filename != '':
                filename = secure_filename(avatar.filename)
                avatar_path = os.path.join('static', 'img', 'avatars', filename)
                avatar.save(avatar_path)
                current_user.avatar = f'img/avatars/{filename}'

        try:
            db.session.commit()
            flash('Perfil atualizado com sucesso!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Erro ao atualizar perfil.', 'danger')

        return redirect(url_for('perfil'))
    
    # GET request - mostrar formulário
    return render_template('editar_perfil.html', titulo='Editar Perfil')

@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST']) #editar usuario + logs atribuidas
@login_required 
def editar_usuario(id):
    if not current_user.is_admin:
        flash('Acesso negado: você não tem permissão para acessar esta página.', 'danger')
        return redirect(url_for('relatorio'))

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

@app.route('/excluir_usuario/<int:id>', methods=['GET', 'POST']) #excluir usuario + logs atribuidas
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
        return redirect(url_for('relatorio'))

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
        return redirect(url_for('relatorio'))

    usuario = request.args.get('usuario')
    acao = request.args.get('acao')
    data_inicio = request.args.get('data_inicio')
    data_fim = request.args.get('data_fim')

    query = LogAuditoria.query

    if usuario:
        query = query.join(Usuario).filter(Usuario.username.ilike(f'%{usuario}%'))
    if acao:
        query = query.filter(LogAuditoria.acao.ilike(f'%{acao}%'))

    try:
        if data_inicio:
            data_inicio_obj = datetime.strptime(data_inicio, "%Y-%m-%d")
            query = query.filter(LogAuditoria.data_hora >= data_inicio_obj)
        if data_fim:
            data_fim_obj = datetime.strptime(data_fim, "%Y-%m-%d")
            query = query.filter(LogAuditoria.data_hora <= data_fim_obj)
    except ValueError:
        flash("Formato de data inválido. Use o formato YYYY-MM-DD.", "warning")

    logs = query.order_by(LogAuditoria.data_hora.desc()).all()

    return render_template('logs_auditoria.html', logs=logs, titulo='Auditoria do Sistema')

@app.route('/exportar_logs')
@login_required
def exportar_logs():
    if not current_user.is_admin:
        flash('Acesso negado: apenas administradores podem exportar logs.', 'danger')
        return redirect(url_for('relatorio'))

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
            to_local_time(log.data_hora).strftime('%d/%m/%Y %H:%M:%S') if log.data_hora else '',
            log.usuario.username if log.usuario else 'Desconhecido',
            log.acao,
            log.ip_origem or '',
            log.detalhes or ''
        ])

    output.seek(0)

    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=logs_auditoria.csv"})

# ------------------------------ COMEÇO: Rotas de Organizações -----------------------------------------------
@app.route('/organizacoes')
@login_required
def organizacoes():
    """Lista todas as organizações cadastradas"""
    if not current_user.is_admin:
        flash('Acesso negado: você não tem permissão para acessar esta página.', 'danger')
        return redirect(url_for('relatorio'))
    
    organizacoes = Organizacao.query.order_by(Organizacao.nome_organizacao).all()
    return render_template('organizacoes.html', organizacoes=organizacoes, titulo='Gerenciar Organizações')

@app.route('/organizacoes/nova', methods=['GET', 'POST'])
@login_required
def nova_organizacao():
    """Cadastra uma nova organização"""
    if not current_user.is_admin:
        flash('Acesso negado: você não tem permissão para acessar esta página.', 'danger')
        return redirect(url_for('relatorio'))
    
    if request.method == 'POST':
        nome_organizacao = request.form['nome_organizacao'].strip()
        
        if not nome_organizacao:
            flash('Nome da organização é obrigatório.', 'warning')
            return render_template('nova_organizacao.html', titulo='Nova Organização')
        
        # Verificar se já existe uma organização com esse nome
        organizacao_existente = Organizacao.query.filter_by(nome_organizacao=nome_organizacao).first()
        if organizacao_existente:
            flash('Já existe uma organização com esse nome.', 'danger')
            return render_template('nova_organizacao.html', titulo='Nova Organização')
        
        try:
            nova_org = Organizacao(nome_organizacao=nome_organizacao)
            db.session.add(nova_org)
            db.session.commit()
            registrar_log('Cadastro de organização', detalhes=f'Organização: {nome_organizacao}')
            flash(f'Organização "{nome_organizacao}" cadastrada com sucesso!', 'success')
            app.logger.info(f'Nova organização cadastrada: {nome_organizacao}')
            return redirect(url_for('organizacoes'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Erro ao cadastrar organização: {str(e)}')
            flash(f'Erro ao cadastrar organização: {str(e)}', 'danger')
    
    return render_template('nova_organizacao.html', titulo='Nova Organização')

@app.route('/organizacoes/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_organizacao(id):
    """Edita uma organização existente"""
    if not current_user.is_admin:
        flash('Acesso negado: você não tem permissão para acessar esta página.', 'danger')
        return redirect(url_for('relatorio'))
    
    organizacao = Organizacao.query.get_or_404(id)
    
    if request.method == 'POST':
        nome_organizacao = request.form['nome_organizacao'].strip()
        
        if not nome_organizacao:
            flash('Nome da organização é obrigatório.', 'warning')
            return render_template('editar_organizacao.html', organizacao=organizacao, titulo='Editar Organização')
        
        # Verificar se já existe outra organização com esse nome
        organizacao_existente = Organizacao.query.filter(
            Organizacao.nome_organizacao == nome_organizacao,
            Organizacao.id_organizacao != id
        ).first()
        
        if organizacao_existente:
            flash('Já existe uma organização com esse nome.', 'danger')
            return render_template('editar_organizacao.html', organizacao=organizacao, titulo='Editar Organização')
        
        try:
            nome_antigo = organizacao.nome_organizacao
            organizacao.nome_organizacao = nome_organizacao
            db.session.commit()
            registrar_log('Edição de organização', detalhes=f'Organização: {nome_antigo} → {nome_organizacao}')
            flash(f'Organização atualizada com sucesso!', 'success')
            app.logger.info(f'Organização atualizada: {nome_antigo} → {nome_organizacao}')
            return redirect(url_for('organizacoes'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Erro ao atualizar organização: {str(e)}')
            flash(f'Erro ao atualizar organização: {str(e)}', 'danger')
    
    return render_template('editar_organizacao.html', organizacao=organizacao, titulo='Editar Organização')

@app.route('/organizacoes/excluir/<int:id>')
@login_required
def excluir_organizacao(id):
    """Exclui uma organização (apenas se não houver registros vinculados)"""
    if not current_user.is_admin:
        flash('Acesso negado: você não tem permissão para acessar esta página.', 'danger')
        return redirect(url_for('relatorio'))
    
    organizacao = Organizacao.query.get_or_404(id)
    
    # Verificar se há registros vinculados a esta organização
    registros_vinculados = Registro.query.filter_by(id_organizacao=id).count()
    
    if registros_vinculados > 0:
        flash(f'Não é possível excluir a organização "{organizacao.nome_organizacao}" pois há {registros_vinculados} máquinas vinculadas a ela.', 'warning')
        return redirect(url_for('organizacoes'))
    
    try:
        nome_organizacao = organizacao.nome_organizacao
        db.session.delete(organizacao)
        db.session.commit()
        registrar_log('Exclusão de organização', detalhes=f'Organização: {nome_organizacao}')
        flash(f'Organização "{nome_organizacao}" excluída com sucesso!', 'success')
        app.logger.info(f'Organização excluída: {nome_organizacao}')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Erro ao excluir organização: {str(e)}')
        flash('Erro ao excluir organização.', 'danger')
    
    return redirect(url_for('organizacoes'))
# ------------------------------ TÉRMINO: Rotas de Organizações -----------------------------------------------

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
def init_database():
    """Inicializa o banco de dados com retry em caso de falha"""
    max_retries = 5
    for attempt in range(max_retries):
        try:
            with app.app_context():
                db.create_all()
                app.logger.info('Banco de dados inicializado com sucesso')
                app.jinja_env.globals['to_local_time'] = to_local_time
                app.logger.info('Função de timezone disponibilizada')
                return True
        except (OperationalError, DisconnectionError) as e:
            app.logger.warning(f'Tentativa {attempt + 1} de inicialização do banco falhou: {str(e)}')
            if attempt == max_retries - 1:
                app.logger.error('Falha crítica: Não foi possível conectar ao banco após múltiplas tentativas')
                raise e
            time.sleep(2 * (attempt + 1))  # Aguarda progressivamente mais tempo
        except Exception as e:
            app.logger.error(f'Erro crítico durante inicialização do banco: {str(e)}')
            raise e

# Inicializar banco de dados
init_database()
# ------------------------------ TÉRMINO: Criar todas as tabelas do banco de dados --------------------------
#

# Script para inserir colunas no banco

from sqlalchemy import text

# Script para criar tabela de dispositivos móveis e adicionar colunas
# with app.app_context():
#    try:
#        # Adicionar colunas se não existirem
#        db.engine.execute(text("ALTER TABLE registros ADD COLUMN IF NOT EXISTS tipo_dispositivo VARCHAR(50) NOT NULL DEFAULT 'desktop'"))
#        db.engine.execute(text("ALTER TABLE registros ADD COLUMN IF NOT EXISTS serial_number VARCHAR(50) NOT NULL DEFAULT 'SEM-SERIAL'"))
#        
#        # Criar tabela de dispositivos móveis
#        db.create_all()
#        
#        print("Tabela 'dispositivos_moveis' criada e colunas 'tipo_dispositivo' e 'serial_number' adicionadas com sucesso!")
#    except Exception as e:
#        print(f"Erro ao executar migração: {e}")


# ------------------------------ COMEÇO: Aplicação principal -----------------------------------------------

#class PrefixMiddleware:
#    def __init__(self, app, prefix=''):
#        self.app = app
#        self.prefix = prefix
#
#    def __call__(self, environ, start_response):
#        if environ['PATH_INFO'].startswith(self.prefix):
#            environ['SCRIPT_NAME'] = self.prefix
#            environ['PATH_INFO'] = environ['PATH_INFO'][len(self.prefix):]
#            return self.app(environ, start_response)
#        else:
#            start_response('404 Not Found', [('Content-Type', 'text/plain')])
#            return [b'This URL does not belong to the app.']

# Envolver o app com o prefixo
#app.wsgi_app = PrefixMiddleware(app.wsgi_app, prefix='/portal-ti-manager')

# ------------------------------ COMEÇO: Aplicação principal -----------------------------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=True)
# ------------------------------ TÉRMINO: Aplicação principal -----------------------------------------------

# inicio da construção codigo v2.0 ---