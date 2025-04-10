from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, SelectField
from wtforms.validators import DataRequired, IPAddress, Regexp, ValidationError, Length
from flask_sqlalchemy import SQLAlchemy
from flask_paginate import Pagination, get_page_parameter
from sqlalchemy.exc import IntegrityError
import os
import csv
from datetime import datetime
from io import StringIO
import logging
from logging.handlers import RotatingFileHandler
import pymysql
from dotenv import load_dotenv

# Carrega as variáveis de ambiente
load_dotenv()

# Configuração do aplicativo
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

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

# Configuração de logs
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

# Modelo de dados
class Registro(db.Model):
    __tablename__ = 'registros'
    
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False, index=True)
    departamento = db.Column(db.String(100), nullable=False, index=True)
    endereco_ip = db.Column(db.String(20), nullable=False, unique=True, index=True)
    mac_adress = db.Column(db.String(20), nullable=False, unique=True, index=True)
    hostname = db.Column(db.String(100), nullable=False, index=True)
    memoria_ram = db.Column(db.Integer, nullable=False)
    ssd = db.Column(db.Integer, nullable=False)
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

# Validadores personalizados
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

# Formulário de cadastro/edição
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

# Rotas
@app.route('/', methods=['GET', 'POST'])
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

@app.route('/editar/<int:id>', methods=['GET', 'POST'])
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

@app.route('/excluir/<int:id>')
def excluir(id):
    registro = Registro.query.get_or_404(id)
    try:
        nome = registro.nome
        db.session.delete(registro)
        db.session.commit()
        flash(f'Máquina "{nome}" removida com sucesso!', 'success')
        app.logger.info(f'Máquina excluída: ID {id} - {nome}')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir registro: {str(e)}', 'danger')
    
    return redirect(url_for('relatorio'))

@app.route('/exportar_csv')
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
        return response
    
    except Exception as e:
        app.logger.error(f'Erro na exportação de CSV: {str(e)}')
        flash(f'Erro ao exportar dados: {str(e)}', 'danger')
        return redirect(url_for('relatorio'))

@app.route('/api/maquinas')
def api_maquinas():
    """API simples para obter dados das máquinas em formato JSON."""
    try:
        registros = Registro.query.all()
        return jsonify([registro.to_dict() for registro in registros])
    except Exception as e:
        app.logger.error(f'Erro na API de máquinas: {str(e)}')
        return jsonify({'error': str(e)}), 500

@app.route('/estatisticas')
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

# Tratamento de erros
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, message="Página não encontrada"), 404

@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f'Erro 500: {str(e)}')
    return render_template('error.html', error_code=500, message="Erro interno do servidor"), 500

# Criar todas as tabelas do banco de dados
with app.app_context():
    db.create_all()
    app.logger.info('Banco de dados inicializado')

# Aplicação principal
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=True)