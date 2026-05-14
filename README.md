# Portal TI Manager

Sistema web para cadastro, gestão e monitoramento de ativos de TI. Desenvolvido em Flask com deploy on-premise via Apache e Systemd.

---

## Funcionalidades

- Cadastro de máquinas (desktop e notebook) e dispositivos móveis (tablet e celular)
- Relatório com filtros por base, departamento, organização, tipo e status
- Exportação de dados em CSV
- Dashboard de estatísticas gerais
- Dashboard financeiro com cálculo de depreciação patrimonial
- Gestão de organizações, bases e departamentos
- Gestão de usuários com perfis admin e usuário comum
- Log de auditoria completo (ação, usuário, IP, data/hora)
- Autenticação com sessão de 15 minutos
- Fluxo de troca de senha obrigatória no primeiro acesso
- Interface responsiva com Bootstrap 5

---

## Stack

| Camada | Tecnologia |
|--------|-----------|
| Linguagem | Python 3.10+ |
| Framework | Flask |
| ORM | Flask-SQLAlchemy + SQLAlchemy |
| Banco de dados | MySQL / MariaDB |
| Driver | PyMySQL |
| Autenticação | Flask-Login |
| Formulários | Flask-WTF + WTForms |
| Paginação | flask-paginate |
| Frontend | Jinja2 + Bootstrap 5 |
| Deploy | Apache2 (proxy reverso) + Systemd |

---

## Pré-requisitos

- Ubuntu Server 22.04+
- Python 3.10+
- MySQL ou MariaDB
- Apache2
- Permissões de sudo/root

---

## Rodar localmente (modo dev)

```bash
# Clonar o repositório
git clone https://github.com/armelingu/Portal-TI-Manager.git
cd Portal-TI-Manager

# Criar e ativar ambiente virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependências
pip install -r requirements.txt

# Configurar variáveis de ambiente
cp .env.example .env
# Edite o .env com suas credenciais

# Rodar a aplicação
python app.py
```

Acesse em: [http://localhost:5050](http://localhost:5050)

> A porta padrão é **5050**. Para alterar, defina a variável `PORT` no `.env`.

---

## Variáveis de ambiente

Copie `.env.example` para `.env` e preencha:

| Variável | Descrição | Obrigatória |
|----------|-----------|-------------|
| `SECRET_KEY` | Chave secreta do Flask (use um valor aleatório longo) | Sim |
| `MYSQL_HOST` | Host do banco de dados | Sim |
| `MYSQL_PORT` | Porta do banco (padrão: `3306`) | Sim |
| `MYSQL_USER` | Usuário do banco | Sim |
| `MYSQL_PASSWORD` | Senha do banco | Sim |
| `MYSQL_DB` | Nome do banco de dados | Sim |
| `PORT` | Porta da aplicação (padrão: `5050`) | Não |
| `FLASK_ENV` | Ambiente (`development` ativa o modo debug) | Não |

---

## Deploy no servidor

### 1. Atualizar o sistema

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Instalar dependências do sistema

```bash
sudo apt install python3 python3-pip python3-venv apache2 -y
```

### 3. Clonar o projeto

```bash
cd /var/www/
sudo git clone https://github.com/armelingu/Portal-TI-Manager.git
cd Portal-TI-Manager
```

### 4. Criar ambiente virtual e instalar pacotes

```bash
sudo python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 5. Configurar o `.env`

```bash
sudo cp .env.example .env
sudo nano .env  # preencha com as credenciais de produção
```

### 6. Ajustar permissões

```bash
sudo chown -R www-data:www-data /var/www/Portal-TI-Manager
```

---

## Configuração do Apache

```bash
sudo a2enmod proxy proxy_http
sudo nano /etc/apache2/sites-available/portal-ti-manager.conf
```

Conteúdo do arquivo:

```apache
<VirtualHost *:80>
    ServerName SEU_DOMINIO_OU_IP

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:5050/
    ProxyPassReverse / http://127.0.0.1:5050/

    ErrorLog ${APACHE_LOG_DIR}/portal-ti-manager_error.log
    CustomLog ${APACHE_LOG_DIR}/portal-ti-manager_access.log combined
</VirtualHost>
```

```bash
sudo a2ensite portal-ti-manager.conf
sudo systemctl reload apache2
```

---

## Configuração do Systemd

```bash
sudo nano /etc/systemd/system/Portal-TI-Manager.service
```

```ini
[Unit]
Description=Portal TI Manager - Flask Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/Portal-TI-Manager
Environment="PATH=/var/www/Portal-TI-Manager/venv/bin"
ExecStart=/var/www/Portal-TI-Manager/venv/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl start Portal-TI-Manager
sudo systemctl enable Portal-TI-Manager
```

### Comandos úteis

```bash
# Ver status
sudo systemctl status Portal-TI-Manager.service

# Reiniciar após atualizações
sudo systemctl restart Portal-TI-Manager.service

# Ver logs em tempo real
sudo journalctl -u Portal-TI-Manager.service -f
```

---

## Acesso ao sistema

```bash
sudo ufw allow 'Apache Full'
```

Acesse em: `http://SEU_DOMINIO_OU_IP/`

### Credenciais padrão

| Perfil | Login | Senha |
|--------|-------|-------|
| Administrador | admin | admin123 |
| Usuário | user | user123 |

> Altere as senhas padrão imediatamente após o primeiro acesso.

---

## Estrutura do projeto

```
Portal-TI-Manager/
├── app.py                  # Aplicação principal (modelos, formulários, rotas)
├── requirements.txt        # Dependências Python
├── .env.example            # Modelo de variáveis de ambiente
├── templates/              # Templates Jinja2 (HTML)
│   ├── base.html
│   ├── login.html
│   ├── index.html          # Cadastro desktop/notebook
│   ├── cadastro_movel.html # Cadastro tablet/celular
│   ├── relatorio.html
│   ├── editar.html
│   ├── estatisticas.html
│   ├── dashboard_financeiro.html
│   ├── usuarios.html
│   ├── logs_auditoria.html
│   └── ...
├── static/
│   ├── css/style.css
│   └── js/script.js
└── logs/                   # Logs da aplicação (não versionados)
```

---

Desenvolvido por **Gustavo Armelin**  
© 2025 — Portal TI Manager
