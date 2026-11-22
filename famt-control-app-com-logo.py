import streamlit as st
import mysql.connector
from mysql.connector import Error, IntegrityError
from pathlib import Path
import pandas as pd
import hashlib
import re
import random
import string
from datetime import datetime, date, time
import calendar
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import plotly.express as px
import plotly.graph_objects as go
import os
import html

# =============================================================================
# CONFIGURAÇÃO INICIAL DA PÁGINA STREAMLIT
# =============================================================================
LOGO_PATH = Path(__file__).resolve().parent / "Logo Fintech FAMT Control.png"

st.set_page_config(
    page_title="FAMT CONTROL - Dashboard",
    page_icon=str(LOGO_PATH) if LOGO_PATH.exists() else "💰",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# LOGO E CONFIGURAÇÃO DA CONEXÃO MYSQL (EXCLUSIVA)
# =============================================================================
def logo_html(css_class="system-logo"):
    """Retorna a logo em base64 para funcionar dentro do HTML do Streamlit."""
    if not LOGO_PATH.exists():
        return ""
    data = base64.b64encode(LOGO_PATH.read_bytes()).decode("utf-8")
    classe = html.escape(css_class, quote=True)
    return f'<img src="data:image/png;base64,{data}" class="{classe}">'

def obter_conexao():
    """Abre conexão MySQL usando secrets.toml ou variáveis de ambiente."""
    try:
        cfg = {}
        if hasattr(st, "secrets") and "mysql" in st.secrets:
            cfg = dict(st.secrets["mysql"])
        return mysql.connector.connect(
            host=cfg.get("host", os.getenv("MYSQL_HOST", "localhost")),
            user=cfg.get("user", os.getenv("MYSQL_USER", "root")),
            password=cfg.get("password", os.getenv("MYSQL_PASSWORD", "root")),
            database=cfg.get("database", os.getenv("MYSQL_DATABASE", "famt_control")),
            port=int(cfg.get("port", os.getenv("MYSQL_PORT", "3306"))),
            connection_timeout=8
        )
    except Exception as e:
        st.error(f"Não foi possível conectar ao MySQL: {e}")
        st.info("Confira se o MySQL está iniciado, se o banco 'famt_control' existe e se usuário/senha estão corretos.")
        st.stop()

# =============================================================================
# FUNÇÃO DE SAUDAÇÃO DINÂMICA (POR HORÁRIO DO DIA)
# =============================================================================
def obter_saudacao_horario():
    """Retorna a saudação apropriada com base na hora atual do sistema."""
    hora = datetime.now().hour
    if 5 <= hora < 12:
        return "☀️ Bom dia"
    elif 12 <= hora < 18:
        return "🌤️ Boa tarde"
    else:
        return "🌙 Boa noite"

# =============================================================================
# MÓDULO DE SEGURANÇA, CRIPTOGRAFIA E VALIDAÇÕES (LGPD - REQ-EXT-01)
# =============================================================================
def _hash_senha(senha: str) -> str:
    """Gera hash SHA-256 irreversível para a senha."""
    return hashlib.sha256(senha.encode("utf-8")).hexdigest()

def validar_complexidade_senha(senha: str) -> tuple[bool, str]:
    """Valida os requisitos mínimos de segurança de senha (LGPD)."""
    if len(senha) < 6:
        return False, "A senha deve conter no mínimo 6 caracteres."
    if not re.search(r"[A-Z]", senha):
        return False, "A senha deve conter pelo menos uma letra maiúscula (A-Z)."
    if not re.search(r"[a-z]", senha):
        return False, "A senha deve conter pelo menos uma letra minúscula (a-z)."
    if not re.search(r"\d", senha):
        return False, "A senha deve conter pelo menos um número (0-9)."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', senha):
        return False, "A senha deve conter pelo menos um caractere especial."
    return True, "Senha válida."

def gerar_senha_provisoria(tamanho: int = 8) -> str:
    """Gera uma senha provisória aleatória com requisitos fortes."""
    maiusculas = string.ascii_uppercase
    minusculas = string.ascii_lowercase
    numeros = string.digits
    simbolos = "!@#$%^&*"
    senha = [
        random.choice(maiusculas),
        random.choice(minusculas),
        random.choice(numeros),
        random.choice(simbolos)
    ]
    todos = maiusculas + minusculas + numeros + simbolos
    senha += [random.choice(todos) for _ in range(tamanho - 4)]
    random.shuffle(senha)
    return "".join(senha)

def enviar_senha_provisoria_email(email_destino: str, senha_provisoria: str) -> bool:
    """Envia a senha provisória por e-mail via SMTP (suporta STARTTLS e SSL)."""
    try:
        if not hasattr(st, "secrets") or "email" not in st.secrets:
            return False
        cfg = st.secrets["email"]
        servidor = cfg.get("servidor", cfg.get("smtp_server", "smtp.gmail.com"))
        porta = int(cfg.get("porta", cfg.get("smtp_port", 587)))
        usuario = cfg.get("usuario", cfg.get("sender_email"))
        senha = cfg.get("senha", cfg.get("sender_password"))
        if not usuario or not senha:
            return False
        
        mensagem = MIMEMultipart()
        mensagem["From"] = usuario
        mensagem["To"] = email_destino
        mensagem["Subject"] = "🔐 Sua Senha Provisória - FAMT Control"
        corpo = (
            "Olá!\n\n"
            f"Sua senha provisória do FAMT Control é: {senha_provisoria}\n\n"
            "Ao acessar o sistema, você deverá cadastrar sua nova senha definitiva."
        )
        mensagem.attach(MIMEText(corpo, "plain", "utf-8"))
        
        if porta == 465:
            with smtplib.SMTP_SSL(servidor, porta, timeout=15) as smtp:
                smtp.login(usuario, senha)
                smtp.send_message(mensagem)
        else:
            with smtplib.SMTP(servidor, porta, timeout=15) as smtp:
                smtp.starttls()
                smtp.login(usuario, senha)
                smtp.send_message(mensagem)
        return True
    except Exception as e:
        st.warning(f"Aviso SMTP: {e}")
        return False

# =============================================================================
# INICIALIZAÇÃO DO BANCO DE DADOS MYSQL
# =============================================================================
def inicializar_banco():
    """Cria as tabelas do MySQL caso ainda não existam."""
    try:
        conexao = obter_conexao()
        cursor = conexao.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS Usuarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                senha_hash VARCHAR(255) NOT NULL,
                primeiro_acesso INT DEFAULT 1 CHECK (primeiro_acesso IN (0, 1))
            ) ENGINE=InnoDB;
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS Transacoes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                usuario_id INT NOT NULL,
                valor DECIMAL(10,2) NOT NULL CHECK (valor > 0),
                tipo VARCHAR(20) NOT NULL CHECK (tipo IN ('Receita', 'Despesa', 'RECEITA', 'DESPESA')),
                data DATETIME NOT NULL,
                descricao VARCHAR(255) NOT NULL,
                categoria VARCHAR(100) NOT NULL,
                FOREIGN KEY (usuario_id) REFERENCES Usuarios(id) ON DELETE CASCADE
            ) ENGINE=InnoDB;
        """)
        conexao.commit()
        cursor.close()
        conexao.close()
    except Exception as e:
        st.error(f"Erro ao inicializar o banco de dados MySQL: {e}")

inicializar_banco()

# =============================================================================
# ESTILIZAÇÃO VISUAL
# =============================================================================
CUSTOM_CSS = """
<style>
    .stApp {
        background-color: #0E1117;
        color: #E8E7F5;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# =============================================================================
# GERENCIAMENTO DE SESSÃO E PERSISTÊNCIA NO CELULAR (ANTI-DESLOGAMENTO)
# =============================================================================
if 'usuario_id' not in st.session_state:
    st.session_state.usuario_id = None
if 'email_logado' not in st.session_state:
    st.session_state.email_logado = None
if 'primeiro_acesso' not in st.session_state:
    st.session_state.primeiro_acesso = 0

if st.session_state.usuario_id is None:
    qp_uid = st.query_params.get("uid")
    if qp_uid:
        try:
            conexao = obter_conexao()
            cursor = conexao.cursor()
            cursor.execute("SELECT id, email, primeiro_acesso FROM Usuarios WHERE id = %s", (qp_uid,))
            usr_rec = cursor.fetchone()
            conexao.close()
            if usr_rec:
                st.session_state.usuario_id = usr_rec[0]
                st.session_state.email_logado = usr_rec[1]
                st.session_state.primeiro_acesso = usr_rec[2]
        except Exception:
            pass

# =============================================================================
# TELA DE AUTENTICAÇÃO / LOGIN / CADASTRO / REDEFINIÇÃO DE SENHA
# =============================================================================
if st.session_state.usuario_id is None:
    col_left, col_center, col_right = st.columns([1, 2, 1])
    with col_center:
        st.markdown("<h1>💰 FAMT CONTROL</h1>", unsafe_allow_html=True)
        st.markdown("<p>Seu dinheiro sob controle • Squad FAMT</p>", unsafe_allow_html=True)
        aba1, aba2, aba3 = st.tabs(["🔑 Entrar", "📝 Nova Conta", "🛡️ Redefinir Senha"])
        
        with aba1:
            st.markdown("### 🔑 Acesse sua conta")
            with st.form(key="form_login_v44"):
                email = st.text_input("E-mail cadastrado", placeholder="seu.email@exemplo.com").strip().lower()
                senha = st.text_input("Senha de acesso", type="password", placeholder="••••••••").strip()
                btn_login = st.form_submit_button("🚀 Entrar no Sistema", use_container_width=True, type="primary")
                if btn_login:
                    if not email or not senha:
                        st.error("❌ Por favor, preencha o e-mail e a senha.")
                    else:
                        conexao = obter_conexao()
                        cursor = conexao.cursor()
                        cursor.execute("SELECT id, senha_hash, primeiro_acesso FROM Usuarios WHERE email = %s", (email,))
                        usuario = cursor.fetchone()
                        conexao.close()
                        if usuario:
                            u_id, hash_banco, prim_acesso = usuario
                            if _hash_senha(senha) == hash_banco:
                                st.session_state.usuario_id = u_id
                                st.session_state.email_logado = email
                                st.session_state.primeiro_acesso = prim_acesso
                                st.query_params["uid"] = str(u_id)
                                st.toast("🔓 Login efetuado com sucesso!", icon="✅")
                                st.rerun()
                            else:
                                st.error("❌ Senha incorreta. Tente novamente.")
                        else:
                            st.error("❌ E-mail não encontrado no sistema.")
                            
        with aba2:
            st.markdown("### 📝 Criar nova conta")
            with st.form(key="form_cad_v44"):
                novo_email = st.text_input("E-mail para cadastro", placeholder="seu.email@exemplo.com").strip().lower()
                btn_cad = st.form_submit_button("✨ Criar Minha Conta", use_container_width=True, type="primary")
                if btn_cad:
                    if not novo_email or "@" not in novo_email:
                        st.error("❌ Por favor, digite um e-mail válido.")
                    else:
                        senha_prov = gerar_senha_provisoria(8)
                        senha_hash = _hash_senha(senha_prov)
                        conexao = obter_conexao()
                        cursor = conexao.cursor()
                        try:
                            cursor.execute("INSERT INTO Usuarios (email, senha_hash, primeiro_acesso) VALUES (%s, %s, 1)", (novo_email, senha_hash))
                            conexao.commit()
                            email_enviado = enviar_senha_provisoria_email(novo_email, senha_prov)
                            st.toast("Conta criada com sucesso!", icon="✅")
                            if email_enviado:
                                st.success(f"Conta criada! A senha provisória foi enviada para {novo_email}.")
                            else:
                                st.warning("A conta foi criada, mas o e-mail não pôde ser enviado. Use a senha provisória abaixo:")
                                st.code(senha_prov)
                        except (IntegrityError, Exception):
                            st.error("❌ Este e-mail já está cadastrado no banco de dados.")
                        finally:
                            conexao.close()
                            
        with aba3:
            st.markdown("### 🛡️ Recuperar / Redefinir Senha")
            with st.form(key="form_rec_v44"):
                rec_email = st.text_input("E-mail cadastrado", placeholder="seu.email@exemplo.com").strip().lower()
                btn_rec = st.form_submit_button("🔑 Gerar Nova Senha Provisória", type="primary", use_container_width=True)
                if btn_rec:
                    if not rec_email or "@" not in rec_email:
                        st.error("❌ Por favor, preencha um e-mail válido.")
                    else:
                        conexao = obter_conexao()
                        cursor = conexao.cursor()
                        cursor.execute("SELECT id FROM Usuarios WHERE email = %s", (rec_email,))
                        usr = cursor.fetchone()
                        if usr:
                            nova_prov = gerar_senha_provisoria(8)
                            novo_hash = _hash_senha(nova_prov)
                            cursor.execute("UPDATE Usuarios SET senha_hash = %s, primeiro_acesso = 1 WHERE email = %s", (novo_hash, rec_email))
                            conexao.commit()
                            conexao.close()
                            email_enviado = enviar_senha_provisoria_email(rec_email, nova_prov)
                            if email_enviado:
                                st.success("Uma nova senha provisória foi enviada para seu e-mail.")
                            else:
                                st.warning("Não foi possível enviar o e-mail. Sua senha provisória é:")
                                st.code(nova_prov)
                        else:
                            conexao.close()
                            st.error("❌ E-mail não encontrado no sistema.")

# =============================================================================
# BLOQUEIO DE PRIMEIRO ACESSO (CONFORMIDADE LGPD - REQ-EXT-01)
# =============================================================================
elif st.session_state.primeiro_acesso == 1:
    col_l, col_c, col_r = st.columns([1, 2, 1])
    with col_c:
        st.warning("⚠️ **Primeiro Acesso Detectado (Conformidade LGPD)**")
        st.info("Por segurança, cadastre uma nova senha atendendo aos requisitos mínimos:")
        st.markdown("- Mínimo de 6 caracteres\n- Pelo menos 1 letra maiúscula\n- Pelo menos 1 letra minúscula\n- Pelo menos 1 número\n- Pelo menos 1 caractere especial (!@#$%^&*)")
        with st.form(key="form_pa_lgpd_v44"):
            nova_senha = st.text_input("Digite sua NOVA senha", type="password")
            confirma_senha = st.text_input("Confirme sua NOVA senha", type="password")
            btn_pa = st.form_submit_button("💾 Salvar Senha Definitiva", use_container_width=True, type="primary")
            if btn_pa:
                valida, msg_erro = validar_complexidade_senha(nova_senha)
                if not valida:
                    st.error(f"❌ {msg_erro}")
                elif nova_senha != confirma_senha:
                    st.error("❌ As senhas digitadas não coincidem.")
                else:
                    novo_hash = _hash_senha(nova_senha)
                    conexao = obter_conexao()
                    cursor = conexao.cursor()
                    cursor.execute("UPDATE Usuarios SET senha_hash = %s, primeiro_acesso = 0 WHERE id = %s", (novo_hash, st.session_state.usuario_id))
                    conexao.commit()
                    conexao.close()
                    st.session_state.primeiro_acesso = 0
                    st.toast("🔑 Senha atualizada com sucesso!", icon="✅")
                    st.rerun()

# =============================================================================
# PAINEL PRINCIPAL E NAVEGAÇÃO
# =============================================================================
else:
    if "menu" not in st.session_state:
        st.session_state.menu = "Painel"
        
    def navegar_para(destino):
        st.session_state.menu = destino
        
    # Sidebar lateral com suporte a Logo
    with st.sidebar:
        if LOGO_PATH.exists():
            st.markdown(logo_html("sidebar-logo"), unsafe_allow_html=True)
        else:
            st.markdown("<h2>FAMT CONTROL</h2>", unsafe_allow_html=True)
        opcoes_menu = ["Painel", "Lançar", "Extrato e Edição", "Metas", "Gráficos", "Notificações", "Alertas e Dicas", "Configurações"]
        idx_menu = opcoes_menu.index(st.session_state.menu) if st.session_state.menu in opcoes_menu else 0
        menu = st.radio("Navegação", opcoes_menu, index=idx_menu, key="nav_radio")
        st.session_state.menu = menu
        st.divider()
        st.markdown(f"👤 **{st.session_state.email_logado}**")
        if st.button("🚪 Sair", use_container_width=True):
            st.session_state.usuario_id = None
            st.session_state.email_logado = None
            st.session_state.primeiro_acesso = 0
            st.query_params.clear()
            st.rerun()
            
    # Período de Análise (Mês Atual) - Corrigido índice [1]
    agora = datetime.now()
    primeiro_dia_mes = agora.replace(day=1).date()
    ultimo_dia_num = calendar.monthrange(agora.year, agora.month)[1]
    ultimo_dia_mes = agora.replace(day=ultimo_dia_num).date()
    
    if "data_inicio_sel" not in st.session_state:
        st.session_state.data_inicio_sel = primeiro_dia_mes
    if "data_fim_sel" not in st.session_state:
        st.session_state.data_fim_sel = ultimo_dia_mes
        
    def moeda(val):
        return f"R$ {val:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
        
    # Consulta dos Lançamentos no MySQL
    conexao = obter_conexao()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT id, tipo, valor, categoria, descricao, data 
        FROM Transacoes 
        WHERE usuario_id = %s 
        ORDER BY data DESC
    """, (st.session_state.usuario_id,))
    historico = cursor.fetchall()
    cursor.close()
    conexao.close()
    
    if historico:
        df_bruto = pd.DataFrame(historico, columns=["ID", "Tipo", "Valor", "Categoria", "Descrição", "Data"])
        df_bruto["Valor"] = pd.to_numeric(df_bruto["Valor"], errors="coerce").fillna(0.0)
        df_bruto["Data_dt"] = pd.to_datetime(df_bruto["Data"], errors="coerce")
        df_bruto["Tipo_Norm"] = df_bruto["Tipo"].astype(str).str.strip().str.upper()
        
        dt_ini = pd.to_datetime(st.session_state.data_inicio_sel)
        dt_fim = pd.to_datetime(st.session_state.data_fim_sel) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
        df_calculo = df_bruto[(df_bruto["Data_dt"] >= dt_ini) & (df_bruto["Data_dt"] <= dt_fim)].copy()
        
        total_receitas = float(df_calculo.loc[df_calculo["Tipo_Norm"] == "RECEITA", "Valor"].sum())
        total_despesas = float(df_calculo.loc[df_calculo["Tipo_Norm"] == "DESPESA", "Valor"].sum())
    else:
        df_calculo = pd.DataFrame(columns=["ID", "Tipo", "Valor", "Categoria", "Descrição", "Data", "Tipo_Norm", "Data_dt"])
        total_receitas = 0.0
        total_despesas = 0.0
        
    # CÁLCULO DO SALDO LÍQUIDO
    saldo_liquido = total_receitas - total_despesas
    
    if "meta_mes" not in st.session_state:
        st.session_state.meta_mes = 1000.00
    meta_mes = st.session_state.meta_mes
    progresso_meta = min(100, int((saldo_liquido / meta_mes) * 100)) if saldo_liquido > 0 and meta_mes > 0 else 0
    
    # Extração segura do nome do usuário logado
    nome_usuario = st.session_state.email_logado.split('@')[0].capitalize() if st.session_state.email_logado else "Usuário"
    saudacao_tempo = obter_saudacao_horario()
    
    # =========================================================================
    # TELA: PAINEL
    # =========================================================================
    if menu == "Painel":
        st.markdown(f"### 👋 {saudacao_tempo}, {nome_usuario}!")
        st.caption("Seja bem-vindo(a) ao seu painel do **FAMT Control**. Confira suas movimentações e saldo consolidado.")
        
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("↗ Total de Receitas", moeda(total_receitas), delta="Entradas", delta_color="normal")
        with c2:
            st.metric("↘ Total de Despesas", moeda(total_despesas), delta="Saídas", delta_color="inverse")
        with c3:
            st.metric("◎ Saldo Líquido", moeda(saldo_liquido), delta="Positivo" if saldo_liquido >= 0 else "Devedor", delta_color="normal" if saldo_liquido >= 0 else "inverse")
        with c4:
            st.metric("🎯 Meta do Mês", moeda(meta_mes), delta=f"{progresso_meta}% Atingido")
        st.markdown("<br />", unsafe_allow_html=True)
        
        # --- FORMULÁRIO DE LANÇAMENTO RÁPIDO INCORPORADO NO PAINEL ---
        with st.expander("＋ **Novo Lançamento Rápido**", expanded=True):
            with st.form("form_quick_lancamento_painel_v44", clear_on_submit=True):
                col_f1, col_f2, col_f3, col_f4 = st.columns([1.2, 1.2, 2, 1.5])
                with col_f1:
                    tipo_p = st.selectbox("Tipo", ["Despesa", "Receita"], key="quick_tipo")
                with col_f2:
                    valor_p = st.number_input("Valor (R$)", min_value=0.01, value=50.00, step=10.00, key="quick_valor")
                with col_f3:
                    desc_p = st.text_input("Descrição", placeholder="Ex: Almoço, Faculdade, Estágio", key="quick_desc")
                with col_f4:
                    cat_p = st.selectbox("Categoria", ["Alimentação", "Moradia", "Transporte", "Educação", "Saúde", "Lazer", "Salário", "Freelance", "Contas", "Outros"], key="quick_cat")
                
                btn_salvar_quick = st.form_submit_button("💾 Salvar no Banco de Dados", type="primary", use_container_width=True)
                if btn_salvar_quick:
                    if not desc_p.strip():
                        st.error("❌ Por favor, informe a descrição do lançamento.")
                    else:
                        conexao = obter_conexao()
                        cursor = conexao.cursor()
                        try:
                            data_hora_quick = datetime.now()
                            tipo_sanitizado_q = tipo_p.strip().upper()
                            cursor.execute("""
                                INSERT INTO Transacoes (usuario_id, valor, tipo, data, descricao, categoria) 
                                VALUES (%s, %s, %s, %s, %s, %s)
                            """, (st.session_state.usuario_id, valor_p, tipo_sanitizado_q, data_hora_quick, desc_p.strip(), cat_p))
                            conexao.commit()
                            st.toast(f"🎉 Lançamento de R$ {valor_p:.2f} salvo com sucesso!", icon="✅")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erro ao salvar: {e}")
                        finally:
                            cursor.close()
                            conexao.close()
                            
        st.divider()
        
        # --- GRÁFICOS ANALÍTICOS ---
        col_g1, col_g2 = st.columns([1.6, 1.4])
        with col_g1:
            st.subheader("📈 Comparativo de Receitas x Despesas")
            if not df_calculo.empty:
                df_c = df_calculo.copy()
                df_c["Mês"] = df_c["Data_dt"].dt.strftime("%m/%Y")
                mensal = df_c.pivot_table(index="Mês", columns="Tipo_Norm", values="Valor", aggfunc="sum", fill_value=0).reset_index()
                for col in ["RECEITA", "DESPESA"]:
                    if col not in mensal.columns:
                        mensal[col] = 0.0
                fig = go.Figure()
                fig.add_trace(go.Bar(x=mensal["Mês"], y=mensal["RECEITA"], name="Receitas", marker_color="#43C6A6"))
                fig.add_trace(go.Bar(x=mensal["Mês"], y=mensal["DESPESA"], name="Despesas", marker_color="#FF4D4D"))
                fig.update_layout(barmode="group", height=320, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#E8E7F5", legend=dict(orientation="h", y=1.12), margin=dict(l=10, r=10, t=10, b=10))
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
            else:
                st.info("ℹ️ Nenhuma movimentação registrada no período selecionado.")
                
        with col_g2:
            st.subheader("🍩 Distribuição de Despesas por Categoria")
            if not df_calculo.empty and "Tipo_Norm" in df_calculo.columns:
                desp = df_calculo[df_calculo["Tipo_Norm"] == "DESPESA"]
                if not desp.empty:
                    cats = desp.groupby("Categoria", as_index=False)["Valor"].sum().sort_values(by="Valor", ascending=False)
                    paleta_despesas = ["#FF4D4D", "#E53935", "#FF6B6B", "#D32F2F", "#FF8A80", "#C62828"]
                    fig_cat = px.pie(cats, names="Categoria", values="Valor", hole=0.6, color_discrete_sequence=paleta_despesas)
                    fig_cat.update_layout(height=320, paper_bgcolor="rgba(0,0,0,0)", font_color="#E8E7F5", legend=dict(orientation="h", y=-0.15), margin=dict(l=10, r=10, t=10, b=10))
                    fig_cat.update_traces(textposition="inside", textinfo="percent+label")
                    st.plotly_chart(fig_cat, use_container_width=True, config={"displayModeBar": False})
                else:
                    st.info("ℹ️ Nenhuma despesa cadastrada no período.")
            else:
                st.info("ℹ️ Nenhuma despesa cadastrada no período.")
                
        st.divider()
        
    # =========================================================================
    # TELA: LANÇAR
    # =========================================================================
    elif menu == "Lançar":
        st.title("＋ Novo Lançamento")
        st.caption("Cadastre receitas ou despesas com atualização automática do saldo.")
        with st.form("form_lancamento_v44", clear_on_submit=True):
            tipo = st.selectbox("Tipo de Movimentação", ["Despesa", "Receita"])
            valor = st.number_input("Valor (R$)", min_value=0.01, value=50.00, step=10.00)
            descricao = st.text_input("Descrição detalhada", placeholder="Ex: Mensalidade, Almoço, Estágio")
            categoria = st.selectbox("Categoria", ["Alimentação", "Moradia", "Transporte", "Educação", "Saúde", "Lazer", "Salário", "Freelance", "Contas", "Outros"])
            salvar = st.form_submit_button("💾 Salvar Movimentação", type="primary", use_container_width=True)
            
            if salvar:
                if not descricao.strip():
                    st.error("❌ Por favor, informe uma descrição para o lançamento.")
                else:
                    conexao = obter_conexao()
                    cursor = conexao.cursor()
                    try:
                        data_hora = datetime.now()
                        tipo_sanitizado = tipo.strip().upper()
                        cursor.execute("""
                            INSERT INTO Transacoes (usuario_id, valor, tipo, data, descricao, categoria)
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (st.session_state.usuario_id, valor, tipo_sanitizado, data_hora, descricao.strip(), categoria))
                        conexao.commit()
                        st.toast(f"🎉 Lançamento de R$ {valor:.2f} salvo com sucesso!", icon="✅")
                        st.session_state.menu = "Painel"
                        st.rerun()
                    except Exception as e:
                        st.error(f"Não foi possível salvar o lançamento: {e}")
                    finally:
                        cursor.close()
                        conexao.close()
                        
    # =========================================================================
    # TELA: EXTRATO E EDIÇÃO
    # =========================================================================
    elif menu == "Extrato e Edição":
        st.title("📄 Extrato e Edição de Lançamentos")
        st.caption("Consulte, edite ou exclua suas movimentações salvas no banco MySQL.")
        
        conexao = obter_conexao()
        cursor = conexao.cursor()
        cursor.execute("""
            SELECT id, tipo, valor, categoria, descricao, data 
            FROM Transacoes 
            WHERE usuario_id = %s 
            ORDER BY data DESC;
        """, (st.session_state.usuario_id,))
        historico_extrato = cursor.fetchall()
        cursor.close()
        conexao.close()
        
        if historico_extrato:
            extrato = pd.DataFrame(historico_extrato, columns=["ID", "Tipo", "Valor", "Categoria", "Descrição", "Data"])
            extrato["Data_Formatada"] = pd.to_datetime(extrato["Data"], errors="coerce").dt.strftime("%d/%m/%Y %H:%M")
            
            st.dataframe(
                extrato[["Data_Formatada", "Tipo", "Descrição", "Categoria", "Valor"]],
                use_container_width=True,
                hide_index=True,
                column_config={"Valor": st.column_config.NumberColumn("Valor", format="R$ %.2f")}
            )
            st.divider()
            
            ids = extrato["ID"].astype(int).tolist()
            selecionado = st.selectbox(
                "Selecione um lançamento para editar ou excluir:",
                ids,
                format_func=lambda x: f"#{x} — {extrato.loc[extrato['ID'].astype(int) == x, 'Descrição'].iloc[0]} (R$ {float(extrato.loc[extrato['ID'].astype(int) == x, 'Valor'].iloc[0]):.2f})"
            )
            
            atual = extrato.loc[extrato["ID"].astype(int) == int(selecionado)].iloc[0]
            st.markdown("### ✏️ Editar Lançamento")
            with st.form("form_editar_v44"):
                novo_tipo = st.selectbox("Tipo", ["Despesa", "Receita"], index=0 if str(atual["Tipo"]).strip().upper() == "DESPESA" else 1)
                novo_valor = st.number_input("Valor (R$)", min_value=0.01, value=max(0.01, float(atual["Valor"])), step=10.00)
                cats = ["Alimentação", "Moradia", "Transporte", "Educação", "Saúde", "Lazer", "Salário", "Freelance", "Contas", "Outros"]
                idx_c = cats.index(atual["Categoria"]) if atual["Categoria"] in cats else 0
                nova_cat = st.selectbox("Categoria", cats, index=idx_c)
                nova_desc = st.text_input("Descrição", value=str(atual["Descrição"]))
                
                if st.form_submit_button("💾 Salvar Alterações", type="primary", use_container_width=True):
                    if not nova_desc.strip():
                        st.error("❌ A descrição é obrigatória.")
                    else:
                        conexao = obter_conexao()
                        cursor = conexao.cursor()
                        try:
                            cursor.execute("""
                                UPDATE Transacoes 
                                SET tipo = %s, valor = %s, categoria = %s, descricao = %s 
                                WHERE id = %s AND usuario_id = %s
                            """, (novo_tipo.strip().upper(), novo_valor, nova_cat.strip(), nova_desc.strip(), int(selecionado), st.session_state.usuario_id))
                            conexao.commit()
                            st.toast("🎉 Lançamento atualizado!", icon="✅")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erro ao atualizar: {e}")
                        finally:
                            cursor.close()
                            conexao.close()
                            
            with st.expander("🗑️ Excluir lançamento"):
                confirmar = st.checkbox("Confirmo a exclusão permanente deste lançamento.", key="del_chk_v44")
                if st.button("Excluir Selecionado", type="secondary", disabled=not confirmar, use_container_width=True):
                    conexao = obter_conexao()
                    cursor = conexao.cursor()
                    try:
                        cursor.execute("""
                            DELETE FROM Transacoes WHERE id = %s AND usuario_id = %s
                        """, (int(selecionado), st.session_state.usuario_id))
                        conexao.commit()
                        st.toast("🗑️ Lançamento excluído com sucesso!", icon="✅")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Erro ao excluir: {e}")
                    finally:
                        cursor.close()
                        conexao.close()
        else:
            st.info("ℹ️ Não existem lançamentos cadastrados.")
            
    # =========================================================================
    # TELA: METAS
    # =========================================================================
    elif menu == "Metas":
        st.title("🎯 Metas Financeiras")
        nova_meta = st.number_input("Definir Meta do Mês (R$)", min_value=1.0, value=float(st.session_state.meta_mes), step=100.0)
        if st.button("Salvar Meta", type="primary"):
            st.session_state.meta_mes = float(nova_meta)
            st.success("Meta atualizada com sucesso!")
            st.rerun()
            
    # =========================================================================
    # TELA: GRÁFICOS
    # =========================================================================
    elif menu == "Gráficos":
        st.title("📈 Relatórios Visuais")
        if not df_calculo.empty:
            fig = px.bar(
                df_calculo, 
                x="Categoria", 
                y="Valor", 
                color="Tipo_Norm", 
                barmode="group", 
                color_discrete_map={"RECEITA": "#43C6A6", "DESPESA": "#FF4D4D"}
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#E8E7F5")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Sem dados para gerar gráficos.")
            
    # =========================================================================
    # TELA: NOTIFICAÇÕES
    # =========================================================================
    elif menu == "Notificações":
        st.title("🔔 Central de Notificações")
        st.info(f"👋 Olá, {nome_usuario}! Aqui ficam registrados os alertas importantes da sua conta.")
        if saldo_liquido < 0:
            st.error(f"🚨 Atenção: Saldo devedor de {moeda(saldo_liquido)}.")
        else:
            st.success("Sua conta está em situação regular.")
            
    # =========================================================================
    # TELA: ALERTAS E DICAS
    # =========================================================================
    elif menu == "Alertas e Dicas":
        st.title("💡 Alertas e Dicas Financeiras")
        if total_despesas > 0 and total_receitas > 0:
            pct = (total_despesas / total_receitas) * 100
            st.metric("Comprometimento de Renda", f"{pct:.1f}%")
            if pct > 80:
                st.warning("⚠️ Mais de 80% das suas receitas estão comprometidas com despesas!")
                
    # =========================================================================
    # TELA: CONFIGURAÇÕES
    # =========================================================================
    elif menu == "Configurações":
        st.title("⚙️ Configurações da Conta")
        st.write(f"**Conta:** {st.session_state.email_logado}")
        st.write("**Banco de Dados:** MySQL (Aiven / Local)")