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
# LOGO E CONFIGURAÇÃO DA CONEXÃO MYSQL
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
# MÓDULO DE SEGURANÇA, CRIPTOGRAFIA E VALIDAÇÕES (LGPD)
# =============================================================================
def _hash_senha(senha: str) -> str:
    """Gera hash SHA-256 para a senha."""
    return hashlib.sha256(senha.encode("utf-8")).hexdigest()

def validar_complexidade_senha(senha: str) -> tuple[bool, str]:
    """
    Valida os requisitos mínimos de segurança de senha:
    - Mínimo de 6 caracteres
    - Pelo menos 1 letra maiúscula
    - Pelo menos 1 letra minúscula
    - Pelo menos 1 número
    - Pelo menos 1 caractere especial
    """
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
    """Gera uma senha provisória aleatória."""
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
    """Envia a senha provisória por SMTP se as credenciais estiverem configuradas."""
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
        mensagem["Subject"] = "Sua senha provisória - FAMT Control"
        corpo_email = (
            "Olá!\n\n"
            f"Sua senha provisória do FAMT Control é: {senha_provisoria}\n\n"
            "Ao entrar, você deverá criar uma nova senha."
        )
        mensagem.attach(MIMEText(corpo_email, "plain", "utf-8"))
        
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
        st.warning(f"Não foi possível enviar o e-mail: {e}")
        return False

# =============================================================================
# INICIALIZAÇÃO DO BANCO DE DADOS
# =============================================================================
def inicializar_banco():
    """Cria as tabelas do sistema caso ainda não existam."""
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
        st.error(f"Erro ao inicializar o banco de dados: {e}")

inicializar_banco()

# =============================================================================
# ESTILIZAÇÃO VISUAL PURPLE DARK MODE
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
# GERENCIAMENTO DE SESSÃO
# =============================================================================
if 'usuario_id' not in st.session_state:
    st.session_state.usuario_id = None
if 'email_logado' not in st.session_state:
    st.session_state.email_logado = None
if 'primeiro_acesso' not in st.session_state:
    st.session_state.primeiro_acesso = 0

# =============================================================================
# TELA DE LOGIN / CADASTRO DE CONTA / RECUPERAÇÃO DE SENHA
# =============================================================================
if st.session_state.usuario_id is None:
    col_left, col_center, col_right = st.columns([1, 2, 1])
    with col_center:
        st.markdown("<h1>💰 FAMT CONTROL</h1>", unsafe_allow_html=True)
        st.markdown("<p>Seu dinheiro sob controle • Squad FAMT</p>", unsafe_allow_html=True)
        
        aba1, aba2, aba3 = st.tabs(["🔑 Entrar", "📝 Nova Conta", "🛡️ Redefinir Senha"])
        
        with aba1:
            st.markdown("### 🔑 Acesse sua conta")
            with st.form(key="form_login_v24"):
                email = st.text_input("E-mail cadastrado", key="login_email_v24", placeholder="seu.email@exemplo.com").strip().lower()
                senha = st.text_input("Senha de acesso", type="password", key="login_senha_v24", placeholder="••••••••").strip()
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
                                st.toast("🔓 Login efetuado com sucesso!", icon="✅")
                                st.rerun()
                            else:
                                st.error("❌ Senha incorreta. Tente novamente.")
                        else:
                            st.error("❌ E-mail não encontrado no sistema.")
                            
        with aba2:
            st.markdown("### 📝 Criar nova conta")
            with st.form(key="form_cad_v24"):
                novo_email = st.text_input("E-mail para cadastro", key="cad_email_v24", placeholder="seu.email@exemplo.com").strip().lower()
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
                                st.warning("A conta foi criada, mas o envio de e-mail não está configurado. Use a senha provisória exibida abaixo:")
                                st.code(senha_prov)
                        except (IntegrityError, Exception):
                            st.error("❌ Este e-mail já está cadastrado no banco de dados.")
                        finally:
                            conexao.close()
                            
        with aba3:
            st.markdown("### 🛡️ Recuperar / Redefinir Senha")
            with st.form(key="form_rec_v24"):
                rec_email = st.text_input("E-mail cadastrado", key="rec_email_v24", placeholder="seu.email@exemplo.com").strip().lower()
                btn_rec = st.form_submit_button("🔑 Enviar E-mail de Confirmação", type="primary", use_container_width=True)
                
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
                                st.warning("O envio de e-mail não está configurado. Sua senha provisória foi gerada abaixo:")
                                st.code(nova_prov)
                        else:
                            conexao.close()
                            st.error("❌ E-mail não encontrado no sistema.")

# =============================================================================
# BLOQUEIO DE PRIMEIRO ACESSO (VALIDAÇÃO RÍGIDA LGPD)
# =============================================================================
elif st.session_state.primeiro_acesso == 1:
    col_l, col_c, col_r = st.columns([1, 2, 1])
    with col_c:
        st.warning("⚠️ **Primeiro Acesso Detectado (Conformidade LGPD)**")
        st.info("Por motivos de segurança, é obrigatório redefinir sua senha provisória atendendo aos requisitos mínimos de complexidade:")
        st.markdown("- Mínimo de **6 caracteres**\n- Pelo menos **1 letra maiúscula** (A-Z)\n- Pelo menos **1 letra minúscula** (a-z)\n- Pelo menos **1 número** (0-9)\n- Pelo menos **1 caractere especial** (`!@#$%^&*` etc.)")
        
        with st.form(key="form_primeiro_acesso_lgpd_v24"):
            nova_senha = st.text_input("Digite sua NOVA senha", type="password")
            confirma_senha = st.text_input("Confirme sua NOVA senha", type="password")
            btn_pa = st.form_submit_button("Salvar Nova Senha Definitiva", use_container_width=True, type="primary")
            
            if btn_pa:
                valida, msg_erro = validar_complexidade_senha(nova_senha)
                if not valida:
                    st.error(f"❌ {msg_erro}")
                elif nova_senha != confirma_senha:
                    st.error("❌ As senhas digitadas não coincidem. Verifique a confirmação.")
                else:
                    novo_hash = _hash_senha(nova_senha)
                    conexao = obter_conexao()
                    cursor = conexao.cursor()
                    cursor.execute("UPDATE Usuarios SET senha_hash = %s, primeiro_acesso = 0 WHERE id = %s", (novo_hash, st.session_state.usuario_id))
                    conexao.commit()
                    conexao.close()
                    st.session_state.primeiro_acesso = 0
                    st.toast("🔑 Senha salva com sucesso!", icon="✅")
                    st.success("✅ Senha atualizada! Acessando o painel...")
                    st.rerun()

# =============================================================================
# PAINEL DE NAVEGAÇÃO E SISTEMA COMPLETO
# =============================================================================
else:
    if "menu" not in st.session_state:
        st.session_state.menu = "Painel"
        
    def navegar_para(destino):
        st.session_state.menu = destino
        
    # Sidebar lateral
    with st.sidebar:
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
            st.rerun()
            
    # Período de Análise (Mês Atual) - Corrigido para índice [1]
    agora = datetime.now()
    primeiro_dia_mes_atual = agora.replace(day=1)
    ultimo_dia_num_atual = calendar.monthrange(agora.year, agora.month)[1]
    ultimo_dia_mes_atual = agora.replace(day=ultimo_dia_num_atual)
    
    if "data_inicio_sel" not in st.session_state:
        st.session_state.data_inicio_sel = primeiro_dia_mes_atual.date()
    if "data_fim_sel" not in st.session_state:
        st.session_state.data_fim_sel = ultimo_dia_mes_atual.date()
        
    d_inicio = st.session_state.data_inicio_sel
    d_fim = st.session_state.data_fim_sel
    
    def moeda(valor):
        return f"R$ {valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
        
    # Consulta dos Lançamentos no MySQL
    conexao = obter_conexao()
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT id, tipo, valor, categoria, descricao, data 
        FROM Transacoes 
        WHERE usuario_id = %s 
        ORDER BY data DESC;
    """, (st.session_state.usuario_id,))
    historico = cursor.fetchall()
    cursor.close()
    conexao.close()
    
    if historico:
        df_bruto = pd.DataFrame(historico, columns=["ID", "Tipo", "Valor", "Categoria", "Descrição", "Data"])
        df_bruto["Valor"] = pd.to_numeric(df_bruto["Valor"], errors="coerce").fillna(0.0)
        df_bruto["Data_dt"] = pd.to_datetime(df_bruto["Data"], errors="coerce")
        df_bruto["Tipo_Norm"] = df_bruto["Tipo"].astype(str).str.strip().str.upper()
        
        dt_ini_pd = pd.to_datetime(d_inicio)
        dt_fim_pd = pd.to_datetime(d_fim) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
        
        mask_periodo = (df_bruto["Data_dt"] >= dt_ini_pd) & (df_bruto["Data_dt"] <= dt_fim_pd)
        df_calculo = df_bruto[mask_periodo].copy()
        
        total_receitas = float(df_calculo.loc[df_calculo["Tipo_Norm"] == "RECEITA", "Valor"].sum()) if not df_calculo.empty else 0.0
        total_despesas = float(df_calculo.loc[df_calculo["Tipo_Norm"] == "DESPESA", "Valor"].sum()) if not df_calculo.empty else 0.0
    else:
        df_calculo = pd.DataFrame(columns=["ID", "Tipo", "Valor", "Categoria", "Descrição", "Data", "Tipo_Norm", "Data_dt"])
        total_receitas = 0.0
        total_despesas = 0.0
        
    saldo_liquido = total_receitas - total_despesas
    
    if "meta_mes" not in st.session_state:
        st.session_state.meta_mes = 1000.00
    meta_mes = st.session_state.meta_mes
    progresso_meta = min(100, int((saldo_liquido / meta_mes) * 100)) if saldo_liquido > 0 and meta_mes > 0 else 0
    
    # =========================================================================
    # TELA: PAINEL
    # =========================================================================
    if menu == "Painel":
        st.title("Visão geral financeira")
        st.caption("Acompanhe suas receitas, despesas e objetivos.")
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("↗ Receitas", moeda(total_receitas))
        c2.metric("↘ Despesas", moeda(total_despesas))
        c3.metric("◎ Saldo líquido", moeda(saldo_liquido))
        c4.metric("🎯 Meta financeira", moeda(meta_mes))
        st.divider()
        
        esquerda, direita = st.columns([1.5, 1])
        with esquerda:
            st.subheader("Receitas x despesas")
            if not df_calculo.empty:
                grafico = df_calculo.copy()
                grafico["Mês"] = grafico["Data_dt"].dt.strftime("%m/%Y")
                mensal = grafico.pivot_table(index="Mês", columns="Tipo_Norm", values="Valor", aggfunc="sum", fill_value=0).reset_index()
                for tipo_col in ["RECEITA", "DESPESA"]:
                    if tipo_col not in mensal.columns:
                        mensal[tipo_col] = 0.0
                fig = go.Figure()
                fig.add_trace(go.Bar(x=mensal["Mês"], y=mensal["RECEITA"], name="Receitas", marker_color="#43C6A6"))
                fig.add_trace(go.Bar(x=mensal["Mês"], y=mensal["DESPESA"], name="Despesas", marker_color="#7C4DFF"))
                fig.update_layout(
                    barmode="group",
                    height=340,
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#E8E7F5",
                    margin=dict(l=8, r=8, t=25, b=8),
                    legend=dict(orientation="h", y=1.12),
                    yaxis=dict(gridcolor="#30314D")
                )
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
            else:
                st.info("Ainda não há movimentações neste período.")
                
        with direita:
            st.subheader("Despesas por categoria")
            if not df_calculo.empty and "Tipo_Norm" in df_calculo.columns:
                despesas = df_calculo[df_calculo["Tipo_Norm"] == "DESPESA"].copy()
                if not despesas.empty:
                    categorias = despesas.groupby("Categoria", as_index=False)["Valor"].sum().sort_values("Valor", ascending=False)
                    fig_cat = px.pie(
                        categorias,
                        names="Categoria",
                        values="Valor",
                        hole=0.66,
                        color_discrete_sequence=["#7C4DFF", "#43C6A6", "#3B9EF8", "#F4A340", "#E84DA8", "#FF647C"]
                    )
                    fig_cat.update_layout(
                        height=340,
                        paper_bgcolor="rgba(0,0,0,0)",
                        font_color="#E8E7F5",
                        margin=dict(l=5, r=5, t=20, b=5),
                        legend=dict(orientation="h", y=-0.12)
                    )
                    fig_cat.update_traces(textposition="inside", textinfo="percent")
                    st.plotly_chart(fig_cat, use_container_width=True, config={"displayModeBar": False})
                else:
                    st.info("Cadastre despesas para visualizar as categorias.")
            else:
                st.info("Cadastre despesas para visualizar as categorias.")
                
        st.divider()
        st.subheader("Últimas movimentações")
        if not df_calculo.empty:
            recentes = df_calculo.sort_values(by="Data_dt", ascending=False).head(6)
            st.dataframe(
                recentes[["Data", "Tipo", "Descrição", "Categoria", "Valor"]],
                use_container_width=True,
                hide_index=True,
                column_config={"Valor": st.column_config.NumberColumn("Valor", format="R$ %.2f")}
            )
        else:
            st.info("Você ainda não possui lançamentos neste período.")
            
        st.divider()
        st.subheader("Progresso da meta")
        st.progress(progresso_meta / 100)
        st.caption(f"{progresso_meta}% — saldo de {moeda(saldo_liquido)} em relação à meta de {moeda(meta_mes)}.")
        
        if saldo_liquido < 0:
            st.warning("Seu saldo está negativo neste período. Revise as despesas e planeje os próximos lançamentos.")
        elif total_receitas > 0:
            taxa_economia = (saldo_liquido / total_receitas) * 100
            st.success(f"Seu saldo está positivo. Você manteve {taxa_economia:.1f}% das receitas neste período.")
            
    # =========================================================================
    # TELA: LANÇAR
    # =========================================================================
    elif menu == "Lançar":
        st.title("Novo lançamento")
        st.caption("Registre uma receita ou despesa na sua conta.")
        with st.form("form_lancamento", clear_on_submit=True):
            tipo = st.selectbox("Tipo de movimentação", ["Despesa", "Receita"])
            valor = st.number_input("Valor (R$)", min_value=0.01, value=1.00, step=1.00, format="%.2f")
            descricao = st.text_input("Descrição", max_chars=255)
            categoria = st.selectbox("Categoria", ["Alimentação", "Moradia", "Transporte", "Educação", "Saúde", "Lazer", "Salário", "Freelance", "Contas", "Compras", "Outros"])
            salvar = st.form_submit_button("Salvar lançamento", type="primary", use_container_width=True)
            
            if salvar:
                if not descricao.strip():
                    st.error("Informe uma descrição para o lançamento.")
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
                        st.success("Lançamento salvo com sucesso!")
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
        st.title("Extrato e edição")
        st.caption("Consulte, edite ou exclua suas movimentações.")
        
        if not df_calculo.empty:
            extrato = df_calculo.copy()
            st.dataframe(
                extrato[["Data", "Tipo", "Descrição", "Categoria", "Valor"]],
                use_container_width=True,
                hide_index=True,
                column_config={"Valor": st.column_config.NumberColumn("Valor", format="R$ %.2f")}
            )
            
            ids = extrato["ID"].astype(int).tolist()
            selecionado = st.selectbox(
                "Selecione um lançamento para editar ou excluir",
                ids,
                format_func=lambda x: f"#{x} — {extrato.loc[extrato['ID'].astype(int) == x, 'Descrição'].iloc[0]}"
            )
            
            atual = extrato.loc[extrato["ID"].astype(int) == int(selecionado)].iloc[0]
            with st.form("form_editar_lancamento"):
                novo_tipo = st.selectbox("Tipo", ["Despesa", "Receita"], index=0 if str(atual["Tipo"]).strip().upper() == "DESPESA" else 1)
                novo_valor = st.number_input("Valor (R$)", min_value=0.01, value=max(0.01, float(atual["Valor"])), step=1.0)
                nova_categoria = st.text_input("Categoria", value=str(atual["Categoria"]))
                nova_descricao = st.text_input("Descrição", value=str(atual["Descrição"]))
                
                salvar_edicao = st.form_submit_button("Salvar alterações", type="primary")
                if salvar_edicao:
                    if not nova_descricao.strip() or not nova_categoria.strip():
                        st.error("Descrição e categoria são obrigatórias.")
                    else:
                        conexao = obter_conexao()
                        cursor = conexao.cursor()
                        try:
                            cursor.execute("""
                                UPDATE Transacoes 
                                SET tipo = %s, valor = %s, categoria = %s, descricao = %s 
                                WHERE id = %s AND usuario_id = %s
                            """, (novo_tipo.strip().upper(), novo_valor, nova_categoria.strip(), nova_descricao.strip(), int(selecionado), st.session_state.usuario_id))
                            conexao.commit()
                            st.success("Lançamento atualizado.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Erro ao atualizar: {e}")
                        finally:
                            cursor.close()
                            conexao.close()
                            
            with st.expander("Excluir lançamento"):
                confirmar = st.checkbox("Confirmo que desejo excluir este lançamento.", key="confirmar_exclusao")
                if st.button("Excluir selecionado", type="secondary", disabled=not confirmar):
                    conexao = obter_conexao()
                    cursor = conexao.cursor()
                    try:
                        cursor.execute("""
                            DELETE FROM Transacoes WHERE id = %s AND usuario_id = %s
                        """, (int(selecionado), st.session_state.usuario_id))
                        conexao.commit()
                        st.success("Lançamento excluído.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Erro ao excluir: {e}")
                    finally:
                        cursor.close()
                        conexao.close()
        else:
            st.info("Não há lançamentos neste período.")
            
    # =========================================================================
    # TELA: METAS
    # =========================================================================
    elif menu == "Metas":
        st.title("Metas financeiras")
        st.caption("Defina o valor que deseja alcançar.")
        nova_meta = st.number_input("Valor da meta (R$)", min_value=1.0, value=float(st.session_state.meta_mes), step=100.0)
        if st.button("Salvar meta", type="primary"):
            st.session_state.meta_mes = float(nova_meta)
            st.success("Meta atualizada nesta sessão.")
            st.rerun()
            
        st.metric("Meta atual", moeda(st.session_state.meta_mes))
        st.progress(progresso_meta / 100)
        
    # =========================================================================
    # TELA: GRÁFICOS
    # =========================================================================
    elif menu == "Gráficos":
        st.title("Relatórios e gráficos")
        st.caption("Análise das movimentações do período selecionado.")
        if not df_calculo.empty:
            graf = df_calculo.copy()
            graf["Mês"] = graf["Data_dt"].dt.strftime("%m/%Y")
            mensal = graf.groupby(["Mês", "Tipo_Norm"], as_index=False)["Valor"].sum()
            fig = px.bar(mensal, x="Mês", y="Valor", color="Tipo_Norm", barmode="group", color_discrete_map={"RECEITA": "#43C6A6", "DESPESA": "#7C4DFF"})
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#E8E7F5", yaxis=dict(gridcolor="#30314D"))
            st.plotly_chart(fig, use_container_width=True)
            
            csv = df_calculo.drop(columns=["Data_dt", "Tipo_Norm"], errors="ignore").to_csv(index=False).encode("utf-8-sig")
            st.download_button("Baixar movimentações em CSV", csv, file_name="famt_control_movimentacoes.csv", mime="text/csv")
        else:
            st.info("Não existem dados suficientes para gerar gráficos.")
            
    # =========================================================================
    # TELA: NOTIFICAÇÕES
    # =========================================================================
    elif menu == "Notificações":
        st.title("Notificações")
        if saldo_liquido < 0:
            st.error(f"Seu saldo no período está negativo: {moeda(saldo_liquido)}.")
        elif total_receitas > 0:
            st.success("Seu saldo está positivo neste período.")
        else:
            st.info("Cadastre movimentações para receber notificações financeiras.")
            
    # =========================================================================
    # TELA: ALERTAS E DICAS
    # =========================================================================
    elif menu == "Alertas e Dicas":
        st.title("Alertas e dicas")
        if saldo_liquido < 0:
            st.warning("Suas despesas superaram suas receitas. Revise gastos não essenciais.")
        elif total_receitas > 0:
            st.success("Você está com saldo positivo. Continue acompanhando seus gastos.")
        else:
            st.info("Comece registrando suas receitas e despesas.")
            
        if total_despesas > 0 and total_receitas > 0:
            percentual = (total_despesas / total_receitas) * 100
            st.metric("Despesas em relação às receitas", f"{percentual:.1f}%")
            if percentual > 80:
                st.warning("Mais de 80% das receitas já estão comprometidas com despesas.")
                
    # =========================================================================
    # TELA: CONFIGURAÇÕES
    # =========================================================================
    elif menu == "Configurações":
        st.title("Configurações")
        st.write("Conta conectada:", st.session_state.email_logado)
        st.write("Banco de dados: MySQL")
        st.caption("Para alterar os dados de conexão, ajuste o arquivo .streamlit/secrets.toml ou as variáveis de ambiente.")