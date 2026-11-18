
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
# CONFIGURAÇÃO DA PÁGINA STREAMLIT
# =============================================================================

st.set_page_config(
    page_title="FAMT CONTROL - Dashboard",
    page_icon="💰",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =============================================================================
# LOGO E CONFIGURAÇÃO DO BANCO DE DADOS MYSQL
# =============================================================================

LOGO_PATH = (
    Path(__file__).resolve().parent
    / "Logo Fintech FAMT Control.png"
)


def logo_html(css_class="system-logo"):
    """Retorna a logo em base64 para renderização HTML."""

    if not LOGO_PATH.exists():
        return ""

    data = base64.b64encode(
        LOGO_PATH.read_bytes()
    ).decode("utf-8")

    classe = html.escape(css_class, quote=True)

    return f'''
        <img
            src="data:image/png;base64,{data}"
            class="{classe}"
            alt="Logo FAMT Control"
        >
    '''


def obter_conexao():
    """Abre conexão MySQL via st.secrets ou variáveis de ambiente local."""

    try:
        cfg = {}

        if hasattr(st, "secrets") and "mysql" in st.secrets:
            cfg = dict(st.secrets["mysql"])

        return mysql.connector.connect(
            host=cfg.get(
                "host",
                os.getenv("MYSQL_HOST", "localhost")
            ),
            user=cfg.get(
                "user",
                os.getenv("MYSQL_USER", "root")
            ),
            password=cfg.get(
                "password",
                os.getenv("MYSQL_PASSWORD", "root")
            ),
            database=cfg.get(
                "database",
                os.getenv("MYSQL_DATABASE", "famt_control")
            ),
            port=int(
                cfg.get(
                    "port",
                    os.getenv("MYSQL_PORT", "3306")
                )
            ),
            connection_timeout=8
        )

    except Exception as e:
        st.error(f"Não foi possível conectar ao MySQL: {e}")

        st.info(
            "Confira se o serviço do MySQL está ativo e se o banco "
            "'famt_control' ou 'defaultdb' existe."
        )

        st.stop()


# =============================================================================
# MÓDULO DE SEGURANÇA, CRIPTOGRAFIA E VALIDAÇÕES (LGPD / REQ-EXT-01)
# =============================================================================

def _hash_senha(senha: str) -> str:
    """Gera hash SHA-256 para a senha do usuário."""

    return hashlib.sha256(
        senha.encode("utf-8")
    ).hexdigest()


def validar_complexidade_senha(senha: str) -> tuple[bool, str]:
    """Valida os requisitos mínimos de segurança de senha (LGPD)."""

    if len(senha) < 6:
        return False, "A senha deve conter no mínimo 6 caracteres."

    if not re.search(r"[A-Z]", senha):
        return False, (
            "A senha deve conter pelo menos uma letra maiúscula (A-Z)."
        )

    if not re.search(r"[a-z]", senha):
        return False, (
            "A senha deve conter pelo menos uma letra minúscula (a-z)."
        )

    if not re.search(r"\d", senha):
        return False, (
            "A senha deve conter pelo menos um número (0-9)."
        )

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', senha):
        return False, (
            "A senha deve conter pelo menos um caractere especial."
        )

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

    senha += [
        random.choice(todos)
        for _ in range(tamanho - 4)
    ]

    random.shuffle(senha)

    return "".join(senha)


def enviar_senha_provisoria_email(
    email_destino: str,
    senha_provisoria: str
) -> bool:
    """Envia a senha provisória via SMTP quando configurado."""

    try:
        if not hasattr(st, "secrets") or "email" not in st.secrets:
            return False

        cfg = st.secrets["email"]

        servidor = cfg.get(
            "servidor",
            cfg.get("smtp_server")
        )

        porta = int(
            cfg.get("porta", cfg.get("smtp_port", 587))
        )

        usuario = cfg.get(
            "usuario",
            cfg.get("sender_email")
        )

        senha = cfg.get(
            "senha",
            cfg.get("sender_password")
        )

        mensagem = MIMEMultipart()

        mensagem["From"] = usuario
        mensagem["To"] = email_destino
        mensagem["Subject"] = (
            "🔐 Sua Senha Provisória - FAMT Control"
        )

        corpo = (
            "Olá!\n\n"
            f"Sua senha provisória do FAMT Control é: "
            f"{senha_provisoria}\n\n"
            "Ao acessar o sistema, você deverá cadastrar "
            "sua nova senha definitiva."
        )

        mensagem.attach(
            MIMEText(corpo, "plain", "utf-8")
        )

        with smtplib.SMTP(
            servidor,
            porta,
            timeout=15
        ) as smtp:

            smtp.starttls()
            smtp.login(usuario, senha)
            smtp.send_message(mensagem)

        return True

    except Exception as e:
        st.warning(f"Aviso SMTP: {e}")
        return False


# =============================================================================
# INICIALIZAÇÃO DO BANCO DE DADOS E SCHEMAS (3FN)
# =============================================================================

def inicializar_banco():
    """Cria as tabelas do sistema caso não existam no MySQL."""

    try:
        conexao = obter_conexao()
        cursor = conexao.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS Usuarios (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                senha_hash VARCHAR(255) NOT NULL,
                primeiro_acesso INT DEFAULT 1
                    CHECK (primeiro_acesso IN (0, 1))
            ) ENGINE=InnoDB;
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS Transacoes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                usuario_id INT NOT NULL,
                valor DECIMAL(10,2) NOT NULL
                    CHECK (valor > 0),
                tipo VARCHAR(20) NOT NULL
                    CHECK (
                        tipo IN (
                            'RECEITA',
                            'DESPESA',
                            'Receita',
                            'Despesa'
                        )
                    ),
                data DATETIME NOT NULL,
                descricao VARCHAR(255) NOT NULL,
                categoria VARCHAR(100) NOT NULL,

                FOREIGN KEY (usuario_id)
                    REFERENCES Usuarios(id)
                    ON DELETE CASCADE

            ) ENGINE=InnoDB;
        """)

        conexao.commit()

        cursor.close()
        conexao.close()

    except Exception as e:
        st.error(
            f"Erro ao inicializar o banco de dados: {e}"
        )


inicializar_banco()


# =============================================================================
# ESTILIZAÇÃO VISUAL PURPLE DARK MODE
# =============================================================================

CUSTOM_CSS = """
"""

st.markdown(
    CUSTOM_CSS,
    unsafe_allow_html=True
)


# =============================================================================
# GERENCIAMENTO DE SESSÃO
# =============================================================================

if "usuario_id" not in st.session_state:
    st.session_state.usuario_id = None

if "email_logado" not in st.session_state:
    st.session_state.email_logado = None

if "primeiro_acesso" not in st.session_state:
    st.session_state.primeiro_acesso = 0

# =============================================================================
# TELA DE LOGIN / NOVO CADASTRO / REDEFINIÇÃO DE SENHA
# =============================================================================

if st.session_state.usuario_id is None:

    col_left, col_center, col_right = st.columns([1, 2, 1])

    with col_center:

        st.markdown(
            "<br />",
            unsafe_allow_html=True
        )

        st.markdown("""
            <div>
                <h1>FAMT <span>CONTROL</span></h1>
                <p>Seu dinheiro sob controle • Squad FAMT</p>
            </div>
        """, unsafe_allow_html=True)

        aba1, aba2, aba3 = st.tabs([
            "🔑 Entrar",
            "📝 Nova Conta",
            "🛡️ Redefinir Senha"
        ])

        # ---------------------------------------------------------------------
        # ABA 1 - LOGIN
        # ---------------------------------------------------------------------

        with aba1:

            with st.form(key="form_login_v33"):

                st.markdown("### 🔑 Acesse sua conta")

                email = st.text_input(
                    "E-mail cadastrado",
                    key="login_email_v33"
                ).strip().lower()

                senha = st.text_input(
                    "Senha de acesso",
                    type="password",
                    key="login_senha_v33"
                ).strip()

                st.markdown(
                    "<br />",
                    unsafe_allow_html=True
                )

                btn_login = st.form_submit_button(
                    "🚀 Entrar no Sistema",
                    use_container_width=True,
                    type="primary"
                )

            if btn_login:

                if not email or not senha:

                    st.error(
                        "❌ Por favor, preencha o e-mail e a senha."
                    )

                else:

                    conexao = obter_conexao()
                    cursor = conexao.cursor()

                    cursor.execute(
                        """
                        SELECT id, senha_hash, primeiro_acesso
                        FROM Usuarios
                        WHERE email = %s
                        """,
                        (email,)
                    )

                    usuario = cursor.fetchone()

                    cursor.close()
                    conexao.close()

                    if usuario:

                        u_id, hash_banco, prim_acesso = usuario

                        if _hash_senha(senha) == hash_banco:

                            st.session_state.usuario_id = u_id
                            st.session_state.email_logado = email
                            st.session_state.primeiro_acesso = prim_acesso

                            st.toast(
                                "🔓 Login efetuado com sucesso!",
                                icon="✅"
                            )

                            st.rerun()

                        else:

                            st.error(
                                "❌ Senha incorreta. Tente novamente."
                            )

                    else:

                        st.error(
                            "❌ E-mail não encontrado no sistema."
                        )

        # ---------------------------------------------------------------------
        # ABA 2 - NOVO CADASTRO
        # ---------------------------------------------------------------------

        with aba2:

            with st.form(key="form_cad_v33"):

                st.markdown("### 📝 Criar nova conta")

                novo_email = st.text_input(
                    "E-mail para cadastro",
                    key="cad_email_v33"
                ).strip().lower()

                st.markdown(
                    "<br />",
                    unsafe_allow_html=True
                )

                btn_cad = st.form_submit_button(
                    "✨ Criar Minha Conta",
                    use_container_width=True,
                    type="primary"
                )

            if btn_cad:

                if not novo_email or "@" not in novo_email:

                    st.error(
                        "❌ Por favor, digite um e-mail válido."
                    )

                else:

                    senha_prov = gerar_senha_provisoria(8)
                    senha_hash = _hash_senha(senha_prov)

                    conexao = obter_conexao()
                    cursor = conexao.cursor()

                    try:

                        cursor.execute(
                            """
                            INSERT INTO Usuarios
                            (email, senha_hash, primeiro_acesso)
                            VALUES (%s, %s, 1)
                            """,
                            (novo_email, senha_hash)
                        )

                        conexao.commit()

                        email_enviado = enviar_senha_provisoria_email(
                            novo_email,
                            senha_prov
                        )

                        st.toast(
                            "Conta criada com sucesso!",
                            icon="✅"
                        )

                        if email_enviado:

                            st.success(
                                f"✅ Conta criada! A senha provisória "
                                f"foi enviada para **{novo_email}**."
                            )

                        else:

                            st.warning(
                                "⚠️ Conta criada! Utilize a senha "
                                "provisória abaixo para seu primeiro acesso:"
                            )

                            st.code(senha_prov)

                    except (IntegrityError, Exception):

                        st.error(
                            "❌ Este e-mail já está cadastrado "
                            "no banco de dados."
                        )

                    finally:

                        cursor.close()
                        conexao.close()

        # ---------------------------------------------------------------------
        # ABA 3 - REDEFINIÇÃO DE SENHA
        # ---------------------------------------------------------------------

        with aba3:

            with st.form(key="form_rec_v33"):

                st.markdown("### 🛡️ Redefinir Senha")

                rec_email = st.text_input(
                    "E-mail cadastrado",
                    key="rec_email_v33"
                ).strip().lower()

                st.markdown(
                    "<br />",
                    unsafe_allow_html=True
                )

                btn_rec = st.form_submit_button(
                    "🔑 Gerar Nova Senha Provisória",
                    type="primary",
                    use_container_width=True
                )

            if btn_rec:

                if not rec_email or "@" not in rec_email:

                    st.error(
                        "❌ Por favor, preencha um e-mail válido."
                    )

                else:

                    conexao = obter_conexao()
                    cursor = conexao.cursor()

                    cursor.execute(
                        """
                        SELECT id
                        FROM Usuarios
                        WHERE email = %s
                        """,
                        (rec_email,)
                    )

                    usr = cursor.fetchone()

                    if usr:

                        nova_prov = gerar_senha_provisoria(8)
                        novo_hash = _hash_senha(nova_prov)

                        cursor.execute(
                            """
                            UPDATE Usuarios
                            SET senha_hash = %s,
                                primeiro_acesso = 1
                            WHERE email = %s
                            """,
                            (novo_hash, rec_email)
                        )

                        conexao.commit()

                        cursor.close()
                        conexao.close()

                        email_enviado = enviar_senha_provisoria_email(
                            rec_email,
                            nova_prov
                        )

                        if email_enviado:

                            st.success(
                                "✅ Uma nova senha provisória foi "
                                "enviada para o seu e-mail."
                            )

                        else:

                            st.warning(
                                "⚠️ Nova senha provisória gerada "
                                "com sucesso:"
                            )

                            st.code(nova_prov)

                    else:

                        cursor.close()
                        conexao.close()

                        st.error(
                            "❌ E-mail não encontrado no sistema."
                        )


# =============================================================================
# BLOQUEIO DE PRIMEIRO ACESSO
# TROCA DE SENHA - LGPD REQ-EXT-01
# =============================================================================

elif st.session_state.primeiro_acesso == 1:

    col_l, col_c, col_r = st.columns([1, 2, 1])

    with col_c:

        st.markdown(
            "<br /><br />",
            unsafe_allow_html=True
        )

        st.warning(
            "⚠️ **Primeiro Acesso Detectado "
            "(Conformidade LGPD)**"
        )

        st.info(
            "Por motivos de segurança, você deve redefinir sua "
            "senha provisória preenchendo os requisitos:"
        )

        st.markdown("""
            - Mínimo de **6 caracteres**
            - Pelo menos **1 letra maiúscula** (A-Z)
              e **1 letra minúscula** (a-z)
            - Pelo menos **1 número** (0-9)
              e **1 caractere especial** (`!@#$%^&*`)
        """)

        with st.form(key="form_primeiro_acesso_lgpd_v33"):

            nova_senha = st.text_input(
                "Digite sua NOVA senha",
                type="password"
            )

            confirma_senha = st.text_input(
                "Confirme sua NOVA senha",
                type="password"
            )

            st.markdown(
                "<br />",
                unsafe_allow_html=True
            )

            btn_pa = st.form_submit_button(
                "Salvar Nova Senha Definitiva",
                use_container_width=True,
                type="primary"
            )

        if btn_pa:

            valida, msg_erro = validar_complexidade_senha(
                nova_senha
            )

            if not valida:

                st.error(f"❌ {msg_erro}")

            elif nova_senha != confirma_senha:

                st.error(
                    "❌ As senhas digitadas não coincidem."
                )

            else:

                novo_hash = _hash_senha(nova_senha)

                conexao = obter_conexao()
                cursor = conexao.cursor()

                cursor.execute(
                    """
                    UPDATE Usuarios
                    SET senha_hash = %s,
                        primeiro_acesso = 0
                    WHERE id = %s
                    """,
                    (
                        novo_hash,
                        st.session_state.usuario_id
                    )
                )

                conexao.commit()

                cursor.close()
                conexao.close()

                st.session_state.primeiro_acesso = 0

                st.toast(
                    "🔑 Senha redefinida com sucesso!",
                    icon="✅"
                )

                st.success(
                    "✅ Senha atualizada! Carregando o painel..."
                )

                st.rerun()
# =============================================================================
# PAINEL DE NAVEGAÇÃO E SISTEMA COMPLETO
# =============================================================================

else:

    if "menu" not in st.session_state:
        st.session_state.menu = "Painel"

    if (
        "nav_radio_key" not in st.session_state
        or st.session_state.nav_radio_key != st.session_state.menu
    ):
        st.session_state.nav_radio_key = st.session_state.menu

    def navegar_para(destino):
        st.session_state.menu = destino
        st.session_state.nav_radio_key = destino

    with st.sidebar:

        st.markdown("""
            <div>
                <div>💰</div>
                <div>FAMT <span>CONTROL</span></div>
            </div>
        """, unsafe_allow_html=True)

        st.markdown("<hr />", unsafe_allow_html=True)

        opcoes_menu = [
            "Painel",
            "Lançar",
            "Extrato e Edição",
            "Metas",
            "Gráficos",
            "Notificações",
            "Alertas e Dicas",
            "Configurações"
        ]

        if st.session_state.menu not in opcoes_menu:
            st.session_state.menu = "Painel"

        idx_menu = opcoes_menu.index(st.session_state.menu)

        def ao_mudar_radio():
            st.session_state.menu = st.session_state.nav_radio_key

        menu = st.radio(
            "Navegação",
            opcoes_menu,
            index=idx_menu,
            key="nav_radio_key",
            on_change=ao_mudar_radio,
            label_visibility="collapsed"
        )

        st.markdown("<br /><br />", unsafe_allow_html=True)

        st.markdown(
            f"""
            <div>
                👤 Conectado como:<br />
                <b>{st.session_state.email_logado}</b>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown("<br />", unsafe_allow_html=True)

        if st.button("🚪 Sair da Conta", use_container_width=True):
            st.session_state.usuario_id = None
            st.session_state.email_logado = None
            st.session_state.primeiro_acesso = 0
            st.rerun()

    # =========================================================================
    # CONFIGURAÇÃO DE PERÍODO E CALENDÁRIO
    # =========================================================================

    agora = datetime.now()

    primeiro_dia_mes_atual = agora.replace(day=1)

    ultimo_dia_num_atual = calendar.monthrange(
        agora.year,
        agora.month
    )[1]

    ultimo_dia_mes_atual = agora.replace(
        day=ultimo_dia_num_atual
    )

    if "data_inicio_sel" not in st.session_state:
        st.session_state.data_inicio_sel = primeiro_dia_mes_atual.date()

    if "data_fim_sel" not in st.session_state:
        st.session_state.data_fim_sel = ultimo_dia_mes_atual.date()

    d_inicio = st.session_state.data_inicio_sel
    d_fim = st.session_state.data_fim_sel

    def moeda(valor):
        return (
            f"R$ {valor:,.2f}"
            .replace(",", "X")
            .replace(".", ",")
            .replace("X", ".")
        )

    # =========================================================================
    # CONSULTA DOS LANÇAMENTOS COM SANITIZAÇÃO DE DADOS
    # =========================================================================

    conexao = obter_conexao()
    cursor = conexao.cursor()

    cursor.execute("""
        SELECT
            id,
            UPPER(tipo),
            valor,
            categoria,
            descricao,
            data
        FROM Transacoes
        WHERE usuario_id = %s
        ORDER BY data DESC;
    """, (st.session_state.usuario_id,))

    historico = cursor.fetchall()

    cursor.close()
    conexao.close()

    if historico:

        df_bruto = pd.DataFrame(
            historico,
            columns=[
                "ID",
                "Tipo",
                "Valor",
                "Categoria",
                "Descrição",
                "Data"
            ]
        )

        df_bruto["Valor"] = pd.to_numeric(
            df_bruto["Valor"],
            errors="coerce"
        ).fillna(0.0)

        df_bruto["Data_dt"] = pd.to_datetime(
            df_bruto["Data"],
            errors="coerce"
        )

        dt_ini_pd = pd.to_datetime(d_inicio)

        dt_fim_pd = (
            pd.to_datetime(d_fim)
            + pd.Timedelta(days=1)
            - pd.Timedelta(seconds=1)
        )

        mask_periodo = (
            (df_bruto["Data_dt"] >= dt_ini_pd)
            & (df_bruto["Data_dt"] <= dt_fim_pd)
        )

        df_calculo = df_bruto[mask_periodo].copy()

        df_calculo["Data_str"] = (
            df_calculo["Data_dt"]
            .dt.strftime("%d/%m/%Y")
            .fillna(df_calculo["Data"].astype(str))
        )

        historico_filtrado = (
            df_calculo[
                [
                    "ID",
                    "Tipo",
                    "Valor",
                    "Categoria",
                    "Descrição",
                    "Data_str"
                ]
            ].values.tolist()
            if not df_calculo.empty
            else []
        )

        total_receitas = (
            float(
                df_calculo.loc[
                    df_calculo["Tipo"] == "RECEITA",
                    "Valor"
                ].sum()
            )
            if not df_calculo.empty
            else 0.0
        )

        total_despesas = (
            float(
                df_calculo.loc[
                    df_calculo["Tipo"] == "DESPESA",
                    "Valor"
                ].sum()
            )
            if not df_calculo.empty
            else 0.0
        )

    else:

        df_calculo = pd.DataFrame(
            columns=[
                "ID",
                "Tipo",
                "Valor",
                "Categoria",
                "Descrição",
                "Data"
            ]
        )

        historico_filtrado = []
        total_receitas = 0.0
        total_despesas = 0.0

    saldo_liquido = total_receitas - total_despesas

    if "meta_mes" not in st.session_state:
        st.session_state.meta_mes = 1000.00

    meta_mes = st.session_state.meta_mes

    progresso_meta = (
        min(100, int((saldo_liquido / meta_mes) * 100))
        if saldo_liquido > 0 and meta_mes > 0
        else 0
    )

    # =========================================================================
    # CABEÇALHO DA MARCA, NOTIFICAÇÕES E SELETOR DE DATA
    # =========================================================================

    col_brand, col_notif, col_date = st.columns([3.0, 1.0, 1.3])

    with col_brand:

        st.markdown("""
            <div>
                <div>
                    <h1>FAMT <span>Control</span></h1>
                    <p>Seu dinheiro sob controle • Squad FAMT</p>
                </div>
            </div>
        """, unsafe_allow_html=True)

    with col_notif:

        qtd_notif = 1 if saldo_liquido < 0 else 0

        rotulo_sininho = (
            "🚨 (1)"
            if saldo_liquido < 0
            else "🔔"
        )

        with st.popover(
            rotulo_sininho,
            use_container_width=True
        ):

            st.markdown("### 🔔 Central de Notificações")

            if saldo_liquido < 0:

                st.markdown(
                    f"""
                    <div>
                        🚨 <b>Saldo Devedor (REQ-BUS-01):</b><br />
                        Suas despesas superam receitas em
                        <b>{moeda(abs(saldo_liquido))}</b>.
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            elif total_receitas > 0:

                st.success(
                    f"🟢 **Saldo Positivo:** "
                    f"Saldo mantido em **{moeda(saldo_liquido)}**."
                )

            else:

                st.info(
                    "ℹ️ Cadastre lançamentos na aba "
                    "'Lançar' para visualizar notificações."
                )

    with col_date:

        rotulo_popover = (
            f"📅 {d_inicio.strftime('%d/%m/%Y')} - "
            f"{d_fim.strftime('%d/%m/%Y')}"
        )

        with st.popover(
            rotulo_popover,
            use_container_width=True
        ):

            st.markdown("### 📅 Selecionar Período")

            datas_selecionadas = st.date_input(
                "Intervalo de Análise:",
                value=(
                    st.session_state.data_inicio_sel,
                    st.session_state.data_fim_sel
                ),
                format="DD/MM/YYYY",
                key="input_calendario_header_v33"
            )

            if (
                isinstance(datas_selecionadas, (list, tuple))
                and len(datas_selecionadas) == 2
            ):

                d1, d2 = datas_selecionadas

                if (
                    d1 != st.session_state.data_inicio_sel
                    or d2 != st.session_state.data_fim_sel
                ):

                    st.session_state.data_inicio_sel = d1
                    st.session_state.data_fim_sel = d2

                    st.rerun()

    # =========================================================================
    # TELA: PAINEL PRINCIPAL
    # =========================================================================

    if menu == "Painel":

        # ---------------------------------------------------------------------
        # ALERTA CONTÁBIL
        # ---------------------------------------------------------------------

        if saldo_liquido < 0:

            st.markdown(
                f"""
                <div>
                    🚨 <b>Alerta Contábil Crítico (REQ-BUS-01):</b><br />
                    Seu saldo acumulado no período está
                    <b>NEGATIVO em {moeda(saldo_liquido)}</b>
                    (Despesas: {moeda(total_despesas)}
                    vs. Receitas: {moeda(total_receitas)}).
                    Recomenda-se conter gastos não essenciais imediatamente.
                </div>
                """,
                unsafe_allow_html=True
            )

        # ---------------------------------------------------------------------
        # CARDS FINANCEIROS
        # ---------------------------------------------------------------------

        c1, c2, c3 = st.columns(3, gap="small")

        with c1:

            st.markdown(
                f"""
                <div>
                    <div>↗️</div>
                    <div>Receitas</div>
                    <div>{moeda(total_receitas)}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with c2:

            st.markdown(
                f"""
                <div>
                    <div>↘️</div>
                    <div>Despesas</div>
                    <div>{moeda(total_despesas)}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with c3:

            st.markdown(
                f"""
                <div>
                    <div>🎯</div>
                    <div>Meta Financeira</div>
                    <div>{moeda(meta_mes)}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("<br />", unsafe_allow_html=True)

        # ---------------------------------------------------------------------
        # GRÁFICOS
        # ---------------------------------------------------------------------

        esquerda, direita = st.columns(
            [1.5, 1],
            gap="medium"
        )

        with esquerda:

            st.subheader("📊 Receitas x Despesas")

            if not df_calculo.empty:

                df_graf = df_calculo.copy()

                df_graf["Mês"] = (
                    df_graf["Data_dt"]
                    .dt.strftime("%m/%Y")
                )

                mensal = (
                    df_graf.pivot_table(
                        index="Mês",
                        columns="Tipo",
                        values="Valor",
                        aggfunc="sum",
                        fill_value=0
                    )
                    .reset_index()
                )

                for t_col in ["RECEITA", "DESPESA"]:

                    if t_col not in mensal.columns:
                        mensal[t_col] = 0.0

                fig = go.Figure()

                fig.add_trace(
                    go.Bar(
                        x=mensal["Mês"],
                        y=mensal["RECEITA"],
                        name="Receitas",
                        marker_color="#10B981"
                    )
                )

                fig.add_trace(
                    go.Bar(
                        x=mensal["Mês"],
                        y=mensal["DESPESA"],
                        name="Despesas",
                        marker_color="#EF4444"
                    )
                )

                fig.update_layout(
                    barmode="group",
                    height=300,
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#E4E1F5",
                    margin=dict(
                        l=10,
                        r=10,
                        t=20,
                        b=10
                    ),
                    legend=dict(
                        orientation="h",
                        y=1.15
                    ),
                    yaxis=dict(
                        gridcolor="#282946"
                    )
                )

                st.plotly_chart(
                    fig,
                    use_container_width=True,
                    config={"displayModeBar": False}
                )

            else:

                st.info(
                    "Nenhum lançamento no período para exibir o gráfico."
                )

        with direita:

            st.subheader("🍩 Despesas por Categoria")

            despesas = df_calculo[
                df_calculo["Tipo"] == "DESPESA"
            ].copy()

            if not despesas.empty:

                categorias = (
                    despesas.groupby(
                        "Categoria",
                        as_index=False
                    )["Valor"].sum()
                )

                fig_cat = px.pie(
                    categorias,
                    names="Categoria",
                    values="Valor",
                    hole=0.6,
                    color_discrete_sequence=[
                        "#EF4444",
                        "#7C3AED",
                        "#3B82F6",
                        "#F59E0B",
                        "#EC4899"
                    ]
                )

                fig_cat.update_layout(
                    height=300,
                    paper_bgcolor="rgba(0,0,0,0)",
                    font_color="#E4E1F5",
                    margin=dict(
                        l=5,
                        r=5,
                        t=10,
                        b=10
                    )
                )

                st.plotly_chart(
                    fig_cat,
                    use_container_width=True,
                    config={"displayModeBar": False}
                )

            else:

                st.info(
                    "Cadastre despesas para visualizar "
                    "o gráfico por categoria."
                )

        # ---------------------------------------------------------------------
        # PROGRESSO DA META
        # ---------------------------------------------------------------------

        st.markdown("<br />", unsafe_allow_html=True)

        st.subheader("🎯 Progresso da Meta")

        st.progress(progresso_meta / 100)

        if saldo_liquido < 0:

            st.markdown(
                f"""
                <div>
                    🚨 0% concluídos — Saldo atual em
                    <b>{moeda(saldo_liquido)}</b>
                    (Saldo devedor impede o alcance da meta de
                    {moeda(meta_mes)}).
                </div>
                """,
                unsafe_allow_html=True
            )

        else:

            st.caption(
                f"{progresso_meta}% concluídos — "
                f"Saldo acumulado de {moeda(saldo_liquido)} "
                f"em relação à meta de {moeda(meta_mes)}."
            )

        st.markdown("<br />", unsafe_allow_html=True)

        # ---------------------------------------------------------------------
        # BOTÕES DE ACESSO RÁPIDO
        # ---------------------------------------------------------------------

        ac1, ac2, ac3 = st.columns(3, gap="small")

        with ac1:

            st.button(
                "＋ Novo Lançamento",
                use_container_width=True,
                type="primary",
                on_click=navegar_para,
                args=("Lançar",)
            )

        with ac2:

            st.button(
                "🧾 Ver Extrato",
                use_container_width=True,
                type="primary",
                on_click=navegar_para,
                args=("Extrato e Edição",)
            )

        with ac3:

            st.button(
                "📊 Ver Gráficos",
                use_container_width=True,
                type="primary",
                on_click=navegar_para,
                args=("Gráficos",)
            )
            # =========================================================================
    # TELA: LANÇAR
    # =========================================================================

    elif menu == "Lançar":

        st.title("＋ Novo Lançamento")

        st.caption(
            "Cadastre receitas ou despesas com atualização automática do saldo."
        )

        with st.form(
            "form_lancamento_v33",
            clear_on_submit=True
        ):

            tipo = st.selectbox(
                "Tipo de Movimentação",
                ["Despesa", "Receita"]
            )

            valor = st.number_input(
                "Valor (R$)",
                min_value=0.01,
                value=50.00,
                step=10.00
            )

            descricao = st.text_input(
                "Descrição detalhada",
                placeholder="Ex: Mensalidade, Almoço, Estágio"
            )

            categoria = st.selectbox(
                "Categoria",
                [
                    "Alimentação",
                    "Moradia",
                    "Transporte",
                    "Educação",
                    "Saúde",
                    "Lazer",
                    "Salário",
                    "Freelance",
                    "Contas",
                    "Outros"
                ]
            )

            data_lancamento = st.date_input(
                "Data",
                value=date.today(),
                format="DD/MM/YYYY"
            )

            hora_lancamento = st.time_input(
                "Horário",
                value=datetime.now().time().replace(
                    second=0,
                    microsecond=0
                )
            )

            salvar = st.form_submit_button(
                "💾 Salvar Movimentação",
                type="primary",
                use_container_width=True
            )

        if salvar:

            if not descricao.strip():

                st.error(
                    "❌ Por favor, informe uma descrição para o lançamento."
                )

            else:

                conexao = obter_conexao()
                cursor = conexao.cursor()

                try:

                    data_hora = datetime.combine(
                        data_lancamento,
                        hora_lancamento
                    )

                    tipo_sanitizado = tipo.strip().upper()

                    cursor.execute("""
                        INSERT INTO Transacoes (
                            usuario_id,
                            valor,
                            tipo,
                            data,
                            descricao,
                            categoria
                        )
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        st.session_state.usuario_id,
                        valor,
                        tipo_sanitizado,
                        data_hora,
                        descricao.strip(),
                        categoria
                    ))

                    conexao.commit()

                    st.toast(
                        f"🎉 Lançamento de R$ {valor:.2f} salvo com sucesso!",
                        icon="💰"
                    )

                    st.session_state.menu = "Painel"

                    st.rerun()

                except Exception as e:

                    conexao.rollback()

                    st.error(
                        f"Não foi possível salvar o lançamento: {e}"
                    )

                finally:

                    cursor.close()
                    conexao.close()

    # =========================================================================
    # TELA: EXTRATO E EDIÇÃO (CRUD DIRETO NO BANCO SQL)
    # =========================================================================

    elif menu == "Extrato e Edição":

        st.title("🧾 Extrato e Edição de Lançamentos")

        st.caption(
            "Consulte, edite ou exclua suas movimentações "
            "salvas no banco MySQL."
        )

        if historico_filtrado:

            extrato = pd.DataFrame(
                historico_filtrado,
                columns=[
                    "ID",
                    "Tipo",
                    "Valor",
                    "Categoria",
                    "Descrição",
                    "Data"
                ]
            )

            st.dataframe(
                extrato.drop(columns=["ID"]),
                use_container_width=True,
                hide_index=True
            )

            st.markdown("---")

            ids = extrato["ID"].astype(int).tolist()

            selecionado = st.selectbox(
                "Selecione um lançamento para editar ou excluir",
                ids,
                format_func=lambda x: (
                    f"#{x} — "
                    f"{extrato.loc[
                        extrato['ID'].astype(int) == x,
                        'Descrição'
                    ].iloc[0]}"
                )
            )

            atual = extrato.loc[
                extrato["ID"].astype(int) == int(selecionado)
            ].iloc[0]

            with st.form("form_editar_lancamento_v33"):

                novo_tipo = st.selectbox(
                    "Tipo",
                    ["Despesa", "Receita"],
                    index=(
                        0
                        if atual["Tipo"] == "DESPESA"
                        else 1
                    )
                )

                novo_valor = st.number_input(
                    "Valor (R$)",
                    min_value=0.01,
                    value=float(atual["Valor"]),
                    step=5.0
                )

                nova_categoria = st.text_input(
                    "Categoria",
                    value=str(atual["Categoria"])
                )

                nova_descricao = st.text_input(
                    "Descrição",
                    value=str(atual["Descrição"])
                )

                col_b1, col_b2 = st.columns(2)

                with col_b1:

                    sub_save = st.form_submit_button(
                        "💾 Salvar Alterações",
                        type="primary",
                        use_container_width=True
                    )

                with col_b2:

                    sub_del = st.form_submit_button(
                        "🗑️ Excluir Lançamento",
                        use_container_width=True
                    )

            # -----------------------------------------------------------------
            # ATUALIZAR LANÇAMENTO
            # -----------------------------------------------------------------

            if sub_save:

                if not nova_descricao.strip():

                    st.error(
                        "Informe uma descrição para o lançamento."
                    )

                elif not nova_categoria.strip():

                    st.error(
                        "Informe uma categoria para o lançamento."
                    )

                else:

                    conexao = obter_conexao()
                    cursor = conexao.cursor()

                    try:

                        tipo_upper = novo_tipo.strip().upper()

                        cursor.execute("""
                            UPDATE Transacoes
                            SET
                                tipo = %s,
                                valor = %s,
                                categoria = %s,
                                descricao = %s
                            WHERE id = %s
                            AND usuario_id = %s
                        """, (
                            tipo_upper,
                            novo_valor,
                            nova_categoria.strip(),
                            nova_descricao.strip(),
                            int(selecionado),
                            st.session_state.usuario_id
                        ))

                        conexao.commit()

                        st.toast(
                            "✅ Lançamento atualizado!",
                            icon="💾"
                        )

                        st.rerun()

                    except Exception as e:

                        conexao.rollback()

                        st.error(
                            f"Erro ao atualizar lançamento: {e}"
                        )

                    finally:

                        cursor.close()
                        conexao.close()

            # -----------------------------------------------------------------
            # EXCLUIR LANÇAMENTO
            # -----------------------------------------------------------------

            if sub_del:

                conexao = obter_conexao()
                cursor = conexao.cursor()

                try:

                    cursor.execute("""
                        DELETE FROM Transacoes
                        WHERE id = %s
                        AND usuario_id = %s
                    """, (
                        int(selecionado),
                        st.session_state.usuario_id
                    ))

                    conexao.commit()

                    st.toast(
                        "🗑️ Lançamento excluído!",
                        icon="✅"
                    )

                    st.rerun()

                except Exception as e:

                    conexao.rollback()

                    st.error(
                        f"Erro ao excluir lançamento: {e}"
                    )

                finally:

                    cursor.close()
                    conexao.close()

        else:

            st.info(
                "Nenhum lançamento encontrado para o período selecionado."
            )

    # =========================================================================
    # TELA: METAS FINANCEIRAS
    # =========================================================================

    elif menu == "Metas":

        st.title("🎯 Metas Financeiras")

        nova_meta = st.number_input(
            "Definir novo valor para a Meta (R$)",
            min_value=1.0,
            value=float(st.session_state.meta_mes),
            step=50.0
        )

        if st.button(
            "💾 Atualizar Meta",
            type="primary"
        ):

            st.session_state.meta_mes = float(nova_meta)

            st.toast(
                "🎯 Meta atualizada com sucesso!",
                icon="✅"
            )

            st.rerun()

        st.metric(
            "Meta Atual do Mês",
            moeda(st.session_state.meta_mes)
        )

        st.progress(progresso_meta / 100)

        if saldo_liquido < 0:

            st.markdown(
                f"""
                <p>
                    🚨 Saldo devedor de {moeda(saldo_liquido)}.
                    Reorganize os gastos para cumprir a meta.
                </p>
                """,
                unsafe_allow_html=True
            )

    # =========================================================================
    # TELA: GRÁFICOS E RELATÓRIOS
    # =========================================================================

    elif menu == "Gráficos":

        st.title("📊 Análise e Gráficos Financeiros")

        if not df_calculo.empty:

            graf = df_calculo.copy()

            graf["Mês"] = (
                graf["Data_dt"].dt.strftime("%m/%Y")
            )

            mensal = (
                graf.groupby(
                    ["Mês", "Tipo"],
                    as_index=False
                )["Valor"].sum()
            )

            fig = px.bar(
                mensal,
                x="Mês",
                y="Valor",
                color="Tipo",
                barmode="group",
                color_discrete_map={
                    "RECEITA": "#10B981",
                    "DESPESA": "#EF4444",
                    "Receita": "#10B981",
                    "Despesa": "#EF4444"
                }
            )

            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#E4E1F5"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

            # EXPORTAÇÃO DOS LANÇAMENTOS EM CSV

            csv = (
                df_calculo
                .to_csv(index=False)
                .encode("utf-8-sig")
            )

            st.download_button(
                "📥 Baixar Movimentações em CSV",
                csv,
                file_name="famt_control_movimentacoes.csv",
                mime="text/csv",
                type="primary"
            )

        else:

            st.info(
                "Não existem lançamentos suficientes para gerar relatórios."
            )

    # =========================================================================
    # TELA: CENTRAL DE NOTIFICAÇÕES (ALERTAS REQ-BUS-01)
    # =========================================================================

    elif menu == "Notificações":

        st.title("🔔 Central de Notificações")

        if saldo_liquido < 0:

            st.markdown(
                f"""
                <div>
                    <h3>🚨 Saldo Devedor (REQ-BUS-01)</h3>

                    <p>
                        Seu saldo atual está
                        <b>NEGATIVO em {moeda(saldo_liquido)}</b>.

                        As despesas acumuladas
                        ({moeda(total_despesas)})
                        ultrapassaram os ganhos do período
                        ({moeda(total_receitas)}).
                    </p>
                </div>
                """,
                unsafe_allow_html=True
            )

        elif total_receitas > 0:

            st.success(
                f"🟢 **Saldo Estável:** Você mantém um saldo "
                f"positivo de **{moeda(saldo_liquido)}**."
            )

        else:

            st.info(
                "ℹ️ Cadastre movimentações para receber alertas automáticos."
            )

    # =========================================================================
    # TELA: ALERTAS E DICAS DE EDUCAÇÃO FINANCEIRA
    # =========================================================================

    elif menu == "Alertas e Dicas":

        st.title(
            "💡 Dicas de Educação Financeira (Squad FAMT)"
        )

        if saldo_liquido < 0:

            st.error(
                f"🚨 **Alerta de Saldo Negativo:** "
                f"Você está com déficit de "
                f"**{moeda(abs(saldo_liquido))}**. "
                f"Priorize o corte de custos supérfluos."
            )

        st.info(
            "💡 **Regra 50/30/20:** Reserve 50% dos seus ganhos "
            "para despesas essenciais, 30% para desejos pessoais "
            "e 20% para a sua reserva de emergência."
        )

    # =========================================================================
    # TELA: CONFIGURAÇÕES DA CONTA E BANCO
    # =========================================================================

    elif menu == "Configurações":

        st.title("⚙️ Configurações da Conta")

        st.write(
            f"**E-mail logado:** "
            f"{st.session_state.email_logado}"
        )

        st.write(
            "**Banco de dados ativo:** MySQL Server"
        )

        st.markdown(
            "<br />",
            unsafe_allow_html=True
        )

        if st.button(
            "🗑️ Resetar Histórico de Transações",
            type="secondary"
        ):

            conexao = obter_conexao()
            cursor = conexao.cursor()

            try:

                cursor.execute("""
                    DELETE FROM Transacoes
                    WHERE usuario_id = %s;
                """, (
                    st.session_state.usuario_id,
                ))

                conexao.commit()

                st.toast(
                    "💥 Histórico resetado com sucesso!",
                    icon="🗑️"
                )

                st.rerun()

            except Exception as e:

                conexao.rollback()

                st.error(
                    f"Erro ao resetar histórico: {e}"
                )

            finally:

                cursor.close()
                conexao.close()