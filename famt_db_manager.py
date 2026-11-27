   
import mysql.connector 
from mysql.connector import Error 

import hashlib
import re
import random
import string

from datetime import datetime


# =============================================================================
# 1. CLASSE DE SEGURANÇA (SECURITY MANAGER)
# =============================================================================

class SecurityManager:
    """
    Gerencia a criptografia SHA-256, complexidade de senhas
    e geração de senhas provisórias.
    """

    @staticmethod
    def hash_senha(senha: str) -> str:
        """Gera um hash SHA-256 irreversível para a senha."""

        return hashlib.sha256(
            senha.encode('utf-8')
        ).hexdigest()

    @staticmethod
    def validar_complexidade_senha(senha: str) -> tuple[bool, str]:
        """
        Valida os requisitos mínimos de segurança de senha:

        - Mínimo de 6 caracteres;
        - Pelo menos 1 letra maiúscula (A-Z);
        - Pelo menos 1 letra minúscula (a-z);
        - Pelo menos 1 número (0-9);
        - Pelo menos 1 caractere especial (!@#$%^&* etc.).
        """

        if len(senha) < 6:
            return False, "A senha deve conter no mínimo 6 caracteres."

        if not re.search(r"[A-Z]", senha):
            return False, "A senha deve conter pelo menos uma letra maiúscula."

        if not re.search(r"[a-z]", senha):
            return False, "A senha deve conter pelo menos uma letra minúscula."

        if not re.search(r"\d", senha):
            return False, "A senha deve conter pelo menos um número."

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", senha):
            return False, (
                "A senha deve conter pelo menos um caractere especial "
                "(!@#$%^&* etc)."
            )

        return True, "Senha válida."

    @staticmethod
    def gerar_senha_provisoria(tamanho: int = 8) -> str:
        """
        Gera uma senha provisória aleatória contendo letras maiúsculas,
        minúsculas, números e símbolos.
        """

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


# =============================================================================
# 2. CLASSE DE SERVIÇO DE E-MAIL (EMAIL SERVICE)
# =============================================================================

class EmailService:
    """
    Gerencia o envio e notificações de e-mail aos usuários.
    """

    @staticmethod
    def enviar_senha_provisoria(
        email_destino: str,
        senha_provisoria: str
    ):
        """
        Simula o disparo de e-mail com a senha provisória
        enviada ao usuário.
        """

        print("\n" + "=" * 60)
        print("📧 [SERVIÇO DE E-MAIL - FAMT CONTROL]")

        print(f"Para: {email_destino}")

        print(
            "Assunto: Sua Senha Provisória de Acesso - FAMT Control"
        )

        print("-" * 60)

        print(
            "Olá,\n\n"
            "Sua solicitação no FAMT Control foi processada com sucesso!\n"
        )

        print(
            f"🔑 Sua senha provisória de acesso é: {senha_provisoria}\n"
        )

        print(
            "Por motivos de segurança, você DEVE alterar essa senha no seu"
        )

        print(
            "próximo acesso por uma nova senha que atenda aos critérios de segurança."
        )

        print("=" * 60 + "\n")


# =============================================================================
# 3. CLASSE GERENCIADORA DO BANCO DE DADOS MYSQL
# (FAMT DATABASE MANAGER)
# =============================================================================

class FAMTDatabaseManager:
    """
    FAMT Control - Classe Gerenciadora do Banco de Dados MySQL.

    Encapsula a conexão, criação de esquema, cadastros, autenticação,
    redefinição de senhas e gerenciamento de transações.
    """

    def __init__(
        self,
        host="localhost",
        database="famt_control",
        user="root",
        password="root"
    ):

        self.config = {
            'host': host,
            'database': database,
            'user': user,
            'password': password,
            'charset': 'utf8mb4',
            'use_unicode': True
        }

        self._init_db()

    def _get_connection(self):
        """Retorna uma conexão ativa com o servidor MySQL."""

        try:
            return mysql.connector.connect(**self.config)

        except Error as e:
            print(f"❌ Erro de conexão com o banco MySQL: {e}")
            raise

    def _init_db(self):
        """
        Inicializa as tabelas Usuarios e Transacoes
        no MySQL, caso ainda não existam.
        """

        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # -----------------------------------------------------------------
            # TABELA: USUARIOS
            # -----------------------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Usuarios (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    senha_hash VARCHAR(255) NOT NULL,
                    primeiro_acesso INT DEFAULT 1
                        CHECK (primeiro_acesso IN (0, 1))
                ) ENGINE=InnoDB;
            """)

            # -----------------------------------------------------------------
            # TABELA: TRANSACOES
            # -----------------------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS Transacoes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    usuario_id INT NOT NULL,
                    valor DOUBLE NOT NULL CHECK (valor > 0),
                    tipo VARCHAR(50) NOT NULL
                        CHECK (tipo IN ('Receita', 'Despesa')),
                    data DATETIME NOT NULL,
                    descricao VARCHAR(255) NOT NULL,
                    categoria VARCHAR(100) NOT NULL,

                    FOREIGN KEY (usuario_id)
                        REFERENCES Usuarios(id)
                        ON DELETE CASCADE

                ) ENGINE=InnoDB;
            """)

            conn.commit()

            cursor.close()
            conn.close()

        except Error as e:
            print(f"❌ Erro ao inicializar esquema do banco: {e}")

    # =========================================================================
    # 4. CADASTRO DE USUÁRIOS
    # =========================================================================

    def cadastrar_usuario(self, email: str) -> str:
        """
        Cadastra um novo usuário, gera uma senha provisória,
        envia por e-mail e registra primeiro_acesso = 1.
        """

        email_clean = email.strip().lower()

        if not email_clean or "@" not in email_clean:
            raise ValueError(
                "Por favor, informe um endereço de e-mail válido."
            )

        senha_provisoria = SecurityManager.gerar_senha_provisoria(8)

        senha_hash = SecurityManager.hash_senha(senha_provisoria)

        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO Usuarios (
                    email,
                    senha_hash,
                    primeiro_acesso
                )
                VALUES (%s, %s, 1);
            """, (email_clean, senha_hash))

            conn.commit()

            EmailService.enviar_senha_provisoria(
                email_clean,
                senha_provisoria
            )

            return senha_provisoria

        except mysql.connector.IntegrityError:
            raise ValueError(
                f"O e-mail '{email_clean}' já está cadastrado no sistema."
            )

        finally:
            cursor.close()
            conn.close()

    # =========================================================================
    # 5. AUTENTICAÇÃO DE USUÁRIOS
    # =========================================================================

    def autenticar_usuario(
        self,
        email: str,
        senha_digitada: str
    ) -> dict:
        """
        Autentica o usuário comparando o hash digitado
        com o valor armazenado no MySQL.
        """

        senha_hash = SecurityManager.hash_senha(
            senha_digitada.strip()
        )

        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    id,
                    email,
                    primeiro_acesso
                FROM Usuarios
                WHERE email = %s
                  AND senha_hash = %s;
            """, (email.strip().lower(), senha_hash))

            usuario = cursor.fetchone()

            return usuario if usuario else None

        finally:
            cursor.close()
            conn.close()

    # =========================================================================
    # 6. REDEFINIÇÃO DE SENHA NO PRIMEIRO ACESSO
    # =========================================================================

    def redefinir_senha_primeiro_acesso(
        self,
        usuario_id: int,
        nova_senha: str,
        confirma_senha: str
    ):
        """
        Valida a complexidade da senha e atualiza o cadastro,
        alterando primeiro_acesso para 0.
        """

        if nova_senha != confirma_senha:
            raise ValueError(
                "As senhas digitadas não coincidem."
            )

        valida, mensagem = SecurityManager.validar_complexidade_senha(
            nova_senha
        )

        if not valida:
            raise ValueError(mensagem)

        novo_hash = SecurityManager.hash_senha(nova_senha)

        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE Usuarios
                SET
                    senha_hash = %s,
                    primeiro_acesso = 0
                WHERE id = %s;
            """, (novo_hash, usuario_id))

            conn.commit()

        finally:
            cursor.close()
            conn.close()

    # =========================================================================
    # 7. RECUPERAÇÃO DE SENHA
    # =========================================================================

    def recuperar_senha(self, email: str) -> str:
        """
        Gera uma nova senha provisória para o e-mail cadastrado
        e reativa primeiro_acesso = 1.
        """

        email_clean = email.strip().lower()

        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute(
                "SELECT id FROM Usuarios WHERE email = %s;",
                (email_clean,)
            )

            usuario = cursor.fetchone()

            if not usuario:
                raise ValueError(
                    "E-mail não encontrado no sistema."
                )

            nova_provisoria = SecurityManager.gerar_senha_provisoria(8)

            novo_hash = SecurityManager.hash_senha(nova_provisoria)

            cursor.execute("""
                UPDATE Usuarios
                SET
                    senha_hash = %s,
                    primeiro_acesso = 1
                WHERE id = %s;
            """, (novo_hash, usuario['id']))

            conn.commit()

            EmailService.enviar_senha_provisoria(
                email_clean,
                nova_provisoria
            )

            return nova_provisoria

        finally:
            cursor.close()
            conn.close()

    # =========================================================================
    # 8. REGISTRO DE TRANSAÇÕES FINANCEIRAS
    # =========================================================================

    def registrar_transacao(
        self,
        usuario_id: int,
        valor: float,
        tipo: str,
        descricao: str,
        categoria: str,
        data: str = None
    ) -> int:
        """
        Persiste uma transação financeira (Receita ou Despesa)
        no banco de dados MySQL.
        """

        if valor <= 0:
            raise ValueError(
                "O valor da transação deve ser estritamente maior que zero."
            )

        if not data:
            data = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO Transacoes (
                    usuario_id,
                    valor,
                    tipo,
                    data,
                    descricao,
                    categoria
                )
                VALUES (%s, %s, %s, %s, %s, %s);
            """, (
                usuario_id,
                float(valor),
                tipo,
                data,
                descricao.strip(),
                categoria.strip()
            ))

            conn.commit()

            return cursor.lastrowid

        finally:
            cursor.close()
            conn.close()

    # =========================================================================
    # 9. CÁLCULO DO SALDO CONSOLIDADO
    # =========================================================================

    def calcular_saldo_consolidado(self, usuario_id: int) -> dict:
        """
        Calcula o total de receitas, despesas e o saldo líquido
        consolidado no MySQL.
        """

        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    SUM(
                        CASE
                            WHEN tipo = 'Receita' THEN valor
                            ELSE 0
                        END
                    ) AS total_receitas,

                    SUM(
                        CASE
                            WHEN tipo = 'Despesa' THEN valor
                            ELSE 0
                        END
                    ) AS total_despesas

                FROM Transacoes
                WHERE usuario_id = %s;
            """, (usuario_id,))

            res = cursor.fetchone()

            rec = float(res['total_receitas'] or 0.0)
            desp = float(res['total_despesas'] or 0.0)

            saldo = rec - desp

            status = (
                "🟢 CONTA SAUDÁVEL"
                if saldo >= 0
                else "🔴 ATENÇÃO: SALDO DEVEDOR!"
            )

            return {
                "total_receitas": rec,
                "total_despesas": desp,
                "saldo_liquido": saldo,
                "status": status
            }

        finally:
            cursor.close()
            conn.close()


# =============================================================================
# 10. FUNÇÕES AUXILIARES
# Exportação de funções diretas para compatibilidade com scripts legados.
# =============================================================================

def validar_complexidade_senha(senha: str) -> tuple[bool, str]:
    """Valida a complexidade da senha."""

    return SecurityManager.validar_complexidade_senha(senha)


def gerar_senha_provisoria(tamanho: int = 8) -> str:
    """Gera uma senha provisória."""

    return SecurityManager.gerar_senha_provisoria(tamanho)


def simular_envio_email_senha(
    email_destino: str,
    senha_provisoria: str
):
    """Simula o envio de e-mail com senha provisória."""

    EmailService.enviar_senha_provisoria(
        email_destino,
        senha_provisoria
    )

