 
from famt_db_manager import FAMTDatabaseManager  


# =============================================================================
# CLASSE PRINCIPAL - INTERFACE DE LINHA DE COMANDO (CLI)
# =============================================================================

class FAMTAppCLI:
    """Interface de linha de comando para terminal."""

    def __init__(self, db_manager: FAMTDatabaseManager): 
        self.db = db_manager

    # =========================================================================
    # CADASTRO DE NOVO USUÁRIO
    # =========================================================================

    def cadastrar_usuario_flow(self):
        """Realiza o cadastro de um novo usuário."""

        print("\n" + "-" * 45)
        print(" CADASTRO DE NOVO USUÁRIO ")
        print("-" * 45)

        email = input(
            "Digite o e-mail do novo usuário: "
        ).strip().lower()

        try:

            senha_prov = self.db.cadastrar_usuario(email)

            print(
                f"\n✅ Usuário '{email}' cadastrado com sucesso!"
            )

            print(
                f"📧 A senha provisória foi gerada e enviada por e-mail: "
                f"{senha_prov}"
            )

        except ValueError as e:

            print(f"\n❌ Erro: {e}")

    # =========================================================================
    # LOGIN DO USUÁRIO
    # =========================================================================

    def realizar_login_flow(self) -> int:
        """Realiza a autenticação e verifica o primeiro acesso."""

        print("\n" + "-" * 45)
        print(" LOGIN DO SISTEMA ")
        print("-" * 45)

        email = input(
            "Digite seu e-mail: "
        ).strip().lower()

        senha = input(
            "Digite sua senha (provisória ou cadastrada): "
        ).strip()

        usuario = self.db.autenticar_usuario(
            email,
            senha
        )

        if not usuario:

            print(
                "\n❌ Erro: E-mail ou senha incorretos."
            )

            return None

        usuario_id = usuario['id']
        primeiro_acesso = usuario['primeiro_acesso']

        # ---------------------------------------------------------------------
        # VERIFICAÇÃO DE PRIMEIRO ACESSO
        # ---------------------------------------------------------------------

        if primeiro_acesso == 1:

            print("\n⚠️ [PRIMEIRO ACESSO DETECTADO]")

            print(
                "Por políticas de segurança, você DEVE alterar "
                "sua senha provisória agora."
            )

            print("A nova senha deve possuir:")

            print(" • Mínimo de 6 caracteres")
            print(" • Pelo menos 1 letra maiúscula (A-Z)")
            print(" • Pelo menos 1 letra minúscula (a-z)")
            print(" • Pelo menos 1 número (0-9)")
            print(
                " • Pelo menos 1 caractere especial (!@#$%^&* etc.)\n"
            )

            while True:

                nova_senha = input(
                    "Digite sua NOVA senha segura: "
                ).strip()

                confirma_senha = input(
                    "Confirme sua NOVA senha: "
                ).strip()

                try:

                    self.db.redefinir_senha_primeiro_acesso(
                        usuario_id,
                        nova_senha,
                        confirma_senha
                    )

                    print(
                        "\n✅ Senha definitiva salva com sucesso!"
                    )

                    break

                except ValueError as e:

                    print(
                        f"❌ {e}\nTente novamente.\n"
                    )

        print(
            "\n🔓 Login efetuado com sucesso! "
            "Bem-vindo(a) ao FAMT Control."
        )

        return usuario_id

    # =========================================================================
    # PAINEL FINANCEIRO
    # =========================================================================

    def exibir_painel_flow(self, usuario_id: int):
        """Exibe o painel financeiro e suas opções."""

        while True:

            print("\n" + "=" * 45)
            print(" PAINEL FINANCEIRO FAMT CONTROL ")
            print("=" * 45)

            print("1. Consultar Saldo e Status")
            print("2. Registrar Receita/Despesa")
            print("3. Fazer Logout")

            op = input(
                "\nEscolha uma opção: "
            ).strip()

            # -----------------------------------------------------------------
            # OPÇÃO 1 - CONSULTAR SALDO
            # -----------------------------------------------------------------

            if op == "1":

                res = self.db.calcular_saldo_consolidado(
                    usuario_id
                )

                print(
                    f"\n(+) Receitas: R$ {res['total_receitas']:.2f}"
                )

                print(
                    f"(-) Despesas: R$ {res['total_despesas']:.2f}"
                )

                print(
                    f"(=) Saldo Líquido: R$ {res['saldo_liquido']:.2f}"
                )

                print(
                    f"Status: {res['status']}"
                )

            # -----------------------------------------------------------------
            # OPÇÃO 2 - REGISTRAR TRANSAÇÃO
            # -----------------------------------------------------------------

            elif op == "2":

                tipo = (
                    "Receita"
                    if input(
                        "Tipo (1-Receita / 2-Despesa): "
                    ).strip() == "1"
                    else "Despesa"
                )

                valor = float(
                    input("Valor (R$): ")
                )

                desc = input("Descrição: ")
                cat = input("Categoria: ")

                self.db.registrar_transacao(
                    usuario_id,
                    valor,
                    tipo,
                    desc,
                    cat
                )

                print(
                    "✅ Transação registrada com sucesso!"
                )

            # -----------------------------------------------------------------
            # OPÇÃO 3 - LOGOUT
            # -----------------------------------------------------------------

            elif op == "3":

                break

    # =========================================================================
    # EXECUÇÃO DO FLUXO PRINCIPAL
    # =========================================================================

    def run(self):
        """Gerencia o menu principal da aplicação CLI."""

        while True:

            print("\n" + "=" * 45)
            print(" SQUAD FAMT CONTROL ")
            print("=" * 45)

            print("1. Fazer Login")
            print("2. Cadastrar Novo Usuário (Receber Senha por E-mail)")
            print("3. Fechar Programa")

            opcao = input(
                "\nEscolha uma opção: "
            ).strip()

            # -----------------------------------------------------------------
            # OPÇÃO 1 - LOGIN
            # -----------------------------------------------------------------

            if opcao == "1":

                user_id = self.realizar_login_flow()

                if user_id:
                    self.exibir_painel_flow(user_id)

            # -----------------------------------------------------------------
            # OPÇÃO 2 - CADASTRO
            # -----------------------------------------------------------------

            elif opcao == "2":

                self.cadastrar_usuario_flow()

            # -----------------------------------------------------------------
            # OPÇÃO 3 - ENCERRAR PROGRAMA
            # -----------------------------------------------------------------

            elif opcao == "3":

                print("Programa encerrado.")

                break


# =============================================================================
# BLOCO DE EXECUÇÃO DO SISTEMA
# =============================================================================

if __name__ == "__main__":

    db_manager = FAMTDatabaseManager(
        host="localhost",
        database="famt_control",
        user="root",
        password="root"
    )

    app = FAMTAppCLI(db_manager)

    app.run()
