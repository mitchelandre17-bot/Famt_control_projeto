-- =============================================================================     
-- ESQUEMA DO BANCO DE DADOS MYSQL - FAMT CONTROL
-- =============================================================================

-- Criação do banco de dados 
CREATE DATABASE IF NOT EXISTS famt_control
    CHARACTER SET utf8mb4 
    COLLATE utf8mb4_unicode_ci;

-- Seleção do banco de dados
USE famt_control;


-- =============================================================================
-- TABELA: USUARIOS
-- Controle de primeiro acesso:
-- 1 = Pendente de redefinição de senha
-- 0 = Acesso liberado
-- =============================================================================

CREATE TABLE IF NOT EXISTS Usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    senha_hash VARCHAR(255) NOT NULL,
    primeiro_acesso INT DEFAULT 1
        CHECK (primeiro_acesso IN (0, 1))
) ENGINE=InnoDB;


-- =============================================================================
-- TABELA: TRANSACOES
-- Armazena as transações financeiras vinculadas a cada usuário.
-- =============================================================================

CREATE TABLE IF NOT EXISTS Transacoes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    valor DOUBLE NOT NULL
        CHECK (valor > 0),
    tipo VARCHAR(50) NOT NULL
        CHECK (tipo IN ('Receita', 'Despesa')),
    data DATETIME NOT NULL,
    descricao VARCHAR(255) NOT NULL,
    categoria VARCHAR(100) NOT NULL,

    -- Relacionamento com a tabela de usuários
    FOREIGN KEY (usuario_id)
        REFERENCES Usuarios(id)
        ON DELETE CASCADE,

    -- Índices para otimização de consultas
    INDEX idx_transacoes_data (data),
    INDEX idx_transacoes_usuario_id (usuario_id)

) ENGINE=InnoDB;