Documentação Final: Projeto Fortaleza
1. Visão Geral
O "Projeto Fortaleza" é uma arquitetura de microsserviços projetada para ser segura e escalável, utilizando Docker para orquestração. O sistema é composto por um serviço de autenticação, um serviço de gerenciamento de segredos, um Web Application Firewall (WAF) como ponto único de entrada, e um banco de dados compartilhado.

2. Desenho da Arquitetura Final

O fluxo de uma requisição do usuário até o banco de dados pode ser visualizado da seguinte forma:

[ Usuário / Navegador ]
         |
         | HTTP/HTTPS (Porta 8080)
         v
+--------------------------------+
|     Contêiner: WAF (Nginx)     |
|   (Módulo ModSecurity Ativado)   |
|                                |
|   /auth/* --+   /segredos/* --+
+--------------------------------+
               |                 |
 <------ Rede Docker Interna ------>
 |                 |
 v                 v
+------------------+  +------------------+
| Contêiner:       |  | Contêiner:       |
| auth-service     |  | secrets-service  |
| (Node.js/Fastify)|  | (Node.js/Fastify)|
+------------------+  +------------------+
         |                 |
         |<- Conexão ->|
         |   Prisma      |
         v                 v
+--------------------------------+
|    Contêiner: db (PostgreSQL)  |
|     (Volume: postgres-data)    |
+--------------------------------+
3. Componentes da Arquitetura

waf (Nginx + ModSecurity)

Propósito: Ponto único de entrada para todo o tráfego. Atua como Proxy Reverso e Web Application Firewall.
Tecnologia: Nginx, ModSecurity com o OWASP Core Rule Set.
Função: Inspeciona todas as requisições em busca de padrões de ataque (SQL Injection, XSS, etc.) e bloqueia as maliciosas. Redireciona o tráfego legítimo para o microsserviço apropriado com base na URL (/auth ou /segredos).
auth-service (Serviço de Autenticação)

Propósito: Gerenciar a identidade dos usuários, incluindo registro local e login federado com o Google (OAuth 2.0).
Tecnologia: Node.js, Fastify, Prisma, Zod (validação), Bcrypt (hashing), JOSE (criação de tokens JWE).
Endpoints Principais:
POST /auth/register: Cadastro de novos usuários.
POST /auth/login: Login de usuários com email e senha.
GET /auth/google: Inicia o fluxo de autenticação com o Google.
GET /auth/google/callback: Recebe a resposta do Google e finaliza o login.
secrets-service (Serviço de Segredos)

Propósito: API protegida para operações de CRUD (Criar, Ler, Atualizar, Deletar) em "segredos" de usuários.
Tecnologia: Node.js, Fastify, Prisma.
Segurança: Valida o token JWE em cada requisição para garantir que o usuário está autenticado e autorizado.
db (Banco de Dados)

Propósito: Armazenamento persistente para os dados dos usuários e segredos.
Tecnologia: PostgreSQL rodando em um contêiner Docker.
Persistência: Utiliza um volume Docker (postgres-data) para garantir que os dados não sejam perdidos ao reiniciar os contêineres.
4. Orquestração

Tecnologia: Docker Compose.
Função: O arquivo docker-compose.yml define, configura e conecta todos os serviços acima, criando uma rede interna para comunicação segura e gerenciando variáveis de ambiente (como chaves de API e strings de conexão com o banco).