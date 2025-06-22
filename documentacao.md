# Projeto Fortaleza: Arquitetura de Microsserviços Segura

## 1. Visão Geral do Projeto

O "Projeto Fortaleza" é uma aplicação Full-Stack desenvolvida como parte de um plano de estudos avançado. O objetivo é construir um sistema robusto e seguro, evoluindo de uma aplicação monolítica para uma arquitetura de microsserviços.

O sistema consiste em uma "agenda de segredos" onde usuários podem se autenticar e gerenciar suas próprias notas de forma segura e isolada.

Atualmente, a arquitetura está em transição, com um serviço de autenticação independente e um serviço de segredos.

## 2. Arquitetura em Andamento

A arquitetura atual consiste em dois microsserviços principais rodando em contêineres Docker, com um banco de dados PostgreSQL centralizado.

* **servico-autenticacao (Porta 3001):** Um microsserviço dedicado, construído em Fastify, responsável por todas as operações de identidade:
    * Cadastro de usuários com email e senha.
    * Hashing de senhas com `bcrypt`.
    * Login com email/senha e emissão de tokens de sessão seguros (JWE).
    * (Em desenvolvimento) Autenticação federada com OAuth 2.0.
    * Validação de tokens para outros serviços.

* **servico-segredos (Porta 3000):** O serviço principal da aplicação, responsável pela lógica de negócio.
    * Gerenciamento completo de "segredos" (CRUD).
    * Delega toda a autenticação e autorização para o `servico-autenticacao` através de chamadas de API internas.

* **Banco de Dados (PostgreSQL em Docker):** Um único banco de dados que serve aos dois microsserviços, com tabelas gerenciadas pelo Prisma e por um sistema de `migrations`.

## 3. Tecnologias e Ferramentas

* **Backend:** Node.js, Fastify
* **Banco de Dados:** PostgreSQL (via Docker)
* **ORM & Migrations:** Prisma
* **Segurança:** JWE (com `jose`), `bcrypt`, `helmet`, `express-rate-limit` (no monolito)
* **Testes:** Jest, Supertest
* **Logging:** Winston
* **Validação:** Zod
* **Infraestrutura:** Docker, Docker Compose
* **Versionamento:** Git, GitHub

## 4. Próximos Passos Planejados

1.  **Finalizar a implementação do OAuth 2.0** usando uma nova estratégia de biblioteca.
2.  **Refatorar o `servico-segredos`** para consumir o `servico-autenticacao`.
3.  **Containerizar os microsserviços** com Dockerfiles e orquestrar com `docker-compose`.
4.  **Implementar um Perímetro de Segurança** com um Reverse Proxy (Nginx) e um WAF (ModSecurity).
5.  **Configurar uma VPN** (WireGuard/OpenVPN) para acesso administrativo seguro.