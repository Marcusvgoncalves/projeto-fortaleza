// authRoutes.js - VERSÃO FINAL COM SINTAXE CORRIGIDA PARA O PASSPORT

const bcrypt = require('bcrypt');
const { EncryptJWT, jwtDecrypt } = require('jose');
const { createSecretKey } = require('crypto');
const { z } = require('zod');
//const passport = require('passport');
const prisma = require('./lib/prisma.js');

async function authRoutes(fastify, options) {

    const schemaCadastro = z.object({
        email: z.string().email({ message: "Formato de email inválido." }),
        senha: z.string().min(8, { message: "A senha deve ter no mínimo 8 caracteres." })
    });

    // Rotas de login e registro (sem alterações)
    fastify.post('/register', async (request, reply) => { /* ... */ });
    fastify.post('/login', async (request, reply) => { /* ... */ });
    fastify.post('/validate', async (request, reply) => { /* ... */ });

    // --- MUDANÇA NA DEFINIÇÃO DAS ROTAS DO GOOGLE ---

    // Rota: GET /google (Início do fluxo OAuth)
    // Passamos o middleware do passport diretamente como o handler da rota
    fastify.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

    // Rota: GET /google/callback (Retorno do Google)
    // Usamos um hook 'preValidation' para o passport, e depois nosso handler executa
    fastify.get(
        '/google/callback',
        { 
            preValidation: passport.authenticate('google', { 
                session: false // Importante: não usaremos sessões do passport, apenas o resultado
            }) 
        },
        async (request, reply) => {
            try {
                // Se chegou aqui, o Google autenticou e nosso 'passport-setup' rodou.
                // O usuário está em request.user. Agora, geramos nosso JWE para ele.
                const usuario = request.user;
                if (!usuario) {
                    // Caso de segurança: se o passport não anexar um usuário por algum motivo
                    throw new Error('Falha na autenticação do Google.');
                }

                const payload = { id: usuario.id, email: usuario.email };
                const secretKey = createSecretKey(Buffer.from(process.env.JWT_SECRET, 'utf-8'));
                const token = await new EncryptJWT(payload)
                    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
                    .setIssuedAt()
                    .setExpirationTime('1h')
                    .setIssuer('urn:exemplo:issuer')
                    .setAudience('urn:exemplo:audience')
                    .encrypt(secretKey);

                // Em uma aplicação real, redirecionaríamos para o frontend com o token.
                // Por agora, vamos apenas exibir o token.
                reply.code(200).send({ token: token });
            } catch (error) {
                fastify.log.error(error);
                reply.code(500).send({ message: 'Erro ao processar o login do Google.' });
            }
        }
    );
}

module.exports = authRoutes;