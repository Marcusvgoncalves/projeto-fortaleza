// authRoutes.js - VERSÃO COM SINTAXE DO FASTIFY CORRIGIDA

const bcrypt = require('bcrypt');
const { EncryptJWT, jwtDecrypt } = require('jose');
const { createSecretKey } = require('crypto');
const { z } = require('zod');
const passport = require('passport');
const prisma = require('./lib/prisma.js');

async function authRoutes(fastify, options) {

    const schemaCadastro = z.object({
        email: z.string().email({ message: "Formato de email inválido." }),
        senha: z.string().min(8, { message: "A senha deve ter no mínimo 8 caracteres." })
    });

    // Rotas /register e /login (sem alterações)
    fastify.post('/register', async (request, reply) => { /* ... */ });
    fastify.post('/login', async (request, reply) => { /* ... */ });
    fastify.post('/validate', async (request, reply) => { /* ... */ });

    // Rota: GET /google (Início do fluxo OAuth)
    fastify.get(
        '/google',
        // AQUI ESTÁ A CORREÇÃO: passport.authenticate está dentro de um array
        { preValidation: [passport.authenticate('google', { scope: ['profile', 'email'] })] },
        async (request, reply) => {
            // Este handler pode ficar vazio, pois o middleware do passport fará o redirecionamento
        }
    );

    // Rota: GET /google/callback (Retorno do Google)
    fastify.get(
        '/google/callback',
        // AQUI ESTÁ A CORREÇÃO: passport.authenticate está dentro de um array
        { preValidation: [passport.authenticate('google', { 
            failureRedirect: '/login-failed', // Redireciona se o usuário negar
            session: false 
        })] },
        async (request, reply) => {
            // Se chegou aqui, o Google autenticou e nosso 'passport-setup' rodou.
            // O usuário está em request.user. Agora, geramos nosso JWE para ele.
            const usuario = request.user;
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
        }
    );
}

module.exports = authRoutes;