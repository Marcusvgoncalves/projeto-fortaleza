// Em servico-autenticacao/index.js - NOVA ESTRATÉGIA COM @fastify/oauth2

require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const { createSecretKey } = require('crypto');
const { EncryptJWT } = require('jose');
const prisma = require('./lib/prisma');

// Registra os plugins de segurança e CORS
fastify.register(require('@fastify/cors'));
fastify.register(require('@fastify/helmet'));

// --- CONFIGURAÇÃO DO @fastify/oauth2 ---
fastify.register(require('@fastify/oauth2'), {
    name: 'googleOAuth2', // Damos um nome para nossa configuração de OAuth
    scope: ['profile', 'email'], // Pedimos ao Google as permissões de perfil e email
    credentials: {
        client: {
            id: process.env.GOOGLE_CLIENT_ID,
            secret: process.env.GOOGLE_CLIENT_SECRET
        },
        auth: require('@fastify/oauth2').GOOGLE_CONFIGURATION
    },
    // A rota que o nosso frontend chamará para iniciar o login com Google
    startRedirectPath: '/auth/google',
    // A rota para onde o Google nos enviará de volta após o usuário autorizar
    callbackUri: 'http://localhost:3001/auth/google/callback'
});

// --- ROTA DE CALLBACK DO GOOGLE ---
fastify.get('/auth/google/callback', async function (request, reply) {
    try {
        // 1. O plugin troca o código de autorização por um token de acesso do Google
        const { token } = await this.googleOAuth2.getAccessTokenFromAuthorizationCodeFlow(request);

        // 2. Com o token do Google, pedimos as informações do usuário
        const googleUserResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: {
                Authorization: `Bearer ${token.access_token}`,
            }
        });
        const googleUser = await googleUserResponse.json();
        const email = googleUser.email;

        // 3. Procuramos ou criamos o usuário no NOSSO banco de dados
        let usuario = await prisma.user.findUnique({ where: { email } });
        if (!usuario) {
            usuario = await prisma.user.create({
                data: {
                    email: email,
                    senha_hash: 'google_auth'
                }
            });
        }

        // 4. Geramos o NOSSO próprio token JWE para o usuário
        const payload = { id: usuario.id, email: usuario.email };
        const secretKey = createSecretKey(Buffer.from(process.env.JWT_SECRET, 'utf-8'));
        const nossoToken = await new EncryptJWT(payload)
            .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
            .setIssuedAt()
            .setExpirationTime('1h')
            .encrypt(secretKey);

        // 5. Enviamos nosso token de volta
        // Em uma app real, redirecionaríamos para o frontend com este token
        reply.code(200).send({ token: nossoToken });

    } catch (error) {
        fastify.log.error(error, "Falha no callback do Google OAuth");
        reply.code(500).send({ message: 'Erro ao processar autenticação com Google.' });
    }
});

// Registra as rotas de login/cadastro normais
fastify.register(require('./authRoutes'), { prefix: '/auth' });

const start = async () => {
    try {
        await fastify.listen({ port: 3001 });
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
};
start();