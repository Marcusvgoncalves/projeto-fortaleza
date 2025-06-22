// servico-autenticacao/index.js - NOVA ESTRATÉGIA

require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { EncryptJWT } = require('jose');
const { createSecretKey } = require('crypto');

// --- REGISTRO DO PLUGIN @fastify/oauth2 ---
fastify.register(require('@fastify/oauth2'), {
    name: 'googleOAuth2',
    scope: ['profile', 'email'],
    credentials: {
        client: {
            id: process.env.GOOGLE_CLIENT_ID,
            secret: process.env.GOOGLE_CLIENT_SECRET
        },
        auth: require('@fastify/oauth2').GOOGLE_CONFIGURATION
    },
    startRedirectPath: '/auth/google',
    callbackUri: 'http://localhost:3001/auth/google/callback'
});

// --- ROTA DE CALLBACK DO GOOGLE ---
fastify.get('/auth/google/callback', async function (request, reply) {
    try {
        // 1. O plugin troca o código por um token de acesso do Google
        const { token } = await this.googleOAuth2.getAccessTokenFromAuthorizationCodeFlow(request);

        // 2. Usamos o token para buscar o perfil do usuário no Google
        const googleUserResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: { 'Authorization': `Bearer ${token.access_token}` }
        });
        const googleUser = await googleUserResponse.json();
        const email = googleUser.email;

        if (!email) {
            throw new Error('Não foi possível obter o email do Google.');
        }

        // 3. Procuramos ou criamos o usuário no nosso banco
        let usuario = await prisma.user.findUnique({ where: { email } });
        if (!usuario) {
            usuario = await prisma.user.create({
                data: { email: email, senha_hash: 'google_auth' }
            });
        }

        // 4. Geramos o nosso próprio token JWE interno
        const payload = { id: usuario.id, email: usuario.email };
        const secretKey = createSecretKey(Buffer.from(process.env.JWT_SECRET, 'utf-8'));
        const nossoToken = await new EncryptJWT(payload)
            .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
            .setIssuedAt()
            .setExpirationTime('1h')
            .encrypt(secretKey);

        // Resposta final com nosso token
        reply.send({ mensagem: 'Login com Google bem-sucedido!', token: nossoToken });

    } catch (error) {
        fastify.log.error(error);
        reply.code(500).send({ mensagem: 'Falha na autenticação com Google.' });
    }
});

// --- INICIALIZAÇÃO DO SERVIDOR ---
const start = async () => {
    try {
        await fastify.listen({ port: 3001 });
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
};
start();