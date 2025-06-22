// Em servico-autenticacao/index.js - VERSÃO FINALÍSSIMA
require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const fastifyPassport = require('@fastify/passport');
const fastifySecureSession = require('@fastify/secure-session');

require('./passport-setup.js');

fastify.register(require('@fastify/express'));
fastify.register(fastifySecureSession, {
    secret: 'EsteEhUmSegredoDeExatos32Bytes!',
    salt: 'EsteEhUmSalt16B!',
});

fastify.register(fastifyPassport.initialize());
fastify.register(fastifyPassport.secureSession());

fastify.register(require('@fastify/cors'));
fastify.register(require('@fastify/helmet'));

// Registra nossas rotas de /register e /login
fastify.register(require('./authRoutes'), { prefix: '/auth' });

// --- ROTAS DO GOOGLE DIRETAMENTE AQUI ---
fastify.get('/auth/google', fastifyPassport.authenticate('google', { scope: ['profile', 'email'] }));

fastify.get('/auth/google/callback', 
    { preHandler: fastifyPassport.authenticate('google', { session: false }) },
    async (request, reply) => {
        try {
            const usuario = request.user;
            if (!usuario) throw new Error('Usuário não encontrado após callback do Google.');
            
            const payload = { id: usuario.id, email: usuario.email };
            const secretKey = createSecretKey(Buffer.from(process.env.JWT_SECRET, 'utf-8'));
            const token = await new EncryptJWT(payload)
                .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
                .setIssuedAt().setExpirationTime('1h')
                .setIssuer('urn:exemplo:issuer').setAudience('urn:exemplo:audience')
                .encrypt(secretKey);

            // Em uma aplicação real, aqui você redirecionaria para o seu frontend,
            // passando o token na URL. Ex: `reply.redirect(`http://meufrontend.com/login-sucesso?token=${token}`)`
            // Por agora, apenas exibimos o token.
            reply.code(200).send({ token });
        } catch (error) {
            fastify.log.error(error, "Erro ao gerar token JWE após callback do Google");
            reply.code(500).send({ message: "Erro ao processar o login." });
        }
    }
);

// ... (seu Health Check e Error Handler continuam aqui) ...
 fastify.get('/', async (request, reply) => { /* ... */ });
 fastify.get('/favicon.ico', async (request, reply) => { /* ... */ });
 fastify.setErrorHandler(function (error, request, reply) { /* ... */ });


const start = async () => { /* ... */ };
start();