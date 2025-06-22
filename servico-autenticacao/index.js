// servico-autenticacao/index.js - VERSÃO FINAL COM A ORDEM CORRETA

require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const fastifyPassport = require('@fastify/passport');
const fastifySecureSession = require('@fastify/secure-session');
const { createSecretKey } = require('crypto');
const { EncryptJWT } = require('jose');

// 1. Registra os plugins de base que o Passport vai precisar
fastify.register(require('@fastify/express'));
fastify.register(fastifySecureSession, {
    secret: 'AquiEstaUmSegredoDeExatos32Bytes', // 32 caracteres
    salt: 'EsteEhUmSalt16B!',               // 16 caracteres
});

// 2. Inicializa o sistema do Passport no Fastify
fastify.register(fastifyPassport.initialize());
fastify.register(fastifyPassport.secureSession());

// 3. AGORA, com o Passport inicializado, ensinamos a ele a estratégia do Google.
// Esta linha executa o código dentro do passport-setup.js.
require('./passport-setup.js');

// 4. Registra os outros plugins de segurança
fastify.register(require('@fastify/cors'));
fastify.register(require('@fastify/helmet'));

// 5. Registra nossas rotas de autenticação por email/senha
fastify.register(require('./authRoutes'), { prefix: '/auth' });

// 6. Define as rotas do Google que usam a estratégia já registrada
fastify.get('/auth/google', fastifyPassport.authenticate('google', { scope: ['profile', 'email'] }));

fastify.get(
    '/auth/google/callback',
    { 
        preHandler: fastifyPassport.authenticate('google', { 
            session: false,
            failureRedirect: '/login-falhou' // Rota hipotética de falha
        }) 
    },
    async (request, reply) => {
        try {
            const usuario = request.user;
            if (!usuario) {
                throw new Error('Usuário não autenticado pelo Google.');
            }

            const payload = { id: usuario.id, email: usuario.email };
            const secretKey = createSecretKey(Buffer.from(process.env.JWT_SECRET, 'utf-8'));
            const token = await new EncryptJWT(payload)
                .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
                .setIssuedAt()
                .setExpirationTime('1h')
                .encrypt(secretKey);

            reply.code(200).send({ message: 'Login com Google bem-sucedido!', token: token });
        } catch (error) {
            fastify.log.error(error, "Erro ao gerar token JWE após callback do Google");
            reply.code(500).send({ message: "Erro ao processar o login com Google." });
        }
    }
);

// Função de Start para ligar o servidor
const start = async () => {
    try {
        await fastify.listen({ port: 3001 });
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
};
start();