// servico-autenticacao/index.js - TUDO EM UM SÓ LUGAR

require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { z } = require('zod');
const bcrypt = require('bcrypt');
const { EncryptJWT, jwtDecrypt } = require('jose');
const { createSecretKey } = require('crypto');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// --- CONFIGURAÇÃO DO PASSPORT (Estratégia Google) ---
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: 'http://localhost:3001/auth/google/callback',
            proxy: true
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const email = profile.emails?.[0]?.value;
                if (!email) {
                    return done(new Error("Não foi possível obter o email do Google."), null);
                }
                let usuario = await prisma.user.findUnique({ where: { email } });
                if (!usuario) {
                    usuario = await prisma.user.create({
                        data: { email: email, senha_hash: 'google_auth' }
                    });
                }
                return done(null, usuario);
            } catch (error) {
                return done(error, null);
            }
        }
    )
);
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await prisma.user.findUnique({ where: { id: parseInt(id) } });
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

// --- REGISTRO DE PLUGINS DO FASTIFY ---
fastify.register(require('@fastify/express'));
fastify.register(require('@fastify/secure-session'), {
    secret: 'EsteEhUmSegredoDeExatos32Bytes!',
    salt: 'EsteEhUmSalt16B!'
});
fastify.register(require('@fastify/passport').initialize());
fastify.register(require('@fastify/passport').session());
fastify.register(require('@fastify/cors'));
fastify.register(require('@fastify/helmet'));

// --- DEFINIÇÃO DAS ROTAS DE AUTENTICAÇÃO ---
fastify.register(async (fastify, options) => {
    const schemaCadastro = z.object({
        email: z.string().email(),
        senha: z.string().min(8)
    });

    fastify.post('/register', async (request, reply) => {
        try {
            const { email, senha } = schemaCadastro.parse(request.body);
            const senhaHash = await bcrypt.hash(senha, 10);
            await prisma.user.create({ data: { email, senha_hash: senhaHash } });
            reply.code(201).send({ mensagem: 'Usuário criado com sucesso!' });
        } catch (error) { throw error; }
    });

    fastify.post('/login', async (request, reply) => {
        try {
            const { email, senha } = request.body;
            if (!email || !senha) throw new Error('Credenciais inválidas.');
            const usuario = await prisma.user.findUnique({ where: { email } });
            if (!usuario) throw new Error('Credenciais inválidas.');
            const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
            if (!senhaValida) throw new Error('Credenciais inválidas.');
            const secretKey = createSecretKey(Buffer.from(process.env.JWT_SECRET, 'utf-8'));
            const token = await new EncryptJWT({ id: usuario.id, email: usuario.email })
                .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
                .setIssuedAt().setExpirationTime('1h').encrypt(secretKey);
            reply.send({ token });
        } catch (error) {
            error.statusCode = 401;
            throw error;
        }
    });

    fastify.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

    fastify.get('/google/callback', 
        { preHandler: passport.authenticate('google', { session: false, failureRedirect: '/login-falhou' }) },
        async (request, reply) => {
            const usuario = request.user;
            if (!usuario) throw new Error('Usuário não autenticado pelo Google.');
            const secretKey = createSecretKey(Buffer.from(process.env.JWT_SECRET, 'utf-8'));
            const token = await new EncryptJWT({ id: usuario.id, email: usuario.email })
                .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
                .setIssuedAt().setExpirationTime('1h').encrypt(secretKey);
            reply.send({ token });
        }
    );

}, { prefix: '/auth' });


// --- ERROR HANDLER E INICIALIZAÇÃO ---
fastify.setErrorHandler((error, request, reply) => {
    fastify.log.error(error);
    reply.status(error.statusCode || 500).send({
        error: error.name || 'Error',
        message: error.message
    });
});

const start = async () => {
    try {
        await fastify.listen({ port: 3001 });
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
};

start();