const bcrypt = require('bcrypt');
const { EncryptJWT, jwtDecrypt } = require('jose');
const { createSecretKey } = require('crypto');
const { z } = require('zod');
const prisma = require('./lib/prisma.js');

async function authRoutes(fastify, options) {
    const schemaCadastro = z.object({
        email: z.string().email({ message: "Formato de email inválido." }),
        senha: z.string().min(8, { message: "A senha deve ter no mínimo 8 caracteres." })
    });

    fastify.post('/register', async (request, reply) => {
        try {
            const { email, senha } = schemaCadastro.parse(request.body);
            const senhaHash = await bcrypt.hash(senha, 10);
            await prisma.user.create({ data: { email: email, senha_hash: senhaHash } });
            reply.code(201).send({ mensagem: 'Usuário criado com sucesso!' });
        } catch (error) {
            if (error instanceof z.ZodError || error?.code === 'P2002') {
                const err = new Error('Dados inválidos ou email já em uso.');
                err.statusCode = 409;
                throw err;
            }
            throw error;
        }
    });

    fastify.post('/login', async (request, reply) => {
        try {
            const { email, senha } = request.body;
            if (!email || !senha) throw new Error('Credenciais inválidas.');
            const usuario = await prisma.user.findUnique({ where: { email } });
            if (!usuario) throw new Error('Credenciais inválidas.');
            const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
            if (!senhaValida) throw new Error('Credenciais inválidas.');
            const payload = { id: usuario.id, email: usuario.email };
            const secretKey = createSecretKey(Buffer.from(process.env.JWT_SECRET, 'utf-8'));
            const token = await new EncryptJWT(payload)
                .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
                .setIssuedAt().setExpirationTime('1h')
                .encrypt(secretKey);
            reply.code(200).send({ token });
        } catch (error) {
            error.statusCode = error.statusCode || 401;
            throw error;
        }
    });
    
    fastify.post('/validate', async (request, reply) => {
        try {
            const { token } = request.body;
            if (!token) throw new Error('Token não fornecido.');
            const secretKey = createSecretKey(Buffer.from(process.env.JWT_SECRET, 'utf-8'));
            const { payload } = await jwtDecrypt(token, secretKey);
            reply.code(200).send({ valido: true, usuario: payload });
        } catch (error) {
            reply.code(401).send({ valido: false, mensagem: 'Token inválido ou expirado.' });
        }
    });
}

module.exports = authRoutes;