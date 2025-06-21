const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
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
            await prisma.user.create({ data: { email, senha_hash: senhaHash } });
            reply.code(201).send({ mensagem: 'Usuário criado com sucesso!' });
        } catch (error) {
            if (error instanceof z.ZodError || error.code === 'P2002') {
                const err = new Error('Dados inválidos ou email já em uso.');
                err.statusCode = 409;
                throw err;
            }
            throw error;
        }
    });

    fastify.post('/login', async (request, reply) => {
        const { email, senha } = request.body;
        if (!email || !senha) {
            const err = new Error('Credenciais inválidas.');
            err.statusCode = 401;
            throw err;
        }
        const usuario = await prisma.user.findUnique({ where: { email } });
        if (!usuario) {
            const err = new Error('Credenciais inválidas.');
            err.statusCode = 401;
            throw err;
        }
        const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
        if (!senhaValida) {
            const err = new Error('Credenciais inválidas.');
            err.statusCode = 401;
            throw err;
        }
        const payload = { id: usuario.id, email: usuario.email };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
        reply.code(200).send({ token });
    });

    fastify.post('/validate', async (request, reply) => {
        try {
            const { token } = request.body;
            if (!token) throw new Error();
            const usuario = jwt.verify(token, process.env.JWT_SECRET);
            reply.code(200).send({ valido: true, usuario: usuario });
        } catch (error) {
            reply.code(401).send({ valido: false, mensagem: 'Token inválido ou expirado.' });
        }
    });
}
module.exports = authRoutes;