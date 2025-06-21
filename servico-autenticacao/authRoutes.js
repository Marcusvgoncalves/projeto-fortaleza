// authRoutes.js - VERSÃO FINAL SEM EXPRESS

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const prisma = require('./lib/prisma.js');
const logger = require('./logger.js');

// Em Fastify, nosso arquivo de rotas exporta uma única função assíncrona
async function authRoutes(fastify, options) {

    const schemaCadastro = z.object({
      email: z.string().email({ message: "Formato de email inválido." }),
      senha: z.string().min(8, { message: "A senha deve ter no mínimo 8 caracteres." })
    });

    // Rota de Cadastro: POST /register
    fastify.post('/register', async (request, reply) => {
        try {
            const { email, senha } = schemaCadastro.parse(request.body);
            const senhaHash = await bcrypt.hash(senha, 10);

            await prisma.user.create({
                data: {
                    email: email,
                    senha_hash: senhaHash,
                },
            });

            reply.code(201).send({ mensagem: 'Usuário criado com sucesso!' });
        } catch (error) {
            if (error?.code === 'P2002') {
                const err = new Error('Este email já está em uso.');
                err.statusCode = 409;
                throw err;
            }
            throw error;
        }
    });

    // Rota de Login: POST /login
    fastify.post('/login', async (request, reply) => {
        try {
            const { email, senha } = request.body;
            if (!email || !senha) {
              const error = new Error('Email e senha são obrigatórios.');
              error.statusCode = 400; 
              throw error;
            }

            const usuario = await prisma.user.findUnique({
                where: { email: email },
            });
            if (!usuario) {
              const error = new Error('Credenciais inválidas.');
              error.statusCode = 401;
              throw error;
            }

            const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
            if (!senhaValida) {
              const error = new Error('Credenciais inválidas.');
              error.statusCode = 401;
              throw error;
            }

            const payload = { id: usuario.id, email: usuario.email };
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

            reply.code(200).send({ token: token });
        } catch (error) {
            throw error;
        }
    });
}

module.exports = authRoutes;