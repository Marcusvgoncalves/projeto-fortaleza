// authRoutes.js ATUALIZADO PARA JWE (CRIPTOGRAFADO)

const bcrypt = require('bcrypt');
const { z } = require('zod');
const { EncryptJWT, jwtDecrypt } = require('jose'); // Importamos do 'jose'
const { createSecretKey } = require('crypto');      // Módulo nativo do Node.js
const prisma = require('./lib/prisma.js');

async function authRoutes(fastify, options) {

    const schemaCadastro = z.object({
        email: z.string().email({ message: "Formato de email inválido." }),
        senha: z.string().min(8, { message: "A senha deve ter no mínimo 8 caracteres." })
    });

    // A rota /register não muda.
    fastify.post('/register', async (request, reply) => {
        try {
            const { email, senha } = schemaCadastro.parse(request.body);
            const senhaHash = await bcrypt.hash(senha, 10);
            await prisma.user.create({ data: { email, senha_hash: senhaHash } });
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

    // Rota de Login agora gera um JWE
    fastify.post('/login', async (request, reply) => {
        try {
            const { email, senha } = request.body;
            if (!email || !senha) throw new Error('Credenciais inválidas.');

            const usuario = await prisma.user.findUnique({ where: { email } });
            if (!usuario) throw new Error('Credenciais inválidas.');

            const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
            if (!senhaValida) throw new Error('Credenciais inválidas.');

            // --- GERAÇÃO DO TOKEN CRIPTOGRAFADO (JWE) ---
            const secretKey = createSecretKey(Buffer.from(process.env.JWT_SECRET, 'utf-8'));
            const payload = { id: usuario.id, email: usuario.email };

            const token = await new EncryptJWT(payload)
                .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' }) // Algoritmos de criptografia
                .setIssuedAt()
                .setExpirationTime('1h')
                .setIssuer('urn:exemplo:issuer') // Boas práticas
                .setAudience('urn:exemplo:audience') // Boas práticas
                .encrypt(secretKey);

            reply.code(200).send({ token: token });
        } catch (error) {
            error.statusCode = error.statusCode || 401;
            throw error;
        }
    });

    // Rota de Validação agora decifra um JWE
    fastify.post('/validate', async (request, reply) => {
        try {
            const { token } = request.body;
            if (!token) throw new Error('Token não fornecido.');

            // --- DECIFRANDO O TOKEN (JWE) ---
            const secretKey = createSecretKey(Buffer.from(process.env.JWT_SECRET, 'utf-8'));
            const { payload } = await jwtDecrypt(token, secretKey, {
                issuer: 'urn:exemplo:issuer',
                audience: 'urn:exemplo:audience',
            });

            reply.code(200).send({ valido: true, usuario: payload });
        } catch (error) {
            reply.code(401).send({ valido: false, mensagem: 'Token inválido ou expirado.' });
        }
    });
}

module.exports = authRoutes;