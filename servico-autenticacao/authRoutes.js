// authRoutes.js ATUALIZADO PARA JWE (CRIPTOGRAFADO)

const bcrypt = require('bcrypt');
const { z } = require('zod');
const { EncryptJWT, jwtDecrypt } = require('jose'); // Importamos do 'jose'
const { createSecretKey } = require('crypto'); // Módulo nativo do Node.js
const prisma = require('./lib/prisma.js');
const logger = require('./logger.js');

async function authRoutes(fastify, options) {
    const schemaCadastro = z.object({ /* ... seu schema zod ... */ });

    // A rota /register continua exatamente igual
    fastify.post('/register', async (request, reply) => { /* ... */ });

    // Rota de Login agora gera um JWE
    fastify.post('/login', async (request, reply) => {
        try {
            // ... (lógica para encontrar usuário e validar senha continua igual) ...
            const { email, senha } = request.body;
            const usuario = await prisma.user.findUnique({ where: { email } });
            const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
            if (!usuario || !senhaValida) { /* ... throw error ... */ }

            // --- GERAÇÃO DO TOKEN CRIPTOGRAFADO (JWE) ---
            const secretKey = createSecretKey(Buffer.from(process.env.JWT_SECRET, 'utf-8'));
            const payload = { id: usuario.id, email: usuario.email };

            const token = await new EncryptJWT(payload)
                .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' }) // Algoritmos de criptografia
                .setIssuedAt()
                .setExpirationTime('1h')
                .encrypt(secretKey);

            reply.code(200).send({ token: token }); // Envia o JWE
        } catch (error) {
            // ... (tratamento de erro continua igual) ...
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
                // Opcional: define os algoritmos esperados para mais segurança
                contentEncryptionAlgorithms: ['A256GCM'],
                keyManagementAlgorithms: ['dir'],
            });

            reply.code(200).send({ valido: true, usuario: payload });
        } catch (error) {
            reply.code(401).send({ valido: false, mensagem: 'Token inválido ou expirado.' });
        }
    });
}

module.exports = authRoutes;