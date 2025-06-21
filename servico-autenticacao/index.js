// Em servico-autenticacao/index.js
require('dotenv').config();
const fastify = require('fastify')({
    logger: true
});

fastify.register(require('@fastify/cors'));
fastify.register(require('@fastify/helmet'));
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