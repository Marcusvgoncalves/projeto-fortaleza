require('dotenv').config();
const fastify = require('fastify')({
    logger: require('./logger.js')
});

// Registra plugins de segurança
fastify.register(require('@fastify/cors'));
fastify.register(require('@fastify/helmet'));

// A LINHA MAIS IMPORTANTE:
// Registra nosso plugin de rotas e diz que todas as rotas dentro dele
// devem começar com o prefixo '/auth'.
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