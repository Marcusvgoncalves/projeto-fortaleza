// Em servico-autenticacao/index.js - VERSÃO FINAL COM O TRADUTOR

 require('dotenv').config();
 const fastify = require('fastify')({ logger: true });
 const fastifyPassport = require('@fastify/passport');
 const fastifySecureSession = require('@fastify/secure-session');

 // Executa nosso arquivo de configuração da estratégia do Google
 require('./passport-setup.js');

 // ADICIONA A CAMADA DE COMPATIBILIDADE COM EXPRESS
 fastify.register(require('@fastify/express'));

 // Registra o plugin de sessão segura
 fastify.register(fastifySecureSession, {
     secret: 'AquiEstaUmSegredoDeExatos32Bytes', // 32 caracteres
     salt: 'EsteEhUmSalt16B!'               // 16 caracteres
 });

 // Registra e inicializa o Passport
 fastify.register(fastifyPassport.initialize());
 fastify.register(fastifyPassport.secureSession());

 // Registra os plugins de segurança
 fastify.register(require('@fastify/cors'));
 fastify.register(require('@fastify/helmet'));

 // Registra nosso plugin de rotas com o prefixo correto
 fastify.register(require('./authRoutes'), { prefix: '/auth' });

 // Rota de Health Check
 fastify.get('/', async (request, reply) => {
     return { status: 'ok', servico: 'autenticacao', timestamp: new Date().toISOString() };
 });

 // Rota para ignorar o favicon
 fastify.get('/favicon.ico', async (request, reply) => {
     return reply.code(204).send();
 });

 // Adiciona o Error Handler do Fastify
 fastify.setErrorHandler(function (error, request, reply) {
     fastify.log.error(error);
     reply.status(error.statusCode || 500).send({
         error: error.name || 'Internal Server Error',
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