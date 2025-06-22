// Em servico-autenticacao/passport-setup.js - VERSÃO FINAL E CORRETA

const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const prisma = require('./lib/prisma.js'); // Garanta que o caminho './lib/prisma.js' está correto

// Esta é a linha que "ensina" o Passport.
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: 'http://localhost:3001/auth/google/callback',
            proxy: true
        },
        // Esta função de callback é executada DEPOIS que o Google nos confirmar o usuário
        async (accessToken, refreshToken, profile, done) => {
            try {
                // Pegamos o email principal que o Google nos forneceu
                const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;

                if (!email) {
                    // Se o perfil do Google não tiver um email, não podemos prosseguir
                    return done(new Error("Não foi possível obter o email do Google."), null);
                }

                // Procuramos se um usuário com este email já existe no nosso banco de dados
                let usuario = await prisma.user.findUnique({
                    where: { email: email },
                });

                // Se o usuário NÃO existe, nós o criamos
                if (!usuario) {
                    usuario = await prisma.user.create({
                        data: {
                            email: email,
                            // Guardamos um valor para indicar que é uma conta Google, sem senha local
                            senha_hash: 'google_auth' 
                        }
                    });
                }

                // Se o usuário existe ou foi criado agora, passamos ele para o Passport.
                // 'done' sinaliza que terminamos com sucesso e retorna o objeto do usuário.
                return done(null, usuario);

            } catch (error) {
                // Se ocorrer qualquer erro no banco de dados, etc.
                return done(error, null);
            }
        }
    )
);

// Estas duas funções são necessárias para o Passport gerenciar a sessão do usuário
// durante o processo de redirecionamento.
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await prisma.user.findUnique({ where: { id: id } });
        done(null, user);
    } catch(error) {
        done(error, null);
    }
});