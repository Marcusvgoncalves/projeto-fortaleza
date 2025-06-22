// Em servico-autenticacao/passport-setup.js

const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const prisma = require('./lib/prisma.js');

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: 'http://localhost:3001/auth/google/callback', // URL completa
            proxy: true // A "dica" crucial para o Passport
        },
    // ... função de callback

        // Esta função é o "coração" da lógica. Ela roda DEPOIS que o Google autentica o usuário.
        async (accessToken, refreshToken, profile, done) => {
            try {
                // Pegamos o email principal do perfil que o Google nos enviou
                const email = profile.emails[0].value;

                // 1. Procuramos se um usuário com este email já existe no NOSSO banco de dados
                let usuario = await prisma.user.findUnique({
                    where: { email: email },
                });

                // 2. Se o usuário NÃO existe, nós o criamos
                if (!usuario) {
                    usuario = await prisma.user.create({
                        data: {
                            email: email,
                            // Não temos senha, então guardamos um valor para indicar que é uma conta Google
                            senha_hash: 'google_auth' 
                        }
                    });
                }

                // 3. Se o usuário existe ou foi criado agora, passamos ele para o Passport.
                // O 'done' é como o 'next' do middleware, sinalizando que terminamos com sucesso.
                done(null, usuario);

            } catch (error) {
                // Se ocorrer qualquer erro, passamos o erro para o Passport
                done(error, null);
            }
        }
    )
);

// Estas duas funções são necessárias para o Passport gerenciar a sessão do usuário
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