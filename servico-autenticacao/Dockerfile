# Estágio 1: Build - Instala dependências e prepara a aplicação
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
# Gera o Prisma Client baseado no schema
RUN npx prisma generate

# Estágio 2: Produção - Copia apenas o necessário para rodar
FROM node:20-alpine
WORKDIR /app
# Copia as dependências já instaladas do estágio de build
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./
# Copia os arquivos do Prisma (schema e client gerado)
COPY --from=builder /app/prisma ./prisma
# Copia o resto do código da aplicação
COPY --from=builder /app .

# Expõe a porta que a aplicação vai usar dentro do contêiner
EXPOSE 3001

# O comando para iniciar a aplicação quando o contêiner ligar
CMD ["node", "index.js"]