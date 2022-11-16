FROM amd64/node:18-alpine as dev
WORKDIR /app
COPY package.json ./ 
RUN npm install
COPY . .
RUN npm i -g prisma
RUN npx prisma generate
EXPOSE 3000
CMD npm run start:dev 
