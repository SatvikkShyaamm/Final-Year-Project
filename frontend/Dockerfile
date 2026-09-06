FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 5173

# Vite's dev server; --host is required so it's reachable from outside the
# container. Production build/serve is added when the project is ready to
# be deployed rather than just developed (Module 10 territory).
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
