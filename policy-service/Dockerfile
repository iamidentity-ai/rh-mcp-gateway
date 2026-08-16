# No dependencies on purpose: node 20's built-in fetch and http are the whole
# runtime. A policy decision point should be boring and auditable.
FROM node:20-slim
WORKDIR /app
COPY package.json ./
COPY src ./src
EXPOSE 8090
USER 1001
CMD ["node", "src/server.js"]
