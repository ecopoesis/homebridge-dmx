FROM node:20-alpine

WORKDIR /app
COPY relay.mjs .

# UDP DMX stream + TCP control session
EXPOSE 2430/udp 2431/tcp

USER node
CMD ["node", "relay.mjs"]
