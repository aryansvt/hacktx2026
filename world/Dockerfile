# the world for the local stack (../docker-compose.yml). NEXT_PUBLIC_ values are
# baked in at build time, so they come in as build args.
FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG NEXT_PUBLIC_MODE=replay
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ARG NEXT_PUBLIC_WS_URL=ws://localhost:8000/live
ENV NEXT_PUBLIC_MODE=$NEXT_PUBLIC_MODE \
    NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL \
    NEXT_PUBLIC_WS_URL=$NEXT_PUBLIC_WS_URL \
    NEXT_TELEMETRY_DISABLED=1
RUN npm run build
ENV NODE_ENV=production
USER node
EXPOSE 3000
CMD ["npx", "next", "start", "-p", "3000", "-H", "0.0.0.0"]
