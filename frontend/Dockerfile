FROM node:18-alpine

WORKDIR /app

# Copy package.json
COPY frontend/package.json ./

# Install dependencies
# Note: In a real repo we'd copy package-lock.json too
RUN npm install

# Copy source
COPY frontend/ .

# Build Next.js app
RUN npm run build

# Expose Port
EXPOSE 3000

# Start App
CMD ["npm", "run", "start"]
