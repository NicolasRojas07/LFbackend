# JWT API

This is a simple Flask API for encoding, decoding, and verifying JSON Web Tokens (JWTs). It uses MongoDB to store test cases.

## Prerequisites

- Docker
- Docker Compose

## Getting Started

1. **Clone the repository:**
   ```sh
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Create a `.env` file:**
   Copy the `.env.example` file to a new file named `.env` and modify the variables as needed.
   ```sh
   cp .env.example .env
   ```

3. **Build and run the application:**
   Use Docker Compose to build and run the application.
   ```sh
   docker-compose up --build
   ```
   The API will be available at `http://localhost:5000`.

## API Endpoints

- `POST /api/jwt/encode`: Creates a JWT.
- `POST /api/jwt/decode`: Decodes a JWT without verification.
- `POST /api/jwt/verify`: Verifies a JWT's signature.
- `POST /api/jwt/save-test`: Saves a test case to the database.
- `GET /api/jwt/tests`: Lists all test cases.
- `DELETE /api/jwt/tests/<test_id>`: Deletes a test case.
