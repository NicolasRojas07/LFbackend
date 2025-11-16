# JWT API

Flask API para decodificar/verificar/crear JWTs. Persiste casos de prueba en MongoDB.

## Endpoints
- `GET /health`: Health check
- `GET /`: Ping básico
- `POST /api/jwt/decode`: Decodifica sin verificar
- `POST /api/jwt/verify`: Verifica firma
- `POST /api/jwt/encode`: Crea token
- `POST /api/jwt/save-test`: Guarda caso de prueba en MongoDB
- `GET /api/jwt/tests`: Lista casos de prueba
- `DELETE /api/jwt/tests/<id>`: Elimina caso de prueba

## Variables de entorno
- `MONGO_URI` (obligatorio): cadena de conexión (Atlas/Render Mongo). Ej: `mongodb+srv://user:pass@cluster.example.mongodb.net/mydb`
- `APP_SECRET` (opcional): secreto por defecto para `encode` si no se envía en el body
- `DEBUG` (opcional): `True/False` (por defecto `True`)

## Ejecución local (Windows PowerShell)
```powershell
$env:MONGO_URI="mongodb+srv://user:pass@cluster.mongodb.net/mydb"
$env:APP_SECRET="cambia_esto"
pip install -r requirements.txt
gunicorn wsgi:app --bind 0.0.0.0:8000
```
Luego visita `http://localhost:8000/health`.

## Despliegue en Render
Este repo incluye `render.yaml` para configurar el servicio web Python:
- Build: `pip install -r requirements.txt`
- Start: `gunicorn wsgi:app`
- Health check: `/health`

Pasos:
1) Crear un Web Service en Render desde este repo (monorepo raíz).
2) Enviar variables de entorno: `MONGO_URI` y `APP_SECRET`.
3) Deploy. Render detectará Python y ejecutará `gunicorn`.

Notas MongoDB (Atlas):
- Usa URI `mongodb+srv://` con base de datos en el path (p.ej. `/mydb`).
- Asegura IP allowlist para la región de Render o `0.0.0.0/0` temporalmente.
- `dnspython` está declarado para resolver SRV.
