# Dras. Leiva Ibañez

Sitio de presentación de Patricia Noelia Leiva Ibañez (Pediatra Neonatóloga) y Maria Veronica Leiva Ibañez (Clínica Médica / Terapia), con atención en Aguilares y San Miguel de Tucumán.

## Estructura

- `index.html`: HTML, CSS, JavaScript, SEO y datos estructurados, sin dependencias externas.
- `recursos/imagenes/`: fotografías originales proporcionadas por el titular del proyecto. Patricia es la doctora vestida de blanco.
- `vercel.json`: configuración del alojamiento estático.

## Sistema de turnos e historias clínicas

El mismo proyecto incluye reserva pública de turnos de 15 minutos y un área privada con perfiles para Secretaría, ambas doctoras y Administración. Los datos se almacenan en Turso mediante una función privada de Vercel; ninguna credencial se expone en `index.html`.

- El público solo ve horarios disponibles y confirma un turno con teléfono obligatorio.
- El comprobante puede imprimirse o guardarse como PDF desde el navegador.
- El correo se solicita únicamente al elegir el envío del comprobante y requiere configurar Resend.
- Secretaría administra turnos sin acceso clínico.
- Las doctoras comparten la historia clínica y cada entrada conserva autoría y fecha.
- Las atenciones cerradas se corrigen mediante nuevas constancias; no se sobrescriben.
- Administración gestiona horarios, usuarios y todos los módulos.
- Cada cuenta puede utilizar una contraseña de 12 o más caracteres o un PIN de 4 números. Los PIN se bloquean temporalmente después de cinco intentos fallidos; para doctoras y Administración se recomienda contraseña.

Variables privadas requeridas en Vercel: `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, `AUTH_SECRET` y `BOOTSTRAP_SECRET`. Para correo se agregan `RESEND_API_KEY` y `EMAIL_FROM`.

## Publicación

Importar este repositorio en Vercel como proyecto estático (Other), sin comando de compilación y con el directorio raíz como salida. La rama de producción es `main`.

Las fotografías no tienen licencia de reutilización para terceros.
