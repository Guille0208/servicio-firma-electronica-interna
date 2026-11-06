# firmad — Servicio de Firma Electrónica Interna

Proyecto académico de Sistemas Operativos (UNAMBA). Servidor TCP secuencial en C, Ed25519/OpenSSL, Jansson y cliente Python. Escucha solo en 127.0.0.1:5050.

## Dependencias (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev libjansson-dev python3 openssl
```

## Preparación
Desde la raíz del repositorio:
```bash
mkdir -p keys
chmod 700 keys
openssl genpkey -algorithm Ed25519 -out keys/private.pem
openssl pkey -in keys/private.pem -pubout -out keys/public.pem
chmod 600 keys/private.pem
chmod 644 keys/public.pem
make
```
No subir claves privadas ni archivos PEM a GitHub.

## Ejecución
Terminal 1:
```bash
./firmad
```
Terminal 2:
```bash
python3 cliente.py firmar ejemplo_informe.txt --salida firma.json
python3 cliente.py verificar ejemplo_informe.txt --firma firma.json
cp ejemplo_informe.txt documento_alterado.txt
printf 'Contenido modificado\n' >> documento_alterado.txt
python3 cliente.py verificar documento_alterado.txt --firma firma.json
```
La última verificación debe devolver valid:false y puede terminar con código de salida 2: es el resultado esperado.

## Pruebas
Con el servidor activo:
```bash
python3 pruebas.py
python3 cliente.py firmar ejemplo_informe.txt --salida firma.json
python3 pruebasextra.py
```
La suite básica incluye 8 pruebas y la adicional 14. Esta última requiere que firma.json corresponda a ejemplo_informe.txt. Las 22 pruebas se documentaron como aprobadas en el Ubuntu del grupo; deben reproducirse si se ejecutan en otro entorno.

## Protocolo y alcance
- TCP solo local (127.0.0.1:5050); un objeto JSON UTF-8 por línea.
- SIGN y VERIFY, clave de laboratorio identificada como demo-local.
- data_b64 y signature_b64 contienen Base64 (codificación, no cifrado).
- Límite de 1 MiB por solicitud JSON y 720 KiB por documento en el cliente.
- El programa usa socket, bind, listen, accept, recv, send y close, con protección local de archivos y claves.
- No incluye concurrencia, autenticación, TLS, PAdES, systemd ni integración IHC.
- No abrir el servicio a redes externas: es un prototipo académico de pruebas, no una firma institucional certificada.

## Estructura
- src/firmad.c: servidor en C.
- cliente.py: cliente Python para firma y verificación.
- pruebas.py: ocho pruebas funcionales.
- pruebasextra.py: catorce pruebas adicionales.
- Makefile: compilación.
- ejemplo_informe.txt: documento de ejemplo.
