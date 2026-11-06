# firmad — Servicio de Firma Electrónica Interna

Prototipo académico del curso de Sistemas Operativos (UNAMBA) para firmar y verificar documentos mediante Ed25519. Incluye un servidor TCP secuencial escrito en C y un cliente de consola en Python. El servidor escucha únicamente en `127.0.0.1:5050`.

> **Alcance:** es un proyecto de laboratorio, no una firma institucional certificada. No lo expongas a redes externas ni uses sus claves de demostración para documentos reales.

## Requisitos

En Ubuntu o Debian, instala el compilador, las bibliotecas de desarrollo y las herramientas utilizadas para generar las claves:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev libjansson-dev python3 openssl
```

El cliente y las pruebas usan la biblioteca estándar de Python; no hay un archivo de dependencias de Python que instalar.

## Compilar y preparar las claves

Desde la raíz del repositorio, crea un par de claves Ed25519 local y compila el servidor:

```bash
mkdir -p keys
chmod 700 keys
openssl genpkey -algorithm Ed25519 -out keys/private.pem
openssl pkey -in keys/private.pem -pubout -out keys/public.pem
chmod 600 keys/private.pem
chmod 644 keys/public.pem
make
```

El servidor espera ambos archivos en `keys/`, comprueba que la clave privada pertenezca al usuario actual y que no tenga permisos para grupo u otros, y verifica que las claves coincidan. `keys/`, los archivos PEM y el ejecutable `firmad` están excluidos de Git. No compartas ni subas la clave privada. Para volver a compilar, ejecuta `make`; para eliminar el ejecutable generado, `make clean`.

## Ejecutar

Inicia el servidor desde la raíz del repositorio:

```bash
./firmad
```

Déjalo activo y, en otra terminal ubicada en la misma raíz, firma y verifica el documento de ejemplo:

```bash
python3 cliente.py firmar ejemplo_informe.txt --salida firma.json
python3 cliente.py verificar ejemplo_informe.txt --firma firma.json
```

El cliente guarda la firma en un archivo JSON separado del documento. Para comprobar que una modificación invalida la firma:

```bash
cp ejemplo_informe.txt documento_alterado.txt
printf 'Contenido modificado\n' >> documento_alterado.txt
python3 cliente.py verificar documento_alterado.txt --firma firma.json
```

En el último comando, `valid: false` y el código de salida `2` indican que la verificación funcionó correctamente: el archivo ya no coincide con el firmado.

## Pruebas

Con `firmad` en ejecución y las claves preparadas, ejecuta la suite básica:

```bash
python3 pruebas.py
```

Para las pruebas adicionales, primero crea una firma para el documento de ejemplo; el script la lee desde `firma.json` y también usa `keys/public.pem` para la verificación independiente con OpenSSL:

```bash
python3 cliente.py firmar ejemplo_informe.txt --salida firma.json
python3 pruebasextra.py
```

`pruebas.py` contiene 8 comprobaciones y `pruebasextra.py` contiene 14. Las pruebas adicionales generan archivos temporales y `resultados_extra.json` en la raíz.

## Protocolo

El cliente envía una solicitud JSON UTF-8 terminada en salto de línea por conexión TCP. El servidor responde con un objeto JSON y cierra la conexión. Cada solicitud requiere `request_id` (de 1 a 64 caracteres), `op`, `key_id` y `data_b64`; para `VERIFY` también requiere `signature_b64`.

```json
{
  "request_id": "ej-local",
  "op": "SIGN",
  "key_id": "demo-local",
  "data_b64": "SG9sYQ=="
}
```

Las operaciones admitidas son `SIGN` y `VERIFY`. La clave del prototipo se identifica como `demo-local`; `data_b64` y `signature_b64` son representaciones Base64, no cifrado. Una firma correcta se responde con `status: "OK"`, `alg: "Ed25519"` y `signature_b64`; una verificación correcta incluye `valid: true` o `valid: false`. Los errores incluyen `status: "ERROR"` y un código, por ejemplo `BAD_REQUEST`, `KEY_NOT_FOUND`, `TOO_LARGE` o `TIMEOUT`.

El servidor limita cada línea JSON a 1 MiB. El cliente limita los archivos a 720 KiB para dejar espacio a la codificación Base64 y al JSON de la solicitud.

## Estructura del repositorio

| Ruta | Descripción |
| --- | --- |
| `src/firmad.c` | Servidor TCP secuencial, manejo del protocolo y operaciones Ed25519 con OpenSSL/Jansson. |
| `cliente.py` | Cliente de consola para firmar y verificar archivos. |
| `pruebas.py` | Ocho pruebas funcionales básicas; requiere que el servidor esté activo. |
| `pruebasextra.py` | Catorce pruebas de casos límite e integración; requiere el servidor, `firma.json` y las claves. |
| `Makefile` | Compilación con GCC y `pkg-config`. |
| `ejemplo_informe.txt` | Documento de ejemplo para probar el cliente. |
