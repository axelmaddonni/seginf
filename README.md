# seginf
Trabajo Practico Final. Seguridad de la información. 2do cuatrimestre 2017. Timestamp authority and signed pdf with screenshot of website.

## myPDFSigner - Instalación

1) Descargar el archivo mypdfsigner_2.7.5-1_amd64.deb
Link: https://www.kryptokoder.com/download.html (ver versión según SO)
Luego instalarlo usando: (en UBUNTU)
```sh
$ sudo gdebi mypdfsigner_2.7.5-1_amd64.deb
```

2) Hacer lo mismo para el siguiente archivo: mypdfsigner-python_2.7.5-1_amd64.deb
Link: https://www.kryptokoder.com/download.html (ver versión según SO)
Luego instalarlo usando: (en UBUNTU)

```sh
$ sudo gdebi mypdfsigner-python_2.7.5-1_amd64.deb
```

3) Creación de certificado para la api del usuario

```sh
$ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
$ openssl x509 -text -noout -in certificate.pem
$ openssl pkcs12 -inkey key.pem -in certificate.pem -export -out certificate.p12
$ openssl pkcs12 -in certificate.p12 -noout -info
```

Seguir todos los pasos, el nombre que definan en CN (Common Name) es el que aparece en la firma del PDF.

4) Configurar MyPDFSigner:
- Abrir myPdfSigner (la interfaz gráfica)
- Seleccionar PKCS12 KeyStore File y hacer click en Change
- Elegir el archivo .p12 que se generó cuando creamos el certificado. Ingresar la password y seleccionar un alias cualquiera del dropdown.
- Hacer click en Profile y completar con el path de la imagen. La ubicación para que aparezca al final a la derecha es: [-170 40 -40 80]. La imagen tiene que estar en formato png con color RGBA.
- Habilitar el TimeStamping escribiendo la url de la tsa. Por ahora usamos la de prueba: https://freetsa.org/tsr sin usuario ni password. Habilitarla. 
- Cerrar y verificar que se haya creado un archivo llamado .mypdfsigner en tu home.

Con eso debería poder ejecutar el código de la api del usuario con el time stamp de la free TSA y firmando con el certificado auto firmado que generamos.

## Pruebas usando open ssl

- Request de prueba
```sh
$ openssl ts -query -data output.pdf -cert -sha256 -no_nonce -text
```
- Envio de request a free tsa

```sh
$ cat request.tsq | curl -s -S -H 'Content-Type: application/timestamp-query' --data-binary @- https://www.freetsa.org/tsr -o response.tsr
```

- Envio de request a nuestra tsa

```sh
$ cat request.tsq | curl -s -S -H 'Content-Type: application/timestamp-query' --data-binary @- http://0.0.0.0:12346/tsr -o response.tsr
```

- Verificacion del response

```sh
$ openssl ts -verify -queryfile request.tsq -in response.tsr
```

## Debugging

```sh
$ dumpasn1 response.tsr
```
----------------

# TO DO

- Aplicar conceptos de seguridad en base a: (LEERLOS)

http://www.etsi.org/deliver/etsi_ts/102000_102099/102023/01.02.02_60/ts_102023v010202p.pdf
https://www.rfc-editor.org/rfc/rfc3628.txt

- Agregar que nuestra página use https en lugar de http

- Documentación. Ejemplos:

https://www.id.ee/index.php?id=36797
https://www.sk.ee/en/services/time-stamping-service/technical-specifications/

- Presentación

1. Hacer un gráfico para explicar Requests y Responses
2. Armar una demo
3. Armar un powerPoint
4. Mejorar la vista de la página para el usuario (que no sea solo un form)

