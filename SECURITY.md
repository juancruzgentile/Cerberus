# Política de seguridad

## Cómo reportar una vulnerabilidad

**No abras un issue público** para reportar un problema de seguridad.

Usa el reporte privado de GitHub:

1. Entra en la pestaña **Security** de este repositorio.
2. Pulsa **Report a vulnerability**.
3. Describe el problema, cómo reproducirlo y qué componente afecta
   (ingestor C, alerter Go, search Rust, esquema o `cerberus.sh`).

El reporte solo lo ven los mantenedores. Se responde lo antes posible y, una
vez corregido, se publica el aviso junto con la versión que lo soluciona.

## Versiones con soporte

Solo recibe correcciones de seguridad la última versión publicada en
[Releases](https://github.com/juancruzgentile/Cerberus/releases).

## Alcance

Cerberus está pensado para ejecutarse en `127.0.0.1` (loopback). Las
garantías y límites conocidos están documentados en el `README.md` y en
`correcciones.txt`; por ejemplo, la entrega de alertas es "al menos una vez"
y el receptor debe deduplicar con la cabecera `Idempotency-Key`.
