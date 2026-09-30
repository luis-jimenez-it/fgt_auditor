# FortiGate Auditor

Aplicación web para analizar backups de configuración de FortiGate,
identificar hallazgos de seguridad y exportar resultados a Excel.

## Requisitos

- Linux
- Python 3
- pip
- Git

## Instalación

### 1. Clonar el repositorio

git clone git@github.com:luis-jimenez-it/fgt_auditor.git
cd fgt_auditor

### 2. Crear el entorno virtual

python3 -m venv venv

### 3. Activar el entorno virtual

source venv/bin/activate

### 4. Instalar las dependencias

python -m pip install --upgrade pip
pip install -r requirements.txt

## Ejecución

Iniciar la aplicación:

python app.py

Acceder desde el navegador utilizando la dirección y el puerto
configurados en la aplicación.

## Uso

1. Acceder a la interfaz web.
2. Cargar el backup de configuración de FortiGate.
3. Ejecutar el análisis.
4. Revisar los resultados y exportar el informe disponible.

## Estructura

- app.py: aplicación web.
- core/: procesamiento y exportación.
- modules/: módulos de análisis.
- templates/: interfaz web.
- requirements.txt: dependencias de Python.

## Seguridad

No publicar backups de clientes, credenciales, claves privadas
ni información sensible de infraestructura.
