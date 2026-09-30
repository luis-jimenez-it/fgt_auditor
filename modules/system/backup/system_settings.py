# modules/system/system_settings.py
import re

def audit(ctx):
    """
    Auditoría de configuraciones globales del sistema (config system global)
    con normalización de espacios especiales.
    """
    checks = []
    raw_content = ctx.get('content', '')

    # Normalizar espacios especiales / non-breaking spaces que vienen de consolas/respaldos
    raw_content = raw_content.replace('\xa0', ' ')

    # =========================================================================
    # EXTRACCIÓN DIRECTA DE PARÁMETROS GLOBALES CON REGEX ROBUSTA
    # =========================================================================

    # 1. admin-https-redirect (Default moderno: True)
    https_redirect_enabled = True
    match = re.search(r'^\s*set\s+admin-https-redirect\s+(enable|disable)', raw_content, re.IGNORECASE | re.MULTILINE)
    if match:
        https_redirect_enabled = (match.group(1).lower() == 'enable')

    # 2. pre-login-banner (Default fábrica: False)
    banner_enabled = False
    match = re.search(r'^\s*set\s+pre-login-banner\s+(enable|disable)', raw_content, re.IGNORECASE | re.MULTILINE)
    if match:
        banner_enabled = (match.group(1).lower() == 'enable')

    # 3. strong-crypto (Default moderno: True)
    strong_crypto_enabled = True
    match = re.search(r'^\s*set\s+strong-crypto\s+(enable|disable)', raw_content, re.IGNORECASE | re.MULTILINE)
    if match:
        strong_crypto_enabled = (match.group(1).lower() == 'enable')

    # 4. admintimeout
    admintimeout_val = 5
    match = re.search(r'^\s*set\s+admintimeout\s+(\d+)', raw_content, re.IGNORECASE | re.MULTILINE)
    if match:
        admintimeout_val = int(match.group(1))

    # 5. admin-lockout-threshold
    lockout_threshold = 3
    match = re.search(r'^\s*set\s+admin-lockout-threshold\s+(\d+)', raw_content, re.IGNORECASE | re.MULTILINE)
    if match:
        lockout_threshold = int(match.group(1))

    # =========================================================================
    # CONSTRUCCIÓN DE CHECKS DE HARDENING
    # =========================================================================

    checks.append({
        'id': 'CHK-SYSSET-GLOBAL-HTTPSREDIRECT',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'System Global HTTPS Redirect',
        'hallazgo': "Configuración global: Redirección automática de HTTP a HTTPS deshabilitada o ausente",
        'estado': 'PASS' if https_redirect_enabled else 'WARNING',
        'sev': 'Alta',
        'peso': 8,
        'afectados': f"Global -> admin-https-redirect: {'Habilitado' if https_redirect_enabled else 'Deshabilitado'}",
        'evidencia': f"Estado evaluado: {'Habilitado' if https_redirect_enabled else 'Deshabilitado'}",
        'rec': 'Habilitar la redirección estricta de HTTP a HTTPS conforme a SEG-LNB-002.',
        'rem': 'config system global\n  set admin-https-redirect enable\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 7.1'
    })

    checks.append({
        'id': 'CHK-SYSSET-GLOBAL-BANNER',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'System Global Pre-Login Banner',
        'hallazgo': "Configuración global: Banner de advertencia legal previo al acceso deshabilitado",
        'estado': 'PASS' if banner_enabled else 'WARNING',
        'sev': 'Baja',
        'peso': 3,
        'afectados': f"Global -> pre-login-banner: {'Habilitado' if banner_enabled else 'Deshabilitado'}",
        'evidencia': f"Estado evaluado: {'Habilitado' if banner_enabled else 'Deshabilitado'}",
        'rec': 'Habilitar el banner legal antes del inicio de sesión conforme a SEG-LNB-002.',
        'rem': 'config system global\n  set pre-login-banner enable\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 7.2'
    })

    checks.append({
        'id': 'CHK-SYSSET-GLOBAL-STRONGCRYPTO',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'System Global Strong Crypto',
        'hallazgo': "Configuración global: El modo de criptografía fuerte (strong-crypto) no se encuentra habilitado",
        'estado': 'PASS' if strong_crypto_enabled else 'WARNING',
        'sev': 'Alta',
        'peso': 9,
        'afectados': f"Global -> strong-crypto: {'Habilitado' if strong_crypto_enabled else 'Deshabilitado'}",
        'evidencia': f"Estado evaluado: {'Habilitado' if strong_crypto_enabled else 'Deshabilitado'}",
        'rec': 'Habilitar strong-crypto para forzar algoritmos criptográficos robustos conforme a SEG-LNB-002.',
        'rem': 'config system global\n  set strong-crypto enable\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 7.3'
    })

    insecure_timeout = admintimeout_val > 15 or admintimeout_val == 0
    checks.append({
        'id': 'CHK-SYSSET-GLOBAL-TIMEOUT',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'System Global Admin Timeout',
        'hallazgo': f"Configuración global: El tiempo de inactividad de la consola administrativa es excesivo ({admintimeout_val} min)",
        'estado': 'WARNING' if insecure_timeout else 'PASS',
        'sev': 'Media',
        'peso': 5,
        'afectados': f"Global -> admintimeout: {admintimeout_val} minutos",
        'evidencia': f"Timeout configurado: {admintimeout_val} minutos",
        'rec': 'Configurar el tiempo de inactividad de administración a un valor seguro (máximo 15 minutos) conforme a SEG-LNB-002.',
        'rem': 'config system global\n  set admintimeout 10\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 7.5'
    })

    insecure_lockout = lockout_threshold > 5
    checks.append({
        'id': 'CHK-SYSSET-GLOBAL-LOCKOUT',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'System Global Brute Force Protection',
        'hallazgo': f"Configuración global: Umbral de bloqueo por intentos fallidos de login muy alto ({lockout_threshold} intentos)",
        'estado': 'WARNING' if insecure_lockout else 'PASS',
        'sev': 'Media',
        'peso': 6,
        'afectados': f"Global -> admin-lockout-threshold: {lockout_threshold} intentos",
        'evidencia': f"Umbral configurado: {lockout_threshold} intentos",
        'rec': 'Reducir el umbral de bloqueo de administración a un máximo de 3 a 5 intentos fallidos conforme a SEG-LNB-002.',
        'rem': 'config system global\n  set admin-lockout-threshold 3\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 7.6'
    })

    return checks
