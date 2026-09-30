# modules/user_auth/auth_settings.py
import re

def extract_nested_block(text, block_header):
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line == block_header:
            block_lines = []
            i += 1
            nesting = 1
            while i < len(lines):
                sub_s = lines[i].strip()
                if sub_s.startswith("config ") or sub_s.startswith("edit "):
                    nesting += 1
                elif sub_s in ["end", "next"]:
                    nesting -= 1
                    if nesting == 0:
                        break
                block_lines.append(lines[i])
                i += 1
            return "\n".join(block_lines)
        i += 1
    return None

def audit(ctx):
    """
    Auditoría de configuraciones globales de autenticación y seguridad de acceso VDOM por VDOM
    alineada a SEG-LNB-002.
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # Extraer bloque global o de system settings relevantes para auth
        global_block = extract_nested_block(vdom_content, "config system global") or vdom_content

        insecure_auth_settings = []

        # 1. Validación de tiempo de expiración de sesión de administración / auth (admout)
        admout_m = re.search(r'set admout\s+(\d+)', global_block)
        if admout_m:
            timeout_val = int(admout_m.group(1))
            if timeout_val > 600 or timeout_val == 0: # Más de 10 min o ilimitado
                insecure_auth_settings.append(f"Timeout de admin excesivo ({timeout_val}s)")
        else:
            insecure_auth_settings.append("Timeout de admin por defecto o ausente")

        # 2. Protección contra fuerza bruta / bloqueo por intentos fallidos de login
        lockout_m = re.search(r'set admin-lockout-threshold\s+(\d+)', global_block)
        if lockout_m:
            threshold = int(lockout_m.group(1))
            if threshold > 5:
                insecure_auth_settings.append(f"Umbral de bloqueo alto ({threshold} intentos)")
        else:
            insecure_auth_settings.append("Umbral de bloqueo de administración no configurado estrictamente")

        # =====================================================================
        # CHECK: Configuración Global de Autenticación y Bloqueos
        # =====================================================================
        auth_summary = f"Observaciones de autenticación: {', '.join(insecure_auth_settings)}" if insecure_auth_settings else "Configuración global de autenticación conforme a baseline"
        checks.append({
            'id': f'CHK-AUTHSET-{vdom_prefix}-GLOBAL',
            'vdom': vdom_name,
            'cat': 'User & Authentication',
            'mod': 'Authentication Global Settings',
            'hallazgo': f"VDOM '{vdom_name}': Parámetros globales de autenticación o tiempos de sesión fuera del estándar corporativo (Total: {len(insecure_auth_settings)})",
            'estado': 'WARNING' if insecure_auth_settings else 'PASS',
            'sev': 'Media',
            'peso': 6,
            'afectados': f"VDOM {vdom_name} -> Observaciones: {len(insecure_auth_settings)}",
            'evidencia': auth_summary[:250],
            'rec': 'Ajustar los tiempos de inactividad de sesión (admout) y umbrales de bloqueo por fuerza bruta conforme a SEG-LNB-002.',
            'rem': 'config system global\n  set admout 480\n  set admin-lockout-threshold 3\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 10.5'
        })

    return checks
