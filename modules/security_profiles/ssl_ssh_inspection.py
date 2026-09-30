# modules/security_profiles/ssl_ssh_inspection.py
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
    Auditoría completa de SSL/SSH Inspection Profiles (config firewall ssl-ssh-profile) VDOM por VDOM.
    Retorna 2 líneas resumen:
      1. Perfiles con configuraciones débiles.
      2. Perfiles huérfanos (sin referencia en ninguna política de firewall).
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    # Exclusión estricta para perfiles predeterminados y especiales
    EXCLUDED_PROFILES = {
        'wifi-default',
        'sniffer-profile',
        'no-inspection',
        'initial'
    }

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # =====================================================================
        # FASE 1: RECOPILAR REFERENCIAS DESDE LAS POLÍTICAS DE FIREWALL
        # =====================================================================
        referenced_ssl = set()
        fw_block = extract_nested_block(vdom_content, "config firewall policy")
        if fw_block:
            ssl_lines = re.findall(r'set ssl-ssh-profile\s+([^\n]+)', fw_block)
            for line in ssl_lines:
                names = re.findall(r'"([^"]+)"|([a-zA-Z0-9_-]+)', line)
                for n1, n2 in names:
                    val = n1 or n2
                    if val:
                        referenced_ssl.add(val)

        # =====================================================================
        # FASE 2: AUDITORÍA DE SSL-SSH PROFILES (config firewall ssl-ssh-profile)
        # =====================================================================
        ssl_block = extract_nested_block(vdom_content, "config firewall ssl-ssh-profile")
        ssl_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', ssl_block, re.DOTALL) if ssl_block else []

        weak_profiles = []
        ssl_names = set()

        for ssl_name, ssl_body in ssl_raw:
            if ssl_name in EXCLUDED_PROFILES:
                continue

            ssl_names.add(ssl_name)

            # Criterio de debilidad: verificar si utiliza algoritmos débiles o descifrado incompleto
            has_weakness = False
            if "unsupported-ssl" in ssl_body.lower() and "allow" in ssl_body.lower():
                has_weakness = True

            if has_weakness:
                weak_profiles.append(ssl_name)

        # 1. Chequeo de Configuración Débil
        weak_summary = f"Perfiles débiles: {', '.join(weak_profiles[:10])}" if weak_profiles else "Ningún perfil SSL/SSH con configuración débil"

        checks.append({
            'id': f'CHK-SSL-SUMMARY-{vdom_prefix}-PROFILES',
            'vdom': vdom_name,
            'cat': 'Security Profiles',
            'mod': 'SSL/SSH Inspection',
            'hallazgo': f"VDOM '{vdom_name}': Perfiles SSL/SSH con configuración débil o permitiendo cifrados no seguros (Total: {len(weak_profiles)})",
            'estado': 'WARNING' if weak_profiles else 'PASS',
            'sev': 'Media',
            'peso': 8,
            'afectados': f"VDOM {vdom_name} -> Perfiles débiles: {len(weak_profiles)}",
            'evidencia': weak_summary[:250],
            'rec': 'Asegurar inspección profunda (Deep Inspection) y bloqueo de protocolos obsoletos conforme a SEG-LNB-002.',
            'rem': 'config firewall ssl-ssh-profile\n  edit "<Nombre_Perfil>"\n    set unsupported-ssl block\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5 / ISO 27001 A.13.2.3'
        })

        # 2. Chequeo de Huérfanos (Excluyendo perfiles predeterminados y especiales)
        ssl_orphans = [name for name in ssl_names if name not in referenced_ssl and name not in EXCLUDED_PROFILES]
        orphan_summary = f"Perfiles huérfanos: {', '.join(ssl_orphans[:10])}" if ssl_orphans else "Ningún perfil SSL/SSH huérfano"

        checks.append({
            'id': f'CHK-SSL-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Security Profiles',
            'mod': 'SSL/SSH Profile Huérfanos',
            'hallazgo': f"VDOM '{vdom_name}': Perfiles SSL/SSH sin referencia en ninguna política de firewall (Total: {len(ssl_orphans)})",
            'estado': 'WARNING' if ssl_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total huérfanos: {len(ssl_orphans)}",
            'evidencia': orphan_summary[:250],
            'rec': 'Depurar y eliminar perfiles SSL/SSH obsoletos o no utilizados en las políticas.',
            'rem': 'config firewall ssl-ssh-profile\n  delete <Nombre_Perfil>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

    return checks
