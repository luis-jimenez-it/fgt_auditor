# modules/security_profiles/ips_sensor.py
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
    Auditoría completa de IPS Sensors (config ips sensor) VDOM por VDOM.
    Retorna 2 líneas resumen:
      1. Sensores con configuraciones débiles o modo monitor.
      2. Sensores huérfanos (sin referencia en ninguna política de firewall).
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    # Exclusión estricta solicitada para perfiles especiales y de fábrica
    EXCLUDED_PROFILES = {'initial', 'wifi-default', 'sniffer-profile'}

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # =====================================================================
        # FASE 1: RECOPILAR REFERENCIAS DESDE LAS POLÍTICAS DE FIREWALL
        # =====================================================================
        referenced_ips = set()
        fw_block = extract_nested_block(vdom_content, "config firewall policy")
        if fw_block:
            ips_lines = re.findall(r'set ips-sensor\s+([^\n]+)', fw_block)
            for line in ips_lines:
                names = re.findall(r'"([^"]+)"|([a-zA-Z0-9_-]+)', line)
                for n1, n2 in names:
                    val = n1 or n2
                    if val:
                        referenced_ips.add(val)

        # =====================================================================
        # FASE 2: AUDITORÍA DE IPS SENSORS (config ips sensor)
        # =====================================================================
        ips_block = extract_nested_block(vdom_content, "config ips sensor")
        ips_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', ips_block, re.DOTALL) if ips_block else []

        weak_profiles = []
        ips_names = set()

        for ips_name, ips_body in ips_raw:
            # Omitir por completo del análisis los perfiles excluidos
            if ips_name in EXCLUDED_PROFILES:
                continue

            ips_names.add(ips_name)

            # Criterio de debilidad: verificar si opera exclusivamente en modo monitor o carece de reglas de bloqueo
            has_weakness = False
            if "block" not in ips_body.lower() and "monitor" in ips_body.lower():
                has_weakness = True

            if has_weakness:
                weak_profiles.append(ips_name)

        # 1. Chequeo de Configuración Débil
        weak_summary = f"Sensores débiles: {', '.join(weak_profiles[:10])}" if weak_profiles else "Ningún sensor IPS con configuración débil"

        checks.append({
            'id': f'CHK-IPS-SUMMARY-{vdom_prefix}-PROFILES',
            'vdom': vdom_name,
            'cat': 'Security Profiles',
            'mod': 'Intrusion Prevention (IPS)',
            'hallazgo': f"VDOM '{vdom_name}': Sensores IPS con configuración débil o modo monitor exclusivo (Total: {len(weak_profiles)})",
            'estado': 'WARNING' if weak_profiles else 'PASS',
            'sev': 'Media',
            'peso': 8,
            'afectados': f"VDOM {vdom_name} -> Sensores débiles: {len(weak_profiles)}",
            'evidencia': weak_summary[:250],
            'rec': 'Asegurar que los sensores IPS bloqueen activamente ataques conocidos conforme a SEG-LNB-002.',
            'rem': 'config ips sensor\n  edit "<Nombre_Sensor>"\n    # Configurar reglas con acción de bloqueo\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5 / ISO 27001 A.12.6.1'
        })

        # 2. Chequeo de Huérfanos (Excluyendo perfiles predeterminados y especiales)
        ips_orphans = [name for name in ips_names if name not in referenced_ips and name not in EXCLUDED_PROFILES]
        orphan_summary = f"Sensores huérfanos: {', '.join(ips_orphans[:10])}" if ips_orphans else "Ningún sensor IPS huérfano"

        checks.append({
            'id': f'CHK-IPS-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Security Profiles',
            'mod': 'IPS Sensor Huérfanos',
            'hallazgo': f"VDOM '{vdom_name}': Sensores IPS sin referencia en ninguna política de firewall (Total: {len(ips_orphans)})",
            'estado': 'WARNING' if ips_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total huérfanos: {len(ips_orphans)}",
            'evidencia': orphan_summary[:250],
            'rec': 'Depurar y eliminar sensores IPS obsoletos o no utilizados en las políticas.',
            'rem': 'config ips sensor\n  delete <Nombre_Sensor>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

    return checks
