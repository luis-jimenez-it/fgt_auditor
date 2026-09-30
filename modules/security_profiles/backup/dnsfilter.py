# modules/security_profiles/dnsfilter.py
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
    Auditoría completa de Perfiles de DNS Filter (config dnsfilter profile) VDOM por VDOM.
    Retorna 2 líneas resumen:
      1. Perfiles con configuraciones débiles.
      2. Perfiles huérfanos (sin referencia en ninguna política de firewall).
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    # Lista de perfiles estándar/especiales a excluir de la auditoría de huérfanos
    EXCLUDED_PROFILES = {'sniffer-profile', 'initial'}

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # =====================================================================
        # FASE 1: RECOPILAR REFERENCIAS DESDE LAS POLÍTICAS DE FIREWALL
        # =====================================================================
        referenced_dns = set()
        fw_block = extract_nested_block(vdom_content, "config firewall policy")
        if fw_block:
            dns_lines = re.findall(r'set dnsfilter-profile\s+([^\n]+)', fw_block)
            for line in dns_lines:
                names = re.findall(r'"([^"]+)"|([a-zA-Z0-9_-]+)', line)
                for n1, n2 in names:
                    val = n1 or n2
                    if val:
                        referenced_dns.add(val)

        # =====================================================================
        # FASE 2: AUDITORÍA DE PERFILES DE DNS FILTER (config dnsfilter profile)
        # =====================================================================
        dns_block = extract_nested_block(vdom_content, "config dnsfilter profile")
        dns_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', dns_block, re.DOTALL) if dns_block else []

        weak_profiles = []
        dns_names = set()

        for dns_name, dns_body in dns_raw:
            dns_names.add(dns_name)
            
            # Criterio de debilidad: verificar si carece de opciones de bloqueo activo de dominios maliciosos
            has_weakness = False
            if "block-botnet" in dns_body.lower() and "disable" in dns_body.lower():
                has_weakness = True

            if has_weakness:
                weak_profiles.append(dns_name)

        # 1. Chequeo de Configuración Débil
        weak_summary = f"Perfiles débiles: {', '.join(weak_profiles[:10])}" if weak_profiles else "Ningún perfil DNS con configuración débil"

        checks.append({
            'id': f'CHK-DNS-SUMMARY-{vdom_prefix}-PROFILES',
            'vdom': vdom_name,
            'cat': 'Security Profiles',
            'mod': 'DNS Filter Inspection',
            'hallazgo': f"VDOM '{vdom_name}': Perfiles de DNS Filter con configuración débil o botnet deshabilitado (Total: {len(weak_profiles)})",
            'estado': 'WARNING' if weak_profiles else 'PASS',
            'sev': 'Media',
            'peso': 8,
            'afectados': f"VDOM {vdom_name} -> Perfiles débiles: {len(weak_profiles)}",
            'evidencia': weak_summary[:250],
            'rec': 'Asegurar que los perfiles DNS habiliten el bloqueo de botnets y dominios maliciosos conforme a SEG-LNB-002.',
            'rem': 'config dnsfilter profile\n  edit "<Nombre_Perfil>"\n    set block-botnet enable\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 7.3'
        })

        # 2. Chequeo de Huérfanos (Excluyendo perfiles predeterminados)
        dns_orphans = [name for name in dns_names if name not in referenced_dns and name not in EXCLUDED_PROFILES]
        orphan_summary = f"Perfiles huérfanos: {', '.join(dns_orphans[:10])}" if dns_orphans else "Ningún perfil de DNS Filter huérfano"

        checks.append({
            'id': f'CHK-DNS-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Security Profiles',
            'mod': 'DNS Filter Huérfanos',
            'hallazgo': f"VDOM '{vdom_name}': Perfiles de DNS Filter sin referencia en ninguna política de firewall (Total: {len(dns_orphans)})",
            'estado': 'WARNING' if dns_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total huérfanos: {len(dns_orphans)}",
            'evidencia': orphan_summary[:250],
            'rec': 'Depurar y eliminar perfiles de DNS Filter obsoletos o no utilizados en las políticas.',
            'rem': 'config dnsfilter profile\n  delete <Nombre_Perfil>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 7.3 / Limpieza'
        })

    return checks
