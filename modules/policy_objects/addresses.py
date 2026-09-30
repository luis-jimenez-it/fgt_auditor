# modules/policy_objects/addresses.py
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
    Auditoría optimizada de Objetos de Dirección y Grupos VDOM por VDOM.
    Retorna 3 líneas resumen:
      1. IPs Duplicadas.
      2. Objetos de dirección huérfanos (sin referencia).
      3. Grupos de dirección huérfanos (sin referencia).
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # =====================================================================
        # 1. AUDITORÍA DE FIREWALL ADDRESS (Duplicados y Huérfanos)
        # =====================================================================
        addr_block = extract_nested_block(vdom_content, "config firewall address")
        addrs_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', addr_block, re.DOTALL) if addr_block else []

        ip_map = {}
        addr_names = set()

        for addr_name, addr_body in addrs_raw:
            addr_names.add(addr_name)
            subnet_m = re.search(r'set (?:subnet|ip)\s+([^\n]+)', addr_body)
            if subnet_m:
                subnet_val = subnet_m.group(1).strip().replace('"', '')
                if subnet_val not in ip_map:
                    ip_map[subnet_val] = []
                ip_map[subnet_val].append(addr_name)

        # Duplicados
        duplicates = {ip: names for ip, names in ip_map.items() if len(names) > 1}
        dup_tags = [f"IP/Subred '{ip}': {names}" for ip, names in duplicates.items()]

        checks.append({
            'id': f'CHK-ADDR-SUMMARY-{vdom_prefix}-DUPLICATES',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'Address Objects (Duplicados)',
            'hallazgo': f"VDOM '{vdom_name}': Objetos con IP duplicada (Total: {len(duplicates)})",
            'estado': 'WARNING' if duplicates else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Duplicados: {len(duplicates)}",
            'evidencia': ' | '.join(dup_tags) if dup_tags else 'Ninguna IP duplicada',
            'rec': 'Consolidar objetos redundantes.',
            'rem': 'config firewall address\n  delete <Objeto>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.3'
        })

        # Huérfanos (Optimizado con set de palabras encontradas en todo el VDOM)
        # Buscamos todas las palabras usadas como referencia en el texto del VDOM de una sola pasada
        used_tokens = set(re.findall(r'"([^"]+)"', vdom_content))

        addr_orphans = [name for name in addr_names if name not in used_tokens]

        addr_orphan_summary = f"Huérfanos: {', '.join(addr_orphans[:15])}" if addr_orphans else "Ningún objeto huérfano"
        checks.append({
            'id': f'CHK-ADDR-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'Address Objects (Huérfanos)',
            'hallazgo': f"VDOM '{vdom_name}': Objetos de dirección sin referencia (Total: {len(addr_orphans)})",
            'estado': 'WARNING' if addr_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total huérfanos: {len(addr_orphans)}",
            'evidencia': addr_orphan_summary[:250],
            'rec': 'Depurar objetos huérfanos.',
            'rem': 'config firewall address\n  delete <Objeto>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.3'
        })

        # =====================================================================
        # 2. AUDITORÍA DE FIREWALL ADDRGRP (Grupos no referenciados)
        # =====================================================================
        group_block = extract_nested_block(vdom_content, "config firewall addrgrp")
        groups_raw = re.findall(r'edit "([^"]+)"', group_block) if group_block else []

        group_orphans = [gname for gname in groups_raw if gname not in used_tokens]

        group_orphan_summary = f"Grupos huérfanos: {', '.join(group_orphans[:15])}" if group_orphans else "Ningún grupo huérfano"
        checks.append({
            'id': f'CHK-ADDRGRP-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'Address Groups (Huérfanos)',
            'hallazgo': f"VDOM '{vdom_name}': Grupos de dirección sin referencia alguna (Total: {len(group_orphans)})",
            'estado': 'WARNING' if group_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total grupos huérfanos: {len(group_orphans)}",
            'evidencia': group_orphan_summary[:250],
            'rec': 'Depurar grupos de dirección obsoletos o no utilizados.',
            'rem': 'config firewall addrgrp\n  delete <Grupo>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.3'
        })

    return checks
