# modules/policy_objects/ippools.py
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
    Auditoría optimizada de IP Pools VDOM por VDOM.
    Retorna 1 línea resumen:
      1. IP Pools huérfanos (sin referencia en políticas de firewall).
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # =====================================================================
        # FASE 1: RECOPILAR REFERENCIAS DESDE LAS POLÍTICAS DE FIREWALL
        # =====================================================================
        referenced_pools = set()
        fw_block = extract_nested_block(vdom_content, "config firewall policy")
        if fw_block:
            # En FortiGate el pool se asigna con set ippool enable / set poolname "nombre"
            pool_lines = re.findall(r'set poolname\s+([^\n]+)', fw_block)
            for line in pool_lines:
                names = re.findall(r'"([^"]+)"|([a-zA-Z0-9_-]+)', line)
                for n1, n2 in names:
                    val = n1 or n2
                    if val:
                        referenced_pools.add(val)

        # =====================================================================
        # FASE 2: AUDITORÍA DE IP POOLS (config firewall ippool)
        # =====================================================================
        ippool_block = extract_nested_block(vdom_content, "config firewall ippool")
        pools_raw = re.findall(r'edit "([^"]+)"', ippool_block) if ippool_block else []

        pool_orphans = [p for p in pools_raw if p not in referenced_pools]
        pool_orphan_summary = f"IP Pools huérfanos: {', '.join(pool_orphans[:15])}" if pool_orphans else "Ningún IP Pool huérfano"

        checks.append({
            'id': f'CHK-IPPOOL-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'IP Pools (Huérfanos)',
            'hallazgo': f"VDOM '{vdom_name}': IP Pools sin referencia en políticas de firewall (Total: {len(pool_orphans)})",
            'estado': 'WARNING' if pool_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total IP Pools huérfanos: {len(pool_orphans)}",
            'evidencia': pool_orphan_summary[:250],
            'rec': 'Depurar y eliminar IP Pools obsoletos o no utilizados.',
            'rem': 'config firewall ippool\n  delete <Nombre_IP_Pool>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.3'
        })

    return checks
