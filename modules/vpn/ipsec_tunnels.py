# modules/vpn/ipsec_tunnels.py
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
    Auditoría completa de túneles IPsec (Phase 1, Phase 2, IKEv2 y Selectores) VDOM por VDOM.
    Retorna 4 líneas resumen de hardening corporativo.
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # =====================================================================
        # FASE 1: IPSEC PHASE 1 (Criptografía e IKEv2)
        # =====================================================================
        p1_block = extract_nested_block(vdom_content, "config vpn ipsec phase1-interface")
        p1_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', p1_block, re.DOTALL) if p1_block else []

        weak_p1 = []
        ikev1_tunnels = []
        p1_names = set()

        for p1_name, p1_body in p1_raw:
            p1_names.add(p1_name)

            # 1. Validar versión de IKE (Exigir IKEv2)
            ike_m = re.search(r'set ike-version\s+([^\n]+)', p1_body)
            if not ike_m or '1' in ike_m.group(1):
                ikev1_tunnels.append(p1_name)

            # 2. Validar criptografía débil en Fase 1
            has_weak_crypto = False
            reasons = []
            if re.search(r'set proposal\s+.*(des|3des|md5)', p1_body, re.IGNORECASE):
                has_weak_crypto = True
                reasons.append("DES/3DES/MD5")

            dh_match = re.search(r'set dhgrp\s+([^\n]+)', p1_body)
            if dh_match and any(d in dh_match.group(1) for d in [' 1 ', ' 2 ', ' 5 ', '1 2', '2 5']):
                has_weak_crypto = True
                reasons.append("DH bajo")

            if has_weak_crypto:
                weak_p1.append(f"{p1_name} ({', '.join(reasons)})")

        # Check 1: Criptografía Fase 1
        crypto_summary = f"Túneles con criptografía débil: {', '.join(weak_p1[:10])}" if weak_p1 else "Ningún túnel con criptografía débil en Fase 1"
        checks.append({
            'id': f'CHK-IPSEC-SUMMARY-{vdom_prefix}-P1-CRYPTO',
            'vdom': vdom_name,
            'cat': 'VPN Hardening',
            'mod': 'IPsec Phase 1 Crypto',
            'hallazgo': f"VDOM '{vdom_name}': Túneles IPsec Phase 1 con algoritmos criptográficos débiles (Total: {len(weak_p1)})",
            'estado': 'WARNING' if weak_p1 else 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': f"VDOM {vdom_name} -> Túneles débiles: {len(weak_p1)}",
            'evidencia': crypto_summary[:250],
            'rec': 'Usar algoritmos robustos como AES256GCM o AES256-SHA256 con Diffie-Hellman 14+ conforme a SEG-LNB-002.',
            'rem': 'config vpn ipsec phase1-interface\n  edit "<Tunel>"\n    set proposal aes256gcm-sha256\n    set dhgrp 14\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.7 / ISO 27001 A.13.1.1'
        })

        # Check 2: Uso estricto de IKEv2
        ike_summary = f"Túneles usando IKEv1: {', '.join(ikev1_tunnels[:10])}" if ikev1_tunnels else "Todos los túneles utilizan IKEv2"
        checks.append({
            'id': f'CHK-IPSEC-SUMMARY-{vdom_prefix}-IKEV2',
            'vdom': vdom_name,
            'cat': 'VPN Hardening',
            'mod': 'IPsec IKE Version',
            'hallazgo': f"VDOM '{vdom_name}': Túneles IPsec que no configuran explícitamente IKEv2 (Total: {len(ikev1_tunnels)})",
            'estado': 'WARNING' if ikev1_tunnels else 'PASS',
            'sev': 'Media',
            'peso': 8,
            'afectados': f"VDOM {vdom_name} -> Sin IKEv2: {len(ikev1_tunnels)}",
            'evidencia': ike_summary[:250],
            'rec': 'Configurar IKE versión 2 (ike-version 2) para mayor seguridad corporativa conforme a SEG-LNB-002.',
            'rem': 'config vpn ipsec phase1-interface\n  edit "<Tunel>"\n    set ike-version 2\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.7'
        })

        # =====================================================================
        # FASE 2: IPSEC PHASE 2 (Selectores 0.0.0.0 / all, Asociación)
        # =====================================================================
        p2_block = extract_nested_block(vdom_content, "config vpn ipsec phase2-interface")
        p2_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', p2_block, re.DOTALL) if p2_block else []

        permissive_selectors = []
        p2_referenced_p1 = set()

        for p2_name, p2_body in p2_raw:
            phase1_m = re.search(r'set phase1name\s+"?([^"\n]+)"?', p2_body)
            if phase1_m:
                p2_referenced_p1.add(phase1_m.group(1).strip())

            # Validar selectores permisivos (0.0.0.0 o all)
            src_m = re.search(r'set src-addr\s+([^\n]+)', p2_body)
            dst_m = re.search(r'set dst-addr\s+([^\n]+)', p2_body)

            is_permissive = False
            for m in [src_m, dst_m]:
                if m:
                    val = m.group(1).lower()
                    if '0.0.0.0' in val or '"all"' in val or val.strip() == 'all':
                        is_permissive = True

            if is_permissive:
                permissive_selectors.append(p2_name)

        # Check 3: Selectores de tráfico restringidos (Evitar 0.0.0.0)
        sel_summary = f"Fase 2 permisivas: {', '.join(permissive_selectors[:10])}" if permissive_selectors else "Ningún selector permisivo (0.0.0.0 / all)"
        checks.append({
            'id': f'CHK-IPSEC-SUMMARY-{vdom_prefix}-SELECTORS',
            'vdom': vdom_name,
            'cat': 'VPN Hardening',
            'mod': 'IPsec Phase 2 Selectors',
            'hallazgo': f"VDOM '{vdom_name}': Selectores de Fase 2 con rangos abiertos/permisivos (0.0.0.0 o 'all') (Total: {len(permissive_selectors)})",
            'estado': 'WARNING' if permissive_selectors else 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': f"VDOM {vdom_name} -> Selectores abiertos: {len(permissive_selectors)}",
            'evidencia': sel_summary[:250],
            'rec': 'Restringir los selectores de tráfico (Proxy IDs) a subredes específicas y prohibir comodines 0.0.0.0 conforme a SEG-LNB-002.',
            'rem': 'config vpn ipsec phase2-interface\n  edit "<Phase2>"\n    set src-addr <Subred_Local>\n    set dst-addr <Subred_Remota>\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.7 / NIST AC-6'
        })

        # Check 4: Túneles sin Phase 2 asociada
        orphan_p1 = [p1 for p1 in p1_names if p1 not in p2_referenced_p1]
        orphan_summary = f"Túneles sin Phase 2: {', '.join(orphan_p1[:10])}" if orphan_p1 else "Todos los túneles tienen Phase 2 asociada"
        checks.append({
            'id': f'CHK-IPSEC-SUMMARY-{vdom_prefix}-PHASE2-ORPHANS',
            'vdom': vdom_name,
            'cat': 'VPN Hardening',
            'mod': 'IPsec Phase 2 Association',
            'hallazgo': f"VDOM '{vdom_name}': Túneles IPsec Phase 1 sin configuración de Phase 2 asociada (Total: {len(orphan_p1)})",
            'estado': 'WARNING' if orphan_p1 else 'PASS',
            'sev': 'Media',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Sin Phase 2: {len(orphan_p1)}",
            'evidencia': orphan_summary[:250],
            'rec': 'Asegurar que cada túnel IPsec cuente con su respectiva Phase 2 o eliminar los registros huérfanos.',
            'rem': 'config vpn ipsec phase1-interface\n  delete <Nombre_Tunel>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.7'
        })

    return checks
