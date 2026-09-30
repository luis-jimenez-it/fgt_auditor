# modules/network/routing_protocols.py
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
    Auditoría Técnica Dinámica de Protocolos de Enrutamiento Dinámico (OSPF, BGP, RIP) VDOM por VDOM.
    Evalúa:
      1. OSPF: Autenticación de áreas/vecinos y parámetros de seguridad.
      2. BGP: Autenticación de vecinos (password) y control de AS.
      3. RIP: Detección de protocolo obsoleto/inseguro.
    Normativa: SEG-LNB-002 (Num 6.1 Enrutamiento y Control de Adyacencias), NIST SC-7, ISO 27001 A.13.1
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():

        # =====================================================================
        # 1. AUDITORÍA DE OSPF
        # =====================================================================
        ospf_block = extract_nested_block(vdom_content, "config router ospf")
        if not ospf_block and vdom_name == 'root':
            ospf_block = extract_nested_block(raw_content, "config router ospf")

        ospf_id = f"CHK-ROUTER-OSPF-{vdom_name.upper().replace('-', '_')}"
        if ospf_block:
            # Revisar autenticación global o por área
            auth_m = re.search(r'set default-information-originate|authentication\s+([a-z]+)', ospf_block)
            has_auth = False
            if "md5" in ospf_block.lower() or "simple" in ospf_block.lower():
                has_auth = True

            if not has_auth:
                checks.append({
                    'id': ospf_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Enrutamiento',
                    'mod': 'Enrutamiento Dinámico (OSPF)',
                    'hallazgo': f"VDOM '{vdom_name}': OSPF activo sin autenticación configurada (riesgo de inyección de rutas)",
                    'estado': 'FAIL',
                    'sev': 'Alta',
                    'peso': 10,
                    'afectados': f"VDOM {vdom_name} -> config router ospf",
                    'evidencia': 'No se detectó autenticación MD5 o simple en el bloque OSPF',
                    'rec': 'Habilitar autenticación OSPF (MD5) en las áreas e interfaces para proteger las adyacencias',
                    'rem': f'config vdom\nedit "{vdom_name}"\nconfig router ospf\n  config area\n    edit "0.0.0.0"\n      set authentication md5\n    next\n  end\nend\nnext\nend',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.6 / NIST SC-7'
                })
            else:
                checks.append({
                    'id': ospf_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Enrutamiento',
                    'mod': 'Enrutamiento Dinámico (OSPF)',
                    'hallazgo': f"VDOM '{vdom_name}': OSPF configurado con mecanismos de autenticación",
                    'estado': 'PASS',
                    'sev': 'Baja',
                    'peso': 5,
                    'afectados': f"VDOM {vdom_name} -> config router ospf",
                    'evidencia': 'Autenticación detectada en áreas/interfaces OSPF',
                    'rec': 'Mantener monitoreo de adyacencias OSPF',
                    'rem': 'N/A - Cumple',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.6 / NIST SC-7'
                })
        else:
            checks.append({
                'id': ospf_id,
                'vdom': vdom_name,
                'cat': 'Red y Enrutamiento',
                'mod': 'Enrutamiento Dinámico (OSPF)',
                'hallazgo': f"VDOM '{vdom_name}': OSPF no se encuentra activo",
                'estado': 'INFO',
                'sev': 'Baja',
                'peso': 0,
                'afectados': f"VDOM {vdom_name} -> config router ospf",
                'evidencia': 'Bloque OSPF ausente',
                'rec': 'N/A - Informativo',
                'rem': 'N/A - Informativo',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.6 / NIST SC-7'
            })

        # =====================================================================
        # 2. AUDITORÍA DE BGP
        # =====================================================================
        bgp_block = extract_nested_block(vdom_content, "config router bgp")
        if not bgp_block and vdom_name == 'root':
            bgp_block = extract_nested_block(raw_content, "config router bgp")

        bgp_id = f"CHK-ROUTER-BGP-{vdom_name.upper().replace('-', '_')}"
        if bgp_block:
            # Extraer vecinos y revisar si tienen password
            neighbors = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', bgp_block, re.DOTALL)
            insecure_neighbors = []

            for n_ip, n_body in neighbors:
                if 'set password' not in n_body:
                    insecure_neighbors.append(n_ip)

            if insecure_neighbors:
                checks.append({
                    'id': bgp_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Enrutamiento',
                    'mod': 'Enrutamiento Dinámico (BGP)',
                    'hallazgo': f"VDOM '{vdom_name}': Se detectaron {len(insecure_neighbors)} vecino(s) BGP sin contraseña de autenticación configurada",
                    'estado': 'FAIL',
                    'sev': 'Alta',
                    'peso': 10,
                    'afectados': f"VDOM {vdom_name} -> vecinos BGP: {', '.join(insecure_neighbors[:3])}",
                    'evidencia': f"Vecinos sin set password: {'; '.join(insecure_neighbors[:3])}",
                    'rec': 'Configurar MD5 password en cada vecino BGP para evitar suplantación de sesiones',
                    'rem': f'config vdom\nedit "{vdom_name}"\nconfig router bgp\n  config neighbor\n    edit "<IP_Vecino>"\n      set password "<password>"\n    next\n  end\nend\nnext\nend',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.6 / NIST SC-7'
                })
            else:
                checks.append({
                    'id': bgp_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Enrutamiento',
                    'mod': 'Enrutamiento Dinámico (BGP)',
                    'hallazgo': f"VDOM '{vdom_name}': Todos los vecinos BGP cuentan con autenticación configurada",
                    'estado': 'PASS',
                    'sev': 'Baja',
                    'peso': 5,
                    'afectados': f"VDOM {vdom_name} -> config router bgp",
                    'evidencia': 'Autenticación detectada en vecinos BGP',
                    'rec': 'Mantener control de políticas de anuncios BGP (Prefix Lists / Route Maps)',
                    'rem': 'N/A - Cumple',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.6 / NIST SC-7'
                })
        else:
            checks.append({
                'id': bgp_id,
                'vdom': vdom_name,
                'cat': 'Red y Enrutamiento',
                'mod': 'Enrutamiento Dinámico (BGP)',
                'hallazgo': f"VDOM '{vdom_name}': BGP no se encuentra activo",
                'estado': 'INFO',
                'sev': 'Baja',
                'peso': 0,
                'afectados': f"VDOM {vdom_name} -> config router bgp",
                'evidencia': 'Bloque BGP ausente',
                'rec': 'N/A - Informativo',
                'rem': 'N/A - Informativo',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.6 / NIST SC-7'
            })

        # =====================================================================
        # 3. AUDITORÍA DE RIP
        # =====================================================================
        rip_block = extract_nested_block(vdom_content, "config router rip")
        if not rip_block and vdom_name == 'root':
            rip_block = extract_nested_block(raw_content, "config router rip")

        rip_id = f"CHK-ROUTER-RIP-{vdom_name.upper().replace('-', '_')}"
        if rip_block:
            checks.append({
                'id': rip_id,
                'vdom': vdom_name,
                'cat': 'Red y Enrutamiento',
                'mod': 'Enrutamiento Dinámico (RIP)',
                'hallazgo': f"VDOM '{vdom_name}': Protocolo RIP activo (Protocolo obsoleto e inseguro)",
                'estado': 'FAIL',
                'sev': 'Alta',
                'peso': 10,
                'afectados': f"VDOM {vdom_name} -> config router rip",
                'evidencia': 'Bloque config router rip presente en la configuración',
                'rec': 'Desactivar RIP y migrar hacia protocolos modernos y seguros como OSPF o BGP',
                'rem': f'config vdom\nedit "{vdom_name}"\nconfig router rip\n  set status disable\nend\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.6 / NIST SC-7'
            })
        else:
            checks.append({
                'id': rip_id,
                'vdom': vdom_name,
                'cat': 'Red y Enrutamiento',
                'mod': 'Enrutamiento Dinámico (RIP)',
                'hallazgo': f"VDOM '{vdom_name}': Sin protocolo RIP activo (Correcto)",
                'estado': 'PASS',
                'sev': 'Baja',
                'peso': 5,
                'afectados': f"VDOM {vdom_name} -> config router rip",
                'evidencia': 'RIP deshabilitado o ausente',
                'rec': 'Mantener estándares de enrutamiento seguro',
                'rem': 'N/A - Cumple',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.6 / NIST SC-7'
            })

    return checks
