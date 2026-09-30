# core/parser.py
import re
from datetime import datetime

def split_vdom_blocks(raw_text):
    """
    Separa el backup de FortiOS en bloques de texto reales por cada VDOM.
    Soporta:
      - Single-VDOM (root)
      - Multi-VDOM donde cada VDOM inicia con 'config vdom' seguido de 'edit <nombre>'
    """
    lines = raw_text.splitlines()
    
    # 1. Detectar si el firewall tiene VDOMs declarados al inicio
    # Ejemplo: config vdom \n edit root \n next \n edit IT ...
    declared_vdoms = []
    i = 0
    while i < min(100, len(lines)):
        if lines[i].strip() == "config vdom":
            i += 1
            while i < min(200, len(lines)):
                s = lines[i].strip()
                if s.startswith("edit "):
                    vname = s.split()[1].replace('"', '')
                    declared_vdoms.append(vname)
                elif s == "end":
                    break
                i += 1
            break
        i += 1

    if not declared_vdoms or len(declared_vdoms) <= 1:
        return {"root": raw_text}

    # 2. Particionar por los bloques reales de cada VDOM (a partir de la línea donde se reabre config vdom)
    vdom_blocks = {v: [] for v in declared_vdoms}
    current_vdom = None

    # Recorremos todas las líneas buscando los encabezados 'config vdom' -> 'edit <vdom>'
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        s = line.strip()

        # Detección del inicio de bloque de un VDOM:
        # Línea actual: config vdom
        # Siguiente línea: edit <vdom> (con o sin comillas)
        if s == "config vdom" and idx + 1 < len(lines):
            next_line = lines[idx + 1].strip()
            if next_line.startswith("edit "):
                target_vdom = next_line.split()[1].replace('"', '')
                if target_vdom in declared_vdoms and idx > 50:  # Omitir el encabezado inicial
                    current_vdom = target_vdom
                    idx += 2  # Saltar 'config vdom' y 'edit <vdom>'
                    continue

        if current_vdom:
            vdom_blocks[current_vdom].append(line)

        idx += 1

    # Si por alguna razón un VDOM no capturó líneas, dejamos fallback
    result = {}
    for v, lines_list in vdom_blocks.items():
        if lines_list:
            result[v] = "\n".join(lines_list)
        else:
            result[v] = raw_text

    return result if result else {"root": raw_text}

def parse_config(raw_text):
    lines = raw_text.splitlines()
    first_line = lines[0] if lines else ""

    # Versión y Modelo
    model_match = re.search(r'#config-version=([A-Za-z0-9\-_]+)-(\d+\.\d+\.\d+)-', first_line)
    build_match = re.search(r'build(\d+)', first_line)
    if model_match:
        model = model_match.group(1)
        version_num = model_match.group(2)
        build_num = build_match.group(1) if build_match else ""
        firmware_full = f"{model} FortiOS v{version_num} (build {build_num})"
    else:
        fw_fallback = re.search(r'#config-version=([^:\s]+)', first_line)
        firmware_full = fw_fallback.group(1) if fw_fallback else "Desconocido"
        version_num = "7.4"

    # Hostname y Serial
    host_match = re.search(r'set hostname "([^"]+)"', raw_text)
    hostname = host_match.group(1) if host_match else "FortiGate"

    serial_match = re.search(r'csf-device "([A-Za-z0-9]+)"', raw_text)
    if not serial_match:
        serial_match = re.search(r'set serial-number "([A-Za-z0-9]+)"', raw_text)
    serial = serial_match.group(1) if serial_match else "Desconocido"

    # Segmentación por bloques reales de VDOM
    vdom_blocks = split_vdom_blocks(raw_text)
    vdom_list = sorted(list(vdom_blocks.keys()))

    # Mapeo de interfaces globales
    parsed_ifaces = []
    seen = set()
    iface_blocks = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit "|\nend\b|\Z)', raw_text, re.DOTALL)
    for name, b in iface_blocks:
        if any(k in b for k in ['set allowaccess', 'set ip', 'set type', 'set vlanid', 'set role']):
            if name in seen:
                continue
            seen.add(name)

            access_m = re.search(r'set allowaccess\s+([^\n]+)', b)
            ip_m = re.search(r'set ip\s+([^\n]+)', b)
            vlan_m = re.search(r'set vlanid\s+(\d+)', b)
            parent_m = re.search(r'set interface\s+"([^"]+)"', b)
            status_m = re.search(r'set status\s+([^\n]+)', b)
            role_m = re.search(r'set role\s+([^\n]+)', b)
            vdom_m = re.search(r'set vdom\s+"([^"]+)"', b)

            parsed_ifaces.append({
                'name': name,
                'ip': ip_m.group(1) if ip_m else None,
                'role': role_m.group(1) if role_m else 'N/A',
                'parent': parent_m.group(1) if parent_m else '',
                'vlan': vlan_m.group(1) if vlan_m else None,
                'status': status_m.group(1) if status_m else 'up',
                'vdom': vdom_m.group(1) if vdom_m else 'root',
                'access': access_m.group(1).split() if access_m else []
            })

    return {
        'content': raw_text,
        'vdom_blocks': vdom_blocks,
        'parsed_interfaces': parsed_ifaces,
        'metadata': {
            'Hostname': hostname,
            'Firmware': firmware_full,
            'Version_Number': version_num,
            'Serial': serial,
            'VDOM': ", ".join(vdom_list),
            'VDOM_List': vdom_list,
            'Is_Multi_VDOM': len(vdom_list) > 1,
            'Fecha': datetime.now().strftime("%Y-%m-%d %H:%M")
        }
    }
