from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

NULLARY_COMPONENT_CASES = {
    "IOLabel",
    "NotConnected",
    "Not",
    "Decode4",
    "Mux2",
    "Mux4",
    "Mux8",
    "Demux2",
    "Demux4",
    "Demux8",
    "DFF",
    "DFFE",
    "MergeWires",
}

LEGACY_GATE_CASES = {"And", "Or", "Xor", "Nand", "Nor", "Xnor"}

SEQUENTIAL_COMPONENT_CASES = {
    "DFF",
    "DFFE",
    "Register",
    "RegisterE",
    "Counter",
    "CounterNoEnable",
    "CounterNoLoad",
    "CounterNoEnableLoad",
    "RAM1",
    "AsyncRAM1",
    "ROM1",
    "AsyncROM1",
}

@dataclass
class WarningCollector:
    warnings: List[str] = field(default_factory=list)

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)


@dataclass
class SheetRecord:
    project_dir: str
    sheet_name: str
    components: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]
    input_signature: List[Dict[str, Any]]
    output_signature: List[Dict[str, Any]]
    warnings: List[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Parse an Issie .dgm file into a semantic JSON structure that is easier "
            "for an LLM to understand."
        )
    )
    parser.add_argument("input", nargs="?", help="Path to a .dgm file or a project directory.")
    parser.add_argument("--project-dir", help="Project directory containing .dgm sheets.")
    parser.add_argument("--sheet", help="Sheet name or path to parse when a project directory is used.")
    parser.add_argument("--output", help="Write JSON output to this path. Defaults to a sibling .json file next to the selected .dgm.")
    parser.add_argument(
        "--max-hierarchy-depth",
        type=int,
        default=6,
        help="Maximum custom-module expansion depth.",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Deprecated; compact JSON is now the default output format.",
    )
    parser.add_argument(
        "--include-layout",
        action="store_true",
        help="Include more detailed component and wire layout information.",
    )
    parser.add_argument(
        "--expand-modules",
        action="store_true",
        help="Deprecated; expanded module bodies are now included by default.",
    )
    parser.add_argument(
        "--root-only",
        action="store_true",
        help="Only include the root module body; referenced modules are reduced to interface summaries.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON. By default the exporter writes compact JSON to reduce token count.",
    )
    return parser.parse_args()


def choose_path_via_gui(input_arg: Optional[str], project_dir_arg: Optional[str], sheet_arg: Optional[str]) -> str:
    if input_arg:
        candidate = Path(input_arg).expanduser().resolve()
        if candidate.is_file():
            return str(candidate)
        if candidate.is_dir():
            return choose_sheet_from_project_dir(str(candidate), sheet_arg)
        raise FileNotFoundError(f"Input path does not exist: {candidate}")

    if project_dir_arg:
        return choose_sheet_from_project_dir(project_dir_arg, sheet_arg)

    chosen = gui_choose_input_file(None)
    if chosen is None:
        raise RuntimeError("No .dgm sheet selected.")
    return str(chosen)


def choose_sheet_from_project_dir(project_dir: Optional[str], sheet_arg: Optional[str]) -> str:
    project_path = Path(project_dir).expanduser().resolve() if project_dir else None

    if sheet_arg:
        sheet_candidate = Path(sheet_arg)
        if sheet_candidate.exists():
            return str(sheet_candidate.expanduser().resolve())
        if sheet_candidate.suffix.lower() == ".dgm":
            return str((project_path / sheet_candidate.name).resolve())
        return str((project_path / f"{sheet_arg}.dgm").resolve())

    if project_path is None:
        chosen = gui_choose_input_file(None)
    else:
        chosen = gui_choose_input_file(project_path)
    if chosen is None:
        raise RuntimeError("No .dgm sheet selected.")
    return str(chosen)


def gui_choose_input_file(initial_dir: Optional[Path]) -> Optional[Path]:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception:
        if initial_dir is not None:
            dgm_files = sorted(initial_dir.glob("*.dgm"))
            if len(dgm_files) == 1:
                return dgm_files[0]
            if len(dgm_files) > 1:
                raise RuntimeError(
                    "Tkinter is unavailable, so GUI file selection cannot be shown. "
                    "Please pass a specific .dgm path."
                )
        return None

    root = tk.Tk()
    root.withdraw()
    root.update()
    dialog_kwargs: Dict[str, Any] = {
        "title": "Select Issie .dgm sheet",
        "filetypes": [("Issie sheet", "*.dgm"), ("All files", "*.*")],
    }
    if initial_dir is not None:
        dialog_kwargs["initialdir"] = str(initial_dir)
    selected = filedialog.askopenfilename(**dialog_kwargs)
    root.destroy()
    if not selected:
        return None
    return Path(selected).expanduser().resolve()


def load_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


JSON_DECODER = json.JSONDecoder()


def extract_json_value_fragment(text: str, start_index: int) -> Tuple[Any, str, int]:
    index = start_index
    length = len(text)
    while index < length and text[index].isspace():
        index += 1
    value, consumed = JSON_DECODER.raw_decode(text[index:])
    end_index = index + consumed
    return value, text[index:end_index], end_index


def extract_object_field(text: str, object_start: int, field_name: str, search_limit: int = 16000) -> Optional[Tuple[Any, str, int]]:
    limit = min(len(text), object_start + search_limit)
    key = f'"{field_name}"'
    key_index = text.find(key, object_start, limit)
    if key_index < 0:
        return None
    colon_index = text.find(":", key_index + len(key), limit)
    if colon_index < 0:
        return None
    try:
        return extract_json_value_fragment(text, colon_index + 1)
    except json.JSONDecodeError:
        return None


def recover_components_from_text(raw_text: str, warnings: WarningCollector) -> List[Dict[str, Any]]:
    recovered_by_id: Dict[str, Tuple[int, Dict[str, Any]]] = {}
    recovered_by_signature: Dict[str, Tuple[int, Dict[str, Any]]] = {}

    for match in re.finditer(r'\{"Id"\s*:', raw_text):
        start = match.start()
        id_field = extract_object_field(raw_text, start, "Id", search_limit=400)
        type_field = extract_object_field(raw_text, start, "Type", search_limit=4000)
        label_field = extract_object_field(raw_text, start, "Label", search_limit=5000)
        input_ports_field = extract_object_field(raw_text, start, "InputPorts", search_limit=9000)
        output_ports_field = extract_object_field(raw_text, start, "OutputPorts", search_limit=12000)

        if not all([id_field, type_field, label_field, input_ports_field, output_ports_field]):
            continue

        comp_id = id_field[0]
        if not isinstance(comp_id, str):
            continue

        x_field = extract_object_field(raw_text, start, "X")
        y_field = extract_object_field(raw_text, start, "Y")
        h_field = extract_object_field(raw_text, start, "H")
        w_field = extract_object_field(raw_text, start, "W")
        symbol_info_field = extract_object_field(raw_text, start, "SymbolInfo", search_limit=30000)

        component = {
            "Id": comp_id,
            "Type": type_field[0],
            "Label": label_field[0],
            "InputPorts": input_ports_field[0],
            "OutputPorts": output_ports_field[0],
            "X": x_field[0] if x_field else 0,
            "Y": y_field[0] if y_field else 0,
            "H": h_field[0] if h_field else 0,
            "W": w_field[0] if w_field else 0,
            "SymbolInfo": symbol_info_field[0] if symbol_info_field else None,
        }

        completeness = sum(
            1
            for key in ("X", "Y", "H", "W", "SymbolInfo")
            if component.get(key) not in (None, 0, {}, [])
        )

        previous = recovered_by_id.get(comp_id)
        if previous is None or completeness >= previous[0]:
            recovered_by_id[comp_id] = (completeness, component)

        signature = json.dumps(
            {
                "Label": component["Label"],
                "Type": component["Type"],
                "InputPorts": [
                    {
                        "PortNumber": port.get("PortNumber"),
                        "PortType": port.get("PortType"),
                    }
                    for port in component["InputPorts"]
                ],
                "OutputPorts": [
                    {
                        "PortNumber": port.get("PortNumber"),
                        "PortType": port.get("PortType"),
                    }
                    for port in component["OutputPorts"]
                ],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        previous_sig = recovered_by_signature.get(signature)
        if previous_sig is None or completeness >= previous_sig[0]:
            recovered_by_signature[signature] = (completeness, component)

    recovered = list(recovered_by_signature.values()) if recovered_by_signature else list(recovered_by_id.values())

    if recovered:
        warnings.warn(
            "Recovered component list from malformed .dgm text; this file does not appear to be valid JSON, so some metadata may be approximate."
        )
    return [item[1] for item in recovered]


def recover_connections_from_text(raw_text: str, warnings: WarningCollector) -> List[Dict[str, Any]]:
    recovered: Dict[str, Tuple[int, Dict[str, Any]]] = {}

    for match in re.finditer(r'\{"Id"\s*:', raw_text):
        start = match.start()
        id_field = extract_object_field(raw_text, start, "Id", search_limit=400)
        source_field = extract_object_field(raw_text, start, "Source", search_limit=4000)
        target_field = extract_object_field(raw_text, start, "Target", search_limit=6000)
        if not all([id_field, source_field, target_field]):
            continue

        conn_id = id_field[0]
        if not isinstance(conn_id, str):
            continue

        vertices_field = extract_object_field(raw_text, start, "Vertices", search_limit=12000)
        connection = {
            "Id": conn_id,
            "Source": source_field[0],
            "Target": target_field[0],
            "Vertices": vertices_field[0] if vertices_field else [],
        }
        completeness = 1 if vertices_field else 0
        signature = json.dumps(
            {
                "SourceHostId": connection["Source"].get("HostId"),
                "SourceId": connection["Source"].get("Id"),
                "TargetHostId": connection["Target"].get("HostId"),
                "TargetId": connection["Target"].get("Id"),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        previous = recovered.get(signature)
        if previous is None or completeness >= previous[0]:
            recovered[signature] = (completeness, connection)

    if recovered:
        warnings.warn(
            "Recovered connection list from malformed .dgm text; direct wire routes may be incomplete if the saved file was truncated."
        )
    return [item[1] for item in recovered.values()]


def recover_sheet_info_from_text(raw_text: str) -> Any:
    matches = list(
        re.finditer(
            r'\{"Form"\s*:\s*(null|"[^"]*")(?:\s*,\s*"Description"\s*:\s*(null|"[^"]*"))?(?:\s*,\s*"(?:ParameterDefinitions|ParameterSlots)"\s*:\s*(?:null|\{.*?\}))?\s*\}',
            raw_text,
            re.DOTALL,
        )
    )
    if not matches:
        return None
    for match in reversed(matches):
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            continue
    return None


def recover_timestamp_from_text(raw_text: str) -> Optional[str]:
    matches = re.findall(r'"(\d{4}-\d{2}-\d{2}T[^"]+)"', raw_text)
    return matches[-1] if matches else None


def recover_saved_state_from_text(raw_text: str, warnings: WarningCollector) -> Optional[Tuple[str, List[Any], Any, Any, Any]]:
    save_variant = None
    for candidate in (
        "NewCanvasWithFileWaveSheetInfoAndNewConns",
        "NewCanvasWithFileWaveInfoAndNewConns",
        "CanvasWithFileWaveInfoAndNewConns",
        "CanvasWithFileWaveInfo",
        "CanvasOnly",
    ):
        if candidate in raw_text:
            save_variant = candidate
            break

    if save_variant is None:
        return None

    components = recover_components_from_text(raw_text, warnings)
    connections = recover_connections_from_text(raw_text, warnings)
    if not components and not connections:
        return None

    sheet_info = recover_sheet_info_from_text(raw_text)
    timestamp = recover_timestamp_from_text(raw_text)
    warnings.warn(
        f"Recovered malformed '{save_variant}' text without parsing the full saved JSON envelope. Waveform/config metadata was ignored."
    )
    return save_variant, [components, connections], None, sheet_info, timestamp


def load_saved_state_from_backup(path: str, warnings: WarningCollector) -> Optional[Tuple[str, List[Any], Any, Any, Any]]:
    source = Path(path).expanduser().resolve()
    backup_dir = source.parent / "backup"
    if not backup_dir.exists():
        return None

    candidates = sorted(backup_dir.glob(f"{source.stem}-*.dgm"), key=lambda item: item.stat().st_mtime, reverse=True)
    for candidate in candidates:
        try:
            raw_text = load_text(str(candidate))
            obj = json.loads(raw_text)
            warnings.warn(
                f"Primary file '{source.name}' was malformed, so a valid backup '{candidate.name}' from the same Issie project folder was used instead."
            )
            return extract_saved_state(obj, warnings)
        except Exception:
            continue
    return None


def decode_union(value: Any) -> Tuple[str, Any]:
    if isinstance(value, str):
        return value, None
    if isinstance(value, dict) and len(value) == 1:
        case_name, payload = next(iter(value.items()))
        return case_name, payload
    raise ValueError(f"Expected Issie union encoding, got: {value!r}")


def parse_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if text == "":
            return default
        try:
            return int(text, 10)
        except ValueError:
            return default
    return default


def stringify_bigint(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value))
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def format_numeric_value(value: Any) -> Optional[Dict[str, Any]]:
    text = stringify_bigint(value)
    if text is None:
        return None
    try:
        int_value = int(text, 10)
    except Exception:
        return {"decimal": text}
    result: Dict[str, Any] = {"decimal": str(int_value)}
    if int_value >= 0:
        result["hex"] = hex(int_value)
        result["binary"] = bin(int_value)
    return result


def map_from_pairs(value: Any, key_parser=lambda x: x, value_parser=lambda x: x) -> Dict[Any, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return {key_parser(k): value_parser(v) for k, v in value.items()}
    result = {}
    if isinstance(value, list):
        for entry in value:
            if isinstance(entry, list) and len(entry) == 2:
                key, item = entry
                result[key_parser(key)] = value_parser(item)
    return result


def parse_param_name(value: Any) -> str:
    if isinstance(value, dict) and "ParamName" in value:
        return str(value["ParamName"])
    if isinstance(value, str):
        return value
    return str(value)


def parse_param_expression(expr: Any, warnings: WarningCollector) -> Dict[str, Any]:
    if expr is None:
        return {"kind": "null", "rendered": "null"}

    case_name, payload = decode_union(expr)
    if case_name == "PInt":
        return {"kind": "integer", "value": parse_int(payload), "rendered": str(parse_int(payload))}
    if case_name == "PParameter":
        name = parse_param_name(payload)
        return {"kind": "parameter_reference", "name": name, "rendered": name}
    if case_name in {"PAdd", "PSubtract", "PMultiply", "PDivide", "PRemainder"} and isinstance(payload, list) and len(payload) == 2:
        left = parse_param_expression(payload[0], warnings)
        right = parse_param_expression(payload[1], warnings)
        operator_map = {
            "PAdd": "+",
            "PSubtract": "-",
            "PMultiply": "*",
            "PDivide": "/",
            "PRemainder": "%",
        }
        operator = operator_map[case_name]
        return {
            "kind": "binary_expression",
            "operator": operator,
            "left": left,
            "right": right,
            "rendered": f"({left['rendered']} {operator} {right['rendered']})",
        }

    warnings.warn(f"Unrecognized parameter expression shape: {expr!r}")
    return {
        "kind": "unrecognized_expression",
        "raw": expr,
        "rendered": json.dumps(expr, ensure_ascii=False),
    }


def parse_memory1(value: Any) -> Dict[str, Any]:
    return {
        "address_width_bits": parse_int(value.get("AddressWidth")) if isinstance(value, dict) else None,
        "word_width_bits": parse_int(value.get("WordWidth")) if isinstance(value, dict) else None,
    }


def normalize_component_type(raw_type: Any, warnings: WarningCollector) -> Dict[str, Any]:
    case_name, payload = decode_union(raw_type)
    normalized_case = case_name

    if case_name in LEGACY_GATE_CASES:
        normalized_case = "GateN"
        payload = [case_name.lower(), 2]
    elif case_name == "Input":
        normalized_case = "Input1"
        payload = [payload, None]
    elif case_name == "Constant":
        width, value = payload
        normalized_case = "Constant1"
        payload = [width, value, stringify_bigint(value)]
    elif case_name == "BusCompare":
        width, value = payload
        normalized_case = "BusCompare1"
        payload = [width, value, stringify_bigint(value)]
    elif case_name in {"RAM", "ROM", "AsyncROM"}:
        normalized_case = {"RAM": "RAM1", "ROM": "ROM1", "AsyncROM": "AsyncROM1"}[case_name]
        payload = {
            "Init": "FromData",
            "AddressWidth": payload.get("AddressWidth") if isinstance(payload, dict) else None,
            "WordWidth": payload.get("WordWidth") if isinstance(payload, dict) else None,
            "Data": payload.get("Data") if isinstance(payload, dict) else [],
        }

    parsed: Dict[str, Any] = {"case": normalized_case}

    if normalized_case in NULLARY_COMPONENT_CASES:
        parsed["parameters"] = {}
        return parsed

    if normalized_case == "Input1":
        bus_width = parse_int(payload[0]) if isinstance(payload, list) and len(payload) >= 1 else None
        default_value = payload[1] if isinstance(payload, list) and len(payload) >= 2 else None
        parsed["parameters"] = {"bus_width_bits": bus_width, "default_value": format_numeric_value(default_value)}
        return parsed

    single_width_cases = {
        "Output",
        "Viewer",
        "Register",
        "RegisterE",
        "Counter",
        "CounterNoLoad",
        "CounterNoEnable",
        "CounterNoEnableLoad",
        "NbitsAdder",
        "NbitsAdderNoCin",
        "NbitsAdderNoCout",
        "NbitsAdderNoCinCout",
        "NbitsAnd",
        "NbitsOr",
        "NbitsNot",
        "NbitSpreader",
        "SplitWire",
    }
    if normalized_case in single_width_cases:
        parsed["parameters"] = {"bus_width_bits": parse_int(payload)}
        return parsed

    if normalized_case == "BusSelection":
        out_width, lsb = payload
        out_width = parse_int(out_width)
        lsb = parse_int(lsb)
        parsed["parameters"] = {
            "output_width_bits": out_width,
            "lsb_index": lsb,
            "msb_index": lsb + out_width - 1 if out_width is not None and lsb is not None else None,
        }
        return parsed

    if normalized_case == "Constant1":
        width, const_value, dialog_text = payload
        parsed["parameters"] = {"bus_width_bits": parse_int(width), "value": format_numeric_value(const_value), "display_text": dialog_text}
        return parsed

    if normalized_case == "BusCompare1":
        width, compare_value, dialog_text = payload
        parsed["parameters"] = {"input_width_bits": parse_int(width), "compare_value": format_numeric_value(compare_value), "display_text": dialog_text}
        return parsed

    if normalized_case == "GateN":
        gate_type_raw, input_count = payload
        gate_type = str(gate_type_raw).upper() if isinstance(gate_type_raw, str) else str(gate_type_raw)
        parsed["parameters"] = {"gate_type": gate_type, "input_count": parse_int(input_count)}
        return parsed

    if normalized_case == "MergeN":
        parsed["parameters"] = {"input_count": parse_int(payload)}
        return parsed

    if normalized_case == "SplitN":
        num_outputs, widths, lsbs = payload
        widths = [parse_int(item) for item in widths]
        lsbs = [parse_int(item) for item in lsbs]
        slices = []
        for index, (width, lsb) in enumerate(zip(widths, lsbs)):
            msb = lsb + width - 1 if width is not None and lsb is not None else None
            slices.append({"output_index": index, "width_bits": width, "lsb_index": lsb, "msb_index": msb})
        parsed["parameters"] = {
            "output_count": parse_int(num_outputs),
            "output_widths_bits": widths,
            "output_lsbs": lsbs,
            "slices": slices,
        }
        return parsed

    if normalized_case == "Custom":
        custom = payload or {}
        input_labels = [{"label": label, "width_bits": parse_int(width)} for label, width in custom.get("InputLabels", [])]
        output_labels = [{"label": label, "width_bits": parse_int(width)} for label, width in custom.get("OutputLabels", [])]
        param_bindings = map_from_pairs(
            custom.get("ParameterBindings"),
            key_parser=parse_param_name,
            value_parser=lambda expr: parse_param_expression(expr, warnings),
        )
        parsed["parameters"] = {
            "sheet_name": custom.get("Name"),
            "input_labels": input_labels,
            "output_labels": output_labels,
            "parameter_bindings": param_bindings,
        }
        return parsed

    if normalized_case == "Shift":
        bus_width, shifter_width, shift_type = payload
        parsed["parameters"] = {
            "input_bus_width_bits": parse_int(bus_width),
            "shifter_bus_width_bits": parse_int(shifter_width),
            "shift_type": shift_type,
        }
        return parsed

    if normalized_case == "NbitsXor":
        bus_width, arithmetic_op = payload
        parsed["parameters"] = {
            "bus_width_bits": parse_int(bus_width),
            "mode": "MULTIPLY" if arithmetic_op == "Multiply" else "XOR",
            "raw_mode": arithmetic_op,
        }
        return parsed

    if normalized_case in {"RAM1", "ROM1", "AsyncRAM1", "AsyncROM1"}:
        parsed["parameters"] = parse_memory1(payload)
        return parsed

    warnings.warn(f"Unrecognized or not yet normalized component type: {raw_type!r}")
    parsed["parameters"] = {"raw_payload": payload}
    return parsed


def parse_port(port: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": port.get("Id"),
        "port_number": parse_int(port.get("PortNumber")),
        "direction": str(port.get("PortType", "")).lower(),
        "host_component_id": port.get("HostId"),
    }


def parse_symbol_info(symbol_info: Any) -> Dict[str, Any]:
    if not isinstance(symbol_info, dict):
        return {}
    label_box = symbol_info.get("LabelBoundingBox")
    return {
        "rotation": symbol_info.get("STransform", {}).get("Rotation") if isinstance(symbol_info.get("STransform"), dict) else None,
        "flipped": symbol_info.get("STransform", {}).get("flipped") if isinstance(symbol_info.get("STransform"), dict) else None,
        "reversed_input_ports": symbol_info.get("ReversedInputPorts"),
        "port_orientation": map_from_pairs(symbol_info.get("PortOrientation")),
        "port_order": map_from_pairs(symbol_info.get("PortOrder")),
        "label_rotation": symbol_info.get("LabelRotation"),
        "label_box": {
            "x": label_box.get("TopLeft", {}).get("X"),
            "y": label_box.get("TopLeft", {}).get("Y"),
            "width": label_box.get("W"),
            "height": label_box.get("H"),
        }
        if isinstance(label_box, dict)
        else None,
        "h_scale": symbol_info.get("HScale"),
        "v_scale": symbol_info.get("VScale"),
    }


def parse_component(component: Dict[str, Any], warnings: WarningCollector) -> Dict[str, Any]:
    ctype = normalize_component_type(component.get("Type"), warnings)
    return {
        "id": component.get("Id"),
        "label": component.get("Label", ""),
        "type": ctype,
        "input_ports_raw": [parse_port(port) for port in component.get("InputPorts", [])],
        "output_ports_raw": [parse_port(port) for port in component.get("OutputPorts", [])],
        "layout": {"x": component.get("X"), "y": component.get("Y"), "width": component.get("W"), "height": component.get("H")},
        "symbol_info": parse_symbol_info(component.get("SymbolInfo")),
    }


def parse_connection_vertices(vertices: Any) -> List[Dict[str, Any]]:
    result = []
    for vertex in vertices or []:
        if not isinstance(vertex, list):
            continue
        if len(vertex) == 3:
            x, y, manual = vertex
        elif len(vertex) == 2:
            x, y = vertex
            manual = (x < 0) or (y < 0)
            x, y = abs(x), abs(y)
        else:
            continue
        result.append({"x": x, "y": y, "manual": bool(manual)})
    return result


def parse_connection(connection: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": connection.get("Id"),
        "source": parse_port(connection.get("Source", {})),
        "target": parse_port(connection.get("Target", {})),
        "vertices": parse_connection_vertices(connection.get("Vertices")),
    }


def convert_legacy_component(component: Dict[str, Any], magnify: bool) -> Dict[str, Any]:
    x = component.get("X", 0)
    y = component.get("Y", 0)
    w = component.get("W", 0)
    h = component.get("H", 0)
    if magnify:
        x = 1.25 * (x + w / 2.0)
        y = 1.25 * (y + h / 2.0)
        w = -1
        h = -1
    return {
        "Id": component.get("Id"),
        "Type": component.get("Type"),
        "Label": component.get("Label", ""),
        "InputPorts": component.get("InputPorts", []),
        "OutputPorts": component.get("OutputPorts", []),
        "X": x,
        "Y": y,
        "W": w,
        "H": h,
        "SymbolInfo": None,
    }


def extract_saved_state(obj: Any, warnings: WarningCollector) -> Tuple[str, List[Any], Any, Any, Any]:
    if isinstance(obj, dict) and len(obj) == 1:
        save_variant, payload = next(iter(obj.items()))
        known = {
            "CanvasOnly",
            "CanvasWithFileWaveInfo",
            "CanvasWithFileWaveInfoAndNewConns",
            "NewCanvasWithFileWaveInfoAndNewConns",
            "NewCanvasWithFileWaveSheetInfoAndNewConns",
        }
        if save_variant in known:
            if save_variant == "CanvasOnly":
                return save_variant, payload, None, None, None
            if isinstance(payload, list):
                canvas = payload[0] if len(payload) > 0 else None
                wave_info = payload[1] if len(payload) > 1 else None
                sheet_info = payload[2] if save_variant == "NewCanvasWithFileWaveSheetInfoAndNewConns" and len(payload) > 2 else None
                timestamp = payload[3] if save_variant == "NewCanvasWithFileWaveSheetInfoAndNewConns" and len(payload) > 3 else payload[2] if len(payload) > 2 else None
                return save_variant, canvas, wave_info, sheet_info, timestamp
        warnings.warn("Top-level object did not match a known SavedInfo union case; trying raw canvas interpretation.")

    if isinstance(obj, list) and len(obj) == 2:
        return "RawCanvasState", obj, None, None, None

    raise ValueError("Unsupported .dgm top-level structure.")


def normalize_canvas_from_saved_state(save_variant: str, canvas_payload: Any, warnings: WarningCollector) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    if not (isinstance(canvas_payload, list) and len(canvas_payload) == 2):
        raise ValueError(f"Expected canvas payload to be [components, connections], got: {type(canvas_payload).__name__}")

    components_raw, connections_raw = canvas_payload

    if save_variant in {"CanvasOnly", "CanvasWithFileWaveInfo"}:
        components = [convert_legacy_component(component, magnify=True) for component in components_raw]
        connections = [{"Id": conn.get("Id"), "Source": conn.get("Source", {}), "Target": conn.get("Target", {}), "Vertices": []} for conn in connections_raw]
    elif save_variant == "CanvasWithFileWaveInfoAndNewConns":
        components = [convert_legacy_component(component, magnify=False) for component in components_raw]
        connections = connections_raw
    else:
        components = components_raw
        connections = connections_raw

    parsed_components = [parse_component(component, warnings) for component in components]
    parsed_connections = [parse_connection(connection) for connection in connections]
    return parsed_components, parsed_connections


def diagram_signature(components: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    def ordered(case_name: str) -> List[Dict[str, Any]]:
        matches = []
        for component in components:
            if component["type"]["case"] != case_name:
                continue
            width = component["type"]["parameters"].get("bus_width_bits")
            matches.append((component["layout"]["y"], component["layout"]["x"], {"label": component["label"], "width_bits": width, "component_id": component["id"]}))
        matches.sort(key=lambda item: (item[0], item[1]))
        return [item[2] for item in matches]

    return ordered("Input1"), ordered("Output")


def load_sheet_record(path: str) -> SheetRecord:
    path = str(Path(path).expanduser().resolve())
    warnings = WarningCollector()
    raw_text = load_text(path)
    try:
        obj = json.loads(raw_text)
        save_variant, canvas_payload, _wave_info, _sheet_info_raw, _timestamp = extract_saved_state(obj, warnings)
    except json.JSONDecodeError as exc:
        warnings.warn(f"Standard JSON parsing failed for '{path}': {exc}. Trying tolerant text recovery.")
        backup_state = load_saved_state_from_backup(path, warnings)
        if backup_state is not None:
            save_variant, canvas_payload, _wave_info, _sheet_info_raw, _timestamp = backup_state
        else:
            recovered = recover_saved_state_from_text(raw_text, warnings)
            if recovered is None:
                raise
            save_variant, canvas_payload, _wave_info, _sheet_info_raw, _timestamp = recovered
    components, connections = normalize_canvas_from_saved_state(save_variant, canvas_payload, warnings)
    input_signature, output_signature = diagram_signature(components)
    return SheetRecord(
        project_dir=str(Path(path).parent),
        sheet_name=Path(path).stem,
        components=components,
        connections=connections,
        input_signature=input_signature,
        output_signature=output_signature,
        warnings=warnings.warnings,
    )


def custom_module_name(component: Dict[str, Any]) -> Optional[str]:
    if component["type"]["case"] != "Custom":
        return None
    return component["type"]["parameters"].get("sheet_name")


def resolve_referenced_sheets(root: SheetRecord, max_depth: int) -> Tuple[Dict[str, SheetRecord], List[str]]:
    records: Dict[str, SheetRecord] = {root.sheet_name: root}
    global_warnings: List[str] = []
    visiting: List[str] = []

    def recurse(record: SheetRecord, depth: int) -> None:
        if depth >= max_depth:
            global_warnings.append(f"Stopped hierarchy expansion at depth {max_depth} while visiting sheet '{record.sheet_name}'.")
            return
        visiting.append(record.sheet_name)
        for component in record.components:
            module_name = custom_module_name(component)
            if not module_name:
                continue
            if module_name in visiting:
                global_warnings.append(f"Detected recursive custom-module reference: {' -> '.join(visiting + [module_name])}")
                continue
            if module_name in records:
                continue
            candidate = Path(record.project_dir) / f"{module_name}.dgm"
            if not candidate.exists():
                global_warnings.append(
                    f"Custom component instance '{component['label']}' references sheet '{module_name}.dgm', but that file was not found in {record.project_dir}."
                )
                continue
            child = load_sheet_record(str(candidate))
            records[module_name] = child
            recurse(child, depth + 1)
        visiting.pop()

    recurse(root, 0)
    return records, global_warnings


def safe_port_index(port: Dict[str, Any], fallback: int) -> int:
    return port.get("port_number") if port.get("port_number") is not None else fallback


def module_contains_state(module_record: Optional[SheetRecord], resolved_modules: Dict[str, SheetRecord], visiting: Optional[set] = None) -> Optional[bool]:
    if module_record is None:
        return None
    if visiting is None:
        visiting = set()
    if module_record.sheet_name in visiting:
        return None
    visiting.add(module_record.sheet_name)
    for component in module_record.components:
        case_name = component["type"]["case"]
        if case_name in SEQUENTIAL_COMPONENT_CASES:
            return True
        if case_name == "Custom":
            child_name = component["type"]["parameters"].get("sheet_name")
            child = resolved_modules.get(child_name) if child_name else None
            child_state = module_contains_state(child, resolved_modules, visiting)
            if child_state:
                return True
    return False


def component_contains_state(component: Dict[str, Any], resolved_modules: Dict[str, SheetRecord]) -> Optional[bool]:
    case_name = component["type"]["case"]

    if case_name in SEQUENTIAL_COMPONENT_CASES:
        return True
    if case_name == "Custom":
        module_name = component["type"]["parameters"].get("sheet_name")
        module_record = resolved_modules.get(module_name) if module_name else None
        return module_contains_state(module_record, resolved_modules) if module_record else None
    return False


def port_specs(component: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    case_name = component["type"]["case"]
    params = component["type"]["parameters"]

    def gins(count: int) -> List[Dict[str, Any]]:
        return [{"name": f"IN{index}", "name_source": "generated_for_clarity"} for index in range(count)]

    def gouts(count: int) -> List[Dict[str, Any]]:
        return [{"name": f"OUT{index}", "name_source": "generated_for_clarity"} for index in range(count)]

    if case_name == "Input1":
        return [], [{"name": "OUT", "name_source": "generated_for_clarity", "expected_width_bits": params.get("bus_width_bits")}]
    if case_name == "Output":
        return [{"name": "IN", "name_source": "generated_for_clarity", "expected_width_bits": params.get("bus_width_bits")}], []
    if case_name == "Viewer":
        return [{"name": "IN", "name_source": "generated_for_clarity", "expected_width_bits": params.get("bus_width_bits")}], []
    if case_name == "IOLabel":
        return [{"name": "IN", "name_source": "generated_for_clarity"}], [{"name": "OUT", "name_source": "generated_for_clarity"}]
    if case_name == "NotConnected":
        return [{"name": "IN", "name_source": "generated_for_clarity"}], []
    if case_name == "Constant1":
        return [], [{"name": "OUT", "name_source": "generated_for_clarity", "expected_width_bits": params.get("bus_width_bits")}]
    if case_name == "BusSelection":
        return [{"name": "IN", "name_source": "generated_for_clarity", "expected_width_rule": f"must contain at least bit {params.get('msb_index')}"}], [{"name": "OUT", "name_source": "generated_for_clarity", "expected_width_bits": params.get("output_width_bits"), "semantic_slice": {"lsb_index": params.get("lsb_index"), "msb_index": params.get("msb_index")}}]
    if case_name == "BusCompare1":
        return [{"name": "IN", "name_source": "generated_for_clarity", "expected_width_bits": params.get("input_width_bits")}], [{"name": "EQ", "name_source": "generated_for_clarity", "expected_width_bits": 1}]
    if case_name == "Not":
        return [{"name": "IN", "name_source": "generated_for_clarity", "expected_width_bits": 1}], [{"name": "OUT", "name_source": "generated_for_clarity", "expected_width_bits": 1}]
    if case_name == "GateN":
        return gins(params.get("input_count") or 0), [{"name": "OUT", "name_source": "generated_for_clarity", "expected_width_bits": 1}]
    if case_name == "Decode4":
        return [{"name": "SEL", "name_source": "confirmed_from_issie_source", "expected_width_bits": 2}, {"name": "DATA", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}], [{"name": str(index), "name_source": "confirmed_from_issie_source", "expected_width_bits": 1} for index in range(4)]
    if case_name == "Mux2":
        return [{"name": "0", "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as input 1 and output"}, {"name": "1", "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as input 0 and output"}, {"name": "SEL", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}], [{"name": "OUT", "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as data inputs"}]
    if case_name == "Mux4":
        return [{"name": str(index), "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as other data inputs"} for index in range(4)] + [{"name": "SEL", "name_source": "confirmed_from_issie_source", "expected_width_bits": 2}], [{"name": "OUT", "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as data inputs"}]
    if case_name == "Mux8":
        return [{"name": str(index), "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as other data inputs"} for index in range(8)] + [{"name": "SEL", "name_source": "confirmed_from_issie_source", "expected_width_bits": 3}], [{"name": "OUT", "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as data inputs"}]
    if case_name == "Demux2":
        return [{"name": "DATA", "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as both outputs"}, {"name": "SEL", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}], [{"name": "0", "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as DATA"}, {"name": "1", "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as DATA"}]
    if case_name == "Demux4":
        return [{"name": "DATA", "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as all outputs"}, {"name": "SEL", "name_source": "confirmed_from_issie_source", "expected_width_bits": 2}], [{"name": str(index), "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as DATA"} for index in range(4)]
    if case_name == "Demux8":
        return [{"name": "DATA", "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as all outputs"}, {"name": "SEL", "name_source": "confirmed_from_issie_source", "expected_width_bits": 3}], [{"name": str(index), "name_source": "confirmed_from_issie_source", "expected_width_rule": "same as DATA"} for index in range(8)]
    if case_name in {"NbitsAdder", "NbitsAdderNoCin", "NbitsAdderNoCout", "NbitsAdderNoCinCout"}:
        width = params.get("bus_width_bits")
        if case_name == "NbitsAdder":
            return [{"name": "CIN", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}, {"name": "P", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}, {"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}], [{"name": "SUM", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}, {"name": "COUT", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}]
        if case_name == "NbitsAdderNoCin":
            return [{"name": "P", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}, {"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}], [{"name": "SUM", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}, {"name": "COUT", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}]
        if case_name == "NbitsAdderNoCout":
            return [{"name": "CIN", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}, {"name": "P", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}, {"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}], [{"name": "SUM", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}]
        return [{"name": "P", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}, {"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}], [{"name": "SUM", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}]
    if case_name in {"NbitsAnd", "NbitsOr", "NbitsXor"}:
        width = params.get("bus_width_bits")
        return [{"name": "P", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}, {"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}], [{"name": "OUT", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}]
    if case_name == "NbitsNot":
        width = params.get("bus_width_bits")
        return [{"name": "IN", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}], [{"name": "OUT", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}]
    if case_name == "NbitSpreader":
        return [{"name": "IN", "name_source": "generated_for_clarity", "expected_width_bits": 1}], [{"name": "OUT", "name_source": "generated_for_clarity", "expected_width_bits": params.get("bus_width_bits")}]
    if case_name == "MergeWires":
        return [{"name": "LOW_BITS", "name_source": "inferred_from_simulator_behavior", "expected_width_rule": "any width >= 1; becomes least-significant slice"}, {"name": "HIGH_BITS", "name_source": "inferred_from_simulator_behavior", "expected_width_rule": "any width >= 1; becomes most-significant slice"}], [{"name": "OUT", "name_source": "generated_for_clarity", "expected_width_rule": "sum of the two input widths"}]
    if case_name == "MergeN":
        count = params.get("input_count") or 0
        inputs = []
        for index in range(count):
            if index == 0:
                inputs.append({"name": "LSB", "name_source": "confirmed_from_issie_source", "expected_width_rule": "any width >= 1"})
            elif index == count - 1:
                inputs.append({"name": "MSB", "name_source": "confirmed_from_issie_source", "expected_width_rule": "any width >= 1"})
            else:
                inputs.append({"name": f"IN{index}", "name_source": "generated_for_clarity", "expected_width_rule": "any width >= 1"})
        return inputs, [{"name": "OUT", "name_source": "confirmed_from_issie_source", "expected_width_rule": "sum of all input widths"}]
    if case_name == "SplitWire":
        width = params.get("bus_width_bits")
        min_width = width + 1 if width is not None else "?"
        return [{"name": "IN", "name_source": "generated_for_clarity", "expected_width_rule": f"at least {min_width} bits"}], [{"name": "LOW_BITS", "name_source": "inferred_from_simulator_behavior", "expected_width_bits": width}, {"name": "HIGH_BITS", "name_source": "inferred_from_simulator_behavior", "expected_width_rule": "input width minus LOW_BITS width"}]
    if case_name == "SplitN":
        outputs = []
        for index, slice_info in enumerate(params.get("slices", [])):
            outputs.append({"name": f"OUT{index}", "name_source": "generated_for_clarity", "expected_width_bits": slice_info.get("width_bits"), "semantic_slice": {"lsb_index": slice_info.get("lsb_index"), "msb_index": slice_info.get("msb_index")}})
        return [{"name": "IN", "name_source": "generated_for_clarity", "expected_width_rule": "must contain every requested output slice"}], outputs
    if case_name == "DFF":
        return [{"name": "D", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}], [{"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}]
    if case_name == "DFFE":
        return [{"name": "D", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}, {"name": "EN", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}], [{"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}]
    if case_name == "Register":
        width = params.get("bus_width_bits")
        return [{"name": "D", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}], [{"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}]
    if case_name == "RegisterE":
        width = params.get("bus_width_bits")
        return [{"name": "D", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}, {"name": "EN", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}], [{"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}]
    if case_name == "Counter":
        width = params.get("bus_width_bits")
        return [{"name": "D", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}, {"name": "LOAD", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}, {"name": "EN", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}], [{"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}]
    if case_name == "CounterNoEnable":
        width = params.get("bus_width_bits")
        return [{"name": "D", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}, {"name": "LOAD", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}], [{"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": width}]
    if case_name == "CounterNoLoad":
        return [{"name": "EN", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}], [{"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": params.get("bus_width_bits")}]
    if case_name == "CounterNoEnableLoad":
        return [], [{"name": "Q", "name_source": "confirmed_from_issie_source", "expected_width_bits": params.get("bus_width_bits")}]
    if case_name in {"ROM1", "AsyncROM1"}:
        return [{"name": "ADDR", "name_source": "confirmed_from_issie_source", "expected_width_bits": params.get("address_width_bits")}], [{"name": "DOUT", "name_source": "confirmed_from_issie_source", "expected_width_bits": params.get("word_width_bits")}]
    if case_name in {"RAM1", "AsyncRAM1"}:
        return [{"name": "ADDR", "name_source": "confirmed_from_issie_source", "expected_width_bits": params.get("address_width_bits")}, {"name": "DIN", "name_source": "confirmed_from_issie_source", "expected_width_bits": params.get("word_width_bits")}, {"name": "WEN", "name_source": "confirmed_from_issie_source", "expected_width_bits": 1}], [{"name": "DOUT", "name_source": "confirmed_from_issie_source", "expected_width_bits": params.get("word_width_bits")}]
    if case_name == "Shift":
        return [{"name": "IN", "name_source": "confirmed_from_issie_source", "expected_width_bits": params.get("input_bus_width_bits")}, {"name": "SHIFTER", "name_source": "confirmed_from_issie_source", "expected_width_bits": params.get("shifter_bus_width_bits")}], [{"name": "OUT", "name_source": "confirmed_from_issie_source", "expected_width_bits": params.get("input_bus_width_bits")}]
    if case_name == "Custom":
        inputs = [{"name": item["label"], "name_source": "confirmed_from_issie_source", "expected_width_bits": item["width_bits"]} for item in params.get("input_labels", [])]
        outputs = [{"name": item["label"], "name_source": "confirmed_from_issie_source", "expected_width_bits": item["width_bits"]} for item in params.get("output_labels", [])]
        return inputs, outputs
    return gins(len(component["input_ports_raw"])), gouts(len(component["output_ports_raw"]))


def build_component_semantics(component: Dict[str, Any], resolved_modules: Dict[str, SheetRecord], include_layout: bool) -> Dict[str, Any]:
    input_specs, output_specs = port_specs(component)

    def annotate_ports(raw_ports: List[Dict[str, Any]], specs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        annotated = []
        orientation = component["symbol_info"].get("port_orientation", {})
        for index, port in enumerate(raw_ports):
            spec = specs[index] if index < len(specs) else {"name": f"PORT{index}", "name_source": "generated_for_clarity"}
            annotated.append(
                {
                    "id": port["id"],
                    "index": safe_port_index(port, index),
                    "name": spec.get("name"),
                    "name_source": spec.get("name_source"),
                    "direction": port["direction"],
                    "host_component_id": port["host_component_id"],
                    "expected_width_bits": spec.get("expected_width_bits"),
                    "expected_width_rule": spec.get("expected_width_rule"),
                    "semantic_slice": spec.get("semantic_slice"),
                    "edge": orientation.get(port["id"]),
                }
            )
        return annotated

    layout = {
        "x": component["layout"]["x"],
        "y": component["layout"]["y"],
        "width": component["layout"]["width"],
        "height": component["layout"]["height"],
        "rotation": component["symbol_info"].get("rotation"),
        "flipped": component["symbol_info"].get("flipped"),
        "reversed_input_ports": component["symbol_info"].get("reversed_input_ports"),
    }

    semantic_component = {
        "id": component["id"],
        "label": component["label"],
        "type_case": component["type"]["case"],
        "type_parameters": component["type"]["parameters"],
        "contains_state": component_contains_state(component, resolved_modules),
        "ports": {
            "inputs": annotate_ports(component["input_ports_raw"], input_specs),
            "outputs": annotate_ports(component["output_ports_raw"], output_specs),
        },
    }

    semantic_component["layout"] = layout if include_layout else {"x": layout["x"], "y": layout["y"], "rotation": layout["rotation"]}

    return semantic_component


def build_port_lookup(components: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    lookup: Dict[str, Dict[str, Any]] = {}
    for component in components:
        for direction in ("inputs", "outputs"):
            for port in component["ports"][direction]:
                lookup[port["id"]] = {
                    "component_id": component["id"],
                    "component_label": component["label"],
                    "component_type_case": component["type_case"],
                    "port_id": port["id"],
                    "port_name": port["name"],
                    "port_index": port["index"],
                    "direction": port["direction"],
                }
    return lookup


def build_connection_semantics(sheet: SheetRecord, components: List[Dict[str, Any]], include_layout: bool) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    warnings: List[str] = []
    port_lookup = build_port_lookup(components)
    direct_connections: List[Dict[str, Any]] = []

    for connection in sheet.connections:
        source_port = port_lookup.get(connection["source"]["id"])
        target_port = port_lookup.get(connection["target"]["id"])
        if source_port is None:
            warnings.append(f"Connection {connection['id']} source port {connection['source']['id']} was not found among component ports.")
        if target_port is None:
            warnings.append(f"Connection {connection['id']} target port {connection['target']['id']} was not found among component ports.")
        item = {
            "id": connection["id"],
            "from": source_port or connection["source"],
            "to": target_port or connection["target"],
        }
        if include_layout:
            item["route_vertices"] = connection["vertices"]
        direct_connections.append(item)

    io_label_components = [component for component in components if component["type_case"] == "IOLabel"]
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for component in io_label_components:
        grouped.setdefault(component["label"], []).append(component)

    derived_via_labels: List[Dict[str, Any]] = []
    semantic_net_groups: List[Dict[str, Any]] = []
    for label, label_components in grouped.items():
        label_ids = {component["id"] for component in label_components}
        incoming = []
        outgoing = []
        for connection in direct_connections:
            from_component = connection["from"].get("component_id")
            to_component = connection["to"].get("component_id")
            if to_component in label_ids:
                incoming.append(connection)
            if from_component in label_ids:
                outgoing.append(connection)
        if len(incoming) > 1:
            warnings.append(f"IOLabel net '{label}' has {len(incoming)} incoming drivers in this sheet; Issie expects such a named net to be driven once.")
        if not incoming:
            warnings.append(f"IOLabel net '{label}' has no driving connection in this sheet.")
        else:
            driver = incoming[0]
            for sink in outgoing:
                target_component = sink["to"].get("component_id")
                if target_component in label_ids:
                    continue
                derived_via_labels.append(
                    {
                        "net_label": label,
                        "driver": driver["from"],
                        "sink": sink["to"],
                    }
                )
        semantic_net_groups.append(
            {
                "net_label": label,
            }
        )

    if warnings:
        semantic_net_groups.append({"warnings": warnings})
    return direct_connections, derived_via_labels, semantic_net_groups


def build_sheet_semantics(sheet: SheetRecord, resolved_modules: Dict[str, SheetRecord], include_layout: bool) -> Dict[str, Any]:
    semantic_components = [build_component_semantics(component, resolved_modules, include_layout) for component in sheet.components]
    direct_connections, derived_via_labels, semantic_net_groups = build_connection_semantics(sheet, semantic_components, include_layout)
    referenced_module_names = sorted({component["type_parameters"].get("sheet_name") for component in semantic_components if component["type_case"] == "Custom"} - {None})

    return {
        "sheet_name": sheet.sheet_name,
        "top_level_io": {"inputs": sheet.input_signature, "outputs": sheet.output_signature},
        "components": semantic_components,
        "connections": {"direct_wires_from_file": direct_connections, "derived_named_net_connections_via_iolabels": derived_via_labels, "semantic_net_groups": semantic_net_groups},
        "referenced_module_names": referenced_module_names,
    }


def clean_dict(value: Dict[str, Any]) -> Dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, [], {}, "")}


def simplify_numeric_repr(value: Any) -> Any:
    if isinstance(value, dict):
        if "decimal" in value and len(value) == 1:
            return value["decimal"]
        if "decimal" in value:
            return value["decimal"]
    return value


def compact_component_attributes(component: Dict[str, Any]) -> Dict[str, Any]:
    case_name = component["type_case"]
    params = component["type_parameters"]

    if case_name in {"Input1", "Output", "Viewer"}:
        return {}
    if case_name == "Constant1":
        return clean_dict({"value": simplify_numeric_repr(params.get("value"))})
    if case_name == "GateN":
        return clean_dict({"gate": params.get("gate_type")})
    if case_name == "BusSelection":
        return clean_dict(
            {
                "lsb": params.get("lsb_index"),
                "msb": params.get("msb_index"),
            }
        )
    if case_name == "BusCompare1":
        return clean_dict(
            {
                "compare_value": simplify_numeric_repr(params.get("compare_value")),
            }
        )
    if case_name in {
        "Register",
        "RegisterE",
        "Counter",
        "CounterNoLoad",
        "CounterNoEnable",
        "CounterNoEnableLoad",
        "NbitsAdder",
        "NbitsAdderNoCin",
        "NbitsAdderNoCout",
        "NbitsAdderNoCinCout",
        "NbitsAnd",
        "NbitsOr",
        "NbitsNot",
        "NbitSpreader",
        "SplitWire",
    }:
        return {}
    if case_name == "MergeN":
        return {}
    if case_name == "SplitN":
        return clean_dict({"slices": params.get("slices")})
    if case_name == "Shift":
        return clean_dict(
            {
                "mode": params.get("shift_type"),
            }
        )
    if case_name == "NbitsXor":
        return clean_dict({"mode": params.get("mode")})
    if case_name in {"RAM1", "AsyncRAM1", "ROM1", "AsyncROM1"}:
        return {}
    if case_name == "Custom":
        return clean_dict(
            {
                "parameter_bindings": params.get("parameter_bindings") or None,
            }
        )
    return clean_dict(params)


def compact_port_text(port: Dict[str, Any]) -> str:
    name = port.get("name") or "PORT"
    bits = port.get("bits")
    if bits is not None and bits != 1:
        return f"{name}[{bits}]"
    slice_info = port.get("slice")
    if isinstance(slice_info, dict):
        lsb = slice_info.get("lsb_index")
        msb = slice_info.get("msb_index")
        if lsb is not None and msb is not None:
            return f"{name}[{msb}:{lsb}]"
    return name


def compact_component(component: Dict[str, Any]) -> Dict[str, Any]:
    attributes = compact_component_attributes(component)
    module_name = None
    if component["type_case"] == "Custom":
        module_name = component["type_parameters"].get("sheet_name")

    result = {
        "type": component["type_case"],
        "attrs": attributes,
        "module": module_name,
        "stateful": True if component.get("contains_state") else None,
    }

    return clean_dict(result)


def component_signature_text(component: Dict[str, Any]) -> str:
    head = component["type"]
    module_name = component.get("module")
    if module_name:
        head = f"{head}[{module_name}]"

    attrs = component.get("attrs") or {}
    if attrs:
        attr_text = ",".join(f"{key}={value}" for key, value in attrs.items())
        head = f"{head}({attr_text})"

    if component.get("stateful"):
        head = f"{head}*"

    return head


def compact_endpoint_text(endpoint: Dict[str, Any], component_refs: Dict[str, str]) -> str:
    component_id = endpoint.get("component_id")
    component_name = component_refs.get(component_id) if component_id else None
    if component_name is None:
        component_name = endpoint.get("component_label") or endpoint.get("host_component_id") or "UNKNOWN"
    component_type = endpoint.get("component_type_case")
    if component_type in {"Input1", "Output"}:
        return component_name
    port_name = endpoint.get("port_name")
    if port_name:
        return f"{component_name}.{port_name}"
    port_index = endpoint.get("port_index")
    if port_index is not None:
        return f"{component_name}.PORT{port_index}"
    return component_name


def compact_connection(
    connection: Dict[str, Any],
    component_refs: Dict[str, str],
    *,
    via_named_net: Optional[str] = None,
    include_layout: bool = False,
) -> Dict[str, Any]:
    result = {
        "from": compact_endpoint_text(connection["from"], component_refs),
        "to": compact_endpoint_text(connection["to"], component_refs),
    }
    if via_named_net:
        result["via"] = via_named_net
    if include_layout and connection.get("route_vertices"):
        result["route_vertices"] = connection["route_vertices"]
    return result


def group_connections(connection_texts: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {}
    for item in connection_texts:
        grouped.setdefault(item["from"], []).append(item["to"])
    for source in grouped:
        grouped[source] = sorted(set(grouped[source]))
    return dict(sorted(grouped.items()))


def group_named_connections(connection_texts: List[Dict[str, Any]]) -> Dict[str, Dict[str, List[str]]]:
    grouped: Dict[str, Dict[str, List[str]]] = {}
    for item in connection_texts:
        via = item.get("via")
        key = f"via:{via}" if via else "via:"
        per_source = grouped.setdefault(key, {})
        per_source.setdefault(item["from"], []).append(item["to"])
    for via_key, per_source in grouped.items():
        for source in per_source:
            per_source[source] = sorted(set(per_source[source]))
        grouped[via_key] = dict(sorted(per_source.items()))
    return dict(sorted(grouped.items()))


def compact_top_level_io(io_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [clean_dict({"name": item.get("label"), "bits": item.get("width_bits")}) for item in io_items]


def build_component_refs(components: List[Dict[str, Any]]) -> Dict[str, str]:
    label_counts: Dict[str, int] = {}
    for component in components:
        base = component.get("label") or component.get("type_case") or "COMP"
        label_counts[base] = label_counts.get(base, 0) + 1

    seen: Dict[str, int] = {}
    refs: Dict[str, str] = {}
    for component in components:
        base = component.get("label") or component.get("type_case") or "COMP"
        seen[base] = seen.get(base, 0) + 1
        ref = base if label_counts[base] == 1 else f"{base}#{seen[base]}"
        refs[component["id"]] = ref
    return refs


def build_compact_sheet_view(sheet_semantics: Dict[str, Any], include_layout: bool) -> Dict[str, Any]:
    component_refs = build_component_refs(sheet_semantics["components"])
    components = {}
    layout = {}
    for component in sheet_semantics["components"]:
        if component["type_case"] in {"Input1", "Output", "Viewer"}:
            continue
        ref = component_refs[component["id"]]
        components[ref] = component_signature_text(compact_component(component))
        if include_layout:
            layout[ref] = clean_dict(component.get("layout", {}))

    direct_connections = [
        compact_connection(connection, component_refs, include_layout=include_layout)
        for connection in sheet_semantics["connections"]["direct_wires_from_file"]
        if connection["from"].get("component_type_case") not in {"IOLabel", "Viewer"}
        and connection["to"].get("component_type_case") not in {"IOLabel", "Viewer"}
    ]
    named_net_connections = [
        compact_connection(
            {"from": connection["driver"], "to": connection["sink"]},
            component_refs,
            via_named_net=connection["net_label"],
        )
        for connection in sheet_semantics["connections"]["derived_named_net_connections_via_iolabels"]
    ]
    named_nets = []
    for group in sheet_semantics["connections"]["semantic_net_groups"]:
        if "net_label" not in group:
            continue
        named_nets.append(clean_dict({"label": group.get("net_label")}))

    grouped_wires = group_connections(direct_connections)
    grouped_named_wires = group_named_connections(named_net_connections)
    named_drive_labels = {via_key.removeprefix("via:") for via_key in grouped_named_wires}
    passive_named_nets = sorted({item["label"] for item in named_nets if item["label"] not in named_drive_labels})

    return clean_dict(
        {
            "io": clean_dict(
                {
                    "in": [compact_port_text(item) for item in compact_top_level_io(sheet_semantics["top_level_io"]["inputs"])],
                    "out": [compact_port_text(item) for item in compact_top_level_io(sheet_semantics["top_level_io"]["outputs"])],
                }
            ),
            "parts": components,
            "drives": grouped_wires,
            "named_drives": grouped_named_wires,
            "named_nets": passive_named_nets,
            "layout": layout if include_layout else None,
        }
    )


def make_final_output(
    root: SheetRecord,
    resolved_records: Dict[str, SheetRecord],
    hierarchy_warnings: List[str],
    include_layout: bool,
    expand_modules: bool,
) -> Dict[str, Any]:
    semantic_sheets = {name: build_sheet_semantics(record, resolved_records, include_layout) for name, record in resolved_records.items()}
    root_semantics = semantic_sheets[root.sheet_name]
    compact_sheets = {name: build_compact_sheet_view(data, include_layout) for name, data in semantic_sheets.items()}
    direct_module_names = root_semantics.get("referenced_module_names", [])
    final_output = {
        "format": "issie_semantic_json",
        "version": 4,
        "root": root.sheet_name,
        "root_module": compact_sheets[root.sheet_name],
        "uncertain": sorted(set(root.warnings + hierarchy_warnings)) or None,
    }
    if expand_modules:
        final_output["expanded_modules"] = {name: data for name, data in compact_sheets.items() if name != root.sheet_name}
    else:
        final_output["module_interfaces"] = {
            name: clean_dict({"io": compact_sheets[name].get("io")})
            for name in direct_module_names
            if name in compact_sheets
        }
    return clean_dict(final_output)


def default_output_path_for_input(input_path: str) -> Path:
    source = Path(input_path).expanduser().resolve()
    return source.with_name(f"{source.stem}.semantic.json")


def main() -> int:
    args = parse_args()
    try:
        target_path = choose_path_via_gui(args.input, args.project_dir, args.sheet)
        root = load_sheet_record(target_path)
        resolved_records, hierarchy_warnings = resolve_referenced_sheets(root, args.max_hierarchy_depth)
        output = make_final_output(
            root,
            resolved_records,
            hierarchy_warnings,
            args.include_layout,
            not args.root_only,
        )
        if args.pretty:
            rendered = json.dumps(output, ensure_ascii=False, indent=2)
        else:
            rendered = json.dumps(output, ensure_ascii=False, separators=(",", ":"))
        output_path = Path(args.output).expanduser().resolve() if args.output else default_output_path_for_input(target_path)
        output_path.write_text(rendered, encoding="utf-8")
        sys.stdout.write(f"Wrote JSON to {output_path}\n")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
