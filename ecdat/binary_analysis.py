"""Static executable import/export analysis; never loads or executes target code."""
import re
import io


def binary_symbols(data):
    if not data.startswith((b'MZ', b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe')):
        return [], None
    from native_worker import request
    try:
        return request('binary', data)
    except (OSError, EOFError, RuntimeError, TimeoutError):
        return [], 'Native binary parser failed or timed out; string detection only.'


def _binary_symbols(data):
    if not data.startswith((b'MZ', b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe')):
        return [], None
    try:
        import lief
        binary = lief.parse(io.BytesIO(data))
        if binary is None:
            return [], 'Executable format could not be parsed; string detection only.'
        names = set()
        for attribute in ('imported_functions', 'exported_functions', 'symbols'):
            for symbol in getattr(binary, attribute, []):
                name = getattr(symbol, 'name', '')
                if name:
                    names.add(name)
                if len(names) >= 20000:
                    return sorted(names), 'Binary symbol limit reached.'
        return sorted(names), None
    except (ImportError, RuntimeError, ValueError, TypeError):
        return [], 'Binary analysis unavailable or executable malformed; string detection only.'


def symbol_findings(data, name, rules):
    symbols, warning = binary_symbols(data)
    findings = []
    for symbol in symbols:
        for algorithm, expression, severity, recommendation in rules:
            if re.search(r'(?<![a-z0-9])(?:' + expression + r')(?![a-z0-9])', symbol, re.I):
                findings.append(dict(file=name, line=None, offset=None, pattern=algorithm, call=symbol,
                    evidence=symbol, kind='binary-symbol', confidence='high', severity=severity,
                    recommendation=recommendation, metadata={'detection': 'executable symbol table'}))
    return findings, warning
