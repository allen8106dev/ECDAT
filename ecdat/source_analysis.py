"""Syntax-based call discovery, with explicit fallback for unsupported languages."""
import ast
import importlib
from functools import lru_cache
from pathlib import PurePosixPath

LANGUAGES = {'.py': 'python', '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.ts': 'typescript', '.tsx': 'tsx', '.java': 'java', '.c': 'c', '.h': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.hpp': 'cpp', '.cxx': 'cpp', '.go': 'go', '.rs': 'rust'}
CALLS = {'call', 'call_expression', 'method_invocation', 'object_creation_expression', 'invocation_expression'}


@lru_cache(maxsize=16)
def _language(name):
    from tree_sitter import Language
    module = importlib.import_module('tree_sitter_' + ('typescript' if name == 'tsx' else name))
    factory = getattr(module, 'language_' + name) if name in {'typescript', 'tsx'} else module.language
    return Language(factory())


def syntax_calls(name, text):
    if PurePosixPath(name).suffix.lower() not in LANGUAGES:
        return [], 'signature-only: no syntax parser for this extension'
    if len(text) > 2 * 1024 * 1024:
        return [], 'signature-only: file exceeds syntax analysis limit (2 MiB)'
    from native_worker import request
    try:
        return request('syntax', name, text)
    except (OSError, EOFError, RuntimeError, TimeoutError):
        return [], 'signature-only: native syntax parser failed or timed out'


def _syntax_calls(name, text):
    language = LANGUAGES.get(PurePosixPath(name).suffix.lower())
    if not language:
        return [], 'signature-only: no syntax parser for this extension'
    if len(text) > 2 * 1024 * 1024:
        return [], 'signature-only: file exceeds syntax analysis limit (2 MiB)'
    aliases = {}
    if language == 'python':
        try:
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Import):
                    aliases.update({a.asname or a.name: a.name for a in node.names})
                elif isinstance(node, ast.ImportFrom) and node.module:
                    aliases.update({a.asname or a.name: node.module + '.' + a.name for a in node.names})
        except (SyntaxError, RecursionError):
            pass
    try:
        from tree_sitter import Parser
        parser = Parser(_language(language))
        source = text.encode('utf-8')
        tree = parser.parse(source)
    except (ImportError, AttributeError, ValueError) as exc:
        return [], f'signature-only: {language} parser unavailable ({type(exc).__name__})'
    calls = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(reversed(node.named_children))
        if node.type not in CALLS or node.end_byte - node.start_byte > 4096:
            continue
        call = source[node.start_byte:node.end_byte].decode('utf-8')
        first = call.split('(', 1)[0].split('.', 1)[0]
        resolved = aliases.get(first, first) + call[len(first):]
        calls.append({'text': call, 'resolved': resolved, 'line': node.start_point.row + 1,
                      'start': node.start_byte, 'end': node.end_byte})
    return calls, 'syntax-errors: some calls may be missed' if tree.root_node.has_error else 'syntax: ' + language
