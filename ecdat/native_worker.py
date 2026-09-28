"""Isolate native parsers so malformed input cannot terminate the API process."""
import atexit
import multiprocessing
import threading

_local = threading.local()
_workers = []
_lock = threading.Lock()


def _serve(connection):
    try:
        while True:
            operation, arguments = connection.recv()
            try:
                if operation == 'syntax':
                    from source_analysis import _syntax_calls
                    result = _syntax_calls(*arguments)
                elif operation == 'binary':
                    from binary_analysis import _binary_symbols
                    result = _binary_symbols(*arguments)
                else:
                    raise ValueError('Unknown parser operation')
                connection.send((True, result))
            except Exception as exc:
                connection.send((False, type(exc).__name__))
    except (EOFError, OSError):
        pass
    finally:
        connection.close()


class NativeWorker:
    def __init__(self):
        context = multiprocessing.get_context('spawn')
        self.connection, child = context.Pipe()
        self.process = context.Process(target=_serve, args=(child,), daemon=True)
        self.process.start()
        child.close()

    def request(self, operation, arguments, timeout=5):
        if not self.process.is_alive():
            raise RuntimeError('native parser exited')
        self.connection.send((operation, arguments))
        if not self.connection.poll(timeout):
            raise TimeoutError('native parser exceeded its per-file time limit')
        success, result = self.connection.recv()
        if not success:
            raise RuntimeError('native parser rejected input: ' + result)
        return result

    def close(self):
        self.connection.close()
        if self.process.is_alive():
            self.process.terminate()
        self.process.join(timeout=1)
        if self.process.is_alive():
            self.process.kill()
            self.process.join(timeout=1)


def request(operation, *arguments):
    worker = getattr(_local, 'worker', None)
    if worker is None:
        worker = NativeWorker()
        _local.worker = worker
        with _lock:
            _workers.append(worker)
    try:
        return worker.request(operation, arguments)
    except (OSError, EOFError, RuntimeError, TimeoutError):
        worker.close()
        _local.worker = None
        with _lock:
            _workers.remove(worker)
        raise


@atexit.register
def close_workers():
    for worker in _workers:
        worker.close()
