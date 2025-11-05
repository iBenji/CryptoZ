import threading


class OperationManager:
    def __init__(self):
        self._operations = {}
        self._lock = threading.Lock()
    
    def start_operation(self, op_id: str, target, *args, **kwargs):
        with self._lock:
            if op_id in self._operations:
                return False
            thread = threading.Thread(target=target, args=args, kwargs=kwargs)
            thread.daemon = True
            self._operations[op_id] = thread
            thread.start()
            return True
    
    def stop_operation(self, op_id: str):
        pass