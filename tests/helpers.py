import socket
import threading

from types import TracebackType


class PausableTCPProxy:
    def __init__(self, upstream_host: str, upstream_port: int) -> None:
        self.upstream_target: tuple[str, int] = (upstream_host, upstream_port)
        self.listener: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(5)
        self.port: int = self.listener.getsockname()[1]
        self._closed: bool = True
        self._sockets: list[socket.socket] = []
        self._flow: threading.Event = threading.Event()
        self._flow.set()
        self._timeout: float | None = None
        self._lock: threading.Lock = threading.Lock()
        self._accept_thread: threading.Thread | None = None

    def __enter__(self):
        if self._closed:
            self._closed = False
            self._accept_thread = threading.Thread(target=self._accept, daemon=True)
            self._accept_thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._flow.set()
        with self._lock:
            sockets = [self.listener, *self._sockets]
            self._sockets.clear()
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        if (
            self._accept_thread is not None
            and self._accept_thread is not threading.current_thread()
        ):
            self._accept_thread.join(timeout=1.0)

    def pause(self):
        self._flow.clear()

    def resume(self):
        self._flow.set()

    def _accept(self) -> None:
        while not self._closed:
            try:
                client_sock, _ = self.listener.accept()
                upstream_sock = socket.create_connection(self.upstream_target)
            except OSError:
                return
            with self._lock:
                if self._closed:
                    client_sock.close()
                    upstream_sock.close()
                    break
                self._sockets.extend([client_sock, upstream_sock])
            threading.Thread(
                target=self._relay,
                args=(client_sock, upstream_sock, False),
                daemon=True,
            ).start()
            threading.Thread(
                target=self._relay, args=(upstream_sock, client_sock, True), daemon=True
            ).start()

    def _relay(self, src: socket.socket, dst: socket.socket, gated: bool) -> None:
        try:
            while not self._closed:
                data = src.recv(65536)
                if not data:
                    break
                if gated:
                    self._flow.wait()
                    if self._closed:
                        break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass
