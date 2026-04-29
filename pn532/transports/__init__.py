class Transport:
    def wakeup(self):
        raise NotImplementedError

    def wait_ready(self, timeout=1):
        raise NotImplementedError

    def read_data(self, count):
        raise NotImplementedError

    def write_data(self, framebytes):
        raise NotImplementedError
