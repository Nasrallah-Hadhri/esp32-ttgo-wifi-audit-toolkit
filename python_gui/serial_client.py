import serial
import serial.tools.list_ports
import threading
import time

class SerialClient:
    def __init__(self, callback):
        self.ser = None
        self.callback = callback
        self.running = False
        self.thread = None

    def get_ports(self):
        return [port.device for port in serial.tools.list_ports.comports()]

    def connect(self, port, baudrate=115200):
        try:
            self.ser = serial.Serial(port, baudrate, timeout=1)
            self.running = True
            self.thread = threading.Thread(target=self._read_loop, daemon=True)
            self.thread.start()
            return True, "Connected"
        except Exception as e:
            return False, str(e)

    def disconnect(self):
        self.running = False
        if self.ser and self.ser.is_open:
            self.ser.close()

    def send_cmd(self, cmd):
        if self.ser and self.ser.is_open:
            full_cmd = f"{cmd}\n".encode('utf-8')
            self.ser.write(full_cmd)

    def _read_loop(self):
        while self.running:
            try:
                if self.ser and self.ser.is_open:
                    line = self.ser.readline()
                    if line:
                        decoded = line.decode('utf-8', errors='ignore').strip()
                        if decoded:
                            self.callback(decoded)
            except Exception as e:
                self.callback(f"ERR: {str(e)}")
                break
            time.sleep(0.01)
