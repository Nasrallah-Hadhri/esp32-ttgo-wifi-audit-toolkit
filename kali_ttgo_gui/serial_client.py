import serial
import serial.tools.list_ports
import threading
import time

class SerialClient:
    def __init__(self, callback):
        self.ser = None
        self.running = False
        self.callback = callback
        self.thread = None

    def get_ports(self):
        ports = serial.tools.list_ports.comports()
        # Filter for typical TTGO / CP210x / CH340 / CH9102 ports
        # On Linux this is usually /dev/ttyUSB* or /dev/ttyACM*
        return [p.device for p in ports]

    def connect(self, port, baud=115200):
        try:
            self.ser = serial.Serial(port, baud, timeout=1)
            self.running = True
            self.thread = threading.Thread(target=self._read_loop, daemon=True)
            self.thread.start()
            return True, ""
        except Exception as e:
            return False, str(e)

    def disconnect(self):
        self.running = False
        if self.ser and self.ser.is_open:
            self.ser.close()

    def send_cmd(self, cmd):
        if self.ser and self.ser.is_open:
            self.ser.write((cmd + "\n").encode())

    def _read_loop(self):
        while self.running and self.ser and self.ser.is_open:
            try:
                line = self.ser.readline().decode('utf-8', errors='ignore').strip()
                if line:
                    self.callback(line)
            except:
                pass
