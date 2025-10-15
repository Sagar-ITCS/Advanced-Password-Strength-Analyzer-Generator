import subprocess
import sys
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class CodeChangeHandler(FileSystemEventHandler):
    def __init__(self, script_path):
        self.script_path = script_path
        self.process = None
        self.restart()
    
    def on_modified(self, event):
        if event.src_path.endswith('.py'):
            print(f"\n🔄 Detected change in {event.src_path}")
            print("⚡ Restarting GUI...")
            self.restart()
    
    def restart(self):
        if self.process:
            self.process.terminate()
            self.process.wait()
        
        self.process = subprocess.Popen(
            [sys.executable, self.script_path, '--gui'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print(f"✅ GUI started (PID: {self.process.pid})")

if __name__ == "__main__":
    script = "password_analyzer.py"
    
    handler = CodeChangeHandler(script)
    observer = Observer()
    observer.schedule(handler, path='.', recursive=False)
    observer.start()
    
    print(f"👀 Watching {script} for changes...")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        if handler.process:
            handler.process.terminate()
    
    observer.join()