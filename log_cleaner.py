import os
import time

LOG_FILES = [
    "/var/log/supervisord.log",
    "/usr/local/openresty/nginx/logs/access.log",
    "/usr/local/openresty/nginx/logs/error.log"
]

MAX_SIZE_BYTES = 50 * 1024 * 1024  # Truncate if larger than 50MB
CLEAN_INTERVAL = 3600               # Run every 1 hour

def truncate_log(file_path):
    if os.path.exists(file_path):
        try:
            size = os.path.getsize(file_path)
            if size > MAX_SIZE_BYTES:
                with open(file_path, 'w') as f:
                    f.truncate(0)
                print(f"[Log Cleaner] Truncated oversized log: {file_path} (was {size / 1024 / 1024:.2f} MB)")
        except Exception as e:
            print(f"[Log Cleaner Error] Failed to truncate {file_path}: {e}")

def main():
    print("[Log Cleaner] Service running...")
    while True:
        for log_file in LOG_FILES:
            truncate_log(log_file)
        time.sleep(CLEAN_INTERVAL)

if __name__ == '__main__':
    main()
