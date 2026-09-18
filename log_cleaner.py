import os
import time
import asyncio

try:
    import uvloop
    uvloop.install()
except ImportError:
    pass

LOG_FILES = [
    "/var/log/supervisord.log",
    "/usr/local/openresty/nginx/logs/access.log",
    "/usr/local/openresty/nginx/logs/error.log"
]

MAX_SIZE_BYTES = 50 * 1024 * 1024  
CLEAN_INTERVAL = 300                

def truncate_log_sync(file_path):
    if os.path.exists(file_path):
        try:
            size = os.path.getsize(file_path)
            if size > MAX_SIZE_BYTES:
                with open(file_path, 'w') as f:
                    f.truncate(0)
                print(f"[Log Cleaner] Truncated oversized log: {file_path} (was {size / 1024 / 1024:.2f} MB)", flush=True)
        except Exception as e:
            print(f"[Log Cleaner Error] Failed to truncate {file_path}: {e}", flush=True)

async def check_and_truncate_async(file_path):
    await asyncio.to_thread(truncate_log_sync, file_path)

async def cleaner_loop():
    print("[Log Cleaner] Service running...", flush=True)
    while True:
        tasks = [check_and_truncate_async(log_file) for log_file in LOG_FILES]
        await asyncio.gather(*tasks)
        await asyncio.sleep(CLEAN_INTERVAL)

def main():
    try:
        asyncio.run(cleaner_loop())
    except KeyboardInterrupt:
        print("\n[Log Cleaner] Service stopped cleanly.", flush=True)

if __name__ == '__main__':
    main()
