import threading

from database import init_database
from sync_service import run_sync_loop
from search_service import run_search_loop


def main():
    init_database()

    sync_thread = threading.Thread(target=run_sync_loop, daemon=True)
    search_thread = threading.Thread(target=run_search_loop)

    sync_thread.start()
    search_thread.start()

    search_thread.join()


if __name__ == "__main__":
    main()
