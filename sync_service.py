import time
from datetime import datetime, timedelta
from ui_state import sync_status
import ui_state

from config import (
    SYNC_INTERVAL_SECONDS,
    RESULTS_PER_PAGE,
    REQUESTS_PER_WINDOW,
    RATE_LIMIT_WINDOW_SECONDS,
)
from database import (
    get_sync_state,
    insert_or_update_cves,
    mark_full_sync_completed,
    update_full_sync_progress,
    get_last_sync,
    update_last_sync,
    update_last_request_at,
)
from nvd_client import fetch_cves, parse_cve, fetch_modified_cves


def run_sync_loop():
    state = get_sync_state()

    if not state["full_sync_completed"]:
        full_sync()

    while True:
        incremental_sync()
        time.sleep(SYNC_INTERVAL_SECONDS)


def full_sync():
    state = get_sync_state()
    start_index = state["full_sync_start_index"] or 0
    total_results = None
    requests_in_window = 0
    window_started_at = time.time()

    print(f"[SYNC] Starting full sync from index {start_index}...")

    while total_results is None or start_index < total_results:
        if requests_in_window >= REQUESTS_PER_WINDOW:
            elapsed = time.time() - window_started_at

            if elapsed < RATE_LIMIT_WINDOW_SECONDS:
                sleep_time = RATE_LIMIT_WINDOW_SECONDS - elapsed
                print(f"[SYNC] Rate limit window reached. Sleeping {sleep_time:.1f}s...")
                time.sleep(sleep_time)

            requests_in_window = 0
            window_started_at = time.time()

        print(f"[SYNC] Downloading page starting at {start_index}")

        data = fetch_cves(
            start_index=start_index,
            results_per_page=RESULTS_PER_PAGE,
        )

        requests_in_window += 1

        total_results = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        parsed_cves = [parse_cve(item) for item in vulnerabilities]
        insert_or_update_cves(parsed_cves)

        next_start_index = start_index + RESULTS_PER_PAGE
        now = datetime.utcnow()

        update_full_sync_progress(next_start_index, now)

        print(
            f"[SYNC] Saved {len(parsed_cves)} CVEs. "
            f"Progress: {next_start_index}/{total_results}"
        )

        start_index = next_start_index

    now = datetime.utcnow()
    mark_full_sync_completed(now)

    print("[SYNC] Full sync completed.")


def incremental_sync():
    last_sync = get_last_sync()

    if last_sync is None:
        full_sync()
        return

    start_date = last_sync - timedelta(minutes=10)
    end_date = datetime.utcnow()

    # print(f"[SYNC] Fetching modified CVEs from {start_date} to {end_date}")
    ui_state.sync_status = (f"Fetching modified CVEs from {start_date} to {end_date}")

    try:
        cves = fetch_modified_cves(start_date, end_date)

        now = datetime.utcnow()
        update_last_request_at(now)

        insert_or_update_cves(cves)
        update_last_sync(end_date)

        # print(f"[SYNC] Incremental sync completed. CVEs processed: {len(cves)}")
        ui_state.sync_status = (f"Incremental sync completed. CVEs processed: {len(cves)}")

    except Exception as error:
        print(f"[SYNC] Incremental sync error: {error}")
