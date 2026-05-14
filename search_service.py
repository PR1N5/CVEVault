import ui_state

from database import get_db_connection


def get_cve_sort_key(cve_id):
    try:
        parts = cve_id.split("-")

        year = int(parts[1])
        number = int(parts[2])

        return year, number

    except (IndexError, ValueError, AttributeError):
        return 0, 0


def get_newest_cves(limit):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            cve_id,
            title,
            severity,
            cvss_score,
            published_date,
            source_url
        FROM cves
    """)

    results = cursor.fetchall()

    cursor.close()
    conn.close()

    results = sorted(
        results,
        key=lambda cve: get_cve_sort_key(cve["cve_id"]),
        reverse=True
    )

    return results[:limit]


def search_local_cves(keyword):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    like = f"%{keyword}%"

    cursor.execute("""
        SELECT
            cve_id,
            title,
            severity,
            cvss_score,
            published_date,
            source_url
        FROM cves
        WHERE
            cve_id LIKE %s
            OR title LIKE %s
            OR description LIKE %s
            OR technologies LIKE %s
    """, (like, like, like, like))

    results = cursor.fetchall()

    cursor.close()
    conn.close()

    results = sorted(
        results,
        key=lambda cve: get_cve_sort_key(cve["cve_id"]),
        reverse=True
    )

    return results


def print_cves(results):
    if not results:
        print("No CVEs found.")
        return

    for cve in results:
        print(
            f"{cve['cve_id']} | "
            f"{cve.get('title', 'NO TITLE')} | "
            f"{cve.get('severity', 'UNKNOWN')} | "
            f"{cve.get('cvss_score', 'N/A')} | "
            f"{cve.get('source_url', 'NO URL')}"
        )


def run_search_loop():
    while True:
        prompt = (
            f"\n[SYNC STATUS] {ui_state.sync_status}\n"
            "Search technology > "
        )

        user_input = input(prompt).strip()

        if user_input.lower() in ("exit", "quit"):
            print("Exiting search...")
            break

        if not user_input:
            continue

        try:
            #
            # .new 10
            #
            if user_input.startswith(".new"):
                parts = user_input.split()

                if len(parts) != 2:
                    print("Usage: .new <NUMBER>")
                    continue

                try:
                    limit = int(parts[1])
                except ValueError:
                    print("Invalid number.")
                    continue

                newest_cves = get_newest_cves(limit)
                print_cves(newest_cves)

                continue

            #
            # local DB search
            #
            results = search_local_cves(user_input)

            print_cves(results)

        except Exception as error:
            print(f"Search error: {error}")

