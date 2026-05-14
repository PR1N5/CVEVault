from database import get_db_connection
from nvd_client import search_cves_by_keyword
import ui_state


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


def run_search_loop():
    while True:
        # user_input = input("\nSearch technology > ").strip()
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

                if not newest_cves:
                    print("No CVEs found.")
                    continue

                print(f"\nNewest {limit} CVEs:\n")

                for cve in newest_cves:
                    print(
                        f"{cve['cve_id']} | "
                        f"{cve.get('title', 'NO TITLE')} | "
                        f"{cve['severity']} | "
                        f"{cve['cvss_score']} | "
                        f"{cve['source_url']}"
                    )

                continue

            #
            # normal keyword search
            #
            results = search_cves_by_keyword(user_input)

            results = sorted(
                results,
                key=lambda cve: get_cve_sort_key(cve["cve_id"]),
                reverse=True
            )

            if not results:
                print("No CVEs found.")
                continue

            for cve in results:
                print(
                    f"{cve['cve_id']} | "
                    f"{cve.get('title', 'NO TITLE')} | "
                    f"{cve['severity']} | "
                    f"{cve['cvss_score']} | "
                    f"{cve['source_url']}"
                )

        except Exception as error:
            print(f"Search error: {error}")

