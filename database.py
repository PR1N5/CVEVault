import mysql.connector
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME


def get_server_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
    )


def get_db_connection():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
    )


def init_database():
    server_conn = get_server_connection()
    cursor = server_conn.cursor()

    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    server_conn.commit()

    cursor.close()
    server_conn.close()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id INT AUTO_INCREMENT PRIMARY KEY,
            cve_id VARCHAR(32) NOT NULL UNIQUE,

            title VARCHAR(255),
            description TEXT,
            technologies LONGTEXT,

            severity VARCHAR(32),
            cvss_score FLOAT,
            cwe_id VARCHAR(64),

            published_date DATETIME,
            last_modified_date DATETIME,

            source_url TEXT,
            reference_url_1 TEXT,
            reference_url_2 TEXT,
            reference_url_3 TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sync_state (
            id INT PRIMARY KEY,
            full_sync_completed BOOLEAN DEFAULT FALSE,
            full_sync_start_index INT DEFAULT 0,
            last_sync DATETIME NULL,
            last_request_at DATETIME NULL
        )
    """)

    cursor.execute("""
        INSERT IGNORE INTO sync_state (
            id,
            full_sync_completed,
            full_sync_start_index,
            last_sync,
            last_request_at
        )
        VALUES (1, FALSE, 0, NULL, NULL)
    """)

    conn.commit()
    cursor.close()
    conn.close()


def insert_or_update_cves(cves):
    if not cves:
        return

    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO cves (
            cve_id,
            title,
            description,
            technologies,
            severity,
            cvss_score,
            cwe_id,
            published_date,
            last_modified_date,
            source_url,
            reference_url_1,
            reference_url_2,
            reference_url_3
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            title = %s,
            description = %s,
            technologies = %s,
            severity = %s,
            cvss_score = %s,
            cwe_id = %s,
            published_date = %s,
            last_modified_date = %s,
            source_url = %s,
            reference_url_1 = %s,
            reference_url_2 = %s,
            reference_url_3 = %s
    """

    try:
        for cve in cves:
            values = (
                cve["cve_id"],
                cve["title"],
                cve["description"],
                cve["technologies"],
                cve["severity"],
                cve["cvss_score"],
                cve["cwe_id"],
                cve["published_date"],
                cve["last_modified_date"],
                cve["source_url"],
                cve["reference_url_1"],
                cve["reference_url_2"],
                cve["reference_url_3"],

                cve["title"],
                cve["description"],
                cve["technologies"],
                cve["severity"],
                cve["cvss_score"],
                cve["cwe_id"],
                cve["published_date"],
                cve["last_modified_date"],
                cve["source_url"],
                cve["reference_url_1"],
                cve["reference_url_2"],
                cve["reference_url_3"],
            )

            cursor.execute(query, values)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        cursor.close()
        conn.close()

def get_sync_state():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM sync_state WHERE id = 1")
    row = cursor.fetchone()

    cursor.close()
    conn.close()

    return row


def update_full_sync_progress(next_start_index, last_request_at):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE sync_state
        SET full_sync_start_index = %s,
            last_request_at = %s
        WHERE id = 1
    """, (next_start_index, last_request_at))

    conn.commit()
    cursor.close()
    conn.close()


def mark_full_sync_completed(last_sync):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE sync_state
        SET full_sync_completed = TRUE,
            full_sync_start_index = 0,
            last_sync = %s,
            last_request_at = %s
        WHERE id = 1
    """, (last_sync, last_sync))

    conn.commit()
    cursor.close()
    conn.close()


def get_last_sync():
    state = get_sync_state()
    return state["last_sync"]


def update_last_sync(last_sync):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE sync_state
        SET last_sync = %s,
            last_request_at = %s
        WHERE id = 1
    """, (last_sync, last_sync))

    conn.commit()
    cursor.close()
    conn.close()


def update_last_request_at(last_request_at):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE sync_state
        SET last_request_at = %s
        WHERE id = 1
    """, (last_request_at,))

    conn.commit()
    cursor.close()
    conn.close()


