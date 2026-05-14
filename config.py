import os
from dotenv import load_dotenv

load_dotenv()

DB_USER = os.getenv("USER_DB")
DB_PASSWORD = os.getenv("PASSWD_DB")
DB_NAME = os.getenv("DATABASE")
DB_HOST = os.getenv("HOST_DB", "localhost")

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

RESULTS_PER_PAGE = 1000
SYNC_INTERVAL_SECONDS = 300

REQUESTS_PER_WINDOW = 4
RATE_LIMIT_WINDOW_SECONDS = 30

REQUEST_TIMEOUT_SECONDS = 90
MAX_RETRIES = 5
