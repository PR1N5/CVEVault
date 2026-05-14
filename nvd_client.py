import time
import requests

from config import (
    NVD_BASE_URL,
    RESULTS_PER_PAGE,
    REQUEST_TIMEOUT_SECONDS,
    MAX_RETRIES,
)

def extract_cvss(cve):
    metrics = cve.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])

        if metric_list:
            metric = metric_list[0]
            cvss_data = metric.get("cvssData", {})

            return {
                "severity": cvss_data.get("baseSeverity") or metric.get("baseSeverity"),
                "cvss_score": cvss_data.get("baseScore"),
            }

    return {
        "severity": None,
        "cvss_score": None,
    }


def extract_cwe(cve):
    weaknesses = cve.get("weaknesses", [])

    for weakness in weaknesses:
        for description in weakness.get("description", []):
            value = description.get("value")

            if value and value.startswith("CWE-"):
                return value

    return None


def extract_references(cve):
    references = cve.get("references", [])

    urls = []
    for ref in references:
        url = ref.get("url")
        if url:
            urls.append(url)

    while len(urls) < 4:
        urls.append(None)

    return {
        "source_url": urls[0] or f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
        "reference_url_1": urls[1],
        "reference_url_2": urls[2],
        "reference_url_3": urls[3],
    }

def request_nvd(params):
    last_error = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                NVD_BASE_URL,
                params=params,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )

            if response.status_code == 429:
                wait_time = 30 * attempt
                print(f"[NVD] Rate limited. Waiting {wait_time}s...")
                time.sleep(wait_time)
                continue

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as error:
            last_error = error
            wait_time = 10 * attempt
            print(f"[NVD] Request failed attempt {attempt}/{MAX_RETRIES}: {error}")
            print(f"[NVD] Waiting {wait_time}s before retry...")
            time.sleep(wait_time)

    raise last_error


def parse_cve(item):
    cve = item["cve"]

    cve_id = cve.get("id")
    published = cve.get("published")
    last_modified = cve.get("lastModified")

    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    technologies = extract_technologies(cve)
    cvss = extract_cvss(cve)
    cwe_id = extract_cwe(cve)
    refs = extract_references(cve)

    title = description[:250] if description else cve_id

    return {
        "cve_id": cve_id,
        "title": title,
        "description": description,
        "technologies": ", ".join(technologies),

        "severity": cvss["severity"],
        "cvss_score": cvss["cvss_score"],
        "cwe_id": cwe_id,

        "published_date": clean_date(published),
        "last_modified_date": clean_date(last_modified),

        "source_url": refs["source_url"],
        "reference_url_1": refs["reference_url_1"],
        "reference_url_2": refs["reference_url_2"],
        "reference_url_3": refs["reference_url_3"],
    }


def extract_technologies(cve):
    technologies = set()

    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                parts = criteria.split(":")

                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    technologies.add(f"{vendor}:{product}")

    return sorted(technologies)


def clean_date(date_str):
    if not date_str:
        return None

    return date_str.replace("T", " ").replace("Z", "").split(".")[0]


def format_nvd_date(date_obj):
    if isinstance(date_obj, str):
        return date_obj

    return date_obj.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_cves(start_index=0, results_per_page=RESULTS_PER_PAGE):
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }

    return request_nvd(params)


def search_cves_by_keyword(keyword, limit=20):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit,
    }

    data = request_nvd(params)

    return [parse_cve(item) for item in data.get("vulnerabilities", [])]


def fetch_modified_cves(start_date, end_date):
    params = {
        "lastModStartDate": format_nvd_date(start_date),
        "lastModEndDate": format_nvd_date(end_date),
        "resultsPerPage": RESULTS_PER_PAGE,
    }

    data = request_nvd(params)

    return [parse_cve(item) for item in data.get("vulnerabilities", [])]

