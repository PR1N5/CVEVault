# CVEVault

CVEVault is a tool designed to collect and store CVEs from 1999 to the present day using the NVD API. All CVEs are stored locally in a MySQL database, allowing fast searches by:

* CVE-ID
* Technology/vendor/product names
* Latest published CVEs


## Setup

Create a Python virtual environment:

```bash
python3 -m venv modules
source modules/bin/activate
```

Install the requirements:

```bash
pip3 install -r requirements.txt
```

Configure the database credentials inside `.env`:

```env
USER_DB=<USER>
PASSWD_DB=<PASS>
DATABASE=CVE
HOST_DB=localhost
```

Start the application:

```bash
python3 main.py
```

## First Launch

During the first execution, the tool performs a full synchronization of all CVEs available in the NVD database.

This process may take ~1 hour without an NVD API key due to public rate limits.

## Search Commands

Retrieve the newest CVEs:

```bash
.new <NUMBER>
```

Example:

```bash
.new 10
```

Search by CVE-ID:

```bash
CVE-2026-31431
```

Search by keyword/technology:

```bash
nginx
openssl
linux kernel
```
