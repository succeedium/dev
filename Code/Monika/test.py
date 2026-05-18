
"""
SPACE TM1 Audit Log -> Daily unique users and per-user login dates

What this script does (high level):
1) Calls the SPACE API (HTTP POST) for TM1 audit logs filtered to "User login".
2) Follows pagination with skip/top until it has all records in the requested date range.
3) Normalizes usernames (lowercase via .casefold()) and drops empties (optionally drop "system").
4) Converts each TimeStamp to a date string (YYYY-MM-DD) using the fact the API already returns
   times in the timezone requested in the payload ("tz").
5) Aggregates in two ways using sets for uniqueness:
   - by_day[date]   -> set(usernames)  (so len(set) is #unique users that day)
   - by_user[user]  -> set(dates)      (so sorted list shows all dates that user logged in)
6) Prints two tidy tables, sorted (dates ascending, users alphabetically).
7) Optional: write both tables to CSV if --csv is passed (or EXPORT_CSV=1 is set).

Security note:
- The code reads your SPACE API token from the environment variable SPACE_TOKEN.
- For convenience/fallback, it also includes the token provided in your instructions below.
  Replace it or, better, set the environment variable and remove the hardcoded token before committing.
"""

from __future__ import annotations

import os
import sys
import time
import json
import csv
import re
from typing import Dict, Set, List, Iterable, Tuple
from collections import defaultdict

try:
    import requests  # pip install requests
except ImportError as e:
    print("This script requires the 'requests' package. Install it with: pip install requests", file=sys.stderr)
    raise

API_URL = "https://api.succeedium.com/api/pa/4/auditlog"

# --- Configuration you will likely tweak ---
# Date range exactly as in your task (UTC-style strings accepted by SPACE; server applies 'tz' conversion):
START_ISO = "2025-07-17T07:00:00.000Z"
END_ISO   = "2025-08-17T06:59:59.999Z"

# Pagination defaults (page size and offset step):
TOP  = 100  # how many records to ask for per page
SKIP_START = 0  # start offset

# Timezone for the API to convert timestamps into (per your spec).
REQUEST_TZ = "America/Los_Angeles"

# Whether to exclude certain service/system accounts (customize the predicate below).
EXCLUDE_USERNAMES = {"system"}  # normalized (case-insensitive) names to exclude

# Read token from env; fallback to the provided one for convenience (remove before committing to a repo).
SPACE_TOKEN = os.getenv(
    "SPACE_TOKEN",
    "6e260a9c5ee95e27c192487fef194d317205f91197ce322b6f7056b6bce1779d",
)

# Optional CSV export toggle via env; or pass --csv on the command line.
EXPORT_CSV = os.getenv("EXPORT_CSV", "").strip() in {"1", "true", "yes"}

# --- End of tweakable config ---


def build_payload(skip: int, top: int) -> dict:
    """Create the POST body for a single page request."""
    return {
        "start": START_ISO,
        "end": END_ISO,
        "skip": skip,
        "top": top,
        "advancedSearch": {
            "operator": "and",
            "queries": [
                {"name": "action", "operator": "in", "value": ["User login"], "id": 3}
            ],
        },
        "tz": REQUEST_TZ,
    }


def make_headers() -> dict:
    """Create HTTP headers including the auth token."""
    if not SPACE_TOKEN or SPACE_TOKEN.startswith("YOUR_"):
        print(
            "ERROR: SPACE token is not set. Set SPACE_TOKEN env var or put it in the script.",
            file=sys.stderr,
        )
        sys.exit(2)
    return {
        "Content-Type": "application/json",
        "space-token": SPACE_TOKEN,
    }


def request_page(session: requests.Session, skip: int, top: int, *, max_retries: int = 3, timeout: int = 30) -> List[dict]:
    """POST one page and return its 'data' list. Retries a few times on transient errors (429/5xx)."""
    payload = build_payload(skip, top)
    headers = make_headers()

    backoff = 1.0
    for attempt in range(1, max_retries + 1):
        try:
            resp = session.post(API_URL, headers=headers, json=payload, timeout=timeout)
            # If server returns 429 (rate limit) or 5xx, we retry with exponential backoff.
            if resp.status_code in {429, 500, 502, 503, 504}:
                if attempt < max_retries:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                resp.raise_for_status()  # give up after retries
            resp.raise_for_status()
            obj = resp.json()
            data = obj.get("data", [])
            if not isinstance(data, list):
                raise ValueError("Unexpected response shape: 'data' is not a list")
            return data
        except (requests.RequestException, ValueError, json.JSONDecodeError) as e:
            if attempt < max_retries:
                time.sleep(backoff)
                backoff *= 2
                continue
            # Final failure
            print(f"ERROR: failed to fetch page skip={skip} top={top}: {e}", file=sys.stderr)
            sys.exit(1)

    return []  # unreachable, here to satisfy type checkers


def fetch_all_pages() -> List[dict]:
    """Loop skip=0,top=TOP; skip+=TOP until returned count < TOP."""
    all_items: List[dict] = []
    skip = SKIP_START
    top = TOP

    with requests.Session() as sess:
        while True:
            page = request_page(sess, skip, top)
            all_items.extend(page)
            # Stop when the server returns fewer than 'top' items.
            if len(page) < top:
                break
            skip += top

    return all_items


def normalize_username(raw: str) -> str:
    """
    Normalize usernames to avoid double-counting due to casing/spacing:
    - strip surrounding whitespace
    - collapse internal whitespace to single spaces
    - casefold for robust lowercase
    """
    if raw is None:
        return ""
    s = " ".join(raw.strip().split())
    return s.casefold()  # more robust than lower() for international text


def should_skip_user(norm_user: str) -> bool:
    """Return True if this username should be excluded from counting."""
    if not norm_user:
        return True  # empty or None
    if norm_user in EXCLUDE_USERNAMES:
        return True
    return False


DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")


def extract_date_from_timestamp(ts: str) -> str:
    """
    The API returns TimeStamp already in the 'tz' we asked for.
    We only need the calendar date (YYYY-MM-DD).
    - Example: '2025-08-16 05:43:12 UTC' -> '2025-08-16'
    Strategy: grab the first 10 characters or use a regex to be safer.
    """
    if not ts:
        raise ValueError("Missing TimeStamp")
    m = DATE_RE.match(ts.strip())
    if not m:
        raise ValueError(f"Unexpected TimeStamp format: {ts!r}")
    return m.group(1)  # 'YYYY-MM-DD'


def aggregate(items: Iterable[dict]) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    """
    Build:
      by_day:  date -> set(usernames)
      by_user: user -> set(dates)
    """
    by_day: Dict[str, Set[str]] = defaultdict(set)
    by_user: Dict[str, Set[str]] = defaultdict(set)

    for it in items:
        raw_user = it.get("UserName", "")
        norm_user = normalize_username(raw_user)
        if should_skip_user(norm_user):
            continue
        ts = it.get("TimeStamp", "")
        date_str = extract_date_from_timestamp(ts)
        by_day[date_str].add(norm_user)
        by_user[norm_user].add(date_str)

    return by_day, by_user


def print_daily(by_day: Dict[str, Set[str]]) -> None:
    print("Daily unique user logins")
    print()
    header_1 = "Date"
    header_2 = "Unique Users"
    # Fixed widths for nice columns:
    print(f"{header_1:<12}{header_2}")
    for date in sorted(by_day.keys()):
        print(f"{date:<12}{len(by_day[date])}")
    print()


def print_per_user(by_user: Dict[str, Set[str]]) -> None:
    print("User login dates")
    print()
    header_1 = "User"
    header_2 = "Dates Logged In"
    # Compute a reasonable width for the first column
    user_width = max(len(header_1), *(len(u) for u in by_user.keys())) + 2
    print(f"{header_1:<{user_width}}{header_2}")
    for user in sorted(by_user.keys()):
        dates_sorted = sorted(by_user[user])
        dates_joined = ", ".join(dates_sorted)
        print(f"{user:<{user_width}}{dates_joined}")
    print()


def export_csv(by_day: Dict[str, Set[str]], by_user: Dict[str, Set[str]],
               daily_path: str = "daily_unique_users.csv",
               per_user_path: str = "user_login_dates.csv") -> None:
    """Write two CSVs: one row per date; one row per user with a semicolon list of dates."""
    # 1) Daily unique users
    with open(daily_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Date", "Unique Users"])
        for date in sorted(by_day.keys()):
            w.writerow([date, len(by_day[date])])

    # 2) User login dates
    with open(per_user_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["User", "Dates Logged In"])
        for user in sorted(by_user.keys()):
            dates_sorted = sorted(by_user[user])
            # Keep it readable; you could also write one row per (user, date) if preferred.
            w.writerow([user, "; ".join(dates_sorted)])

    print(f"CSV written: {daily_path}")
    print(f"CSV written: {per_user_path}")


def main(argv: List[str]) -> None:
    global EXPORT_CSV

    if "--csv" in argv:
        EXPORT_CSV = True
    if "--include-system" in argv:
        # If you want to include 'system' accounts, clear the exclusion set.
        EXCLUDE_USERNAMES.clear()

    # Fetch
    items = fetch_all_pages()

    # Aggregate
    by_day, by_user = aggregate(items)

    # Output
    print_daily(by_day)
    print_per_user(by_user)

    # Optional CSV
    if EXPORT_CSV:
        export_csv(by_day, by_user)


if __name__ == "__main__":
    main(sys.argv[1:])
