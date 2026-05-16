"""
messy_data_generator.py
────────────────────────────────────────────────────────────────
Generates gloriously broken CSV data for testing data-cleaning
pipelines.

Usage:
    python messy_data_generator.py                  # defaults
    python messy_data_generator.py --mess disgusting --fields 20 --rows 1000
    python messy_data_generator.py --mess filthy --fields 10 --rows 100 --output my_data.csv
    python messy_data_generator.py --mess dirty --fields 5 --rows 100 --injection

Arguments:
    --mess      dirty | filthy | disgusting  (default: dirty)
    --fields    5 | 10 | 20                  (default: 5)
    --rows      10 | 100 | 1000              (default: 100)
    --injection                              (default: off) sprinkle SQL/XSS/cmd injection payloads
    --output    filename                     (default: messy_data_<mess>_<fields>f_<rows>r.csv)
"""

import csv
import random
import argparse
import io
import sys
from datetime import date


# ── Lookup data ──────────────────────────────────────────────────────────────

FIRST_NAMES = [
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael",
    "Linda", "William", "Barbara", "David", "Susan", "richard", "SARAH",
    "thomas", "KAREN", "charles", "Lisa", "christopher", "nancy", "daniel",
    "Betty", "Matthew", "margaret", "Anthony", "Sandra", "mark", "Ashley",
    "Donald", "emily", "Steven", "Donna", "paul", "Michelle", "Andrew",
    "Dorothy", "Joshua", "carol", "Kenneth", "amanda", "kevin", "Melissa",
    "brian", "deborah", "george", "stephanie", "timothy", "Rebecca",
    "Ronald", "sharon",
]

LAST_NAMES = [
    "Smith", "JOHNSON", "Williams", "Brown", "jones", "GARCIA", "Miller",
    "Davis", "wilson", "anderson", "Taylor", "Thomas", "hernandez", "moore",
    "martin", "JACKSON", "Thompson", "white", "lopez", "Lee", "gonzalez",
    "harris", "Clark", "Lewis", "robinson", "walker", "Perez", "Hall",
    "young", "allen",
]

CITIES = [
    "New York, NY", "Los Angeles, CA", "Chicago, IL", "Houston TX",
    "Phoenix, Arizona", "Philadelphia, PA", "San Antonio,TX", "San Diego, CA",
    "dallas, tx", "san jose CA", "Austin, Texas", "Jacksonville FL",
    "Fort Worth, TX", "Columbus OH", "Charlotte, NC",
]

DEPARTMENTS = [
    "Engineering", "Sales", "HR", "Marketing", "Finance", "Operations",
    "Legal", "IT", "Product", "Design", "engineering", "SALES",
    "Human Resources", "Mktg", "Fin",
]

EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "company.com", "corp.net",
    "outlook.com",
]

PRODUCTS = [
    "Widget A", "Gadget Pro", "Tool X", "Device Y", "Gizmo Z",
    "Part 1234", "Component B", "Module 7",
]

STATUSES = [
    "Active", "active", "ACTIVE", "Inactive", "inactive",
    "pending", "Pending", "PENDING", "N/A", "n/a", "",
    "NULL", "None", "yes", "no", "1", "0",
]

COUNTRIES = [
    "US", "USA", "United States", "U.S.A.", "United States of America",
    "uk", "UK", "United Kingdom", "GB", "Canada", "CA", "CAN",
]

BOOL_CHAOS = [
    "true", "True", "TRUE", "false", "False", "FALSE",
    "1", "0", "yes", "no", "Yes", "No", "Y", "N", "T", "F",
]

MONTH_NAMES = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]

# ── Injection payloads ────────────────────────────────────────────────────────

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "'; DROP TABLE users;--",
    "'; DROP TABLE orders;--",
    "1' UNION SELECT null,null,null--",
    "1' UNION SELECT username,password,null FROM users--",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "' OR 'x'='x",
    "1; SELECT * FROM information_schema.tables--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "'; EXEC xp_cmdshell('whoami');--",
    "' AND SLEEP(5)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' WAITFOR DELAY '0:0:5'--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg onload=alert(1)>",
    '"><script>alert(document.domain)</script>',
    "<body onload=alert('XSS')>",
]

CMD_INJECTION_PAYLOADS = [
    "../../../etc/passwd",
    "| ls -la",
    "; cat /etc/shadow",
    "$(whoami)",
    "`id`",
    "%0a cat /etc/passwd",
]

# SQL payloads are weighted twice as they're the most common real-world vector
ALL_INJECTION_PAYLOADS = SQL_INJECTION_PAYLOADS * 2 + XSS_PAYLOADS + CMD_INJECTION_PAYLOADS


# ── Mess-level config ─────────────────────────────────────────────────────────

# Each key maps to which levels activate it, and a base probability.
MESS_CATALOGUE = {
    "null_empty":        {"levels": {"dirty", "filthy", "disgusting"}, "base": 0.08},
    "mixed_case":        {"levels": {"dirty", "filthy", "disgusting"}, "base": 0.25},
    "date_formats":      {"levels": {"dirty", "filthy", "disgusting"}, "base": 1.00},  # always varied
    "currency_symbols":  {"levels": {"dirty", "filthy", "disgusting"}, "base": 0.12},
    "phone_formats":     {"levels": {"dirty", "filthy", "disgusting"}, "base": 0.15},
    "unquoted_commas":   {"levels": {"dirty", "filthy", "disgusting"}, "base": 1.00},  # data contains commas
    "semicolon_rows":    {"levels": {"dirty", "filthy", "disgusting"}, "base": 0.08},
    "trailing_spaces":   {"levels": {"filthy", "disgusting"},          "base": 0.15},
    "duplicate_ids":     {"levels": {"filthy", "disgusting"},          "base": 0.10},
    "unicode_chars":     {"levels": {"filthy", "disgusting"},          "base": 0.08},
    "negative_amounts":  {"levels": {"filthy", "disgusting"},          "base": 0.10},
    "mixed_delimiters":  {"levels": {"filthy", "disgusting"},          "base": 0.06},
    "html_injection":    {"levels": {"disgusting"},                    "base": 0.05},
    "newlines_in_fields":{"levels": {"disgusting"},                    "base": 0.04},
    "number_as_string":  {"levels": {"disgusting"},                    "base": 0.10},
    "boolean_chaos":     {"levels": {"disgusting"},                    "base": 1.00},
    "null_string":       {"levels": {"disgusting"},                    "base": 0.08},
    "encoding_artifacts":{"levels": {"disgusting"},                    "base": 0.05},
}

LEVEL_MULTIPLIERS = {"dirty": 1.0, "filthy": 2.5, "disgusting": 5.0}


# ── Generator class ───────────────────────────────────────────────────────────

class MessyDataGenerator:
    def __init__(self, mess: str = "dirty", num_fields: int = 5, num_rows: int = 100, injection: bool = False):
        assert mess in ("dirty", "filthy", "disgusting"), "mess must be dirty, filthy, or disgusting"
        assert num_fields in (5, 10, 20), "num_fields must be 5, 10, or 20"
        assert num_rows in (10, 100, 1000), "num_rows must be 10, 100, or 1000"

        self.mess = mess
        self.num_fields = num_fields
        self.num_rows = num_rows
        self.injection = injection
        self.multiplier = LEVEL_MULTIPLIERS[mess]
        self._seen_ids: set = set()
        self._injection_count: int = 0

    def _maybe_inject(self, value: str) -> str:
        """12% chance to replace a text field with an injection payload when enabled."""
        if not self.injection:
            return value
        if random.random() < 0.12:
            self._injection_count += 1
            return random.choice(ALL_INJECTION_PAYLOADS)
        return value

    def _active(self, key: str) -> bool:
        return self.mess in MESS_CATALOGUE[key]["levels"]

    def _chance(self, key: str, override: float | None = None) -> bool:
        if not self._active(key):
            return False
        base = override if override is not None else MESS_CATALOGUE[key]["base"]
        return random.random() < min(base * self.multiplier, 0.95)

    def _make_id(self, i: int) -> int | str:
        if self._active("duplicate_ids") and self._chance("duplicate_ids") and i > 1:
            return random.randint(1, i)
        return i + 1

    def _make_name(self) -> str:
        first = random.choice(FIRST_NAMES)
        last = random.choice(LAST_NAMES)
        if self._chance("mixed_case", 0.3):
            first = first.upper() if random.random() < 0.5 else first.lower()
        if self._chance("unicode_chars", 0.08):
            first = first + "\u00e9"  # é
        result = f"{first} {last}"
        if self._chance("trailing_spaces", 0.15):
            result = result + "   "
        return self._maybe_inject(result)

    def _make_email(self, name: str = "user") -> str:
        if self._chance("null_empty", 0.08):
            return ""
        if self._chance("null_string", 0.05):
            return random.choice(["NULL", "None", "N/A"])
        clean = "".join(c for c in name.strip().lower() if c.isalpha() or c == " ")
        local = clean.replace(" ", ".")[:20]
        email = f"{local}@{random.choice(EMAIL_DOMAINS)}"
        if self._chance("unicode_chars", 0.06):
            email = email.replace("@", "@@")
        return self._maybe_inject(email)

    def _make_date(self) -> str:
        if self._chance("null_empty", 0.07):
            return ""
        y = random.randint(2018, 2024)
        m = random.randint(1, 12)
        d = random.randint(1, 28)
        formats = [
            f"{y}-{m:02d}-{d:02d}",                          # ISO 8601
            f"{m}/{d}/{y}",                                    # US
            f"{m}/{d}/{str(y)[2:]}",                           # US short year
            f"{d:02d}-{m:02d}-{y}",                           # European dashes
            f"{d}/{m}/{y}",                                    # European slashes
            f"{MONTH_NAMES[m-1]} {d}, {y}",                   # Long form
            f"{y}{m:02d}{d:02d}",                              # Compact YYYYMMDD
        ]
        return random.choice(formats)

    def _make_amount(self) -> str:
        if self._chance("null_empty", 0.06):
            return ""
        amount = round(random.uniform(-150.50, 5000.00), 2)
        result = str(abs(amount)) if self._chance("negative_amounts", 0.10) and amount > 0 else str(amount)
        if self._chance("currency_symbols", 0.12):
            symbol = random.choice(["$", "£", "€"])
            result = f"{symbol}{result}"
        if self._chance("number_as_string", 0.10):
            result = f'"{result}"'
        return result

    def _make_phone(self) -> str:
        if self._chance("null_empty", 0.09):
            return ""
        area = random.randint(100, 999)
        mid = random.randint(100, 999)
        end = random.randint(1000, 9999)
        base = f"{area}-{mid}-{end}"
        if self._chance("phone_formats", 0.15):
            base = base.replace("-", "")
        elif self._chance("phone_formats", 0.10):
            base = f"({area}) {mid}-{end}"
        elif self._chance("phone_formats", 0.08):
            base = f"+1{area}{mid}{end}"
        if self._chance("unicode_chars", 0.05):
            base = base.replace("-", "x", 1)
        return base

    def _make_city(self) -> str:
        city = random.choice(CITIES)
        if self._chance("trailing_spaces", 0.12):
            city = city + "  "
        return city

    def _make_notes(self) -> str:
        if self._chance("null_empty", 0.15):
            return ""
        if self._chance("null_string", 0.08):
            return random.choice(["NULL", "None", "null", "NaN"])
        if self._chance("html_injection", 0.05):
            return random.choice(["<b>urgent</b>", "<script>alert(1)</script>", "<!-- comment -->"])
        options = [
            "Processed", "processed", "PROCESSED", "Pending review",
            "Follow up needed", "Done", "done", "complete", "Complete", "COMPLETE",
        ]
        return self._maybe_inject(random.choice(options))

    def _make_age(self) -> str:
        if self._chance("null_empty", 0.08):
            return ""
        if self._chance("null_string", 0.06):
            return "N/A"
        age = random.randint(18, 80)
        if self._chance("number_as_string", 0.12):
            return f'"{age}"'
        return str(age)

    def _make_department(self) -> str:
        if self._chance("null_empty", 0.07):
            return ""
        dept = random.choice(DEPARTMENTS)
        if self._chance("trailing_spaces", 0.10):
            dept = "  " + dept
        return self._maybe_inject(dept)

    def _make_country(self) -> str:
        return random.choice(COUNTRIES)

    def _make_status(self) -> str:
        pool = STATUSES if self._active("boolean_chaos") else STATUSES[:4]
        return random.choice(pool)

    def _make_product(self) -> str:
        if self._chance("null_empty", 0.07):
            return ""
        product = random.choice(PRODUCTS)
        if self._chance("unicode_chars", 0.08):
            product = product + " \u2122"  # ™
        return product

    def _make_salary(self) -> str:
        if self._chance("null_empty", 0.06):
            return ""
        salary = random.randint(30000, 200000)
        result = str(salary)
        if self._chance("currency_symbols", 0.15):
            result = f"${salary:,}"
        if self._chance("number_as_string", 0.10):
            result = f'"{result}"'
        return result

    def _make_score(self) -> str:
        if self._chance("null_empty", 0.08):
            return ""
        decimals = random.randint(0, 4)
        score = round(random.uniform(0, 100), decimals)
        result = str(score)
        if self._chance("number_as_string", 0.10):
            result = result + "%"
        return result

    def _make_website(self) -> str:
        if self._chance("null_empty", 0.07):
            return ""
        domains = ["example.com", "test.org", "company.net", "demo.io"]
        scheme = "http" if self._chance("encoding_artifacts", 0.10) else "https"
        return f"{scheme}://www.{random.choice(domains)}"

    def _make_is_active(self) -> str:
        if self._active("boolean_chaos"):
            return random.choice(BOOL_CHAOS)
        return random.choice(["true", "false"])

    def _make_category(self) -> str:
        pool = ["A", "B", "C", "a", "b", "c", "cat_a", "CAT_B", "", "N/A"]
        return random.choice(pool)

    # ── Field registry (ordered – first N are used) ──────────────────────────

    def _field_defs(self):
        return [
            ("id",           lambda i, _: self._make_id(i)),
            ("name",         lambda i, _: self._make_name()),
            ("join_date",    lambda i, _: self._make_date()),
            ("amount",       lambda i, _: self._make_amount()),
            ("phone",        lambda i, _: self._make_phone()),
            ("city_state",   lambda i, _: self._make_city()),
            ("notes",        lambda i, _: self._make_notes()),
            ("email",        lambda i, ctx: self._make_email(ctx.get("name", "user"))),
            ("age",          lambda i, _: self._make_age()),
            ("department",   lambda i, _: self._make_department()),
            ("country",      lambda i, _: self._make_country()),
            ("status",       lambda i, _: self._make_status()),
            ("product",      lambda i, _: self._make_product()),
            ("salary",       lambda i, _: self._make_salary()),
            ("score",        lambda i, _: self._make_score()),
            ("website",      lambda i, _: self._make_website()),
            ("last_updated", lambda i, _: self._make_date()),
            ("is_active",    lambda i, _: self._make_is_active()),
            ("order_date",   lambda i, _: self._make_date()),
            ("category",     lambda i, _: self._make_category()),
        ]

    # ── Row assembly ──────────────────────────────────────────────────────────

    def _build_row(self, i: int) -> tuple[list[str], dict]:
        fields = self._field_defs()[:self.num_fields]
        ctx: dict = {}
        values: list[str] = []

        for name, fn in fields:
            val = fn(i, ctx)
            ctx[name] = str(val)
            s = str(val)
            if self._chance("newlines_in_fields", 0.04):
                s = s + "\n(continued)"
            if self._chance("encoding_artifacts", 0.05):
                s = s + "\ufffd"  # replacement character
            values.append(s)

        return values, ctx

    def _serialise_row(self, values: list[str], row_index: int) -> str:
        """Return a single CSV row string, potentially with deliberate delimiter chaos."""

        if self._chance("semicolon_rows", 0.08):
            return ";".join(values)

        if self._chance("mixed_delimiters", 0.06):
            sep = "|" if row_index % 2 == 0 else ","
            return sep.join(values)

        # Standard CSV escaping
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(values)
        return buf.getvalue().rstrip("\r\n")

    # ── Public API ────────────────────────────────────────────────────────────

    def generate(self) -> str:
        """Return the full CSV content as a string."""
        field_names = [name for name, _ in self._field_defs()[:self.num_fields]]
        lines = [",".join(field_names)]

        for i in range(self.num_rows):
            values, _ = self._build_row(i)
            lines.append(self._serialise_row(values, i))

        return "\n".join(lines)

    def generate_to_file(self, path: str) -> None:
        """Write CSV to a file and print a summary."""
        self._injection_count = 0
        content = self.generate()
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(content)

        active_mess = [k for k, v in MESS_CATALOGUE.items() if self.mess in v["levels"]]
        print(f"Generated '{path}'")
        print(f"  Mess level : {self.mess}")
        print(f"  Fields     : {self.num_fields}")
        print(f"  Rows       : {self.num_rows}")
        print(f"  File size  : {len(content) / 1024:.1f} KB")
        print(f"  Mess types : {', '.join(active_mess)}")
        if self.injection:
            print(f"  Injection  : ENABLED — {self._injection_count} payload(s) injected")


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate messy CSV data for testing data-cleaning pipelines."
    )
    parser.add_argument(
        "--mess",
        choices=["dirty", "filthy", "disgusting"],
        default="dirty",
        help="How messy the data should be (default: dirty)",
    )
    parser.add_argument(
        "--fields",
        type=int,
        choices=[5, 10, 20],
        default=5,
        help="Number of fields/columns (default: 5)",
    )
    parser.add_argument(
        "--rows",
        type=int,
        choices=[10, 100, 1000],
        default=100,
        help="Number of rows (default: 100)",
    )
    parser.add_argument(
        "--injection",
        action="store_true",
        default=False,
        help="Sprinkle SQL, XSS, and command injection payloads into text fields (default: off)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output filename (default: messy_data_<mess>_<fields>f_<rows>r.csv)",
    )
    args = parser.parse_args()

    inj_suffix = "_injection" if args.injection else ""
    output = args.output or f"messy_data_{args.mess}_{args.fields}f_{args.rows}r{inj_suffix}.csv"

    gen = MessyDataGenerator(mess=args.mess, num_fields=args.fields, num_rows=args.rows, injection=args.injection)
    gen.generate_to_file(output)


if __name__ == "__main__":
    main()
