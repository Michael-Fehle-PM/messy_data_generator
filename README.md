# Messy Data Generator

A configurable messy CSV data generator for testing data-cleaning pipelines, ETL processes, and input sanitisation. Supports three mess levels, up to 20 field types, and optional SQL/XSS injection payloads. Available as a standalone HTML tool and a Python CLI script.

---

## What it does

Real-world data is never clean. This tool generates CSV files that mirror the kinds of problems you'll encounter in production data: inconsistent formats, missing values, encoding issues, duplicate records, and adversarial input strings.

Useful for:

- Testing data-cleaning and ETL pipelines
- Validating input sanitisation and parameterised queries
- Benchmarking data quality tools
- Generating realistic fixtures for unit and integration tests
- Demonstrating data quality issues to stakeholders

---

## Mess levels

| Level | Approx. corruption | Active mess types |
|---|---|---|
| **Dirty** | ~15% | 7 types |
| **Filthy** | ~35% | 13 types |
| **Disgusting** | ~60% | 18 types |

### Full catalogue of mess types

| Type | Dirty | Filthy | Disgusting |
|---|:---:|:---:|:---:|
| Null / empty values | ✓ | ✓ | ✓ |
| Mixed case names | ✓ | ✓ | ✓ |
| Inconsistent date formats (7 variants) | ✓ | ✓ | ✓ |
| Currency symbols in numeric fields | ✓ | ✓ | ✓ |
| Mangled phone numbers | ✓ | ✓ | ✓ |
| Unquoted commas in strings | ✓ | ✓ | ✓ |
| Semicolon-delimited rows | ✓ | ✓ | ✓ |
| Trailing / leading whitespace | | ✓ | ✓ |
| Duplicate IDs | | ✓ | ✓ |
| Unicode and special characters | | ✓ | ✓ |
| Negative amounts | | ✓ | ✓ |
| Mixed delimiters within file | | ✓ | ✓ |
| HTML tags in text fields | | | ✓ |
| Newlines embedded in fields | | | ✓ |
| Numbers stored as strings | | | ✓ |
| Boolean chaos (`true`/`TRUE`/`1`/`yes`/`Y`…) | | | ✓ |
| `"NULL"` / `"None"` / `"NaN"` as literal strings | | | ✓ |
| Encoding artifacts (`\uFFFD`) | | | ✓ |

---

## Injection payloads (opt-in)

When enabled, ~12% of text fields are replaced with adversarial payloads drawn from three categories:

**SQL injection**
```
' OR '1'='1
'; DROP TABLE users;--
1' UNION SELECT username,password,null FROM users--
' AND SLEEP(5)--
' WAITFOR DELAY '0:0:5'--
```

**XSS**
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

**Command injection / path traversal**
```
../../../etc/passwd
$(whoami)
; cat /etc/shadow
```

These are inert strings in a CSV — they only become dangerous if passed unsanitised into a database query, template, or shell command, which is exactly what they're designed to test against.

---

## Files

| File | Description |
|---|---|
| `messy_data_generator.html` | Standalone browser tool — no server, no dependencies |
| `messy_data_generator.py` | Python CLI script — no third-party dependencies |

---

## HTML tool

Open `messy_data_generator.html` directly in any browser. No server required.

- Choose mess level, number of fields (5 / 10 / 20), and number of rows (10 / 100 / 1,000)
- Toggle injection payloads on or off
- Preview the first few rows before downloading
- Download named `messy_data_<level>_<fields>f_<rows>r[_injection].csv`

Supports light and dark mode via `prefers-color-scheme`.

---

## Python CLI

### Requirements

Python 3.10+ — no third-party dependencies.

### Usage

```bash
# Defaults: dirty, 5 fields, 100 rows
python messy_data_generator.py

# Full options
python messy_data_generator.py --mess disgusting --fields 20 --rows 1000

# With injection payloads
python messy_data_generator.py --mess filthy --fields 10 --rows 100 --injection

# Custom output filename
python messy_data_generator.py --mess dirty --fields 5 --rows 1000 --output test_fixture.csv
```

### Arguments

| Argument | Options | Default |
|---|---|---|
| `--mess` | `dirty` \| `filthy` \| `disgusting` | `dirty` |
| `--fields` | `5` \| `10` \| `20` | `5` |
| `--rows` | `10` \| `100` \| `1000` | `100` |
| `--injection` | flag (no value needed) | off |
| `--output` | any filename | auto-generated |

### Programmatic use

The `MessyDataGenerator` class is importable:

```python
from messy_data_generator import MessyDataGenerator

gen = MessyDataGenerator(mess="filthy", num_fields=10, num_rows=100)
csv_string = gen.generate()

# With injection payloads
gen = MessyDataGenerator(mess="disgusting", num_fields=20, num_rows=1000, injection=True)
gen.generate_to_file("test_data.csv")
```

---

## Field types

The generator includes 20 field types. Selecting 5, 10, or 20 fields takes the first N from this list:

`id` · `name` · `join_date` · `amount` · `phone` · `city_state` · `notes` · `email` · `age` · `department` · `country` · `status` · `product` · `salary` · `score` · `website` · `last_updated` · `is_active` · `order_date` · `category`

---

## Example output

Filthy, 5 fields, 10 rows:

```
id,name,join_date,amount,phone
1,JAMES smith   ,6/3/2022,$1842.50,555-210-4837
2,mary JOHNSON,03-11-2023,,-
3,Robert williams,20230715,£-94.20,(312) 555-0192
4,PATRICIA Brown,11/8/23,"$3,201.00",+13125550143
5,,Jan 2 2024,2987.11,555-831x9204
6,david garcia   ,2/14/2022,,5558319204
7,jennifer Davis,2024-02-28,-442.60,
8;MICHAEL wilson;9/3/21;$77.00;5553409981
9,Lisa MOORE,20220417,4103.90,(404) 555-2291
10,William anderson,4/5/2022,"$1,500.00",404-555-2291
```

Row 8 uses a semicolon delimiter. Row 2 has an empty amount. Row 5 has a missing ID and an `x` in the phone number.

---

## Licence

MIT
