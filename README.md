![Usage Example](/assets/banner.png)

---

![Python](https://img.shields.io/badge/python-3.x-blue)
![License](https://img.shields.io/badge/license-MIT-green)

SafeMX is your **first line of defense** against email spoofing and phishing attacks. Effortlessly check your domain's **SPF**, **DKIM**, and **DMARC** records to ensure your emails are authenticated and secure.

![Usage Example](/assets/example.png)

## Features

- 🛡 **SPF**, **DKIM**, and **DMARC** record validation
- ⚡ Fast, reliable, and easy to use
- 🌐 **JSON** and **console** output formats for flexibility
- 🚀 Cool modern design with easy setup and execution

## 🚀 Getting Started

Follow these simple steps to install and use **SafeMX**:

### Prerequisites
- Python 3.x
- `pip` package manager

### Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/MarkoGordic/SafeMX.git
    ```

2. Navigate to the project directory:
    ```bash
    cd safemx
    ```

3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

---

## 🛠️ Usage

Run **SafeMX** to check SPF, DMARC, and DKIM records for a domain. You can specify the output format (console or JSON).

### Checking SPF, DMARC, and DKIM

- To check **SPF**:
    ```bash
    python3 main.py example.com -spf
    ```

- To check **DMARC**:
    ```bash
    python3 main.py example.com -dmarc
    ```

- To check **DKIM**:
    ```bash
    python3 main.py example.com -dkim -selector default
    ```

### Output Formats

- **Console Output** (default):
    ```bash
    python3 main.py example.com -spf -dmarc
    ```

- **JSON Output**:
    ```bash
    python3 main.py example.com -spf -dmarc --output json --outfile result.json
    ```

---

## Example Output

### Console Output:
```text
[+] SPF record for example.com found!
    spf: "v=spf1 ip4:192.0.2.0/24 -all"
[+] DMARC record for example.com found!
    dmarc: "v=DMARC1; p=quarantine; adkim=s; aspf=s;"
```

### JSON Output:
```json
{
  "spf": {
    "record": "v=spf1 ip4:192.0.2.0/24 -all",
    "version": "v=spf1",
    "mechanisms": [
      {
        "type": "ip",
        "value": "ip4:192.0.2.0/24"
      },
      {
        "type": "all",
        "value": "-all"
      }
    ]
  },
  "dmarc": {
    "record": "v=DMARC1; p=quarantine; adkim=s; aspf=s;",
    "fields": {
      "v": "DMARC1",
      "p": "quarantine",
      "adkim": "s",
      "aspf": "s"
    }
  }
}
```

---

## 📜 License

**SafeMX** is open-source software licensed under the MIT License.