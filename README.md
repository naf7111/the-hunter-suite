# The Hunter Suite v1.0

**Advanced Reconnaissance and JavaScript Security Analysis Platform**

The Hunter Suite is a comprehensive security tool developed for penetration testers and security researchers. It provides a modular approach to web reconnaissance, focusing on the discovery of hidden assets, auditing infrastructure security, and performing deep analysis of JavaScript source code.

---

## Core Modules

The platform is built on a modular architecture, allowing users to execute specific security tasks:

1. **JavaScript Security Analysis:** Performs deep scanning of local or remote JS files to identify hardcoded secrets, API keys, and potentially malicious code patterns such as eval() or unsafe DOM manipulations.
2. **Endpoint Discovery:** Automated extraction of hidden API endpoints, internal paths, and URLs embedded within complex client-side scripts.
3. **Security Headers Audit:** Evaluates server responses to ensure the presence of critical security headers like Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), and X-Frame-Options.
4. **Technology Fingerprinting:** Identifies the underlying technology stack, including web servers, frameworks (React, Vue, etc.), and Content Management Systems (CMS).
5. **Sensitive File Leak Scanner:** Proactively scans for exposed configuration files and directories such as .git, .env, and .htaccess.
6. **Custom Keyword Detection:** Allows researchers to define specific strings (e.g., internal-dev, staging-db) to be tracked and highlighted throughout the scanning process.
7. **Proxy Integration:** Supports seamless integration with interception proxies like Burp Suite through a configurable proxy toggle.

---

## Security and Logic Implementation

The Hunter Suite is designed with several advanced logic layers to ensure accuracy and safety:

### Intelligent Context Analysis
The tool distinguishes between standard third-party libraries and potential vulnerabilities. It includes a pre-defined whitelist of services like Rollbar, Sentry, and Google Analytics to reduce false positives and categorize them separately in reports.

### Data Sanitization and Safe Preview
To protect the security researcher, all extracted code snippets are processed through an HTML-escaping engine. This prevents the execution of malicious payloads when viewing the generated reports in a browser.



---

## Installation and Setup

### Prerequisites
- Python 3.x
- Requests library
##Execution
python3 recon.py
### Installation
Reporting
For every session, the tool generates a standalone HTML report featuring:

Subdomain mapping with status codes and IP resolution.

Categorized findings (Secrets, Suspicious Code, Third-party Services).

Highlighted matches for user-defined custom keywords.

Legal Disclaimer
This tool is intended for authorized security testing and educational purposes only. The developer assumes no liability for any misuse or damage caused by the application of this software. Proper authorization from target owners is mandatory before any scanning activity.

Author
Developed by: Nawaf Alshamrani


```bash
git clone [https://github.com/naf7111/the-hunter-suite.git](https://github.com/naf7111/the-hunter-suite.git)
cd the-hunter-suite
pip install requests urllib3

