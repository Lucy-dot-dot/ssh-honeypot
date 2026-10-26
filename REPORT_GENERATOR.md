# SSH Honeypot Report Generator

The SSH Honeypot includes a built-in report generator that can create detailed reports for specific IP addresses based on the authentication data stored in the database.

## Building

The report generator is built automatically when you build the project:

```bash
cargo build --release
```

This creates the `report-generator` binary in `target/release/`.

## Usage

### Basic Usage

Generate a text report for a specific IP address:

```bash
./target/release/report-generator --ip 192.168.1.100
```

### Command Line Options

- `--ip, -i`: **(Required)** IP address to generate report for
- `--format, -f`: Report format (text, html, markdown) - defaults to "text"
- `--output, -o`: Output file path (if not specified, prints to stdout)
- `--database-url, -d`: PostgreSQL database connection URL
- `--source, -s`: Data source view/table to query from (defaults to "auth_password_enriched")

### Examples

#### Generate a text report to stdout
```bash
./target/release/report-generator --ip 192.168.1.100
```

#### Save report to a file
```bash
./target/release/report-generator --ip 192.168.1.100 --output /tmp/ip_report.txt
```

#### Generate Markdown report
```bash
./target/release/report-generator --ip 192.168.1.100 --format markdown --output /tmp/ip_report.md
```

#### Generate HTML report
```bash
./target/release/report-generator --ip 192.168.1.100 --format html --output /tmp/ip_report.html
```

#### Use custom database URL
```bash
./target/release/report-generator --ip 192.168.1.100 --database-url "postgresql://user:pass@localhost:5432/custom_db"
```

## Report Contents

The text report includes the following sections:

### Geolocation Information
- Country and country code
- Region and city
- Geographic coordinates
- Timezone

### Network Information
- Internet Service Provider (ISP)
- Organization
- AS (Autonomous System) information

### Threat Intelligence
- AbuseIPDB confidence score
- Tor exit node detection
- Total abuse reports

### Attack Statistics
- Total authentication attempts
- Unique usernames attempted
- Unique passwords attempted
- First and last seen timestamps

### Top Lists
- Most attempted usernames (top 10)
- Most attempted passwords (top 10)

### Recent Activity
- Last 20 authentication attempts with timestamps

### Complete Data Section
- **Collapsible details section** with all authentication data
- **Complete schema data** (excluding raw response JSON)
- **Comprehensive table** with all available fields:
  - Timestamp, Username, Password
  - Country, City, ISP
  - Abuse Score, Tor Status, Total Reports

## Data Source

The report generator queries the `auth_password_enriched` view by default, which combines:

- Core authentication data from the `auth` table
- Geolocation data from IP-API
- Threat intelligence from AbuseIPDB

This view provides enriched data including geographic location, ISP information, and security intelligence for comprehensive threat analysis.

## Database Configuration

The report generator uses the same PostgreSQL database as the main honeypot application. You can configure the database connection using:

1. Environment variable: `DATABASE_URL`
2. Command line argument: `--database-url`
3. Default: `postgresql://honeypot:honeypot@localhost:5432/ssh_honeypot`

## Markdown Report Features

The markdown format includes:

- **Structured sections** with clear headings
- **Tables** for organized data presentation
- **Code formatting** for usernames and passwords
- **Emphasis** for important metrics (abuse scores, Tor detection)
- **GitHub-compatible markdown** for easy viewing and sharing

The markdown reports are perfect for:
- Documentation and incident reports
- Sharing threat intelligence with teams
- Integration with markdown-based wikis
- Version control and change tracking

**Collapsible Details:** Both markdown and HTML formats include a collapsible details section with complete authentication data, providing access to all schema fields except raw response JSON.

## HTML Report Features

The HTML format provides a modern, accessible web interface with:

### **Professional Design**
- **Clean, corporate-friendly styling** with professional color scheme
- **Responsive design** that works on desktop, tablet, and mobile devices
- **Print-optimized** styles for physical report generation

### **Accessibility Features (WCAG 2.1 Compliant)**
- **Semantic HTML5** structure with proper heading hierarchy
- **ARIA labels** and roles for screen reader compatibility
- **High contrast support** for users with visual impairments
- **Reduced motion support** for users with vestibular disorders
- **Keyboard navigation** friendly
- **Focus indicators** for interactive elements

### **Interactive Elements**
- **Hover effects** on table rows for better data scanning
- **Color-coded threat levels** (high/medium/low abuse scores)
- **Responsive grid layouts** that adapt to screen size
- **Visual indicators** for Tor exit nodes and threat levels

### **Data Visualization**
- **Statistics cards** with prominent metrics display
- **Information grids** for organized geolocation and network data
- **Professional tables** with proper headers and alternating row colors
- **Monospace formatting** for technical data (IPs, usernames, passwords)
- **Collapsible details section** with complete authentication data

The HTML reports are perfect for:
- Executive security briefings and board presentations
- Incident response documentation
- Client-facing security assessments
- Web-based threat intelligence dashboards
- Embedding in security portals and wikis

## Future Enhancements

- Charts and graphs for trend analysis
- Additional data sources and views
- Time-based filtering options
- Bulk report generation for multiple IPs
- Export to JSON/CSV formats
- Interactive JavaScript features for sorting and filtering