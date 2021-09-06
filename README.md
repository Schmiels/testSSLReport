# testSSLReport

## USAGE
python3 generateReport.py \[OPTIONS\]

With OPTIONS:
- h: Help output")
- v: SSL/TLS versions
   - "ALL"
   - one or more from "SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"
- o: Output directory (current directory if empty)
- d: Input directory
- f: Input file

Example:
- `python3 generateReport.py v SSLv2,SSLv3,TLSv1 o ./output/ d ./input/`
- `python3 generateReport.py v ALL o ./output/ d ./input/`
- `python3 generateReport.py d ./input/`

## ISSUES
The report layout/format differs in different `testssl.sh` versions. Due to the lack of information regarding those differences, there is only one supported .html "format". Upcomming versions will fix this issue.