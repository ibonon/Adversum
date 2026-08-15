TLS_VULN_PATTERNS = [
    (r'verify\s*=\s*False', 'TLS certificate verification disabled', 'CWE-295', 'HIGH', 7.4),
    (r'ssl\.CERT_NONE', 'SSL certificate not required', 'CWE-295', 'HIGH', 7.4),
    (r'check_hostname\s*=\s*False', 'Hostname verification disabled', 'CWE-297', 'HIGH', 7.4),
    (r'SSLv2|SSLv3|TLSv1\.0|TLSv1\.1', 'Deprecated TLS version', 'CWE-326', 'HIGH', 7.5),
    (r'cipher.*RC4|RC4.*cipher', 'RC4 cipher is broken', 'CWE-327', 'HIGH', 7.5),
    (r'rejectUnauthorized\s*:\s*false', 'Node.js TLS rejectUnauthorized=false', 'CWE-295', 'HIGH', 7.4),
]
