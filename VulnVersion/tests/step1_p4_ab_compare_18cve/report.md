# Step1 P4 A/B Validation: Packet Only vs Read-only Git Tools

## Summary

| variant | success CVEs | failed CVEs | avg latency s | unknown failed regions |
| --- | ---: | ---: | ---: | ---: |
| packet-only | 16/18 | 2 | 96.458 | 3 |
| packet+git-tools | 16/18 | 2 | 154.278 | 13 |

## Case Diffs

| repo | CVE | packet success | git success | packet latency | git latency | delta | note |
| --- | --- | --- | --- | ---: | ---: | ---: | --- |
| FFmpeg | CVE-2022-3965 | False | False | 77.328 | 250.343 | 173.015 | git slower |
| FFmpeg | CVE-2020-24020 | True | True | 32.844 | 264.532 | 231.688 | git slower |
| ImageMagick | CVE-2023-3195 | True | True | 21.203 | 365.687 | 344.484 | git slower |
| ImageMagick | CVE-2020-27768 | True | True | 30.484 | 29.125 | -1.359 | git faster |
| curl | CVE-2024-9681 | True | True | 80.11 | 88.422 | 8.312 | git slower |
| curl | CVE-2024-8096 | True | True | 23.343 | 162.672 | 139.329 | git slower |
| httpd | CVE-2022-30522 | True | False | 48.5 | 900.375 | 851.875 | success regression |
| httpd | CVE-2022-31813 | True | True | 16.0 | 149.5 | 133.5 | git slower |
| linux | CVE-2022-0171 | True | True | 56.625 | 87.14 | 30.515 | git slower |
| linux | CVE-2022-0185 | False | True | 900.282 | 43.204 | -857.078 | success improvement |
| openjpeg | CVE-2020-27843 | True | True | 7.734 | 7.531 | -0.203 | git faster |
| openjpeg | CVE-2020-27842 | True | True | 15.375 | 25.015 | 9.64 | git slower |
| openssl | CVE-2023-1255 | True | True | 106.391 | 63.688 | -42.703 | git faster |
| openssl | CVE-2023-6129 | True | True | 94.156 | 90.297 | -3.859 | git faster |
| qemu | CVE-2023-0664 | True | True | 130.609 | 96.219 | -34.39 | git faster |
| qemu | CVE-2020-12829 | True | True | 12.985 | 46.937 | 33.952 | git slower |
| wireshark | CVE-2024-24479 | True | True | 33.093 | 79.609 | 46.516 | git slower |
| wireshark | CVE-2021-39926 | True | True | 49.188 | 26.704 | -22.484 | git faster |

## Conclusion

On this 18-CVE real OpenCode sample, read-only git tools are not safe as the default P4 path: success count is unchanged, average latency is higher, and one CVE regresses from success to unknown_agent_failed. Git tools remain useful as a fallback for selected timeout/unknown cases, not as unconditional default.