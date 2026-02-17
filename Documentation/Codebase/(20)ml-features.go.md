# The SessionFeatures struct:
- 12 floats that represent one session numerically
    - fingerprint/recon/exploit ratios, suspicion score (normalized 0–1), average and minimum command delay in ms, session duration in seconds, unique command count, total command count, detection event count, sequence detected flag, timing detected flag.

Also Contains `ExtractFromSession` live extraction from active session and `ExtractFromLogs` post-session extraction from log files.