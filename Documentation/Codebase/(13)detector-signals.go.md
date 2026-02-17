# 3 independent detection signals taht run after every command:
- ThresholdSignal: Runs at score 50(warning), 75(high), 100(critical). Each level runs exactly once per session.
- SequenceSignal: Runs when 3+ fingerprint command appears consecutively. Indicates automated scanning tool.
- TimingSignal: Runs when the median delay across the last 5 commands is under 300ms. This detects bots as human types slower.