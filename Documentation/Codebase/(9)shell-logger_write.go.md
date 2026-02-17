# Recieves a RAW terminal output byte-by-byte
# Buffers it -> extracts lines -> identifies actual typed command by matching the bash prompt pattern
# For every real command records timing, incremnets counter, call analyzer, logs the even and runs the detector