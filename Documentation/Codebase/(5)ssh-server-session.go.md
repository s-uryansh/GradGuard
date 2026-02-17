Takes a raw TCP connection, performs the SSH handshake, generates a session ID from IP + nanosecond timestamp, creates a SessionState, then dispatches SSH channels to the shell handler.
