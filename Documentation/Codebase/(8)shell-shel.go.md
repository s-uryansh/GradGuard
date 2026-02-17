# Starts a real docker container
# runs `/bin/bash` inside it via docker exec
# So attacker gets a genuine interactive Linux shell. 
# A session logger is attached -> every byte the shell outputs passes through it.
# At the end of the sessions generates a report and tear downs the container.