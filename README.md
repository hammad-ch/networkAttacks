# Mitnick Attack
Step 1: Information gathering <br />
    Determine the trusted relationship between X-terminal and server. <br />
Step 2: The flood <br />
    Flood the server so that it can not respond anymore (DoS). <br />
Step 3: Trusted connection <br />
    Send a SYN request to X-Terminal with spoofed IP address as the Server. <br />
Step 4: Remote command for back door <br />
    Install back door to avoid authentication. <br />
Step 5: Clean up <br />
    Send RESET responses to the Server to cancel all his SYN requests. <br />
