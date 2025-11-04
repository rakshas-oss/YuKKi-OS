YuKKi OS 3.2: P2P Secure Chat & Distributed Build System
This repository contains a single, self-extracting shell script (YuKKi-3.2.sh) that generates a complete C-based, mTLS-secured, peer-to-peer (P2P) network suite. This suite includes a central bootstrap server for peer discovery and a multi-featured peer client for secure chat, file transfer, and distributed build job execution.
The script automatically downloads, verifies, and vendors all necessary dependencies, including Mongoose, cJSON, and Linenoise.
Features
peer_client (The Client)
 * Interactive REPL: A robust command-line interface powered by linenoise, featuring command history and context-aware tab-completion.
 * (New in 3.2) Configurable Visual Prompt: Includes an optional "Zsh-style" visual prompt (e.g., [HH:MM:SS] [profile_name] ✔ > ) that is configurable via the yukki_configurator.sh script, all while retaining full linenoise functionality.
 * P2P Messaging: Send private, mTLS-encrypted messages to a specific peer (msg ...) or broadcast a message to all known peers (say ...).
 * P2P File Transfer: Securely send local files to any peer. Files are received in a sandboxed received_files directory.
 * P2P File Discovery: Request a file from a peer (get <uuid> <filename>) or list the contents of their shared directory (ls <uuid>).
 * Distributed Build System ("JobbySlotty"):
   * job submit: Submit a local build job (e.g., make, ./run.sh) to a local execution queue.
   * job queue: View the status of all local jobs (Pending, Running, Completed, Failed).
   * Dependency Management: Define dependencies for local jobs (e.g., job submit "build" "make" deps:1,2) to create a build graph.
   * rjob submit: Delegate a build job to a remote peer.
   * rjob status: Check the status of a job you submitted to a remote peer.
 * CRTC/PIPEDA Compliance Features:
   * Explicit Consent: On first launch, the client requires explicit user consent before any network activity, logging it locally for audit.
   * Internal Blocklist: Users can block and unblock any peer UUID to refuse all incoming P2P connections and commands from them.
bootstrap_server (The "C2")
 * Secure Peer Discovery: Acts as a central server for peers to find each other. It does not participate in or log any P2P communication.
 * mTLS Authentication: Uses mTLS to ensure only clients with a valid certificate signed by the network's Certificate Authority (CA) can connect.
 * Volatile In-Memory Store: The peer list (UUID and IP/Port) is held in-memory only. When a peer disconnects, their information is removed. No data is logged or persisted.
How It Works: Dual-Channel "Bootstrap" Architecture
The entire system is built on a custom Public Key Infrastructure (PKI) that you control. It separates peer discovery from peer communication for security and privacy.
 * yukki_configurator.sh (The CA & Identity Manager):
   * This helper script (generated with the project) creates your network's Certificate Authority (CA).
   * It then issues a server certificate for the bootstrap_server and unique client certificates for each peer profile you create (e.g., 'alice', 'bob').
   * Cryptographic Identity: A peer's identity is their UUID, which is embedded directly into their certificate's Common Name (CN). This makes identity-spoofing nearly impossible and powers the blocklist feature.
 * Bootstrap Channel (The Matchmaker):
   * A peer (e.g., 'alice') starts up and establishes a secure WebSocket (wss://) connection to the bootstrap_server.
   * The server validates 'alice's' client certificate against the CA.
   * If valid, it extracts her UUID (from the cert) and her IP/Port (from the connection).
   * The server adds 'alice' to its in-memory list and broadcasts the new, complete peer list (all UUIDs and IPs) to all connected clients.
 * P2P Channel (The "Real" Work):
   * The 'alice' client now has a local list of all other online peers (e.g., 'bob').
   * When 'alice' runs msg bob ..., her client looks up 'bob's' IP/Port from its local list.
   * It establishes a new, direct, peer-to-peer mTLS connection to 'bob'.
   * 'bob's' client accepts the connection, validates 'alice's' certificate against the same CA, and (if not blocked) accepts the incoming message.
   * Concurrency: All P2P connections are handled in dedicated threads, and the client uses connection pooling to re-use active mTLS sessions for efficiency.
 * adi_protocol.h (The P2P Protocol):
   * All P2P communication (after the mTLS handshake) uses a simple, custom ADI (Advanced Data Interchange) binary packet protocol.
   * This protocol defines lightweight, header-based commands like P2P_MSG_CMD, P2P_SEND_REQ, P2P_FILE_CHUNK, and P2P_JOB_SUBMIT_REQ, allowing for structured and high-performance data exchange.
Getting Started: Build & Run
1. Prerequisites (Linux)
You must have a build environment, OpenSSL development libraries, and uuid-dev.
For Debian/Ubuntu-based systems:
sudo apt-get update
sudo apt-get install build-essential libssl-dev uuid-dev

2. Generate the Project
Run the shell script. This will create a new directory, yukki_os_final, download all dependencies, and lay out the full project structure.
bash ./YuKKi-3.2.sh

3. Configure PKI & Client Profiles
This is the most important step. You must create your CA and at least two client profiles to test the network.
 * Navigate to the newly created project:
   cd yukki_os_final

 * Run the configurator:
   ./bin/yukki_configurator.sh

 * The script will first create the CA and the server certificate.
 * It will then prompt you to create a client profile.
   * Profile Name: alice
   * C2 Server URL: wss://127.0.0.1:8443 (if running locally)
   * P2P Listen Port: 9001 (must be unique for this client)
   * Enable enhanced visual prompt? (yes/no): yes
 * Run the configurator again to create a second peer.
   * Profile Name: bob
   * C2 Server URL: wss://127.0.0.1:8443
   * P2P Listen Port: 9002 (must be unique)
   * Enable enhanced visual prompt? (yes/no): no
4. Compile All Components
 * Compile the bootstrap server:
   make -C yukki_c2_suite/bootstrap_server

 * Compile the peer client:
   make -C yukki_c2_suite/peer_client

5. Run the Network
Open three separate terminals, all from the yukki_os_final directory.
 * Terminal 1: Start the Bootstrap Server
   ./yukki_c2_suite/bootstrap_server/bootstrap_server

   Output: Server listening on wss://0.0.0.0:8443
 * Terminal 2: Start Peer 'alice'
   ./yukki_c2_suite/peer_client/peer_client alice

   * It will ask for consent. Type "yes" and press Enter.
   * Output (if prompt enabled): [HH:MM:SS] [alice] ✔ > 
 * Terminal 3: Start Peer 'bob'
   ./yukki_c2_suite/peer_client/peer_client bob

   * It will also ask for consent. Type "yes" and press Enter.
   * Output (if prompt disabled): > 
You now have a running P2P network!
Client Usage (REPL Commands)
Once the peer_client is running, type help to see all available commands.
--- [ Yukki OS 3.2 Help ] ---
Compliance Commands:
  profile               - View your UUID and blocklist.
  block <uuid>          - Block all P2P from a peer.
  unblock <uuid>        - Unblock a peer.

Local Build Commands (JobbySlotty):
  job submit "<name>" "<cmd>" [deps:id1,id2] - Submit local job with optional deps.
  job queue             - View the local build job queue.
  job status <id>       - Check status of a local job.

Remote Build Commands (JobbySlotty):
  rjob submit <uuid> "<name>" "<cmd>" [deps:id1,id2] - Submit job to a remote peer.
  rjob status <uuid> <id> - Check status of a job on a remote peer.

P2P Commands (ADI Protocol):
  peers                 - List peers visible on the network.
  msg <uuid> <message>  - Send a secure message to a peer.
  say <message>         - [Chat] Broadcast message to all known peers.
  join <room>           - [Chat] (Alias for 'peers', chat is global).
  send <uuid> <path>    - Securely send a local file to a peer.
  get <uuid> <filename> - Request a file from a peer (must be in their share dir).
  ls <uuid>             - List files in a peer's share directory.

Other Commands:
  help                  - Show this message.
  quit, exit            - Shut down the client.

Example Workflow
In 'alice's' terminal:
--- [ Visible Peers ] ---
- 550e8400-e29b-41d4-a716-446655440001 (127.0.0.1:9002)  <-- This is bob
 [alice] ✔ > say Hello bob!
[Broadcasting to all peers]...

In 'bob's' terminal, you will see:
[Message from 550e8400-e29b-41d4-a716-446655440000]: Hello bob!
> 

In 'bob's' terminal:
> job submit "List Files" "ls -la"
Job 1 ('List Files') submitted to local queue.
--- [Build Worker] Starting job 1: List Files ---
--- [Build Worker] Job 1 ('List Files') finished with status: COMPLETED ---
--- [Build Worker] Log available at: logs/job_1.log ---
> 

