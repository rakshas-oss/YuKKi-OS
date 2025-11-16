YuKKi OS 4 Release: Changes Since 3.2

YuKKi OS 4 marks a major shift from the 3.x series, focusing on enhanced developer experience and deeper integration for distributed collaboration. While the core security model (mTLS, Dual-Channel Architecture) remains the backbone of the platform, this version introduces significant upgrades to the user interface and the JobbySlotty build system.
Key Changes and New Features in YuKKi OS 4
1. Enhanced Distributed Build System ("JobbySlotty")

The most critical functional update is the introduction of a formal mechanism to share complex project structures, making collaborative compilation much easier.

    NEW: Dependency Manifest Exchange

        We have formalized the process of sharing project build definitions. Peers can now exchange complete, structured dependency manifests.

        New Commands:

            manifest submit <uuid>: Pushes your project's build tree structure to a specified peer.

            manifest get <uuid>: Requests a manifest from a peer, queuing their complex build steps on your system.

        ADI Protocol Update: The custom ADI (Advanced Data Interchange) Protocol now includes a dedicated packet type (P2P_DEP_MANIFEST) for efficient, low-overhead transmission of these manifest files.

2. Configurable Visual Prompt (UI/UX Overhaul)

We've brought the user-facing experience up to modern standards by replacing the classic, simple prompt with a fully configurable visual display that is deeply integrated with the linenoise terminal.

    NEW: Zsh-Style Visual Prompt:

        The prompt is now highly informative, displaying the current time, your user profile, and a status indicator (e.g., ✔).

        Example Prompt: [HH:MM:SS] [profile_name] ✔ >

        Configurable: The yukki_configurator.sh script now offers a clear opt-in option to enable this "enhanced visual prompt."

    Zero Loss of Functionality: This visual upgrade is handled entirely by the robust linenoise library, ensuring you retain full command history and context-aware tab-completion.

3. General Platform and Documentation Updates

    Version Bump: The major version number reflects the fundamental commitment to these new capabilities and the move away from the 3.x framework.

    Compliance Framework: Minor refinements were made to the CRTC and PIPEDA compliance logging procedures to better track user consent specific to the new manifest exchange feature.
