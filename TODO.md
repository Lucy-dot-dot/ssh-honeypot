# SSH Honeypot - Unix Commands Implementation Plan

## Current Implementation Status
**Already implemented:** ls, pwd, whoami, id, uname, ps, cat, wget, curl, sudo (blocked), cd, exit/logout, date, free, echo, basic grep (piped)

## Recommended Command Implementation Plan

### **Tier 1: High Priority - Essential Attacker Commands** 
*Most commonly used by attackers for reconnaissance and exploitation*

1. **`cp` / `mv` / `rm`** - File manipulation commands
   - Critical for observing file operations
   - Moderate complexity (filesystem interaction)
   - Should show realistic errors for system files

2. **`find`** - File search command  
   - Heavily used for privilege escalation research
   - High complexity (recursive directory traversal)
   - Very valuable for threat intelligence

3. **`which` / `whereis`** - Command location utilities
   - Used to check available tools
   - Low complexity, high value

4. **`history`** - Command history
   - Simple fake history with common commands
   - Low complexity, moderate value

5. **`netstat` / `ss`** - Network status
   - Critical for network reconnaissance
   - Moderate complexity (fake network data)

### **Tier 2: Medium Priority - System Information**
*Used for system profiling and situational awareness*

6. **`mount` / `df` / `du`** - Filesystem information
   - Show fake disk usage and mount points
   - Low-moderate complexity

7. **`ifconfig` / `ip`** - Network configuration
   - Network interface information
   - Moderate complexity

8. **`w` / `who` / `last`** - User activity
   - Show fake logged-in users
   - Low complexity

9. **`top` / `htop`** - Process monitoring
   - Interactive process viewer simulation
   - Moderate complexity

10. **`crontab`** - Task scheduling
    - Show fake cron jobs or "permission denied"
    - Low complexity

### **Tier 3: Medium Priority - Development/Admin Tools**
*Often used for payload deployment and system manipulation*

11. **`vim` / `nano` / `vi`** - Text editors
    - Basic editor simulation (view-only)
    - High complexity for full implementation

12. **`chmod` / `chown`** - Permission commands
    - File permission changes (fake)
    - Low complexity

13. **`tar` / `gzip` / `unzip`** - Archive utilities
    - Archive extraction simulation
    - Moderate complexity

14. **`docker`** - Container management
    - Show "docker not found" or fake containers
    - Low-moderate complexity

15. **`systemctl` / `service`** - Service management
    - System service control
    - Moderate complexity

### **Tier 4: Advanced - Exploitation Tools**
*Commands that indicate malicious intent*

16. **`ssh` / `scp`** - Remote access tools
    - Show connection attempts/failures
    - Moderate complexity

17. **`nmap` / `nc` (netcat)** - Network tools
    - Port scanning/network utilities
    - Low complexity (show "not installed")

18. **`python` / `python3` / `perl`** - Scripting languages
    - Script execution simulation
    - High complexity for full implementation

19. **`gcc` / `make`** - Compilation tools
    - Show compilation attempts
    - Low complexity (show errors)

20. **`iptables`** - Firewall management
    - Network security configuration
    - Moderate complexity

## Implementation Strategy

### **Phase 1 (Immediate):** 
Implement Tier 1 commands 1-5 as they provide the highest threat intelligence value.

### **Phase 2 (Short-term):** 
Add Tier 2 commands 6-10 for better system simulation realism.

### **Phase 3 (Long-term):** 
Selectively implement Tier 3-4 commands based on observed attacker patterns.

## Special Considerations

- **File operations** (cp, mv, rm) should interact with the virtual filesystem
- **Network commands** should return realistic but fake data
- **Privilege escalation attempts** should be logged but denied
- **Package managers** (apt, yum, pacman) could show fake package information
- **Text processing** (grep, awk, sed) should have basic functionality

## Architecture Refactoring

Before implementing new commands, the current giant match statement in `server.rs` should be refactored into a modular command system using:

1. **Command Trait** - Standard interface for all commands
2. **CommandContext** - Shared state (cwd, filesystem, user info)
3. **CommandRegistry** - HashMap-based command lookup
4. **CommandDispatcher** - Command parsing and execution management

This will make adding the 20+ planned commands much cleaner and more maintainable.