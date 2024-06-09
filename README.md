# linforce
Linux BruteForce detection

# Description
Module based on btmp/wtmp files to search for possible brute force attacks comparing the logs:
- Brute Force detection: Time interval between failed logins attempts (BTMP). To determine if there is brute force.
- Brute Force followed by a successful login detection: Time interval if there are more than the determined failed logins (considered as risky or brute force) and any successful login (WTMP).

# Log Files
- BTMP Linux Log: contains failed login (remote and local) attempts.
*Path*: /var/log/btmp* (*: could be more than one file).
- WTMP Linux Log: contains successful login (remote and local) attempts.
*Path*: /var/log/wtmp* (*: could be more than one file).

# Use
1. Download the code:
<code> git clone https://github.com/RCarras/linforce.git </code>

2. Give permissions to linforce script:
<code> chmod +x linforce.sh </code>

3. Execution:
<code> sudo ./linforce.sh </code>

4. Check results:
<code> /tmp/linforce_analysis </code>
