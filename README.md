# linforce
Linux BruteForce detection

Rafael Carrasco https://www.linkedin.com/in/rafael-carrasco-vilaplana-3199a492?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app

David Rosado https://www.linkedin.com/in/david-rosado-soria-4416b8230?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app

# Description
Module based on btmp/wtmp files to search for possible brute force attacks comparing the logs:
- Brute Force detection: Time interval between failed logins attempts (BTMP). To determine if there is brute force.
- Brute Force followed by a successful login detection: Time interval if there are more than the determined failed logins (considered as risky or brute force) with any successful login (WTMP).

# Log Files
- BTMP Linux Log: contains failed login (remote and local) attempts.
*Path*: /var/log/btmp* (*: could be more than one file).
- WTMP Linux Log: contains successful login (remote and local) attempts.
*Path*: /var/log/wtmp* (*: could be more than one file).

# Use
1. Download the code:
```
git clone https://github.com/RCarras/linforce.git
```

2. Join script path:
```
cd linforce
```

3. Give permissions to linforce script:
```
chmod +x linforce.sh
```

4. Default Execution:
```
sudo ./linforce.sh
```

5. Check results:
```
/tmp/linforce_analysis
```

# Usage Options
- *-b < number >*:      Number of attempts to consider as brute force (default: 80)

- *-t < seconds >*:     Time interval between attempts to be considered as consecutive (default: 30 seconds)

- *-i < timestamp >*:   Initial timestamp for the analysis in the format YYYYmmddHHMMSS (default: 20220901000000)

- *-m < timestamp >*:   Maximum timestamp for the analysis in the format YYYYmmddHHMMSS (default: current date)

- *-h*:               Show this help message

