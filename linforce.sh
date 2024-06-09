#!/bin/bash

linux_bruteforce_analysis() {

    local thisnow=$(date +%Y%m%d)
    local evo_log="/var/log"
    local modod="/tmp/linforce_analysis" # Configurar carpeta de salida, por ejemplo: /tmp

    if [[ ! -d $modod ]]; then
        mkdir -p $modod
    fi

    # SUBMODULES  ====================================================================

    # VARIABLES
    # Outputs
    local btmpof="${modod}/btmp.logs"
    local wtmpof="${modod}/wtmp.logs"
    local prevfolder="${modod}/previous_analysis"
    local hitsof="${modod}/hits_login"
    local attemptsof="${modod}/brute_force_attempts.log"
    local redzoneof="${modod}/red_zone_attempts.log"
    # Basic Brute Force Variables (Test different passwords in the same user and from the same IP)
    local -A last_attempt
    local -A ip_count
    local -A thisipcount
    # Password Spraying Variables (Test the same password in different users)
    local -A user_count
    local -A thisusercount
    local -A last_user
    local -A users_tested
    # Dynamic IP Variables (Test differente passwords in the same user from differents IPs)
    local -A latest_diff_ip_count
    local -A diff_ip_count
    local -A last_ip
    local -A ips_used
    # Global Brute Force Variables | PODRIAMOS ADAPTARLO A VELOCI Y METER LAS VARIABLES DENTRO DE LA CONFIGURACIÓN DEL MÓDULO
    # Consecutive attempts to be considered as bruteforce
    local brute_force=80
    # Interval between considered consecutive attempts
    local time_interval=30
    local min_timestamp=20220901000000
    local min_timestamp_epoch=$(date -d "${min_timestamp:0:4}-${min_timestamp:4:2}-${min_timestamp:6:2} ${min_timestamp:8:2}:${min_timestamp:10:2}:${min_timestamp:12:2}" +"%s")
    local max_timestamp # SI SE PONE MAX_TIMESTAMP SE CREA UN ARCHIVO DE REDZONE ATTEMPTS, PARA VER LOS INTENTOS ENTRE UNA FECHA
    if [[ ! -z $max_timestamp ]]; then
        local max_timestamp_epoch=$(date -d "${max_timestamp:0:4}-${max_timestamp:4:2}-${max_timestamp:6:2} ${max_timestamp:8:2}:${max_timestamp:10:2}:${max_timestamp:12:2}" +"%s")
    fi

    # Store previous output files
    if [[ ! -d "$modod/previous_analysis" ]]; then
     mkdir $prevfolder
    fi
    # Compress previous analysis files
    sudo tar -cvf "$thisnow.tar" $hitsof $btmpof $wtmpof $secureof $authof $attemptsof $redzoneof >/dev/null 2>/dev/null
    sudo rm $hitsof $btmpof $wtmpof $secureof $authof $attemptsof $redzoneof >/dev/null 2>/dev/null
    sudo mv "$thisnow.tar" $prevfolder 2>/dev/null



    #>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    # BTMP | WTMP: check failed attempts and successful logins #
    #>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    # Module based on btmp/wtmp files to search for possible brute force attacks comparing the logs, time interval between failed logins attempts; and time interval if there are #
    # more than the determined failed logins ($brute_force) between attempts considered risky (after $brute_force) and any successful login.                                      #
    #>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    # Check failed attempts (btmp dump)
    # File Header
    echo 'IP    Reps    Date        User' > $btmpof
    # Loop to get all btmp files info
    for btmp in $(ls $evo_log | grep btmp); do
    # Check if btmp file is compressed; .gz, .bz2, .xz compression formats
     if [ ! -z $(echo $btmp | grep 'gz') ]; then
      # Copy btmp file to output directory
      sudo rsync -avP $evo_log/$btmp $modod/$btmp >/dev/null
      sudo gunzip $modod/$btmp >/dev/null
      btmp=$(echo $btmp | awk -F'.' '{print $1}')
      # Parse btmp file to human readable format
      sudo utmpdump $modod/$btmp | awk -F']'  '{print $7, $8, $4}'  | awk -F'T' '{print $1 " -> " $2}' | awk -F',' '{print $1" "$2}' | uniq -c | awk '{print $2, $1, $3 $5, $7}' | sed 's/\[//g' | sed 's/-//g' | sed 's/://g' >> $btmpof
      sudo rm $modod/$btmp
     elif [ ! -z $(echo $btmp | grep 'bz2') ]; then
      sudo rsync -avP $evo_log/$btmp $modod/$btmp >/dev/null
      sudo bunzip2 $modod/$btmp >/dev/null
      btmp=$(echo $btmp | awk -F'.' '{print $1}')
      sudo utmpdump $modod/$btmp | awk -F']'  '{print $7, $8, $4}'  | awk -F'T' '{print $1 " -> " $2}' | awk -F',' '{print $1" "$2}' | uniq -c | awk '{print $2, $1, $3 $5, $7}' | sed 's/\[//g' | sed 's/-//g' | sed 's/://g' >> $btmpof
      sudo rm $modod/$btmp $modod/$btmp.bz2 2>/dev/null
     elif [ ! -z $(echo $btmp | grep '.xz') ]; then
      sudo rsync -avP $evo_log/$btmp $modod/$btmp >/dev/null
      sudo xz -d $modod/$btmp >/dev/null
      btmp=$(echo $btmp | awk -F'.' '{print $1}')
      sudo utmpdump $modod/$btmp | awk -F']'  '{print $7, $8, $4}'  | awk -F'T' '{print $1 " -> " $2}' | awk -F',' '{print $1" "$2}' | uniq -c | awk '{print $2, $1, $3 $5, $7}' | sed 's/\[//g' | sed 's/-//g' | sed 's/://g' >> $btmpof
      sudo rm $modod/$btmp
     else
     # Parse without decompress the file
      sudo utmpdump $evo_log/$btmp | awk -F']'  '{print $7, $8, $4}'  | awk -F'T' '{print $1 " -> " $2}' | awk -F',' '{print $1" "$2}' | uniq -c | awk '{print $2, $1, $3 $5, $7}' | sed 's/\[//g' | sed 's/-//g' | sed 's/://g' >> $btmpof
     fi
    done

    # Check for possible brute force successful attempts (wtmp dump). Same process as btmp
    echo 'IP    Reps    Date        User' > $wtmpof
    for wtmp in $(ls $evo_log | grep wtmp); do
     if [ ! -z $(echo $wtmp | grep 'gz') ]; then
      sudo rsync -avP $evo_log/$wtmp $modod/$wtmp >/dev/null
      sudo gunzip $modod/$wtmp >/dev/null
      wtmp=$(echo $wtmp | awk -F'.' '{print $1}')
      sudo utmpdump $modod/$wtmp | awk -F']'  '{print $7, $8, $4}'  | awk -F'T' '{print $1 " -> " $2}' | awk -F',' '{print $1" "$2}' | uniq -c | awk '{print $2, $1, $3 $5, $7}' | sed 's/\[//g' | sed 's/-//g' | sed 's/://g' >> $wtmpof
      sudo rm $modod/$wtmp
     elif [ ! -z $(echo $wtmp | grep 'bz2') ]; then
      sudo rsync -avP $evo_log/$wtmp $modod/$wtmp >/dev/null
      sudo bunzip2 $modod/$wtmp >/dev/null
      wtmp=$(echo $wtmp | awk -F'.' '{print $1}')
      sudo utmpdump $modod/$wtmp | awk -F']'  '{print $7, $8, $4}'  | awk -F'T' '{print $1 " -> " $2}' | awk -F',' '{print $1" "$2}' | uniq -c | awk '{print $2, $1, $3 $5, $7}' | sed 's/\[//g' | sed 's/-//g' | sed 's/://g' >> $wtmpof
      sudo rm $modod/$wtmp $modod/$wtmp.bz2 2>/dev/null
     elif [ ! -z $(echo $wtmp | grep '.xz') ]; then
      sudo rsync -avP $evo_log/$wtmp $modod/$wtmp >/dev/null
      sudo xz -d $modod/$wtmp >/dev/null
      wtmp=$(echo $wtmp | awk -F'.' '{print $1}')
      sudo utmpdump $modod/$wtmp | awk -F']'  '{print $7, $8, $4}'  | awk -F'T' '{print $1 " -> " $2}' | awk -F',' '{print $1" "$2}' | uniq -c | awk '{print $2, $1, $3 $5, $7}' | sed 's/\[//g' | sed 's/-//g' | sed 's/://g' >> $wtmpof
      sudo rm $modod/$wtmp
     else
      sudo utmpdump $evo_log/$wtmp | awk -F']'  '{print $7, $8, $4}'  | awk -F'T' '{print $1 " -> " $2}' | awk -F',' '{print $1" "$2}' | uniq -c | awk '{print $2, $1, $3 $5, $7}' | sed 's/\[//g' | sed 's/-//g' | sed 's/://g' >> $wtmpof
     fi
    done


    echo -e "\n\nSuspicious login attempts\n"

    # Check possible brute force attacks, comparing consecutive timestamps between failed logs from an IP | User | Differents IPs
    tail -n +2 $btmpof | while read -r thisip thisrep thistime thisuser; do
     # Get timestamp in epoch
     thistimestamp=$(date -d "${thistime:0:4}-${thistime:4:2}-${thistime:6:2} ${thistime:8:2}:${thistime:10:2}:${thistime:12:2}" +"%s")
    # Initialize counters
     # Counter for an IP
     if [[ -z "${ip_count[$thisip]}" ]]; then
      ip_count[${thisip}]=0
     fi
     if [[ -z "${thisipcount[$thisip]}" ]]; then
      thisipcount[${thisip}]=0
     fi
     # Counter for users from the same IP
     if [[ -z "${user_count[$thisip]}" ]]; then
      user_count[${thisip}]=0
     fi
     if [[ -z "${thisusercount[$thisip]}" ]]; then
      thisusercount[${thisip}]=0
     fi
     # Counter for different IP from the same user
     if [[ -z "${diff_ip_count['$thisuser']}" ]]; then
      diff_ip_count['${thisuser}']=0
     fi
     if [[ -z "${latest_diff_ip_count['$thisuser']}" ]]; then
      latest_diff_ip_count['${thisuser}']=0
     fi

     # Password Spraying and Basic Brute Force Attack
     if [[ -n "${thisip}" && $thistimestamp -ge $min_timestamp_epoch ]]; then
      # Conditional: if doesn't exist a last attempt from an IP: is set last attempt time and user as the current
      if [[ -z "${last_attempt[$thisip]}" ]]; then
       last_attempt[${thisip}]=$(($thistimestamp))
       last_user[${thisip}]="$thisuser"

     # If the IP and last attempt exists it continues module flow
      else
       # Check difference between last attempt and current attempt
       local diff_time=$((${thistimestamp}-${last_attempt[$thisip]}))
       # Check if the previous difference is less than the time interval that is set at the beginning of the script
       if [[ "${diff_time}" -le "${time_interval}" ]]; then
        # Add the attempt to the total count of the current I
        last_ip_count="${ip_count[${thisip}]}"
        ip_count[${thisip}]=$((${ip_count[${thisip}]} + $thisrep))
        # Set as last attempt the current timestamp
        last_attempt[${thisip}]=$((${thistimestamp}))

     # Check possible PASSWORD SPRAYING attack
        # Avoid the script to break if the username contains backslash
        local thisusername="$thisuser"
            if [[ $thisusername == *"\\"* ]]; then
             thisusername=$(echo "$thisuser" | sed 's/\\/\\\\/g')
            fi
        # Check if the user doesn't exist in the array of users for the current IP
        if [[ -z $(echo "${users_tested[$thisip]}" | grep "$thisusername") ]]; then
         # Add the attempt to the total count of the current IP
         last_user_count="${user_count[${thisip}]}"
         user_count[${thisip}]=$((${user_count[${thisip}]} + $thisrep))
         # Check if the user array exist
         if [[ -z $(echo "${users_tested[$thisip]}") ]]; then
          # Add the new user to the array of users for the current IP, if the user array didn't exist before
          users_tested[${thisip}]="${thisuser}"
         else
          # Add the new user to the array of users for the current IP
          users_tested[${thisip}]="${users_tested[${thisip}]}, ${thisuser}"
         fi
         # Add as last user the current attempted user
         last_user[${thisip}]="$thisuser"
        else
         # If the previous difference doesn't satisfy the time interval the variables are reset for Password Spraying
         user_count[${thisip}]=0
         users_tested[${thisip}]=""
         last_user[${thisip}]="$thisuser"
        fi

       else
        # If the previous difference doesn't satisfy the time interval the variables are reset for Basic Brute Force
        ip_count[${thisip}]=0
        last_attempt[${thisip}]=$((${thistimestamp}))
       fi

       # Check if after too many attempts (brute force variable is considered) of the IP, it got a successful login with WTMP
       if [[ "${ip_count[$thisip]}" -ge $brute_force ]]; then
        # Print successfull brute force attempts in module logs
        if [[ ${ip_count[$thisip]} -gt ${thisipcount[$thisip]} ]]; then
         echo "Brute Force: ${ip_count[$thisip]} attempts from ip $thisip at $(date -ud @$thistimestamp)" | tee -a $attemptsof
         # Set to the same value thisipcount to check later if there's a new attempt and add to the log as the previous command
         thisipcount[$thisip]=${ip_count[$thisip]}
        fi
        # Check if IP attempts is equal to attempts considered as brute force variable
        if [[ "${ip_count[$thisip]}" -ge $brute_force && "$last_ip_count" -lt $brute_force ]]; then
         echo "[ALERT] Possible Brute Force attack from IP $thisip to user '$thisuser' at $(date -ud @$thistimestamp) [ALERT]" >> $hitsof
        fi
        # Loop to analyze successful attempts for this IP
        for u in $(cat $wtmpof | grep $thisip | awk '{print $4}' | sort | uniq); do
         # Check if the IP is in hits file and if this user at that moment is in hits file for this IP
         if [[ -z $(cat $hitsof 2>/dev/null | egrep "Successful.*$u.*$(date -ud @$thistimestamp)") ]]; then
          # Loop for successfuls user attempts searching
          for l in $(cat $wtmpof | grep $thisip | grep $u | awk '{print $3}'); do
           # Modify l timestamp to epoch
           l=$(date -d "${l:0:4}-${l:4:2}-${l:6:2} ${l:8:2}:${l:10:2}:${l:12:2}" +"%s")
           # Compare last failed attempt against successful login, checking if last failed is lower than successfull attempt
           if [[ $(echo ${l}) -gt ${last_attempt[${thisip}]} ]]; then
            diff_time=$(($(echo ${l})-${last_attempt[${thisip}]}))
            # Check if difference time is lower than time interval and if the user at that moment isn't in hits file add to it
            if [[ "${diff_time}" -le "${time_interval}" ]]; then
             echo "[WARN] Successful Login to '$u' user in a Possible Brute Force attack from IP $thisip at $(date -ud @$thistimestamp), after ${ip_count[$thisip]} attempts [WARN]" >> $hitsof
            fi
           fi
          done
         fi 
        done
       fi

       # Check if after too many attempts of the IP to differents users [Password Spraying], it got a successful login with WTMP. User count is bigger or equal to attempts of brute force variable
       if [[ "${user_count[$thisip]}" -ge $brute_force ]]; then
        # Print in module logs brute force attempts
        if [[ ${user_count[$thisip]} -gt ${thisusercount[$thisip]} ]]; then
         echo "Brute Force: ${user_count[$thisip]} attempts from ip $thisip at $(date -ud @$thistimestamp) time. Last user tested: ${last_user[${thisip}]}" | tee -a $attemptsof
         # Set to the same value thisusercount to check later if there's a new attempt and add to the log as the previous command
         thisusercount[$thisip]=${user_count[$thisip]}
        fi
               # Check if Users attempts are equal to attempts considered as brute force variable
        if [[ "${user_count[$thisip]}" -ge $brute_force && "$last_user_count" -lt $brute_force ]]; then
         echo "[ALERT] Possible Password Spraying attack from IP $thisip at $(date -ud @$thistimestamp), testing users: '${users_tested[$thisip]}' [ALERT]" >> $hitsof
        fi
        # Check users to analyze successful attempts. Check if they are in hits file, and if they aren't compare last failed attempt against successful login
        for u in $(cat $wtmpof | grep $thisip | awk '{print $4}' | sort | uniq); do
         # Check if the IP is in hits file and if this user isn't in hits file as Password Spraying at this timestamp
         if [[ ! -z $(cat $wtmpof | grep $thisip) && -z $(cat $hitsof 2>/dev/null | egrep "$u.*Spraying.*$(date -ud @$thistimestamp)") ]]; then
          # Loop for successfuls user attempts searching
          for l in $(cat $wtmpof | grep $thisip | grep $u | awk '{print $3}'); do
           # Modify l timestamp to epoch
           l=$(date -d "${l:0:4}-${l:4:2}-${l:6:2} ${l:8:2}:${l:10:2}:${l:12:2}" +"%s")
           # Compare last failed attempt against successful login, checking if last failed is lower than successfull attempt
           if [[ $(echo ${l}) -gt ${last_attempt[${thisip}]} ]]; then
            diff_time=$(($(echo ${l})-${last_attempt[${thisip}]}))
            # Check if difference time is lower than time interval and if the user isn't in hits file add to it
            if [[ "${diff_time}" -le "${time_interval}" && -z $(cat $hitsof 2>/dev/null | grep $u) ]]; then
             echo "[WARN] Successful Login to '$u' user in a Possible Password Spraying attack from IP $thisip at $(date -ud @$thistimestamp), after testing '${user_count[$thisip]}' users [WARN]" >> $hitsof
             echo "Users tested: ${users_tested[$thisip]}" >> $hitsof
            fi
           fi
          done
         fi
        done
       fi
      fi
     fi

     # Consecutives failed attempts from differents IPs to the same user [Dynamic IP attack]
     if [[ -n "${thisuser}" && $thistimestamp -ge $min_timestamp ]]; then
      # Conditional: if doesn't exist a last attempt from an IP: is set last attempt time, user and IP as the current
      if [[ -z "${last_attempt[$thisuser]}" ]]; then
       last_attempt[${thisuser}]=$(($thistimestamp))
       last_user[${thisuser}]="$thisuser"
       last_ip[${thisuser}]="$thisip"
      else
       # Check difference between last attempt for this user and current attempt
       local diff_time=$((${thistimestamp}-${last_attempt[$thisuser]}))
       # Dynamic IP conditions: Last user should be the same (=) current user | Last IP should be different (!=) than current IP
       if [[ "${diff_time}" -le "${time_interval}" && "${last_ip[$thisuser]}" != "$thisip" && "${last_user[$thisuser]}" == "$thisuser" ]]; then
        # Add the attempt to the total count of the current user
        last_diff_ip_count="${diff_ip_count[${thisuser}]}"
        diff_ip_count[${thisuser}]=$((${diff_ip_count[${thisuser}]} + $thisrep))
        # Set as last attempt the current timestamp
        last_attempt[${thisuser}]=$((${thistimestamp}))
        # Set as last IP the current IP
        last_ip[${thisuser}]="$thisip"
        # Check if the ip array for this user exist
        if [[ ! -z "${ips_used[$thisuser]}" ]]; then
         # Add the new ip to the array of IPs for the current user, if the user array didn't exist before
         ips_used[${thisuser}]="${thisip}"
        else
        # Add the new ip to the array of IPs for the current user
         ips_used[${thisuser}]="${ips_used[${thisuser}]}, ${thisip}"
        fi
       else
       # If the previous difference doesn't satisfy the time interval the variables are reset for Dynamic IP Attack
        diff_ip_count[${thisuser}]=0
        last_attempt[${thisuser}]=$((${thistimestamp}))
        ips_used[${thisuser}]=""
       fi

       # Check if after too many attempts (brute force) of the IP, it got a successful login with WTMP
       if [[ ${diff_ip_count[$thisuser]} -ge $brute_force ]]; then
        # Print in module logs brute force attempts
        if [[ ${diff_ip_count[$thisuser]} -gt ${latest_diff_ip_count[$thisuser]} ]]; then
         echo "Brute Force: ${diff_ip_count[$thisuser]} attempts to user $thisuser at $(date -ud @$thistimestamp). Last attempt from IP: $thisip" | tee -a $attemptsof
         # Set to the same value latest_diff_ip_count to check later if there's a new attempt and add to the log as the previous command
         latest_diff_ip_count[$thisuser]=${diff_ip_count[$thisuser]}
        fi
        # First time IP attempts are considered as brute force
        # Check if IP attempts are equal to attempts considered as brute force variable
        if [[ "${diff_ip_count[$thisip]}" -ge $brute_force && "$last_diff_ip_count" -lt $brute_force ]]; then
         echo "[ALERT] Possible Dynamic IP attack to user '$thisuser' at $(date -ud @$thistimestamp) time. IPs used: ${ips_used[$thisuser]} [ALERT]" >> $hitsof
        fi
        # Check user in wtmp to analyze successful attempts. if they aren't, compare last failed attempt against successful login
        for l in $(cat $wtmpof | grep $thisuser | grep $thisip | awk '{print $3}'); do
         # Modify l timestamp to epoch
         l=$(date -d "${l:0:4}-${l:4:2}-${l:6:2} ${l:8:2}:${l:10:2}:${l:12:2}" +"%s")
         # Check if timestamp is greater than last attempt timestamp and if the user isn't in hits file at this moment
         if [[ $(echo ${l}) -gt ${last_attempt[${thisuser}]} && -z $(cat $hitsof 2>/dev/null | egrep "Succesful.*Dynamic.*$thisuser.*$(date -ud @$thistimestamp)") ]]; then
          diff_time=$(($(echo ${l})-${last_attempt[${thisuser}]}))
          # Check if difference time is lower than time interval and if the user isn't in hits file add to it  
          if [[ "${diff_time}" -le "${time_interval}" && -z $(cat $hitsof 2>/dev/null | grep $thisuser) ]]; then
           echo "[WARN] Successful Login to '$thisuser' user in a Possible Dynamic IP attack from IP $thisip at $(date -ud @$thistimestamp) time, after ${diff_ip_count[$thisuser]} attempts [WARN]" >> $hitsof
           echo "Ips used: ${ips_used[$thisuser]}" >> $hitsof
          fi
         fi
        done
       fi
      fi
     fi
    done

    # If there is a Red Zone defined it will create a new file with those attempts
    if [[ ! -z $max_timestamp_epoch ]]; then
     cat $attemptsof | while read -r line; do
      if [[ $(echo $line | awk '{print $9}') -ge $min_timestamp_epoch && $(echo $line | awk '{print $9}') -le $max_timestamp_epoch ]]; then
       echo $line >> $redzoneof
      fi
     done
    fi
}

linux_bruteforce_analysis
