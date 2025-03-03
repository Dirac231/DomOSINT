# Exploit Research Function
ssp(){
    echo -e "\nEXPLOITDB SEARCH\n"
    searchsploit $1 -j | jq '.RESULTS_EXPLOIT[] | select(.Verified == "1") | {Title, Date_Published, Path}'

    echo -e "\nCVE GENERAL SEARCH\n"
    cvemap -silent -q "$1" -j | jq '.[] | select(.is_poc == true) | {cve_id, cve_description, pocs: [.poc[].url]}'
}

# Username/e-mail tracking along internet
sherlock(){
    echo -e "\nSEARCHING USERNAME WITH SHERLOCK\n"
    cd ~/TOOLS/sherlock/sherlock; python3 sherlock.py $1; cd ~
}

# Shodan DB statistics lookup
hackstat(){
    top_results=50

    echo -e "Performing top $top_results search\n"
    shodan stats --facets org,domain,product,port,ip,http.title,vuln.verified --limit $top_results $1
}

# WayBackMachine GET parameter scraping
paramine(){
    echo -e "\nFETCHING PARAMETERS FROM DOMAIN\n"
    echo $1 | waymore -mode U && cat ~/.config/waymore/results/$1/waymore.txt | qsreplace FUZZ | grep FUZZ > $(echo $1 | unfurl format %d)_params.txt

    echo -e "\nFUZZING PARAMETERS\n"
    nuclei -up &> /dev/null && nuclei -ut &> /dev/null
    nuclei -rl 20 -silent -ss host-spray -l $(echo $1 | unfurl format %d)_params.txt -dast -headless -t dast/  -v
}

# Google fingerprinting for a root domain
gmine(){
    cur=$(pwd)
    cd /home/kali/TOOLS/GooFuzz

    ./GooFuzz -t $1 -d 15 -p 10 -s
    sleep 15
    ./GooFuzz -t $1 -d 15 -p 10 -e ./wordlists/extensions.txt
    sleep 15

    echo -e "\nEXTRACTING USEFUL METADATA\n"
    metagoofil -d $1 -t 7z,avi,djvu,doc,docx,exe,iso,mov,mp4,pptx,ppt,rar,zip,pdf,txt,xls,xlsx -w -o metagoofil_$1
    exiftool -r ./metagoofil_$1/* | egrep -i "Author|Creator|Email|Producer|Template" | sort -u

    sleep 15
    ./GooFuzz -t $1 -d 15 -p 10 -w ./wordlists/words.txt

    cd $cur
}

# WayBackMachine 200-URL Mining
urlmine(){
    httpx -up &>/dev/null
    echo -e "\nGETTING ALL URLS FOR DOMAIN \"$1\" -> \"~/.config/waymore/results/$1/waymore.txt\"\n"
    echo $1 | waymore -mode U

    echo -e "\nGETTING 200-STATUS URLS\n"
    cat ~/.config/waymore/results/$1/waymore.txt | httpx -random-agent -fr -mc 200 -silent -sc -server -title -cdn -cname > URL_WEB_MINED_$1.txt
}

# WayBackMachine sensitive file mining
filemine(){
    httpx -up &>/dev/null 

    echo -e "\nFETCHING RAW ARCHIVE DATA\n"
    echo $1 | waymore -mode U

    echo -e "\nSEARCHING GOOGLE DRIVE / DOCS\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -E "(drive.google | docs.google)" | httpx -fr -mc 200

    echo -e "\nMINING PUBLIC ARCHIVES\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -E "\.zip$|\.rar$|\.tar$|\.gz$|\.7z$|\.bz2$|\.xz$|\.tar.gz$|\.tar.bz2$|\.tar.xz$|\.tar.7z$|\.tgz$|\.tbz2$|\.txz$|\.zipx$|\.gzip$" | httpx -fr -mc 200

    echo -e "\nMINING CONFIGURATION FILES\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -E "\.log$|\.txt$|\.syslog$|\.swf$\.ini$|\.cfg$|\.conf$|\.yaml$|\.yml$|\.properties$|\.xml$|\.axd$|\.json$|\.toml$|\.env$|\.config$|\.prefs$|\.cnf$|\.plist$|\.sql$|\.sqlite3$|\.kbdx$|\.htaccess$|\.htpasswd$|\.config$|\.sys$" | httpx -fr -mc 200

    echo -e "\nMINING BACKUP FILES\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -E "\.bak$|\.backup$|\.bkp$|\.old$|\.tmp$|\.~$|\.swp$|\.sav$" | httpx -fr -mc 200

    echo -e "\nMINING EXECUTABLE FILES\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -e "\.exe$|\.dll$|\.bat$|\.sh$|\.app$|\.jar$|\.msi$|\.vbs$|\.cmd$|\.go$|\.cpp$|\.c$|\.run$|\.py$|\.pl$|\.rb$|\.ps1$" | httpx -fr -mc 200

    echo -e "\nMINING NON-STANDARD PUBLIC DOCUMENTS\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -E "\.docx$|\.xlsx$|\.rtf$|\.csv$|\.xls$|\.psd$|\.odt$|\.mp4$" | httpx -fr -mc 200

    echo -e "\nSCRAPING JAVASCRIPT FILES FOR SECRETS/ENDPOINTS\n"
    cat ~/.config/waymore/results/$1/waymore.txt | grep -E "\.js$" | httpx -fr -mc 200 > js_files_$1.txt
}

# WHOIS Record Checker
whoiscan_ut(){
    whois $1
    whois -a "z $1*"
    whois -a "z @$1*"
    whois -a $1
}
whoiscan(){
    echo -e "\nREGISTRY DATA\n"
    whoiscan_ut $1 | grep -wiE "Registrant|Registrar" | sed -e 's/^[[:space:]]*//' | sort -u

    echo -e "\nSERVER DATA\n"
    whoiscan_ut $1 | grep -wiE "Server|Domain|ifaddr|local-as|DNSSEC|Updated|Page" | sed -e 's/^[[:space:]]*//' | sort -u

    echo -e "\nCONTACT DATA\n"
    whoiscan_ut $1 | grep -wiE "Email|Phone|Street|City|Postal|Fax" | sed -e 's/^[[:space:]]*//' | sort -u

    echo -e "\nADMIN DATA\n"
    whoiscan_ut $1 | grep -wiE "Admin" | sed -e 's/^[[:space:]]*//' | sort -u
}

# Passive subdomain enumeratio
subfind(){
    echo -e "\nPASSIVE SOURCE ENUMERATION\n"
    chaos --update && chaos -d $1 -silent -key $chaos_key | anew -q subdomains_$1.txt
    amass enum -passive -norecursive -d $1 | anew -q subdomains_$1.txt
	subfinder -d $1 -config ~/.config/subfinder/config.yaml -silent | anew -q subdomains_$1.txt
    echo $1 | haktrails subdomains | anew -q subdomains_$1.txt
	assetfinder --subs-only $1 | anew -q subdomains_$1.txt
    findomain -quiet -t $1 | anew -q subdomains_$1.txt; rm iet 2>/dev/null

    echo -e "\nAPPENDING PERMUTATION LIST\n"
    cat subdomains_$1.txt | alterx -enrich -silent | dnsgen - | anew -q subdomains_$1.txt

    echo -e "\nSCANNING SNI RANGES FOR WEB SUBDOMAINS\n"
    echo "amazon\ndigitalocean\ngoogle\nmicrosoft\noracle" | while read provider; do curl -ks https://kaeferjaeger.gay/sni-ip-ranges/$provider/ipv4_merged_sni.txt -o ~/WORDLISTS/ipv4_sni_$provider.txt; done
    cat ~/WORDLISTS/ipv4_sni_*.txt | grep -F ".$1" | awk -F'-- ' '{print $2}'| tr ' ' '\n' | tr '[' ' ' | sed 's/ //' | sed 's/\]//' | grep -F ".$1" | sort -u > tmpdomsni_$1 && cat tmpdomsni_$1 && cat tmpdomsni_$1 | anew -q subdomains_$1.txt && rm tmpdomsni_$1

    echo -e "\nFINISHED GETTING SUBDOMAINS\n"
}

# CIDR -> PTR Mapper
ptr(){
    dnsx --update &>/dev/null
    cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"
    asn_regex='^(AS)|(as)[0-9]+$'

    if [[ $1 =~ $asn_regex ]]; then
        whois -h whois.radb.net -- "-i origin $1" | grep -Eo "([0-9.]+){4}/[0-9]+" | anew -q cidr_$1.txt
        touch ptr_domains.txt && while read -r cidr; do echo $cidr | mapcidr -silent | dnsx -ptr -resp-only | anew -q ptr_domains.txt; done < cidr_$1.txt
    elif [[ $1 =~ $cidr_regex ]]; then
        echo $1 | mapcidr -silent | dnsx -ptr -resp-only | anew -q ptr_domains.txt
    else
        cat $1 | dnsx -ptr -resp-only | anew -q ptr_domains.txt
    fi
}

# DNS Resolving function
resolve(){
    echo -e "\nFETCHING RESOLVERS\n"
    wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O ~/WORDLISTS/public_resolvers.txt

    echo -e "\nRESOLVING DOMAINS\n"
	puredns resolve $1 -w resolved.txt -r ~/WORDLISTS/public_resolvers.txt

    echo -e "\nFETCHING IP/CNAME RECORDS\n"
    massdns -r ~/WORDLISTS/public_resolvers.txt -t A -o S -w dns_records.txt resolved.txt
    grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' dns_records.txt > ipv4_addresses.txt

    read -r resp\?"DO YOU WANT TO RECURSIVELY BRUTEFORCE DOMAINS? (Y/N): "
    if [[ $resp =~ [yY] ]]; then
        root_dom=$(cat $1 | head -n 1 | awk -F"." '{print $NF}')
        mkdir BRUTEFORCED_$root_dom
        puredns bruteforce -r ~/WORDLISTS/public_resolvers.txt ~/WORDLISTS/subdomains.txt $root_dom --threads 10 --write ./BRUTEFORCED_$root_dom/bruteforced_$root_dom.txt
        while read dom; do  puredns bruteforce -r ~/WORDLISTS/public_resolvers.txt ~/WORDLISTS/subdomains.txt $dom --threads 10 --write ./BRUTEFORCED_$root_dom/bruteforced_$dom.txt; done < resolved.txt
    fi
}

# Subdomain Takeover function
takeover(){
    echo -e "\nTESTING NUCLEI TAKEOVERS\n"
    nuclei -up >/dev/null && nuclei -ut >/dev/null
    nuclei -rl 20 -silent -l $1 -t http/takeovers 

    echo -e "\nTESTING DNS TAKEOVERS\n"
    sudo service docker start
    sleep 1
    sudo docker run -it --rm -v $(pwd):/etc/dnsreaper punksecurity/dnsreaper file --filename /etc/dnsreaper/$1

    echo -e "\nTESTING SUBZY TAKEOVERS\n"
    subzy run --targets $1 --hide_fails --vuln
}

# Web application probing on resolved domains
webprobe(){
    mkdir WEB_SCAN && cd WEB_SCAN && cp ../$1 .

    echo -e "\nWEB PORT SCANNING\n"
    sudo /home/kali/.local/bin/unimap --fast-scan -f $1 --ports $COMMON_PORTS_WEB -q -k --url-output > web_unimap_scan
    rm -rf unimap_logs

    echo -e "\nFILTERING ALIVE APPLICATIONS\n"
    httpx -up &>/dev/null
    cat web_unimap_scan | httpx -random-agent -fr -silent -fc 404 -sc -server -title -td -cdn -cname -o websites_alive.txt

    echo -e "\nSCREENSHOOTING SERVICES\n"
    cat websites_alive.txt | awk -F" " '{print $1}' | sort -u > alive_urls.txt
    gowitness scan file -f alive_urls.txt --write-db && gowitness report server
}

# Alive Host IP/CIDR Scanning
alive(){
    cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"
    if [ -f ./$1 ]; then
        echo -e "\nNMAP SWEEPING\n"
        sudo nmap -n -sn -PE -PP -PM -PS21,22,23,25,80,113,443,31339 -PA80,113,443,10042 -g 53 -iL $1 | grep for | cut -d" " -f5 > alive_ips.txt && cat alive_ips.txt

    elif [[ $1 =~ $cidr_regex ]]; then
    	echo -e "\nFPING SWEEPING\n"
	    fping -asgq $1

        echo -e "\nNMAP SWEEPING\n"
        sudo nmap -n -sn -PE -PP -PM -PS21,22,23,25,80,113,443,31339 -PA80,113,443,10042 -g 53 $1 | grep for | cut -d" " -f5 > alive_ips.txt && cat alive_ips.txt
    fi
}

# Passive Shodan Fingerprinting (CIDR / ASN / FILE)
shodscan(){
    cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"
    asn_regex='^(AS)|(as)[0-9]+$'

    if [[ $1 =~ $asn_regex ]]; then
        echo -e "\nDISPLAYING SHODAN STATISTICS\n"
        hackstat "asn:$1"
        whois -h whois.radb.net -- "-i origin $1" | grep -Eo "([0-9.]+){4}/[0-9]+" | mapcidr -silent | anew -q $1_IP.txt
        cat $1_IPS.txt | nrich -

    elif [[ $1 =~ $cidr_regex ]]; then
        echo -e "\nDISPLAYING SHODAN STATISTICS\n"
        hackstat "net:$1"

        echo -e "\nDISPLAYING HOSTS INFORMATION\n"
        filename=$(echo $1 | tr -d '/')
        echo $1 | mapcidr -silent | anew -q $filename.txt
        cat $filename.txt | nrich -

    else
        echo -e "\nDISPLAYING HOSTS INFORMATION\n"
        cat $1 | nrich -
    fi
}

# Active Fingerprinting (CIDR / FILE)
fingerprint(){
    cidr_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$"
    if [[ $1 =~ $cidr_regex ]]; then
        echo -e "\nTCP TOP-1000 SCAN\n"
        sudo masscan $1 --top-ports 100

        echo -e "\nUDPX FINGERPRINT\n"
        udpx -t $1 -c 128 -w 1000
    else
        echo -e "\nTCP TOP-100 SCAN\n"
        sudo masscan -iL $1 --top-ports 100

        echo -e "\nUDPX FINGERPRINT\n"
        udpx -tf $1 -c 128
    fi
}

# Host Mapping Search -> Using https://wordlists-cdn.assetnote.io/data/technologies
hostmap() {
    local search_string="$1"
    local hostmap_folder=~/WORDLISTS/HOSTMAP

    if [[ -z "$search_string" ]]; then
        echo "Usage: search_in_hostmap <string>"
        return 1
    fi

    for file in "$hostmap_folder"/*; do
        if [[ -f "$file" ]]; then
            # Extract filename without path and extension
            local filename=$(basename "$file" .txt)
            echo "Searching in $filename:"
            cat $file | grep $search_string | sort -u || echo "No match found"
            echo "" # Print a newline for better readability
        fi
    done
}

# Cloud assets searching
cloudfind(){
    echo -e "\nENUMERATING CLOUD SERVICES\n"
    root=$(echo $1 | cut -f1 -d'.')
    /home/kali/TOOLS/cloud_enum/venv/bin/python3 ~/TOOLS/cloud_enum/cloud_enum.py -k $1 -k $root
}
