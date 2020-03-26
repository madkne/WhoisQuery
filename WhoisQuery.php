<?php

/*************************************************************************
Whois Query :: whois lookup script
==========================================================================
Author:      madkne, (forked from www.phpeasycode.com)
*************************************************************************/

class WhoisQuery{

    public $version='1.2';
    private $domain=null;
    private $tld=null;
    private $ip=null;
    public $errors=array();
    // For the full list of TLDs/Whois servers see http://www.iana.org/domains/root/db/ and http://www.whois365.com/en/listtld/
    public $whoisservers = array(
        "ac" => "whois.nic.ac", // Ascension Island
        // ad - Andorra - no whois server assigned
        "ae" => "whois.nic.ae", // United Arab Emirates
        "aero"=>"whois.aero",
        "af" => "whois.nic.af", // Afghanistan
        "ag" => "whois.nic.ag", // Antigua And Barbuda
        "ai" => "whois.ai", // Anguilla
        "al" => "whois.ripe.net", // Albania
        "am" => "whois.amnic.net",  // Armenia
        // an - Netherlands Antilles - no whois server assigned
        // ao - Angola - no whois server assigned
        // aq - Antarctica (New Zealand) - no whois server assigned
        // ar - Argentina - no whois server assigned
        "arpa" => "whois.iana.org",
        "as" => "whois.nic.as", // American Samoa
        "asia" => "whois.nic.asia",
        "at" => "whois.nic.at", // Austria
        "au" => "whois.aunic.net", // Australia
        // aw - Aruba - no whois server assigned
        "ax" => "whois.ax", // Aland Islands
        "az" => "whois.ripe.net", // Azerbaijan
        // ba - Bosnia And Herzegovina - no whois server assigned
        // bb - Barbados - no whois server assigned
        // bd - Bangladesh - no whois server assigned
        "be" => "whois.dns.be", // Belgium
        "bg" => "whois.register.bg", // Bulgaria
        "bi" => "whois.nic.bi", // Burundi
        "biz" => [
            "server"=>"whois.biz",
            "port" => 43,
            "query_begin" => "",
            "query_end" => "\r\n",
            "redirect_string" => "",
            "no_match_string" => "Not found:",
        ],
        "bj" => "whois.nic.bj", // Benin
        // bm - Bermuda - no whois server assigned
        "bn" => "whois.bn", // Brunei Darussalam
        "bo" => "whois.nic.bo", // Bolivia
        "br" => "whois.registro.br", // Brazil
        "bt" => "whois.netnames.net", // Bhutan
        // bv - Bouvet Island (Norway) - no whois server assigned
        // bw - Botswana - no whois server assigned
        "by" => "whois.cctld.by", // Belarus
        "bz" => "whois.belizenic.bz", // Belize
        "ca" => [
            "server"=>"whois.cira.ca",
            "port" => 43,
            "query_begin" => "",
            "query_end" => "\r\n",
            "redirect_string" => "",
            "no_match_string" => "Domain status:         available"
        ], // Canada
        "cat" => "whois.cat", // Spain
        "cc" => "whois.nic.cc", // Cocos (Keeling) Islands
        "cd" => "whois.nic.cd", // Congo, The Democratic Republic Of The
        // cf - Central African Republic - no whois server assigned
        "ch" => "whois.nic.ch", // Switzerland
        "ci" => "whois.nic.ci", // Cote d'Ivoire
        "ck" => "whois.nic.ck", // Cook Islands
        "cl" => "whois.nic.cl", // Chile
        // cm - Cameroon - no whois server assigned
        "cn" => "whois.cnnic.net.cn", // China
        "co" => "whois.nic.co", // Colombia
        "com" => [
            "server"=>"whois.verisign-grs.com",
            "port" => 43,
            "query_begin" => "domain ",
            "query_end" => "\r\n",
            "redirect_string" => "Registrar WHOIS Server:",
            "no_match_string" => "No match for domain"
        ],
        "coop" => "whois.nic.coop",
        // cr - Costa Rica - no whois server assigned
        // cu - Cuba - no whois server assigned
        // cv - Cape Verde - no whois server assigned
        // cw - Curacao - no whois server assigned
        "cx" => "whois.nic.cx", // Christmas Island
        // cy - Cyprus - no whois server assigned
        "cz" => "whois.nic.cz", // Czech Republic
        "de" => "whois.denic.de", // Germany
        // dj - Djibouti - no whois server assigned
        "dk" => "whois.dk-hostmaster.dk", // Denmark
        "dm" => "whois.nic.dm", // Dominica
        // do - Dominican Republic - no whois server assigned
        "dz" => "whois.nic.dz", // Algeria
        "ec" => "whois.nic.ec", // Ecuador
        "edu" => "whois.educause.edu",
        "ee" => "whois.eenet.ee", // Estonia
        "eg" => "whois.ripe.net", // Egypt
        // er - Eritrea - no whois server assigned
        "es" => "whois.nic.es", // Spain
        // et - Ethiopia - no whois server assigned
        "eu" => "whois.eu",
        "fi" => "whois.ficora.fi", // Finland
        // fj - Fiji - no whois server assigned
        // fk - Falkland Islands - no whois server assigned
        // fm - Micronesia, Federated States Of - no whois server assigned
        "fo" => "whois.nic.fo", // Faroe Islands
        "fr" => "whois.nic.fr", // France
        // ga - Gabon - no whois server assigned
        "gd" => "whois.nic.gd", // Grenada
        // ge - Georgia - no whois server assigned
        // gf - French Guiana - no whois server assigned
        "gg" => "whois.gg", // Guernsey
        // gh - Ghana - no whois server assigned
        "gi" => "whois2.afilias-grs.net", // Gibraltar
        "gl" => "whois.nic.gl", // Greenland (Denmark)
        // gm - Gambia - no whois server assigned
        // gn - Guinea - no whois server assigned
        "gov" => "whois.nic.gov",
        // gr - Greece - no whois server assigned
        // gt - Guatemala - no whois server assigned
        "gs" => "whois.nic.gs", // South Georgia And The South Sandwich Islands
        // gu - Guam - no whois server assigned
        // gw - Guinea-bissau - no whois server assigned
        "gy" => "whois.registry.gy", // Guyana
        "hk" => "whois.hkirc.hk", // Hong Kong
        // hm - Heard and McDonald Islands (Australia) - no whois server assigned
        "hn" => "whois.nic.hn", // Honduras
        "hr" => "whois.dns.hr", // Croatia
        "ht" => "whois.nic.ht", // Haiti
        "hu" => "whois.nic.hu", // Hungary
        // id - Indonesia - no whois server assigned
        "ie" => "whois.domainregistry.ie", // Ireland
        "il" => "whois.isoc.org.il", // Israel
        "im" => "whois.nic.im", // Isle of Man
        "in" => "whois.inregistry.net", // India
        "info" => "whois.afilias.net",
        "int" => "whois.iana.org",
        "io" => "whois.nic.io", // British Indian Ocean Territory
        "iq" => "whois.cmc.iq", // Iraq
        "ir" => "whois.nic.ir", // Iran, Islamic Republic Of
        "is" => "whois.isnic.is", // Iceland
        "it" => "whois.nic.it", // Italy
        "je" => "whois.je", // Jersey
        // jm - Jamaica - no whois server assigned
        // jo - Jordan - no whois server assigned
        "jobs" => "jobswhois.verisign-grs.com",
        "jp" => "whois.jprs.jp", // Japan
        "ke" => "whois.kenic.or.ke", // Kenya
        "kg" => "www.domain.kg", // Kyrgyzstan
        // kh - Cambodia - no whois server assigned
        "ki" => "whois.nic.ki", // Kiribati
        // km - Comoros - no whois server assigned
        // kn - Saint Kitts And Nevis - no whois server assigned
        // kp - Korea, Democratic People's Republic Of - no whois server assigned
        "kr" => "whois.kr", // Korea, Republic Of
        // kw - Kuwait - no whois server assigned
        // ky - Cayman Islands - no whois server assigned
        "kz" => "whois.nic.kz", // Kazakhstan
        "la" => "whois.nic.la", // Lao People's Democratic Republic
        // lb - Lebanon - no whois server assigned
        // lc - Saint Lucia - no whois server assigned
        "li" => "whois.nic.li", // Liechtenstein
        // lk - Sri Lanka - no whois server assigned
        "lt" => "whois.domreg.lt", // Lithuania
        "lu" => "whois.dns.lu", // Luxembourg
        "lv" => "whois.nic.lv", // Latvia
        "ly" => "whois.nic.ly", // Libya
        "ma" => "whois.iam.net.ma", // Morocco
        // mc - Monaco - no whois server assigned
        "md" => "whois.nic.md", // Moldova
        "me" => "whois.nic.me", // Montenegro
        "mg" => "whois.nic.mg", // Madagascar
        // mh - Marshall Islands - no whois server assigned
        "mil" => "whois.nic.mil",
        // mk - Macedonia, The Former Yugoslav Republic Of - no whois server assigned
        "ml" => "whois.dot.ml", // Mali
        // mm - Myanmar - no whois server assigned
        "mn" => "whois.nic.mn", // Mongolia
        "mo" => "whois.monic.mo", // Macao
        "mobi" => "whois.dotmobiregistry.net",
        "mp" => "whois.nic.mp", // Northern Mariana Islands
        // mq - Martinique (France) - no whois server assigned
        // mr - Mauritania - no whois server assigned
        "ms" => "whois.nic.ms", // Montserrat
        // mt - Malta - no whois server assigned
        "mu" => "whois.nic.mu", // Mauritius
        "museum" => "whois.museum",
        // mv - Maldives - no whois server assigned
        // mw - Malawi - no whois server assigned
        "mx" => "whois.mx", // Mexico
        "my" => "whois.domainregistry.my", // Malaysia
        // mz - Mozambique - no whois server assigned
        "na" => "whois.na-nic.com.na", // Namibia
        "name" => "whois.nic.name",
        "nc" => "whois.nc", // New Caledonia
        // ne - Niger - no whois server assigned
        "net" => [
            "server"=>"whois.verisign-grs.net",
            "port" => 43,
            "query_begin" => "domain ",
            "query_end" => "\r\n",
            "redirect_string" => "Registrar WHOIS Server:",
            "no_match_string" => "No match for domain"
        ],
        "nf" => "whois.nic.nf", // Norfolk Island
        "ng" => "whois.nic.net.ng", // Nigeria
        // ni - Nicaragua - no whois server assigned
        "nl" => "whois.domain-registry.nl", // Netherlands
        "no" => "whois.norid.no", // Norway
        // np - Nepal - no whois server assigned
        // nr - Nauru - no whois server assigned
        "nu" => "whois.nic.nu", // Niue
        "nz" => "whois.srs.net.nz", // New Zealand
        "om" => "whois.registry.om", // Oman
        "org" => "whois.pir.org",
        // pa - Panama - no whois server assigned
        "pe" => "kero.yachay.pe", // Peru
        "pf" => "whois.registry.pf", // French Polynesia
        // pg - Papua New Guinea - no whois server assigned
        // ph - Philippines - no whois server assigned
        // pk - Pakistan - no whois server assigned
        "pl" => "whois.dns.pl", // Poland
        "pm" => "whois.nic.pm", // Saint Pierre and Miquelon (France)
        // pn - Pitcairn (New Zealand) - no whois server assigned
        "post" => "whois.dotpostregistry.net",
        "pr" => "whois.nic.pr", // Puerto Rico
        "pro" => "whois.dotproregistry.net",
        // ps - Palestine, State of - no whois server assigned
        "pt" => "whois.dns.pt", // Portugal
        "pw" => "whois.nic.pw", // Palau
        // py - Paraguay - no whois server assigned
        "qa" => "whois.registry.qa", // Qatar
        "re" => "whois.nic.re", // Reunion (France)
        "ro" => "whois.rotld.ro", // Romania
        "rs" => "whois.rnids.rs", // Serbia
        "ru" => "whois.tcinet.ru", // Russian Federation
        // rw - Rwanda - no whois server assigned
        "sa" => "whois.nic.net.sa", // Saudi Arabia
        "sb" => "whois.nic.net.sb", // Solomon Islands
        "sc" => "whois2.afilias-grs.net", // Seychelles
        // sd - Sudan - no whois server assigned
        "se" => "whois.iis.se", // Sweden
        "sg" => "whois.sgnic.sg", // Singapore
        "sh" => "whois.nic.sh", // Saint Helena
        "si" => "whois.arnes.si", // Slovenia
        "sk" => "whois.sk-nic.sk", // Slovakia
        // sl - Sierra Leone - no whois server assigned
        "sm" => "whois.nic.sm", // San Marino
        "sn" => "whois.nic.sn", // Senegal
        "so" => "whois.nic.so", // Somalia
        // sr - Suriname - no whois server assigned
        "st" => "whois.nic.st", // Sao Tome And Principe
        "su" => "whois.tcinet.ru", // Russian Federation
        // sv - El Salvador - no whois server assigned
        "sx" => "whois.sx", // Sint Maarten (dutch Part)
        "sy" => "whois.tld.sy", // Syrian Arab Republic
        // sz - Swaziland - no whois server assigned
        "tc" => "whois.meridiantld.net", // Turks And Caicos Islands
        // td - Chad - no whois server assigned
        "tel" => "whois.nic.tel",
        "tf" => "whois.nic.tf", // French Southern Territories
        // tg - Togo - no whois server assigned
        "th" => "whois.thnic.co.th", // Thailand
        "tj" => "whois.nic.tj", // Tajikistan
        "tk" => "whois.dot.tk", // Tokelau
        "tl" => "whois.nic.tl", // Timor-leste
        "tm" => "whois.nic.tm", // Turkmenistan
        "tn" => "whois.ati.tn", // Tunisia
        "to" => "whois.tonic.to", // Tonga
        "tp" => "whois.nic.tl", // Timor-leste
        "tr" => "whois.nic.tr", // Turkey
        "travel" => "whois.nic.travel",
        // tt - Trinidad And Tobago - no whois server assigned
        "tv" => "tvwhois.verisign-grs.com", // Tuvalu
        "tw" => "whois.twnic.net.tw", // Taiwan
        "tz" => "whois.tznic.or.tz", // Tanzania, United Republic Of
        "ua" => "whois.ua", // Ukraine
        "ug" => "whois.co.ug", // Uganda
        "uk" => [
            "server"=>"whois.nic.uk",
            "port" => 43,
            "query_begin" => "",
            "query_end" => "\r\n",
            "redirect_string" => "",
            "no_match_string" => "No match for"
        ]
            , // United Kingdom
        "us" => "whois.nic.us", // United States
        "uy" => "whois.nic.org.uy", // Uruguay
        "uz" => "whois.cctld.uz", // Uzbekistan
        // va - Holy See (vatican City State) - no whois server assigned
        "vc" => "whois2.afilias-grs.net", // Saint Vincent And The Grenadines
        "ve" => "whois.nic.ve", // Venezuela
        "vg" => "whois.adamsnames.tc", // Virgin Islands, British
        // vi - Virgin Islands, US - no whois server assigned
        // vn - Viet Nam - no whois server assigned
        // vu - Vanuatu - no whois server assigned
        "wf" => "whois.nic.wf", // Wallis and Futuna
        "ws" => "whois.website.ws", // Samoa
        "xxx" => "whois.nic.xxx",
        // ye - Yemen - no whois server assigned
        "yt" => "whois.nic.yt", // Mayotte
        "yu" => "whois.ripe.net");
    /************************************* */
    public function __construct(string $domain=null,string $ip=null)
    {
        if($domain!=null){
            $this->domain=$domain;
        }
        if($ip!=null && self::ValidateIP($ip)){
            $this->ip=$ip;
        }
    }
    /************************************* */
    /**
     * get a whois server domain name and whois it and return result or false on failed!
     * @param string $whoisserver
     * @param bool is_raw : if true return result as string and is false return it as an array list
     * @return string|array|bool
     * @author madkne
     * @version 1.1
     */
    public function QueryWhoisServer($whoisserver,$is_raw=true) {
        //=>init vars
        $connection_timeout = 10;
        $whois_server = is_array($whoisserver)?$whoisserver['server']:$whoisserver;
        $port = is_array($whoisserver)?$whoisserver['port']:43;
        $query_begin = is_array($whoisserver)?$whoisserver['query_begin']:'';
        $query_end = is_array($whoisserver)?$whoisserver['query_end']:"\r\n";
        $whois_redirect_string = is_array($whoisserver)?$whoisserver['redirect_string']:'';
        $no_match_string = is_array($whoisserver)?$whoisserver['no_match_string']:'';
        $whois_redirect_server = "";
        $response = "";
        $result_raw='';
        $fp=null;
        $result_array=array();
        // print_r([$whois_server, $port,$query_begin.$this->domain.$query_end]);
        //=>try to open web socket
        try{
            $fp = fsockopen($whois_server, $port, $errno, $errstr, $connection_timeout);
            //=>check if socket is opened!
        }
        finally{
            if(!$fp){
                $this->errors[]="(1) Socket Error " . $errno . " - " . $errstr;
                return false;
            }
        }
        //=>send domain info request on socket
        fputs($fp, $query_begin.$this->domain.$query_end);
        // dump($fp);
        //=>read response of socket line by line
        while(!feof($fp)){
            $line = fgets($fp);
            // echo $line."\n";
            $response .= $line;
            // Check for whois redirect server.
            if ($whois_redirect_string!='' && stristr($line, $whois_redirect_string)) {
                $whois_redirect_server = trim(str_replace($whois_redirect_string, "", $line));
                break;
            }
        }
        fclose($fp);
        // echo $whois_redirect_server;
        //=>Query redirect server if set.
        if ($whois_redirect_server!='') {
            // Query the redirect server.  Might be different values for port etc, so give the option to change them from those set previously.  Using defaults below.
            $whois_server = $whois_redirect_server;
            $port = "43";
            $connection_timeout = 5;
            $query_begin = "";
            $query_end = "\r\n";
            $response = "";
            //=>open web socket
            $fp = fsockopen($whois_server, $port, $errno, $errstr, $connection_timeout);
            //=>check if socket is opened!
            if (!$fp) {
                $this->errors[]="(2) Socket Error " . $errno . " - " . $errstr;
                return false;
            }
            //=>send domain info request on socket
            fputs($fp, $query_begin.$this->domain.$query_end);
            while (!feof($fp)) {
                $response .= fgets($fp);
            }
            fclose($fp);
        }
        // print_r($response);
        //=>Check result for no-match phrase.
        if (($no_match_string!='' && stristr($response, $no_match_string)) || (strpos(strtolower($response), "error") !== FALSE) || (strpos(strtolower($response), "not allocated") !== FALSE)) {
            $this->errors[]="{$this->domain} domain is not registered";
            return false;
        }

        //=>simple parse response (remove comments)
        $rows = explode("\n", $response);
        // print_r($rows);
        foreach($rows as $row) {
            $row = trim($row);
            // echo $row."\n\r";
            if($row != '' && $row[0] != '#' && $row[0] != '%') {
                $result_raw .= $row."\n";
                $result_array[]=$row;
            }
        }
        if($is_raw){
            return $result_raw;
        }
        return $result_array;
    }
    /************************************* */
    /**
     * get global domain name and return array of whois result lines
     * @return array|bool
     * @author madkne
     * @version 1.1
     */
    public function LookupWhoisDomain(){
        if($this->domain==null) return false;
        $domain_parts = explode(".", $this->domain);
        $tld = strtolower(array_pop($domain_parts));
        $this->tld=$tld;
        $whoisserver = $this->whoisservers[$tld];
        // print_r([$this->domain,$tld,$domain_parts,$whoisserver]);
        if(!$whoisserver) {
            $this->errors[]= "Error: No appropriate Whois server found for {$this->domain} domain!";
            return false;
        }
        $result = $this->QueryWhoisServer($whoisserver,false);
        // print_r($result);
        if(!$result) {
            $this->errors[]=  "Error: No results retrieved from {$whoisserver} server for {$this->domain} domain!";
            return false;
        }
        else {
            //TODO:
            // while(strpos($result, "Whois Server:") !== FALSE){
            //     preg_match("/Whois Server: (.*)/", $result, $matches);
            //     $secondary = $matches[1];
            //     if($secondary) {
            //         $result = $this->QueryWhoisServer($secondary, false);
            //         $whoisserver = $secondary;
            //     }
            // }
        }
        return $result;
    }
    /************************************* */
    public function LookupIP() {
        $whoisservers = array(
            //"whois.afrinic.net", // Africa - returns timeout error :-(
            "whois.lacnic.net", // Latin America and Caribbean - returns data for ALL locations worldwide :-)
            "whois.apnic.net", // Asia/Pacific only
            "whois.arin.net", // North America only
            "whois.ripe.net" // Europe, Middle East and Central Asia only
        );
        $results = array();
        foreach($whoisservers as $whoisserver) {
            $result = $this->QueryWhoisServer($whoisserver, $this->ip);
            if($result && !in_array($result, $results)) {
                $results[$whoisserver]= $result;
            }
        }
        $res = "RESULTS FOUND: " . count($results);
        foreach($results as $whoisserver=>$result) {
            $res .= "\n\n-------------\nLookup results for " . $this->ip . " from " . $whoisserver . " server:\n\n" . $result;
        }
        return $res;
    }

    /************************************* */
	public function query(){
        //=>query on whois server and get result(array of lines)
        $data = $this->LookupWhoisDomain();
        // $data=$this->getWhoisResult($tld);
        if($data===false){
            return false;
        }
        // print_r($data);
        // print_r($this->tld);
        $whoisServerFromWhois = $this->splitResult($data);
        // if(!empty($whoisServerFromWhois['whois_server'][0])){
        //     $data = $this->getWhoisResult( $tld, $whoisServerFromWhois['whois_server'][0]);
        //     // $data = $this->QueryWhoisServer($whoisserver,false);
        // }
        // print_r($whoisServerFromWhois);
        $parsedResult = $this->parseWhoisResult($whoisServerFromWhois);

        return $parsedResult;
	}
    /************************************* */
    /**
     * get data of whois result query and split its lines to map array (key,value)
     * @param array data
     * @author madkne
     * @version 1.3
     */
	private function splitResult(array $data=null)
	{
        //=>init vars
        $res = [];
        $datac=count($data);
        $exclude_tlds=['edu','eu','uk'];

        //=>iterate data lines
        for ($i=0; $i < $datac; $i++) {
            //=>init vars
            $line=trim($data[$i]);
            $key='';
            $value='';
            $mode='key';
            $par_count=0; //=>count of parantesis : ()
            //=>get key and value of line
            for ($j=0; $j < strlen($line); $j++) {
                if($line[$j]=='(') $par_count++;
                else if($line[$j]==')') $par_count--;
                else if($par_count==0 && $line[$j]==':'){
                    $mode='value';
                    continue;
                }
                else if($line[$j]=='\t') continue;
                if($mode=='key'){
                    $key.=$line[$j];
                }else if($mode=='value'){
                    $value.=$line[$j];
                }
            }
            //=>normalize key,value
            $key=strtolower(trim($key));
            $value=trim($value);
            //=>if mode is value and value is empty (for .edu,.eu,.uk tlds)
            /* like:
            * Name Servers:
                    SCOTT.NS.CLOUDFLARE.COM
                    ROBIN.NS.CLOUDFLARE.COM
                    ns1.eurid.eu (2001:67c:9c:3937::252)
                    ns1.eurid.eu (185.36.4.252)
                    nsp.netnod.se
            */
            if(in_array($this->tld,$exclude_tlds) && $mode=='value' && empty($value) && $i+1<$datac){
                $j=$i;
                for ($j=$i+1; $j < $datac; $j++) {
                    $isbreak=false;
                    $value='';
                    $par_count=0; //=>count of parantesis : ()
                    $line=trim($data[$j]);
                    for ($k=0; $k < strlen($line); $k++) {
                        if($line[$k]=='(') $par_count++;
                        else if($line[$k]==')') $par_count--;
                        else if($par_count==0 && $line[$k]==':'){
                            $isbreak=true;
                            break;
                        }
                        $value.=$line[$k];
                    }
                    if($isbreak) break;
                    //=>append to res list
                    $res[$key][]=trim($value);
                }
                $i=$j-1;
                continue;
            }
            //=>check if value not exist or not valid (like: //icann.org/epp)
            if($value==null || $value=='' || strpos($value,'//')===0){
                continue;
            }
            //=>append to res list
            $res[$key][]=$value;

        }
		return $res;
	}
    /************************************* */
    /**
     * get an gields array (split key, value) and parse them to structure array
     * tested for:
     * - ac.ir  (yazd.ac.ir)
     * - ir     (caket.ir)
     * - gov.ir (mcls.gov.ir)
     * - com    (filimo.com)
     * - org    (wikipedia.org)
     * - cn
     * - net
     * - edu    (educause.edu)
     * - eu     (eurid.eu)
     * - ru     (cctld.ru)
     * - uk     (hello.uk)
     * - co.uk  (ovh.co.uk)
     * - ac     (info.ac)
     * - info   (info.info)
     * - me     (google.me)
     * ---------------------
     * less supported for:
     * - de(nsserver not shown!)
     * - ac.uk (jisc.ac.uk)
     * @param array fields
     * @return array
     * @author madkne
     * @version 1.2
     */
	private function parseWhoisResult(array $fields)
	{
        //=>init vars
        $parseResult=[];
		$WhoisKeywords = [
            'id' =>
                ['domain id', 'domain name id', 'registry domain id', 'roid'],
            'domain' =>
                ['domain name', 'domain name', 'domain','ascii'],
            'bundled_domain' =>
                ['bundled domain name'],
            'name_server' =>
                ['name server', 'nameservers', 'name servers', 'name servers information', 'domain servers in listed order', 'nserver'],
            'registrar'	=>
                ['registrar', 'registrant', 'registrar name', 'created by registrar','registrant id'],
            'registrar_url'	=>
                ['registrar url', 'registrar url (registration services)'],
            'sponsoring_registrar' =>
                [ 'sponsoring registrar'],
            'whois_server' =>
                ['whois server', 'registrar whois server'],
            'created_at' =>
                ['creation date', 'created on', 'registration time', 'domain create date', 'domain registration date', 'domain name commencement date', 'created','domain record activated','registered on'],
            'updated_at' =>
                ['last-update', 'updated date', 'domain last updated date', 'last modified','last-updated','domain record last updated','last updated'],
            'expired_at' =>
                ['expiry date', 'expiration date', 'expiration time', 'domain expiration date', 'registrar registration expiration date', 'record expires on', 'registry expiry date', 'renewal date','expire-date','domain expires','paid-till','free-date'],
            'status' =>
                ['status', 'domain status','state'],
            'holder_name' =>
                ['person','name'],
            'holder_address' =>
                ['street','address'],
            'holder_email' =>
                ['email','e-mail','registrant email'],
            'holder_phone' =>
                ['phone', 'phone number'],
            'holder_fax' =>
                ['fax', 'facsimile number','fax-no'],
            'holder_org' =>
                ['organization','organisation','org','registrant organization','registrant'],
            'holder_country' =>
                ['registrant country','country', 'country/economy'],
            'holder_city' =>
                ['city'],
            'holder_province' =>
                ['state/province','registrant state/province'],
            'admin' =>
                ['admin', 'administrative', 'administrative contact','admin-c','admin email','admin-contact'],
            'tech' =>
                ['tech', 'technical', 'technical contact','tech-c','tech email'],
            'billing' =>
                ['bill', 'billing', 'billing contact'],
            'dns_security' => /*Domain Name System Security Extensions */
                ['dnssec']
		];

        //=>iterate all fields
        foreach ($fields as $key => $val) {
            //=>iterate all whois keywords for any fields
            foreach ($WhoisKeywords as $wkey => $wvals) {
                //=>check if key of field is exist on whois keywords list
                if(in_array($key,$wvals)){
                    for ($i=0; $i < count($val); $i++) {
                        //=>check $val not duplicate in parse result!
                        if(isset($parseResult[$wkey]) && in_array($val[$i],$parseResult[$wkey])){
                            continue;
                        }
                        //=>append to parse result list
                        $parseResult[$wkey][]=$val[$i];
                    }

                }
            }
        }
        //=>return parse result list
		return $parseResult;
	}

    /************************************* */
    /**********STATIC METHODS************* */
    /************************************* */

    public static function ValidateIP($ip) {
        $packed = inet_pton ($ip);
        if (FALSE == $packed || FALSE === inet_ntop ($packed)) {
            return FALSE;
            }
        return $ip;
    }
    /************************************* */
    public static function ValidateDomain($domain) {
        if(!preg_match("/^([-a-z0-9]{2,100})\.([a-z\.]{2,8})$/i", $domain)) {
            return false;
        }
        return $domain;
    }

}
