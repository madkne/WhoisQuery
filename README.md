# WhoisQuery V1.2
get whois query and parse its records simply in php 7

# How to use it
```
<?php
  $whois=new WhoisQuery('google.com');
  $result = $whois->query();
  print_r($result);
  print_r($whois->errors);
?>
```
# how to get results
```
 Array
(
    [domain] => Array
        (
            [0] => google.com
        )

    [id] => Array
        (
            [0] => 2138514_DOMAIN_COM-VRSN
        )

    [whois_server] => Array
        (
            [0] => whois.markmonitor.com
        )

    [registrar_url] => Array
        (
            [0] => http//www.markmonitor.com
        )

    [updated_at] => Array
        (
            [0] => 2019-09-09T083904-0700
        )

    [created_at] => Array
        (
            [0] => 1997-09-15T000000-0700
        )

    [expired_at] => Array
        (
            [0] => 2028-09-13T000000-0700
        )

    [registrar] => Array
        (
            [0] => MarkMonitor, Inc.
        )

    [status] => Array
        (
            [0] => clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)
            [1] => clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)
            [2] => clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)
            [3] => serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)
            [4] => serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)
            [5] => serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)
        )

    [holder_org] => Array
        (
            [0] => Google LLC
        )

    [holder_province] => Array
        (
            [0] => CA
        )

    [holder_country] => Array
        (
            [0] => US
        )

    [holder_email] => Array
        (
            [0] => Select Request Email Form at https//domains.markmonitor.com/whois/google.com
        )

    [admin] => Array
        (
            [0] => Select Request Email Form at https//domains.markmonitor.com/whois/google.com
        )

    [tech] => Array
        (
            [0] => Select Request Email Form at https//domains.markmonitor.com/whois/google.com
        )

    [name_server] => Array
        (
            [0] => ns3.google.com
            [1] => ns1.google.com
            [2] => ns2.google.com
            [3] => ns4.google.com
        )

    [dns_security] => Array
        (
            [0] => unsigned
        )

)
Array
(
)
```
# list of all whois result field
|field        |description                |
| ------------|:-------------------------:|
|id           | domain id                 |
|domain       | domain name               |
|name_server  | list of name server       |
|registrar    | registrar name            |
|registrar_url| registrar url             |
|sponsoring_registrar| sponsoring registrar|
|whois_server | registrar whois server    |
|created_at   | domain registration date  |
|updated_at   | domain last updated date  |
|expired_at   | domain expiration date    |
|status       | domain status             |
|holder_name  | domain holder person name |
|holder_address| domain holder address    |
|holder_email | domain holder email address|
|holder_phone | domain holder phone number|
|holder_fax   | domain holder fax number  |
|holder_org   | domain holder organization|
|holder_country| domain holder country    |
|holder_city  | domain holder city        |
|holder_province| domain holder state/province|
|admin        | administrative contact    |
|tech         | technical contact         |
|bill         | billing contact           |
|dns_security | Domain Name System Security Extensions|

# How to help me!
you can test it by different domain TLDs and if a record not parsed or occurs any errors, then just report to fix it!
**Thanks :)**
