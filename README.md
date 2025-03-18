# doh
dns over https based on cloudflare worker, support EDNS(if upstream support).

### please set environment parameters
PATH: /path

UPSTREAM: https://dns.google/dns-query


### usage
```bash
curl https://www.example.com/path/edns+192.168.110.0?dns=xxxxx

or

curl https://www.example.com/path?dns=xxxxx
```
