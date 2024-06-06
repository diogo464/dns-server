# dns-server

a dns recursor with caching. implements most of rfc1035 and rfc3596.

## usage

```bash
go run .    # start the server listening for UDP requests on port 2053.
```

```bash
$ dig +noedns +retry=0 -4 @127.0.0.1 -p 2053 github.com

; <<>> DiG 9.18.26 <<>> +noedns +retry -4 @127.0.0.1 -p 2053 github.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 516
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;github.com.                    IN      A

;; ANSWER SECTION:
github.com.             54      IN      A       140.82.121.4

;; Query time: 0 msec
;; SERVER: 127.0.0.1#2053(127.0.0.1) (UDP)
;; WHEN: Thu Jun 06 17:11:36 WEST 2024
;; MSG SIZE  rcvd: 54
```

## references

- https://datatracker.ietf.org/doc/html/rfc1034
- https://datatracker.ietf.org/doc/html/rfc1035
- https://datatracker.ietf.org/doc/html/rfc3596
- https://blog.cloudflare.com
