# ssltest

Программа для тестирования сертификатов.

Многопоточная, хотя и в 1 поток проверяет сертификаты довольно быстро

Проверяет домены, переданные как через аргумент строки, так и через stdin, на случай если доменов будет много
```
ssltest -d "api.insales.ru"
OK - Good: [api.insales.ru]
```

Резолвит ip и проверяет сертификат на каждом хосте. В оригинале, откуда брал, были какие-то хаки для ipv6 https://github.com/wycore/check-ssl
```
ssltest -d "ietf.com" -debug
2021/03/01 14:56:52 Worker 4 start with domain ietf.com
2021/03/01 14:56:53 ietf.com (104.200.22.130) OK. remainingValidity: 1877h22m5.893788988s
2021/03/01 14:56:53 ietf.com (104.200.23.95) OK. remainingValidity: 1877h22m5.280547167s
2021/03/01 14:56:53 Worker 4 finish with domain ietf.com
2021/03/01 14:56:53 okDomains: [ietf.com]
2021/03/01 14:56:53 warningDomains: []
2021/03/01 14:56:53 criticalDomains: []
OK - Good: [ietf.com]
```

Детектит почти все проблемы, которые есть на badssl.com
```
ssltest -d "expired.badssl.com wrong.host.badssl.com self-signed.badssl.com untrusted-root.badssl.com  null.badssl.com mitm-software.badssl.com mitm.watch sha1-2016.badssl.com"       
Critical - Problems: [mitm.watch null.badssl.com expired.badssl.com self-signed.badssl.com mitm-software.badssl.com sha1-2016.badssl.com wrong.host.badssl.com untrusted-root.badssl.com]
```

Не детектит revoked сертификаты
```
ssltest -d "revoked.badssl.com" -debug
2021/03/01 14:42:47 Worker 6 start with domain revoked.badssl.com
2021/03/01 14:42:48 revoked.badssl.com (104.154.89.105) OK. remainingValidity: 5301h17m11.290908216s
2021/03/01 14:42:48 Worker 6 finish with domain revoked.badssl.com
2021/03/01 14:42:48 okDomains: [revoked.badssl.com]
2021/03/01 14:42:48 warningDomains: []
2021/03/01 14:42:48 criticalDomains: []
OK - Good: [revoked.badssl.com]
```
```
ssltest -d "mozilla-old.badssl.com mozilla-intermediate.badssl.com mozilla-modern.badssl.com no-sct.badssl.com"
OK - Good: [mozilla-modern.badssl.com mozilla-intermediate.badssl.com no-sct.badssl.com mozilla-old.badssl.com]
```

И выдает результат в формате пригодном для nagios
```
echo "github.com" | ssltest
OK - Good: [github.com]

```
Warning, если осталось меньше дней, чем задано параметром -w
```
echo "www.githubstatus.com" | ssltest -w 70
Warning - Problems: [www.githubstatus.com]

```

Critical отдается при проблемах с сертификатом, если домен не резолвится, либо осталось дней меньше, чем задано параметром -с
```
echo "example" | ssltest      
Critical - Problems: [example]

```
