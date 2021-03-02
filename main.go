package main

import (
    "bufio"
    "crypto/tls"
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "os"
    "strings"
    "time"
)

const (
    OK       = iota
    Warning  = iota
    Critical = iota
    Unknown  = iota
)

type CheckResult struct {
    domain string
    status int
}


func main() {
    var warningFlag, criticalFlag, workersPool uint
    var hosts string
    var warningValidity, criticalValidity time.Duration
    var debug bool
    flag.StringVar(&hosts, "d", "", "the domain names of the hosts to check, if not provided then read from stdin")
    flag.UintVar(&warningFlag, "w", 25, "warning validity in days")
    flag.UintVar(&criticalFlag, "c", 14, "critical validity in days")
    flag.UintVar(&workersPool, "p", 10, "count of workers")
    flag.BoolVar(&debug, "debug", false, "print debug information")
    flag.Parse()
    warningValidity = time.Duration(warningFlag) * 24 * time.Hour
    criticalValidity = time.Duration(criticalFlag) * 24 * time.Hour

    if !debug {
        // Если debug отключен то выводим логи в /dev/null
        // может правильнее было бы их не выводить, но тогда пришлось бы заморачиваться
        log.SetOutput(ioutil.Discard)
    }
    
    var domains = []string{}
    if hosts == "" {
        // Чтение списка доменов из stdin
        hosts, _ = bufio.NewReader(os.Stdin).ReadString('\n')
    }
    domains = strings.Fields(hosts)
    numDomains := len(domains)
    
    // Создание пула воркеров
    // Взято из https://gobyexample.com/worker-pools
    jobs := make(chan string, numDomains)
    results := make(chan CheckResult, numDomains)
    for w := 1; w <= int(workersPool); w++ {
        go worker(w, jobs, results, warningValidity, criticalValidity)
    }
    for _, domain := range domains {
        jobs <- domain
    }
    close(jobs)

    var okDomains []string
    var warningDomains []string
    var criticalDomains []string
    for a := 1; a <= numDomains; a++ {
        result := <-results
        switch result.status {
            case OK:
                okDomains = append(okDomains, result.domain)
            case Warning:
                warningDomains = append(warningDomains, result.domain)
            case Critical:
                criticalDomains = append(criticalDomains, result.domain)
        }
    }
    log.Printf("okDomains: %s", okDomains)
    log.Printf("warningDomains: %s", warningDomains)
    log.Printf("criticalDomains: %s", criticalDomains)

    // Выводим результат в формате удобном для Nagios
    if len(criticalDomains)>0 {
        fmt.Printf("Critical - Problems: %s\n", criticalDomains)
        os.Exit(Critical)
    } else if len(warningDomains)>0 {
        fmt.Printf("Warning - Problems: %s\n", warningDomains)
        os.Exit(Warning)
    } else if len(okDomains)>0 {
        fmt.Printf("OK - All domains SSL good\n")
        os.Exit(OK)
    }  
}

// Во многом взято из https://github.com/wycore/check-ssl/blob/master/check-ssl.go
func worker(id int, jobs <-chan string, results chan<- CheckResult, warningValidity time.Duration, criticalValidity time.Duration) {
    for domain := range jobs {
        var certificateStatus = OK
        log.Printf("Worker %d start with domain %s", id, domain)
        // Резолвинг ip
        ips, err := net.LookupIP(domain)
        if err != nil {
            certificateStatus = Critical
            log.Printf("%s set Critical. LookupIP: %s", domain, err)
        }
        // Проверяем каждый ip на который резолвится домен
        for _, ip := range ips {
            const connectionTimeout = 30*time.Second
            dialer := net.Dialer{Timeout: connectionTimeout, Deadline: time.Now().Add(connectionTimeout + 5*time.Second)}
            connection, err := tls.DialWithDialer(&dialer, "tcp", fmt.Sprintf("[%s]:443", ip), &tls.Config{ServerName: domain})
            if err != nil {
                certificateStatus = Critical
                log.Printf("%s (%s) set Critical. DialWithDialer: %s", domain, ip, err)
                continue
            }
            checkedCerts := make(map[string]struct{})
            for _, chain := range connection.ConnectionState().VerifiedChains {
                for _, cert := range chain {
                    if _, checked := checkedCerts[string(cert.Signature)]; checked {
                        continue
                    }
                    checkedCerts[string(cert.Signature)] = struct{}{}
                    if cert.IsCA {
                        // Не проверяем Certificate Authority, если корневые сертификаты недействительны
                        // то ошибка будет уже на DialWithDialer 
                        continue
                    }
                    // Вычисляем как долго еще действителен ssl
                    remainingValidity := cert.NotAfter.Sub(time.Now())
                    if remainingValidity < criticalValidity {
                        certificateStatus = Critical
                        log.Printf("%s (%s) set Critical. remainingValidity: %s < %s", domain, ip, remainingValidity, criticalValidity)
                    } else if remainingValidity < warningValidity && certificateStatus != Critical {
                        certificateStatus = Warning
                        log.Printf("%s (%s) set Warning. remainingValidity: %s < %s", domain, ip, remainingValidity, warningValidity)
                    } else {
                        log.Printf("%s (%s) OK. remainingValidity: %s", domain, ip, remainingValidity)
                    }
                }
            }
            connection.Close()
        }

        results <- CheckResult{domain: domain, status: certificateStatus}
        log.Printf("Worker %d finish with domain %s", id, domain)
    }
}
