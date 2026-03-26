ui = true

listener "tcp" {
    address = "0.0.0.0:8200"
    tls_disable = true
    telemetry {
        disable_hostname = true
    }
}

storage "file" {
    path = "/vault/data"
}

api_addr = "http://0.0.0.0:8200"

cluster_addr = "http://0.0.0.0:8201"

disable_mlock = true

log_level = "info"

telemetry {
    prometheus_retention_time = "30s"
    disable_hostname = true
}

default_lease_ttl = "1h"
max_lease_ttl = "24h"

seal "transit" {
    disable = true
}
