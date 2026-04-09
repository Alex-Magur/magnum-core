# OPA Policy — Network Egress Control
# ADR Б3.1: sandbox egress controlled by OPA
package forge.sandbox.egress

default allow = false

allow {
    input.method == "GET"
    input.host == "api.github.com"
}

allow {
    input.method == "POST"
    input.host == "api.github.com"
}

allow {
    input.method == "PATCH"
    input.host == "api.github.com"
}
