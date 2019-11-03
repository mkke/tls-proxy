TLS-Proxy
=========

`tls-proxy` is meant to be used as a seemingly transparent proxy for
TLS connections (that provide server name indication).

For example, you have a private network environment where you access
a TLS server (say, a private docker registry as docker.inside.example.com:443).
Now you want to access that server from outside, e.g. via a SSH tunnel,
but don't want to make changes to your client configuration.

To do that, you need to:

* redirect access to port 443 into the tunnel
* resolve the hostname docker.inside.example.com to the address of the local tunnel end
* if you want to access multiple hosts with the same target port: select different target tunnels by hostname

`tls-proxy` makes that easier by:

* providing a TLS proxy that snoops the TLS handshake and selects the target according to the indicated server name
* providing a DNS server that returns it's own IP address for requests for the hostnames it proxies
* just in case providing a HTTP proxy that selects the target according to the host header

### Basic example
A configuration for our docker registry example could be:

``` yaml
# tls-proxy.yaml
dns:
  listen: 127.0.0.1:53
  nameserver:
    - 1.1.1.1
tls:
  - match-host: docker.inside.example.com
    match-port: 443
    target-host: 127.0.0.1
    target-port: 8443
```

We also have to update DNS resolving to use `tls-proxy`'s DNS server:

```
# resolv.conf
search outside.example.com
nameserver 127.0.0.1
```

And we have to actually open the tunnel:

``` bash
ssh -N -o 'ExitOnForwardFailure=yes' -L 8443:docker.inside.example.com:443 jumphost.example.com
```

### SSH Dynamic Forwarding
Alternatively, `tls-proxy` can use SSH dynamic forwarding with a SOCKS5 client.
Enable dynamic forwarding in SSH, e.g. with:

``` bash
ssh -N -D '127.0.0.1:2222' jumphost.example.com
```

The add the SOCKS5 proxy host to `tls-proxy`'s config:
``` yaml
# tls-proxy.yaml
dns:
  listen: 127.0.0.1:53
  nameserver:
    - 1.1.1.1
tls:
  - match-host: docker.inside.example.com
    match-port: 443
    target-host: docker.inside.example.com
    proxy: 127.0.0.1:2222
```

`target-host` can be anything the socks server can resolve.
If `target-port` is not specified, `match-port` is used as fall-back.

### pfSense
In case you use a system like pfSense, `tls-proxy` can be used by a whole LAN:

* Create a new IP Alias in Firewall -> Virtual IPs (e.g. 192.168.0.2), `tls-proxy` will then listen on that address on all configured ports
* Add a Domain Override in Services -> DNS Resolver -> General Settings for inside.example.com and set 192.168.0.2@15353 as upstream nameserver
* Run `tls-proxy` on the router (e.g. with the shellcmd package with Command `/root/tls-proxy -c /root/tls-proxy.yaml --daemon --log=/var/log/tls-proxy.log`) and listen on 192.168.0.2:

``` yaml
# /root/tls-proxy.yaml
host-address: 192.168.0.2
dns:
  listen: 192.168.0.2:15353
[...]
```
