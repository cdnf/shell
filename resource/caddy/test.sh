#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# cat t.json
a=$(cat t.json | sed "/\/\/.*$/d")
network_host=a.com

cat << EOF
{
  "apps": {
    "layer4": {
      "servers": {
        "sni": {
          "routes": [
            {
              "match": [
                {
                  "tls": {
                    "sni": [
                      "${network_host}"
                  }
                }
              ],
              "handle": [
                {
                  "handler": "proxy",
                  "upstreams": [
                    {
                      "dial": [
                        "127.0.0.1:${inbound_port}"
                    }
                  ],
                }
              ]
            }
        }
      }
    }
  }
}
EOF