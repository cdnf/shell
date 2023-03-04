function FindProxyForURL(url, host) {
    url = url.toLowerCase();
    if (
        shExpMatch(url, "*ip138.com*") ||
        shExpMatch(url, "*facebook.com*") ||
        shExpMatch(url, "*googlecode.com*") ||
        shExpMatch(url, "*twitter.com*") ||
        shExpMatch(url, "*youtube.com*") ||
        shExpMatch(url, "*appspot.com*") ||
        shExpMatch(url, "*.google.com*")
    ) {
        return "SOCKS 127.0.0.1:2022";
    } else {
        return "DIRECT";
    }
}


function FindProxyForURL(url, host)
{
    var ip = dnsResolve(host);
    if(isInNet(ip, "10.0.0.0", "255.0.0.0") ||
        isInNet(ip, "172.16.0.0", "255.240.0.0") ||
        isInNet(ip, "192.168.0.0", "255.255.0.0"))
        return "DIRECT";
    return "SOCKS 127.0.0.1:2022";
}
