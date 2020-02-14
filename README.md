# james

james is a utility to be used as a `AuthorizedKeysCommand` for OpenSSH.

It is designed to fetch a list of authorized keys from a remote HTTPS
server.

## Installation

Grab a binary from a releases or compile from source. Nothing magical.

## Running

james should be added to `sshd_config` as `AuthorizedKeysCommand`.

The following tokens from OpenSSH are supported:

| Token | Flag | Description                                              | Form key    |
|-------|------|----------------------------------------------------------|-------------|
| %f    | -f   | The fingerprint of the key or certificate                | fingerprint |
| %h    | -h   | The home directory of the user                           | home        |
| %k    | -k   | The base64-encoded key or certificate for authentication | key         |
| %t    | -t   | The key or certificate type                              | keytype     |
| %U    | -U   | The numeric user ID of the target user                   | uid         |
| %u    | -u   | The username                                             | username    |

### Additional flags

| Flag              | Default                            | Description                           |
|-------------------|------------------------------------|---------------------------------------|
| --url             | https://github.com/[username].keys | URL to retrieve keys from             |
| --hostname        | auto-detected                      | The local hostname                    |
| --port            | 22                                 | TCP port of the local SSH server      |
| --use-syslog      | true                               | Log to syslog                         |
| --guess-remote-ip | true                               | Try to guess remote IP. Requires root |

## Implement the server-side

james will issue a `GET` request containing the following parameters.
Most optional.

| Name             | Description                                                      |
|------------------|------------------------------------------------------------------|
| service_hostname | Will try to guess or use hostname provided from --hostname       |
| service_port *   | Will assume standard port if none provided using --port          |
| remote_ip *      | Will only be provided if --guess-remote-ip=false is not provided |
| fingerprint *    | -f flag                                                          |
| home *           | -h flag                                                          |
| key *            | -k flag                                                          |
| keytype *        | -t flag                                                          |
| uid *            | -U flag                                                          |
| username *       | -u flag                                                          |

*: Optional

The complete response from the server will be written to standard
output. Server failures (HTTP response code 5xx) will be retried
five times with exponential backoff before giving up.

## Examples

### Allowing all keys from the Github user nat

```
AuthorizedKeysCommand /sbin/james --url https://github.com/nat.keys --guess-remote-ip=false
AuthorizedKeysCommandUser nobody
```

### Retrieving keys from a Github user named as the user trying to authenticate

```
AuthorizedKeysCommand /sbin/james --guess-remote-ip=false
AuthorizedKeysCommandUser nobody
```

### Contact something intelligent getting a list of keys

```
AuthorizedKeysCommand /sbin/james --url https://ssh-gatekeeper.example.com -f %f -u %u
AuthorizedKeysCommandUser root # required to guess remote IP
```

## Known limitations

IPv6 is currently not supported.
