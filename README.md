# Private Access Tokens application

This tool can be used to run any of the Origin, Attester, Issuer, or Client roles in the Private Access Tokens ecosystem. Each role supports the following capabiliies:

- Attester: Implement client attestation and bookkeeping for PAT issuance.
- Issuer: Issue tokens for pre-configured origins from any attester.
- Origin: Challenge clients for access to any resource and return the corresponding resource data in response.
- Client: Perfrom simple HTTP GET requests for select resources, like a simplified version of cURL.

## Localhost tests

One can deploy and run all roles on localhost to test the PAT issuance and redemption protocols end-to-end. This requires creating per-client secrets per-server TLS certificates, configuring /etc/hosts to point to localhost, and then running each service. Instructions for each step follow.

### Creating server certificates

First, install [mkcert](https://github.com/FiloSottile/mkcert). Then, run the following:

```
$ make secrets certs
```

### Configure /etc/hosts

Append the following rules to the /etc/hosts file to ensure that queries for test issuer, origin, and attester all resolve to localhost.

```
127.0.0.1 issuer.example 
127.0.0.1 origin.example 
127.0.0.1 attester.example 
```

### Configuring services

The services must be started in the following order: Issuer, Origin, and Attester. Sample commands for starting each are below.

```
$ ./pat-app issuer --cert issuer.example+3.pem --key issuer.example+3-key.pem --port 4567 --origins origin.example:4568
$ ./pat-app origin --cert origin.example+3.pem --key origin.example+3-key.pem --port 4568 --issuer issuer.example:4567 --name origin.example:4568
$ ./pat-app attester --cert attester.example+3.pem --key attester.example+3-key.pem --port 4569
```

### Running the client

Once each service is running, run the client to fetch a resource from the origin.

```
./pat-app fetch --origin origin.example:4568 --secret `cat client.secret` --attester attester.example:4569 --resource "/index.html"
```
