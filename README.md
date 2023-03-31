# mTLS authentication example

A simple demonstration of using CA-signed certificates to implement
mTLS in Go.

## Running instructions

1. Clone the repository.

2. Start the server in the terminal.

`$ go run . --server=true`

3. Start the client in a different terminal.

`$ go run . --server=false`

## Key re-generation

1. Generate CA private key, use the password "foo".

`openssl genrsa -des3 -out ca.key 2048`

2. Generate the root public key:

`openssl req -x509 -new -nodes -key ca.key -sha256 -days 1825 -out ca.pem`


3. Generate client private key:

`openssl genrsa -out client.key 2048`

4. Generate the client certificate service request.

`openssl req -new -key client.key -out client.csr`

5. Generate the client certificate. Use the CA password "foo".

`openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.crt -days 825 -sha256 -extfile tls.ext`

6. Generate server private key:

`openssl genrsa -out server.key 2048`

7. Generate the server certificate service request.

`openssl req -new -key server.key -out server.csr`

8. Generate the server certificate. Use the CA password "foo".

`openssl req -x509 -new -CA ca.pem -CAkey ca.key -CAcreateserial -key server.key -out server.crt -days 825 -sha256`