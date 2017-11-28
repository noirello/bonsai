openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/C=XX/CN=bonsai.test"
openssl x509 -req -days 500 -in server.csr -CA ./tests/testenv/certs/cacert.pem -CAkey ./tests/testenv/certs/cacert.key -CAcreateserial -out server.pem -sha256