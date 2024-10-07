rm *.pem

#-nodes turns off the requesting of a pass phrase
# 1. Generate CA's private key and self-signed certificate
openssl req -x509 -newkey rsa:4096 -days 365 -nodes -keyout ca-key.pem -out ca-cert.pem -subj "/C=DE/ST=Bayern/L=Regensburg/O=test/OU=test/CN=test/emailAddress=test"

echo "CA's self-signed certificate"
openssl x509 -in ca-cert.pem -noout -text

# 2.1 Generate web server's private key and certificate signing request (CSR)
openssl req -newkey rsa:4096 -nodes -keyout server-key.pem -out server-req.pem -subj "/C=DE/ST=Bayern/L=Regensburg/O=test/OU=test/CN=test/emailAddress=test"

# 2.2 Generate clients's private key and certificate signing request (CSR)
openssl req -newkey rsa:4096 -nodes -keyout client-key.pem -out client-req.pem -subj "/C=DE/ST=Bayern/L=Regensburg/O=test/OU=test/CN=test/emailAddress=test"

# 3.1 Use CA's private key to sign web server's CSR and get back the signed certificate
openssl x509 -req -in server-req.pem -days 60 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -extfile server-ext.cnf

# 3.2 Use CA's private key to sign clients's CSR and get back the signed certificate
openssl x509 -req -in client-req.pem -days 60 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -extfile server-ext.cnf

echo "Server's signed certificate"
openssl x509 -in server-cert.pem -noout -text

echo "Client's signed certificate"
openssl x509 -in client-cert.pem -noout -text

