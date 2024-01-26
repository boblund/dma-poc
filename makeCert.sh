echo 'Making X509 certificate for' ${1}
openssl req -new -x509 -key ${1}-privateKey.pem -out ${1}-cert.pem -days 360 -subj "/C=US/ST=CO/L=Denver/CN=${1}/O=Occamns Solitions LLC"
