echo 'Making X509 certificate for' ${1}
openssl req -new -x509 -key keys/${1}-privateKey.pem -out keys/${1}-cert.pem -days 360 -subj "/C=US/ST=CO/L=Denver/CN=${1}/O=${2}"
