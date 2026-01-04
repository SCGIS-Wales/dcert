set -euo pipefail

rm -rf out demoCA
mkdir -p out demoCA/{certs,crl,newcerts,private}
chmod 700 demoCA/private
: > demoCA/index.txt
echo 1000 > demoCA/serial

# Minimal CA config for local signing
cat > out/openssl-ca.cnf <<'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ./demoCA
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem
default_md        = sha256
policy            = policy_loose
email_in_dn       = no
copy_extensions   = copy
unique_subject    = no
default_days      = 365
x509_extensions   = v3_ca

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
default_md          = sha256
prompt              = no
distinguished_name  = dn

[ dn ]
CN = Demo Root CA

[ v3_ca ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ v3_leaf ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

# 1) Create a root CA key and certificate
openssl genrsa -out demoCA/private/ca.key.pem 2048
openssl req -new -x509 -days 3650 \
  -key demoCA/private/ca.key.pem \
  -out demoCA/certs/ca.cert.pem \
  -config out/openssl-ca.cnf \
  -extensions v3_ca

cp demoCA/certs/ca.cert.pem out/ca.cert.pem
cp demoCA/private/ca.key.pem out/ca.key.pem

# Helper to make a CSR config with SAN
make_req_conf() {
  local cn="$1"
  local san="$2"
  cat > "out/${cn}.req.cnf" <<EOF
[ req ]
default_bits = 2048
default_md = sha256
prompt = no
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = ${cn}

[ req_ext ]
subjectAltName = ${san}
EOF
}

# 2) Create a valid leaf (expires in the future)
make_req_conf "leaf-valid" "DNS:leaf-valid.test,IP:127.0.0.1"
openssl genrsa -out out/leaf-valid.key.pem 2048
openssl req -new -key out/leaf-valid.key.pem -out out/leaf-valid.csr.pem -config out/leaf-valid.req.cnf

openssl ca -batch -config out/openssl-ca.cnf \
  -extensions v3_leaf \
  -in out/leaf-valid.csr.pem \
  -out out/leaf-valid.cert.pem

# 3) Create an expired leaf (end date in the past)
make_req_conf "leaf-expired" "DNS:leaf-expired.test,IP:127.0.0.1"
openssl genrsa -out out/leaf-expired.key.pem 2048
openssl req -new -key out/leaf-expired.key.pem -out out/leaf-expired.csr.pem -config out/leaf-expired.req.cnf

# Pick a window fully in the past. Format is YYMMDDHHMMSSZ
openssl ca -batch -config out/openssl-ca.cnf \
  -extensions v3_leaf \
  -startdate 240101000000Z \
  -enddate   240201000000Z \
  -in out/leaf-expired.csr.pem \
  -out out/leaf-expired.cert.pem

# 4) Build chain bundles ("TLS stack" PEM files)
cat out/leaf-valid.cert.pem out/ca.cert.pem > out/tls-stack-valid-chain.pem
cat out/leaf-expired.cert.pem out/ca.cert.pem > out/tls-stack-expired-chain.pem

# A mixed bundle containing multiple certs (some tools accept this as an input set)
cat out/leaf-valid.cert.pem out/leaf-expired.cert.pem out/ca.cert.pem > out/tls-stack-mixed.pem

echo "Done. Files are in ./out"
