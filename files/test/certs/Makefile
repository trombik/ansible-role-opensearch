ALL_TARGETS=	\
	root-ca.pem \
	admin-key.pem \
	admin.pem \
	node-key.pem \
	node.pem

root-ca-key.pem:
	echo "===> ${.TARGET}"
	openssl genrsa -out ${.TARGET} 2048

root-ca.pem: root-ca-key.pem
	echo "===> ${.TARGET}"
	openssl req -new -x509 -sha256 -key root-ca-key.pem -out ${.TARGET}

admin-key-temp.pem:
	echo "===> ${.TARGET}"
	openssl genrsa -out ${.TARGET} 2048

admin-key.pem:	admin-key-temp.pem
	echo "===> ${.TARGET}"
	openssl pkcs8 -inform PEM -outform PEM -in admin-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out ${.TARGET}

admin.csr:	admin-key.pem
	echo "===> ${.TARGET}"
	openssl req -new -key admin-key.pem -out admin.csr

admin.pem:	root-ca.pem root-ca-key.pem admin.csr
	echo "===> ${.TARGET}"
	openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out ${.TARGET}

node-key-temp.pem:
	echo "===> ${.TARGET}"
	openssl genrsa -out ${.TARGET} 2048

node-key.pem:	node-key-temp.pem
	echo "===> ${.TARGET}"
	openssl pkcs8 -inform PEM -outform PEM -in node-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out ${.TARGET}

node.csr: node-key.pem
	echo "===> ${.TARGET}"
	openssl req -new -key node-key.pem -out ${.TARGET}

node.pem:	node.csr root-ca.pem root-ca-key.pem
	echo "===> ${.TARGET}"
	openssl x509 -req -in node.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out ${.TARGET}

all:	${ALL_TARGETS}

clean:
	rm -f *.pem *.csr *.srl
