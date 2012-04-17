/*
 * ssl_conn.cc
 *
 *  Created on: 25.03.2012
 *      Author: aureliano
 */

#include <iostream>
#include <unistd.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <boost/asio.hpp>
#include <string>

#include "ssl_conn.hh"


SSL_CONN::SSL_CONN(tcp::socket *_socket, enum role _role) {
	if (_role != SERVER && _role != CLIENT)
		exit(EXIT_FAILURE);

	socket = _socket;
	role = _role;
	str_role = (role==CLIENT) ? "CLIENT":"SERVER";

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	SSL_library_init();

	// Check for "openssl 0.9.8o release" when using SSL_CTX_new
	#if OPENSSL_VERSION_NUMBER == 0x0009080ff
		SSL_METHOD *meth;
	#else
		const SSL_METHOD *meth;
	#endif

    meth = (role==CLIENT)? TLSv1_client_method() : TLSv1_server_method();
	ctx = SSL_CTX_new(meth);
	if (!ctx) print_err();

	char password[] = "test";
	SSL_CTX_set_default_passwd_cb(ctx, &pem_passwd_cb); //passphrase for both the same
	SSL_CTX_set_default_passwd_cb_userdata(ctx, password);

	// used following cmd to get list of correct cipher lists
	// $ openssl ciphers -tls1 "aRSA:AES:-kEDH:-ECDH:-SRP:-PSK:-NULL:-EXP:-MD5:-DES"
	if(!SSL_CTX_set_cipher_list(ctx, "RC4-SHA"))
		print_err();

	if(role==CLIENT) {
		SSL_CTX_use_certificate_file(ctx, "../certs/client.pem", SSL_FILETYPE_PEM);
		SSL_CTX_use_RSAPrivateKey_file(ctx, "../certs/key.pem", SSL_FILETYPE_PEM);
		if (!SSL_CTX_load_verify_locations(ctx,"../certs/demoCA/cacert.pem",NULL))
			print_err();

	} else if(role==SERVER) {
		SSL_CTX_use_certificate_file(ctx, "../certs/demoCA/cacert.pem", SSL_FILETYPE_PEM);
		SSL_CTX_use_RSAPrivateKey_file(ctx, "../certs/demoCA/private/cakey.pem", SSL_FILETYPE_PEM);
	}

	if(!SSL_CTX_check_private_key(ctx)) {
		if (SSL_DEBUG) cout << str_role << ": Dooong. Private key check failed!" << endl;
		print_err();
	}

	conn = SSL_new(ctx);
	if (!conn) print_err();

	bioIn = BIO_new(BIO_s_mem());
	if (!bioIn) print_err();

	bioOut = BIO_new(BIO_s_mem());
	if (!bioOut) print_err();

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	if (!bio_err) print_err();
	SSL_set_bio(conn,bioIn,bioOut); // connect the ssl-object to the bios
}

SSL_CONN::~SSL_CONN() {
	SSL_shutdown(conn);
	ERR_free_strings();
	SSL_CTX_free(ctx);
	SSL_free(conn); // frees also BIOs, cipher lists, SSL_SESSION
	BIO_free(bio_err);
}


void SSL_CONN::start() {
	// Must be called before first SSL_read or SSL_write
	(role==CLIENT)? SSL_set_connect_state(conn) : SSL_set_accept_state(conn);

	//do_handshake();
}

// non-blocking
void SSL_CONN::send(void *data, int size) {
	if(size<=0){
		BIO_puts(bio_err, "SSL_write with bufsize=0 is undefined.");
		print_err();
		return;
	}

	bool handshaked = false;

	// re-negotiation is always possible, so SSL_read must be repeated
	for(int tries = 0; tries < 2; tries++) {

		int ret = SSL_write(conn,data,size);
		if(ret>0) snd_data(); // read from membuf and put into socket

		if(ret>0) {
			return;
		} else if (!handshaked) {
			do_handshake();
			handshaked = true;
		}
	}
}

/*
 * On SSL_CONN::receive(): What if multiple records were sent? How do I handle this
 * in this function?
 */

// non-blocking
data_t *SSL_CONN::receive() {
	bool handshaked = false;

	rcv_data(); // read from socket to feed SSL_read

	// It's okay to try several times. Reasons are re-negotiation; SSL_read
	// uncomplete; SSL_pending returns 0.
	for(int tries = 0; tries < 3; tries++) {
		/* Check for application data.
		 * No matter if size is 0, it's possibly more important
		 * to go on to SSL_read and do_handshake. Just a guess :)
		 * In case of size>0 SSL proccessed a full record which
		 * is ready to pick.
		 */
		int size = SSL_pending(conn);
		data_t *data = (data_t *)malloc(size);
		if(!data) {
			BIO_puts(bio_err, "SSL_CONN::receive no memory allocated.");
			print_err();
			return NULL;
		}

		int ret = SSL_read(conn,data,size); // data received in records of max 16kB

		// if SSL_read was successful receiving full records, then ret > 0
		if(ret > 0) {
			return data;
		} else if (!handshaked) {
			do_handshake();
			handshaked = true;
		}

		// if no app data retrievable, free memory
		if(data) free(data);
	}
	return NULL;
}


/*
 * *******************************************************
 *               private functions
 * *******************************************************
 */
int SSL_CONN::do_handshake() {

	if (SSL_DEBUG) cout << str_role << ": Handshake needed? ..." << endl;

	for(;;) {
		int temp = SSL_do_handshake(conn);
		snd_data(); // push data manually as we are dealing with membufs

		// take action based on SSL errors
		switch (SSL_get_error(conn, temp)) {
		case SSL_ERROR_NONE:
			if (SSL_DEBUG) cout << str_role << ": handshake complete" << endl;
			return 1;
			break;
		case SSL_ERROR_WANT_READ:
			rcv_data();
			break;
		case SSL_ERROR_WANT_WRITE:
			snd_data();
			break;
		case SSL_ERROR_SSL:
		case SSL_ERROR_SYSCALL:
		case SSL_ERROR_ZERO_RETURN:
		default:
			print_err();
			return 0;
		}
	}

	return 0;
}


int SSL_CONN::rcv_data() {
	int len_rcv = 0;

	if (SSL_DEBUG) cout << str_role << ": Check read buffer ... " << endl;

	unsigned char buf[BUFSIZE];
	while(socket->available()>0) {

		// blocking socket
		int len = socket->receive(boost::asio::buffer(buf, sizeof(buf)));
		BIO_write(bioIn,buf,len);
		len_rcv += len;

		if (SSL_DEBUG) cout << str_role << ": socket rcv " << len_rcv << " bytes" << endl;
	}

	return len_rcv;
}

int SSL_CONN::snd_data() {
	int len_sent = 0;

	if (SSL_DEBUG) cout << str_role << ": Check send buffer ... " << endl;

	unsigned char buf[BUFSIZE];
	while(BIO_ctrl_pending(bioOut) > 0) {
		int len_pending = BIO_read(bioOut,buf,sizeof(buf));

		// todo: Prüfung, ob socket->send die Daten wirklich gesendet hat,
		// if len_pending != len_sent; then send again
		len_sent += socket->send(boost::asio::buffer(buf, len_pending));

		// todo: this output is not precisely formulated, should be socket sent len
		if (SSL_DEBUG) cout << str_role << ": socket sent " << len_pending << endl;
	}

	return len_sent;
}

void SSL_CONN::print_err() {
	ERR_print_errors(bio_err);
	cerr << str_role << ": " << ERR_error_string(ERR_get_error(), NULL) << endl;
	// exit(EXIT_FAILURE);
}


/*
 * *******************************************************
 *               extra functions
 * *******************************************************
 */
int pem_passwd_cb(char *buf, int size, int rwflag, void *password) {
	strncpy(buf, (char *)(password), size);
	buf[size - 1] = '\0';
	return(strlen(buf));
}



