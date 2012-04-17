/*
 * ssl_conn.hh
 *
 *  Created on: 25.03.2012
 *      Author: aureliano
 */

#ifndef SSL_CONN_HH_
#define SSL_CONN_HH_


using namespace std;
using boost::asio::ip::tcp;

const bool SSL_DEBUG = false;

enum role {SERVER, CLIENT};
const size_t BUFSIZE = 128;

typedef unsigned char data;


class SSL_CONN{
public:
	SSL_CONN(tcp::socket *socket, enum role _role);
	~SSL_CONN();

	void start();
	void send(void *data, int size);
	data * receive();
private:
	enum role role;
	string str_role;

	SSL_CTX *ctx;
	SSL* conn;
	BIO* bioIn;
	BIO* bioOut;
	BIO* bio_err;

	tcp::socket *socket;

	int do_handshake();
	int snd_data();
	int rcv_data();
	void print_err();
};

// For now, this functions is not integrable because
// SSL_CTX_set_default_passwd_cb needs a function pointer. But
// class functions do not provide static function pointers.
int pem_passwd_cb(char *buf, int size, int rwflag, void *password);


#endif /* SSL_CONN_HH_ */
