/*
 * client.cc
 *
 *  Created on: 14.03.2012
 *      Author: aureliano
 */

#include <iostream>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "client.hh"
#include "ssl_conn.hh"


int main() {
	Client client = Client();
	client.connect();
	return 0;
}


Client::Client() {
	cout << "Client: Starting client" << endl;

}

Client::~Client() {
	// destructor
}

void Client::connect() {


	try {
		boost::asio::io_service io_service;
		tcp::socket socket(io_service);
		tcp::endpoint _server(boost::asio::ip::address_v4::from_string("127.0.0.1"),50012);

		// Try to connect until server is up and ready to serve
		for(;;) {
			boost::system::error_code ec;
			socket.connect(_server,ec);
			if (!ec) {
				cout << "Client: connected" << endl;
				break;
			}
		}

		SSL_CONN ssl_conn(&socket, CLIENT);
		ssl_conn.start();

		// Lets start communicating over a secure connection
		// ssl_conn.send(&buf);
		// ssl_conn.receive(&buf);

		cout << "Client: Closing" << endl;

		socket.close();


	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}

}



