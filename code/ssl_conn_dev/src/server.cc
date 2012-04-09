/*
 * server.cc
 *
 *  Created on: 14.03.2012
 *      Author: aureliano
 */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <boost/asio.hpp>
#include <iostream>
#include <string>

#include "server.hh"
#include "ssl_conn.hh"

int main() {
	Server server = Server();
	server.start();
	return 0;
}


Server::Server() {
	cout << "Server: Starting server" << endl;
}

Server::~Server() {

}

void Server::start() {

	try {
		boost::asio::io_service io_service;
		// listen on port 50012
		tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), 50012));

		tcp::socket socket(io_service);
		boost::system::error_code ec;
		acceptor.accept(socket, ec);
		if(!ec)
			cout << "Server: connected" << endl;

		SSL_CONN ssl_conn(&socket, SERVER);
		ssl_conn.start();

		// Lets start communicating over a secure connection
		// ssl_conn.send(&buf);
		// ssl_conn.receive(&buf);

		cout << "Server: Closing" << endl;
		socket.close();


	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}

}
