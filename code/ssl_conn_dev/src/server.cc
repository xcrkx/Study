/*
 * server.cc
 *
 *  Created on: 14.03.2012
 *      Author: aureliano
 */
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <boost/asio.hpp>
#include <iostream>
#include <string>

#include "ssl_conn.hh"

int main() {

	cout << "Server: started" << endl;

	try {
		boost::system::error_code ec;
		boost::asio::io_service io_service;
		tcp::acceptor acceptor(io_service, tcp::endpoint(tcp::v4(), 50012));

		tcp::socket socket(io_service);

		for(;;) {
			cout << "Server: Ready to accept new connection" << endl;
			acceptor.accept(socket, ec);

			if(!ec)
				cout << "Server: connected" << endl;

			SSL_CONN ssl_conn(&socket, SERVER);
			ssl_conn.start();

			// benchmarking
			if (true) {
				int attempts = 3;
				int tries = attempts;

				// Benchmark-Test
				while(tries > 0) {

					char test[256];
					int len = 256;

					if ((len = ssl_conn.receive(&test, len)) > 0) {
						string test_string;
						test_string = test;
						cout << "Server: SSL: Received " << len << " bytes: " << test_string.c_str() << endl;
						tries = attempts; // reset tries
					}

					sleep(1); tries--;
				}
			}

			cout << "Server: Closing" << endl;
			socket.close();
		}




	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}
