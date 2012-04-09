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

			// start ssl communication
			int tries = 5, test, len;
			while (0 < tries--) {

				if ((len = ssl_conn.receive(&test, sizeof(int))) > 0) {

					cout << "Server: SSL: Received " << len << " bytes: " << test << endl;
					tries = 5; // reset tries
				}
				sleep(1);
			}

			cout << "Server: Closing" << endl;
			socket.close();
		}




	} catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}
