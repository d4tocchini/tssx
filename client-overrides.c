#include "tssx/overrides.h"

void connect(int client_socket, const sockaddr* address, size_t length) {
	Connection connection;
	int return_code;

	real_connect(client_socket, address, length);

	// clang-format off
	return_code = real_read(
		client_socket,
		&connection.segment_id,
		sizeof connection.segment_id
	);
	// clang-format on

	if (return_code == -1) {
		throw("Error receiving segment ID on client side");
	}

	setup_connection(&connection, &DEFAULT_OPTIONS);

	ht_insert(&connection_map, client_socket, &connection);
}

ssize_t read(int socket_fd, void* destination, size_t requested_bytes) {
	// clang-format off
	return connection_read(
		socket_fd,
		destination,
		requested_bytes,
		SERVER_BUFFER
	);
	// clang-format on
}

ssize_t write(int socket_fd, void* source, size_t requested_bytes) {
	// clang-format off
	return connection_write(
		socket_fd,
		source,
		requested_bytes,
		CLIENT_BUFFER
	);
	// clang-format on
}

int close(int socket_fd) {
	Connection* connection;

	connection = ht_get(&connection_map, socket_fd);
	disconnect(connection);

	return real_close(socket_fd);
}
