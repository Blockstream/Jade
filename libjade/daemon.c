#define _XOPEN_SOURCE 600

#include "libjade.h"

#include <arpa/inet.h>
#include <errno.h>
#include <esp_log.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static int master_fd = -1;

#define BUFFER_SIZE 1024
#define UNIX_PATH_MAX sizeof(((struct sockaddr_un*)0)->sun_path)

static bool set_nonblocking(int fd, const char* context)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        fprintf(stderr, "fcntl(F_GETFL) failed for %s: %s\n", context, strerror(errno));
        return false;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        fprintf(stderr, "fcntl(F_SETFL O_NONBLOCK) failed for %s: %s\n", context, strerror(errno));
        return false;
    }
    return true;
}

static void serial_init(const char* serial_link_path)
{
    char* slave_name;

    master_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (master_fd < 0) {
        perror("posix_openpt");
        exit(EXIT_FAILURE);
    }

    if (grantpt(master_fd) < 0) {
        perror("grantpt");
        close(master_fd);
        exit(EXIT_FAILURE);
    }

    if (unlockpt(master_fd) < 0) {
        perror("unlockpt");
        close(master_fd);
        exit(EXIT_FAILURE);
    }

    slave_name = ptsname(master_fd);
    if (slave_name == NULL) {
        perror("ptsname");
        close(master_fd);
        exit(EXIT_FAILURE);
    }

    if (!set_nonblocking(master_fd, "serial master")) {
        close(master_fd);
        exit(EXIT_FAILURE);
    }

    printf("Virtual serial port: %s\n", slave_name);

    if (serial_link_path) {
        unlink(serial_link_path);
        if (symlink(slave_name, serial_link_path) < 0) {
            fprintf(stderr, "Warning: failed to create symlink at %s -> %s: %s\n", serial_link_path, slave_name,
                strerror(errno));
        } else {
            printf("Created symlink: %s -> %s\n", serial_link_path, slave_name);
        }
    }
}

static bool write_all(int fd, const uint8_t* buffer, size_t size)
{
    size_t written = 0;
    while (written < size) {
        ssize_t result = write(fd, buffer + written, size - written);
        if (result < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                fprintf(stderr, "Warning: write would block, data might be delayed or lost.\n");
                return false;
            } else {
                perror("write failed");
                return false;
            }
        } else if (result == 0) {
            fprintf(stderr, "Warning: write returned 0\n");
            return false;
        }
        written += result;
    }
    return true;
}

static bool handle_jade_to_client(int client_fd, const char* client_info)
{
    size_t jade_size = 0;
    uint8_t* jade_data = libjade_receive(0, &jade_size);

    if (jade_data != NULL) {
        if (jade_size > 0) {
            if (!write_all(client_fd, jade_data, jade_size)) {
                fprintf(
                    stderr, "WARNING: write_all to %s failed (errno: %d - %s).\n", client_info, errno, strerror(errno));

                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    fprintf(stderr, "ERROR: Fatal write error to %s. Disconnecting.\n", client_info);
                    libjade_release(jade_data);
                    return false;
                } else {
                    fprintf(stderr, "WARNING: Data for %s might be lost due to write block.\n", client_info);
                }
            }
        }
        libjade_release(jade_data);
    }
    return true;
}

static void handle_client(int client_fd, const char* client_info)
{
    printf("Connection accepted from %s (fd: %d)\n", client_info, client_fd);

    if (!set_nonblocking(client_fd, client_info)) {
        close(client_fd);
        return;
    }

    bool client_connected = true;
    uint8_t buffer[BUFFER_SIZE];
    fd_set readfds;
    struct timeval timeout;

    while (client_connected) {
        FD_ZERO(&readfds);
        FD_SET(client_fd, &readfds);

        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;

        int select_result = select(client_fd + 1, &readfds, NULL, NULL, &timeout);

        if (select_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "select failed for %s: %s\n", client_info, strerror(errno));
            client_connected = false;
            break;
        }

        if (select_result > 0 && FD_ISSET(client_fd, &readfds)) {
            ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE);
            if (bytes_read < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    /* no data */
                } else if (errno == ECONNRESET) {
                    fprintf(stderr, "Connection reset by peer (%s).\n", client_info);
                    client_connected = false;
                } else {
                    fprintf(stderr, "read from %s failed: %s\n", client_info, strerror(errno));
                    client_connected = false;
                }
            } else if (bytes_read == 0) {
                printf("Connection closed by peer (%s, EOF).\n", client_info);
                client_connected = false;
            } else {
                if (!libjade_send(buffer, bytes_read)) {
                    fprintf(stderr, "ERROR: libjade_send failed! Dropping connection to %s.\n", client_info);
                    client_connected = false;
                }
            }
        }

        if (client_connected) {
            client_connected = handle_jade_to_client(client_fd, client_info);
        }
    }

    printf("Connection handler finished for %s (fd: %d).\n", client_info, client_fd);
    close(client_fd);
}

static void serial_bridge(void)
{
    printf("libjade serial daemon started, available via %s\n", ptsname(master_fd));
    uint8_t serial_buffer[BUFFER_SIZE];
    fd_set readfds;
    struct timeval timeout;

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(master_fd, &readfds);

        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;

        int select_result = select(master_fd + 1, &readfds, NULL, NULL, &timeout);

        if (select_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select failed");
            break;
        }

        if (select_result > 0 && FD_ISSET(master_fd, &readfds)) {
            ssize_t bytes_read = read(master_fd, serial_buffer, BUFFER_SIZE);

            if (bytes_read < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EIO) {
                    perror("read from serial failed");
                    break;
                }
            } else if (bytes_read == 0) {
                printf("Serial port connection closed/EOF.\n");
            } else {
                if (!libjade_send(serial_buffer, bytes_read)) {
                    fprintf(stderr, "Warning: libjade_send failed (buffer full?)\n");
                }
            }
        }

        handle_jade_to_client(master_fd, "serial port");
    }
    close(master_fd);
}

static void tcp_bridge(int port)
{
    printf("-> TCP mode enabled on port %d.\n", port);

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket creation failed (tcp)");
        return;
    }

    int optval = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind failed (tcp)");
        close(listen_fd);
        return;
    }

    if (listen(listen_fd, 1) < 0) {
        perror("listen failed (tcp)");
        close(listen_fd);
        return;
    }

    printf("TCP bridge listening on port %d\n", port);

    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);

        int client_fd = accept(listen_fd, (struct sockaddr*)&cli_addr, &clilen);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept failed (tcp)");
            sleep(1);
            continue;
        }

        char client_info[64];
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, client_ip, sizeof(client_ip));
        snprintf(client_info, sizeof(client_info), "%s:%d", client_ip, ntohs(cli_addr.sin_port));

        handle_client(client_fd, client_info);
    }

    printf("Closing listening socket (fd: %d).\n", listen_fd);
    close(listen_fd);
    printf("TCP bridge exiting.\n");
}

static void socket_bridge(const char* socket_path)
{
    printf("-> Socket mode enabled on %s.\n", socket_path);

    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket creation failed (unix socket)");
        return;
    }

    struct sockaddr_un serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strncpy(serv_addr.sun_path, socket_path, sizeof(serv_addr.sun_path) - 1);

    unlink(socket_path);

    if (bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind failed (unix socket)");
        close(listen_fd);
        return;
    }

    if (listen(listen_fd, 1) < 0) {
        perror("listen failed (unix socket)");
        close(listen_fd);
        return;
    }

    printf("Socket bridge listening on %s\n", socket_path);

    while (1) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept failed (unix socket)");
            sleep(1);
            continue;
        }

        char client_info[64];
        snprintf(client_info, sizeof(client_info), "unix socket client");

        handle_client(client_fd, client_info);
    }

    printf("Closing listening socket (fd: %d).\n", listen_fd);
    close(listen_fd);
    unlink(socket_path);
    printf("Socket bridge exiting.\n");
}

static int usage(const char* cmd, const char* error)
{
    fprintf(stderr, "Error: %s.\n", error);
    fprintf(stderr, "Usage: %s [--serialport [SYMLINK_PATH] | --tcp PORT | --socketfile PATH]\n", cmd);
    return EXIT_FAILURE;
}

int main(int argc, char* argv[])
{
    int serial_mode = 0;
    char* serial_link_path = NULL;
    int tcp_mode = 0;
    int tcp_port = 0;
    int socket_mode = 0;
    char* socket_path = NULL;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--serialport") == 0) {
            serial_mode = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                serial_link_path = argv[++i];
            }
        } else if (strcmp(argv[i], "--tcp") == 0) {
            tcp_mode = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                char* endptr;
                errno = 0;
                long port_val = strtol(argv[i + 1], &endptr, 10);
                if (endptr == argv[i + 1] || *endptr || errno == ERANGE || port_val <= 0 || port_val > 65535) {
                    return usage(argv[0], "--tcp PORT must be an integer from 1-65535");
                } else {
                    tcp_port = (int)port_val;
                    ++i;
                }
            } else {
                return usage(argv[0], "--tcp requires a PORT argument");
            }
        } else if (strcmp(argv[i], "--socketfile") == 0) {
            socket_mode = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                socket_path = argv[++i];
            } else {
                return usage(argv[0], "--socketfile requires a PATH argument");
            }
        } else {
            return usage(argv[0], "Unknown option");
        }
    }

    if (serial_mode + tcp_mode + socket_mode != 1) {
        return usage(argv[0], "Exactly one of --serialport, --tcp, or --socketfile must be given");
    }

    libjade_start();
    // FIXME: Add log-level cmdline parameter
    libjade_set_log_level(ESP_LOG_NONE);

    if (serial_mode) {
        serial_init(serial_link_path);
        printf("-> Serial mode enabled.\n");
        serial_bridge();
    } else if (tcp_mode) {
        tcp_bridge(tcp_port);
    } else {
        socket_bridge(socket_path);
    }

    printf("Exiting libjade daemon.\n");
    libjade_stop();

    return EXIT_SUCCESS;
}
