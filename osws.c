// Copyright (C) 2009 Michael Homer <=mwh>
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <libgen.h>

#define VERSION "0.3"

struct http_request {
    char request[256];
    char type[8];
    char protocol[10];
};

void read_http_request(int fd, struct http_request *hr) {
    // Consume an HTTP request from fd, filling an http_request with details.
    char buf[1024];
    char hdr[1024];
    int ramt, npos, i;
    ramt = recv(fd, buf, 1024, 0);
    buf[ramt] = 0;
    npos = ramt;
    while (!strstr(buf, "\n")) {
        ramt = recv(fd, &buf + ramt, 1024-ramt, 0);
        npos += ramt;
        buf[npos] = 0;
    }
    strncpy(hdr, buf, 1024);
    strncpy(hr->type, strtok(hdr, " \n"), 7);
    strncpy(hr->request, strtok(NULL, " \n"), 255);
    strncpy(hr->protocol, strtok(NULL, " \n"), 8);
    while (strstr(buf, "\r\n\r\n") == NULL && ramt > 0) {
        ramt = recv(fd, buf, 1024, 0);
        buf[ramt] = 0;
    }
}

void write_redirect(int fd, char *dest) {
    char resp[1024];
    printf("osws: Sending redirect to /%s.\n", dest);
    sprintf(resp, "HTTP/1.0 302 Found\nLocation: /%s\n"
            "Connection: close\n\n", dest);
    send(fd, resp, strlen(resp), 0);
    close(fd);
}

void write_file(int fd, char *path) {
    // Write the file named by path in HTTP form to the stream fd.
    FILE *fp;
    char buf[10240];
    size_t nels;
    int tbytes = 0;
    send(fd, "HTTP/1.0 200 OK\nConnection: close\n\n", 35, 0);
    fp = fopen(path, "rb");
    if (fp == NULL) {
        puts("osws: error: error opening file.");
        close(fd);
        return;
    }
    while (!feof(fp)) {
        char *spos = buf;
        size_t nwrt = 0;
        nels = fread(buf, 1, 10240, fp);
        while (nwrt != nels) {
            nels -= nwrt;
            nwrt = send(fd, spos, nels, 0);
            spos += nwrt;
            tbytes += nwrt;
        }
    }
    fclose(fp);
    close(fd);
    printf("osws: wrote %i bytes of %s.\n", tbytes, path);
}

void print_help() {
    puts("osws " VERSION " - the one-shot web server");
    puts("Usage: osws [-i] [-r] [-p NN] file1 [file2 ...]");
    puts("Serve out individual files over HTTP.");
    puts("");
    puts("  -i      Infinite loop: serve the files over and over.");
    puts("  -r      Serve from root: do not redirect to the filename.");
    puts("  -p NN   Bind to port NN instead of default.");
    puts("");
    puts("osws will serve out the files given on the command-line exactly");
    puts("once, in the order given. By default a request to / (the root)");
    puts("returns a redirection to the basename of the file, so that wget");
    puts("or similar tools save to the correct filename.");
    puts("");
    puts("Default port is 8080, unless run as root when it is 80.");
    puts("");
    puts("Home page: <https://gytha.org/osws/>");
}

void print_version() {
    puts("osws " VERSION " - the one-shot web server");
    puts("Copyright (C) 2009 Michael Homer");
    puts("Licence GPLv3+: GNU GPL version 3 or later "
         "<http://gnu.org/licenses/gpl.html>.");
    puts("This is free software: you are free to change and redistribute it.");
    puts("There is NO WARRANTY, to the extent permitted by law.");
    puts("\nHomepage: <https://gytha.org/osws/>");
}

// Get sockaddr, IPv4 or IPv6:
// From <http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html>
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int init_server(char *port) {
    // Start listening on port, and return the socket descriptor.
    // Based on code from above URL as well with some modification.
    int status;
    int sock;
    struct addrinfo hints;
    struct addrinfo *servinfo;
    int yes = 1;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ((status = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(1);
    }
    sock = socket(servinfo->ai_family, servinfo->ai_socktype,
                    servinfo->ai_protocol);
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
    } 
    bind(sock, servinfo->ai_addr, servinfo->ai_addrlen);
    freeaddrinfo(servinfo);
    listen(sock, 5);
    return sock;
}

int main(int argc, char **argv) {
    int i;
    int sock;
    int addr_size;
    int fd;
    // Position of file currently being served.
    int fpos = 1;
    // Offset: added to fpos to determine position in argv.
    int foffset = 0;
    int nfiles = 0;
    char buf[1024];
    char ipstr[80];
    char *port = "8080";
    char *curfile;
    struct sockaddr_storage raddr;
    struct addrinfo *servinfo;
    struct http_request req;

    // These are changed by command-line options.
    int repeat = 0;
    int redirect = 1;

    addr_size = sizeof raddr;

    if (argc == 1) {
        puts("osws - the one-shot web server");
        puts("Usage: osws [-r] [-i] [-p NN] file1 [file2 ...]");
        exit(0);
    }
    if (geteuid() == 0)
        port = "80";
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            // Infinite repeat.
            repeat = 1;
        } else if (strcmp(argv[i], "-r") == 0) {
            // Serve in root.
            redirect = 0;
        } else if (strcmp(argv[i], "-p") == 0) {
            // Change local port.
            port = argv[i + 1];
            i++;
        } else if ((strcmp(argv[i], "--help") == 0)
                   || (strcmp(argv[i], "-h") == 0)) {
            print_help();
            exit(0);
        } else if ((strcmp(argv[i], "--version") == 0)
                   || (strcmp(argv[i], "-v") == 0)) {
            print_version();
            exit(0);
        } else {
            // First file.
            foffset = i - 1;
            break;
        }
    }
    nfiles = argc - i;
    if (nfiles == 0) {
        puts("osws: error: no filenames given.\n");
        exit(1);
    }
    sock = init_server(port);
    curfile = argv[foffset + fpos];
    printf("osws: Ready for connections on port %s...\n", port);
    printf("osws: Preparing to serve %s (%i/%i).\n", curfile, fpos,
           nfiles);
    while (fd = accept(sock, (struct sockaddr *)&raddr, &addr_size)) {
        inet_ntop(raddr.ss_family, get_in_addr((struct sockaddr *)&raddr),
                  ipstr, sizeof ipstr);
        printf("osws: Incoming request from %s:\n", ipstr);
        memset(&req, 0, sizeof req);
        read_http_request(fd, &req);
        printf("osws:  %s %s %s\n", req.type, req.request, req.protocol);
        if (redirect && strcmp("/", req.request) == 0)
            write_redirect(fd, basename(curfile));
        else {
            write_file(fd, curfile);
            fpos++;
        }
        if (fpos > nfiles) {
            if (!repeat)
                break;
            else
                fpos = 1;
        }
        curfile = argv[foffset + fpos];
        printf("\nosws: Preparing to serve %s (%i/%i).\n", curfile, fpos,
               nfiles);
    }
    puts("\nosws: Served all files, terminating.");
    close(sock);
}
