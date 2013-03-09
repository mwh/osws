// Copyright (C) 2009, 2013 Michael Homer <mwh@mwh.geek.nz>
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
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <libgen.h>
#include <dirent.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef SO_NOSIGPIPE
#define SO_NOSIGPIPE 0
#endif

#define VERSION "0.4"
#define STDBUFSIZE 1024
#define LRGBUFSIZE 4*1024*1024

struct http_request {
    char request[256];
    char type[8];
    char protocol[10];
    char headers[STDBUFSIZE];
    int numheaders;
};

struct line {
    char buf[STDBUFSIZE];
    int offset;
    char *start;
    int length;
};

void olog(char *fmt, ...) {
    char buf[STDBUFSIZE];
    va_list args;
    time_t rawtime;
    struct tm *tdata;
    time(&rawtime);
    tdata = localtime(&rawtime);
    strftime(buf, STDBUFSIZE, "%H:%M:%S", tdata);
    printf("osws: [%s] ", buf);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

int receive_line(int fd, struct line *line) {
    int i;
    int startoffset = line->offset;
    if (line->offset > 0)
        line->start = line->start + line->length + 1;
    else
        line->start = line->buf;
    for (i=line->start-line->buf; i<line->offset; i++) {
        if (line->buf[i] == '\n') {
            line->length = i - (line->start - line->buf);
            return 0;
        }
    }
    while (1) {
        int ramt = recv(fd, line->buf + line->offset,
                STDBUFSIZE-line->offset, 0);
        line->offset += ramt;
        for (i=line->start-line->buf; i<line->offset; i++)
            if (line->buf[i] == '\n') {
                line->length = i - (line->start - line->buf);
                return 0;
            }
        if (ramt == 0)
            return 1;
    }
    return 0;
}
int read_http_request(int fd, struct http_request *hr) {
    // Consume an HTTP request from fd, filling an http_request with details.
    char hdr[STDBUFSIZE];
    int i = 0;
    struct line line;
    char *tmp;
    line.offset = 0;
    if (receive_line(fd, &line))
        return 1;
    strncpy(hdr, line.start, line.length);
    strncpy(hr->type, strtok(hdr, " \n"), 7);
    strncpy(hr->request, strtok(NULL, " \n"), 255);
    strncpy(hr->protocol, strtok(NULL, " \n"), 8);
    char *begin_headers = NULL;
    while (!receive_line(fd, &line)) {
        if (!begin_headers)
            begin_headers = line.start;
        strncpy(hdr, line.start, line.length);
        hdr[line.length] = 0;
        if (strcmp(hdr, "\r") == 0)
            break;
        *(line.start + line.length - 1) = 0;
        i++;
    }
    memcpy(hr->headers, begin_headers, line.offset);
    hr->headers[line.offset] = 0;
    hr->numheaders = i;
    return 0;
}

void write_redirect(int fd, char *dest) {
    char resp[STDBUFSIZE];
    olog("Sending redirect to /%s.", dest);
    sprintf(resp, "HTTP/1.0 302 Found\nLocation: /%s\n"
            "Connection: close\n\n", dest);
    send(fd, resp, strlen(resp), MSG_NOSIGNAL);
    close(fd);
}

void write_file(int fd, char *path) {
    // Write the file named by path in HTTP form to the stream fd.
    FILE *fp;
    char buf[LRGBUFSIZE];
    size_t nels;
    int tbytes = 0;
    send(fd, "HTTP/1.0 200 OK\nConnection: close\n\n", 35, MSG_NOSIGNAL);
    fp = fopen(path, "rb");
    if (fp == NULL) {
        olog("error: error opening file %s.", path);
        close(fd);
        return;
    }
    while (!feof(fp)) {
        char *spos = buf;
        size_t nwrt = 0;
        nels = fread(buf, 1, LRGBUFSIZE, fp);
        while (nwrt != nels) {
            nels -= nwrt;
            nwrt = send(fd, spos, nels, MSG_NOSIGNAL);
            if (-1 == nwrt) {
                olog("error: write error: %s", strerror(errno));
                fclose(fp);
                close(fd);
                olog("wrote %i bytes of %s.", tbytes, path);
                return;
            }
            spos += nwrt;
            tbytes += nwrt;
        }
    }
    fclose(fp);
    close(fd);
    olog("wrote %i bytes of %s.", tbytes, path);
}

void write_404(int fd, char *path) {
    // Write a 404 not found response.
    char data[STDBUFSIZE];
    olog("serving 404 error.");
    data[0] = 0;
    strcat(data, "HTTP/1.0 404 Not Found\nConnection: close\n\n");
    send(fd, data, strlen(data), MSG_NOSIGNAL);
    close(fd);
}

void write_file_list(int fd, char *directory) {
    // Write an HTML directory listing to the stream in HTTP format.
    // This is really for testing purposes, but I suppose it might
    // be genuinely useful sometime.
    DIR *dp;
    struct dirent *ep;
    char * fn;
    char data[STDBUFSIZE];
    char path[STDBUFSIZE];
    struct stat stat_struct;
    olog("serving directory listing.");
    dp = opendir(directory);
    if (dp == NULL)
        return;
    data[0] = 0;
    strcat(data, "HTTP/1.0 200 OK\nConnection: close\n\n"
           "<!DOCTYPE html>\n<html>\n <head>\n"
           "  <title>osws directory listing</title>\n </head>\n"
           " <body>\n  <ul>\n");
    send(fd, data, strlen(data), MSG_NOSIGNAL);
    while (ep = readdir(dp)) {
        path[0] = 0;
        fn = ep->d_name;
        strcpy(path, directory);
        strcat(path, "/");
        strcat(path, fn);
        if (strcmp(fn, ".") == 0 || strcmp(fn, "..") == 0)
            continue;
        if (stat(path, &stat_struct))
            continue;
        if (S_ISDIR(stat_struct.st_mode))
            sprintf(data, "   <li><a href=\"%s/\">%s/</a></li>\n", fn, fn);
        else
            sprintf(data, "   <li><a href=\"%s\">%s</a></li>\n", fn, fn);
        send(fd, data, strlen(data), MSG_NOSIGNAL);
    }
    data[0] = 0;
    strcat(data, "  </ul>\n </body>\n</html>\n");
    send(fd, data, strlen(data), MSG_NOSIGNAL);
    close(fd);
}

void serve_directory(int fd, char *directory, char *file) {
    // If file is /, serve a directory listing; otherwise write the
    // named file in the given directory to the stream. If the file is
    // itself a directory, give a listing for it.
    int i;
    char path[STDBUFSIZE];
    struct stat stat_struct;
    if (strstr(file, "../") != NULL || strlen(directory) + strlen(file)
        >= STDBUFSIZE) {
        close(fd);
        return;
    }
    if (strcmp(file, "/") == 0) {
        write_file_list(fd, directory);
        return;
    }
    strcpy(path, directory);
    strcat(path, file);
    // For the moment, this only deals with URL-encoded spaces,
    // since that's all I had around.
    char *ch;
    while (ch = strstr(path, "%20")) {
        ch[0] = 32;
        for (i = 1; i< strlen(path) - (ch - path); i++) {
            ch[i] = ch[i+2];
        }
        printf("made one replacement: %s\n", path);
    }
    if (stat(path, &stat_struct)) {
        olog("error: could not stat %s", path);
        write_404(fd, path);
        return;
    }
    if (S_ISDIR(stat_struct.st_mode))
        write_file_list(fd, path);
    else
        write_file(fd, path);
}

void print_help() {
    puts("osws " VERSION " - the one-shot web server");
    puts("Usage: osws [-i] [-r] [-p NN] file1 [file2 ...]");
    puts("Serve out individual files over HTTP.");
    puts("");
    puts("  -i      Infinite loop: serve the files over and over.");
    puts("  -r      Serve from root: do not redirect to the filename.");
    puts("  -p NN   Bind to port NN instead of default.");
    puts("  -d      Serve file1 as a directory, returning requested files.");
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
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_NOSIGPIPE, &yes,
                   sizeof(int)) == -1) {
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
    char ipstr[80];
    char *port = "8080";
    char *curfile;
    struct sockaddr_storage raddr;
    struct addrinfo *servinfo;
    struct http_request req;

    // These are changed by command-line options.
    int repeat = 0;
    int redirect = 1;
    int directory = 0;

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
        } else if (strcmp(argv[i], "-d") == 0) {
            // Serve a directory instead.
            directory = 1;
            redirect = 0;
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
        olog("error: no filenames given.");
        exit(1);
    }
    sock = init_server(port);
    curfile = argv[foffset + fpos];
    olog("Ready for connections on port %s...", port);
    olog("Preparing to serve %s (%i/%i).", curfile, fpos, nfiles);
    while (fd = accept(sock, (struct sockaddr *)&raddr, &addr_size)) {
        inet_ntop(raddr.ss_family, get_in_addr((struct sockaddr *)&raddr),
                  ipstr, sizeof ipstr);
        olog("Incoming request from %s:", ipstr);
        memset(&req, 0, sizeof req);
        if (read_http_request(fd, &req)) {
            olog(" Error reading request; aborting.");
            continue;
        }
        olog(" %s %s %s", req.type, req.request, req.protocol);
        char *hdrs = req.headers;
        char hdr[STDBUFSIZE];
        olog("  %i headers:", req.numheaders);
        for (i=0; i<req.numheaders; i++) {
            strcpy(hdr, hdrs);
            olog("   %s", hdr);
            hdrs += strlen(hdr) + 2;
        }
        if (redirect && strcmp("/", req.request) == 0)
            write_redirect(fd, basename(curfile));
        else if (directory) {
            serve_directory(fd, curfile, req.request);
        } else {
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
        puts("");
        olog("Preparing to serve %s (%i/%i).", curfile, fpos,
               nfiles);
    }
    puts("");
    olog("Served all files, terminating.");
    close(sock);
}
