#include <gtk/gtk.h>
#include <glib/gunicode.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include <string.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <arpa/inet.h> 

#include "dh.h"
#include "keys.h"

static GtkTextBuffer* tbuf;
static GtkEntry* entry;
static int sockfd;

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

mpz_t A_pk, A_sk, B_pk;


char hmac_key[256+1];
unsigned char aes_key[256];

unsigned char iv_val[16+1];

static GtkTextBuffer* mbuf; 
static GtkTextView*  tview; 
static GtkTextMark*   mark; 

static pthread_t trecv;     

#define max(a, b) ((a) > (b) ? (a) : (b))


static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
    int reuse = 1;
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (listensock < 0)
        error("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    fprintf(stderr, "listening on port %i...\n", port);
    listen(listensock, 1);
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
    if (sockfd < 0)
        error("error on accept");
    close(listensock);
    fprintf(stderr, "connection made, starting session...\n");
    return 0;
}

int initClientNet(char *hostname, int port)
{
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server = gethostbyname(hostname);
    if (sockfd < 0)
        error("ERROR opening socket");
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    return 0;
}

static int shutdownNetwork()
{
    shutdown(sockfd, 2);
    unsigned char dummy[64];
    ssize_t r;
    do {
        r = recv(sockfd, dummy, 64, 0);
    } while (r != 0 && r != -1);
    close(sockfd);
    return 0;
}

static void tsappend(char* message, char** tagnames, int ensurenewline)
{
    GtkTextIter t0;
    gtk_text_buffer_get_end_iter(tbuf, &t0);
    size_t len = strlen(message);
    if (ensurenewline && message[len - 1] != '\n')
        message[len++] = '\n';
    gtk_text_buffer_insert(tbuf, &t0, message, len);
    GtkTextIter t1;
    gtk_text_buffer_get_end_iter(tbuf, &t1);
    t0 = t1;
    gtk_text_iter_backward_chars(&t0, len);
    if (tagnames) {
        for (char** tag = tagnames; *tag != NULL; tag++) {
            gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);
        }
    }
    if (ensurenewline) {
        gtk_text_buffer_add_mark(tbuf, mark, &t1);
        gtk_text_view_scroll_to_mark(tview, mark, 0.0, FALSE, 0, 0);
    }
}


gboolean append_to_buffer(gchar *message) {
    GtkTextIter iter;
    gtk_text_buffer_get_end_iter(tbuf, &iter);
    gtk_text_buffer_insert(tbuf, &iter, message, -1);
    g_free(message);
    return FALSE;
}


gboolean append_to_buffer(gchar *message);

void sendMessage(GtkButton *button, gpointer user_data) {
    GtkEntry* entry = GTK_ENTRY(user_data);
    const gchar* message = gtk_entry_get_text(entry);
    if (strlen(message) == 0)
        return;

    ssize_t nbytes = send(sockfd, message, strlen(message), 0);
    if (nbytes == -1)
        error("send failed");

 
    GtkTextIter iter;
    gtk_text_buffer_get_end_iter(tbuf, &iter);
    gtk_text_buffer_insert(tbuf, &iter, message, -1);
	

   
    gdk_threads_add_idle((GSourceFunc) append_to_buffer, g_strdup(message));

    gtk_entry_set_text(entry, ""); 
}


void* recvMsg(void* unused) {
    char buffer[1024];
    while (1) {
        ssize_t nbytes = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (nbytes <= 0) {
            if (nbytes == 0) {
               
                printf("chat: client closed connection\n");
            } else {
                error("recv failed");
            }
            return NULL;
        }
        buffer[nbytes] = '\0'; 

        
        gdk_threads_add_idle((GSourceFunc) append_to_buffer, g_strdup(buffer));
    }
}


int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

  
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *view = gtk_text_view_new();


    gtk_container_add(GTK_CONTAINER(scroll), view);

    
    tbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));

    entry = GTK_ENTRY(gtk_entry_new());
    GtkWidget *send_button = gtk_button_new_with_label("Send");

    GtkWidget *vbox = gtk_vbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(window), vbox);

   
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    GtkWidget *hbox = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), GTK_WIDGET(entry), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), send_button, FALSE, FALSE, 0);

    g_signal_connect(G_OBJECT(send_button), "clicked", G_CALLBACK(sendMessage), entry);


    int opt;
    while ((opt = getopt(argc, argv, "lc:")) != -1) {
        switch (opt) {
        case 'l':
            initServerNet(12345); 
            break;
        case 'c':
            initClientNet(optarg, 12345); 
            break;
        default:
            fprintf(stderr, "Usage: %s [-l] [-c hostname]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    pthread_create(&trecv, NULL, recvMsg, NULL);

    gtk_widget_show_all(window);
    gtk_main();

    return 0;
}

