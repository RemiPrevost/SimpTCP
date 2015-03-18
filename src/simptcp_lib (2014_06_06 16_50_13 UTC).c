/*! \file simptcp_lib.c
  \brief Defines the functions that gather the actions performed by a simptcp protocol entity in 
  reaction to events (system calls, simptcp packet arrivals, timeouts) given its state at a point in time  (closed, ..established,..). 

  \author{DGEI-INSAT 2010-2011}
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>              /* for errno macros */
#include <sys/socket.h>
#include <netinet/in.h>         /* for htons,.. */
#include <arpa/inet.h>
#include <unistd.h>             /* for usleep() */
#include <sys/time.h>           /* for gettimeofday,..*/

#include <libc_socket.h>
#include <simptcp_packet.h>
#include <simptcp_entity.h>
#include "simptcp_func_var.c"    /* for socket related functions' prototypes */
#include <term_colors.h>        /* for color macros */
#define __PREFIX__              "[" COLOR("SIMPTCP_LIB", BRIGHT_YELLOW) " ] "
#include <term_io.h>

#ifndef __DEBUG__
#define __DEBUG__               1
#endif





/*! \fn char *  simptcp_socket_state_get_str(simptcp_socket_state_funcs * state)
 * \brief renvoie une chaine correspondant a l'etat dans lequel se trouve un socket simpTCP. Utilisee a des fins d'affichage
 * \param state correspond typiquement au champ socket_state de la structure #simptcp_socket qui indirectement identifie l'etat dans lequel le socket se trouve et les fonctions qu'il peut appeler depuis cet etat
 * \return chaine de carateres correspondant a l'etat dans lequel se trouve le socket simpTCP
 */
char *  simptcp_socket_state_get_str(simptcp_socket_state_funcs * state) {
    if (state == &  simptcp_socket_states.closed)
        return "CLOSED";
    else if (state == & simptcp_socket_states.listen)
        return "LISTEN";
    else if (state == & simptcp_socket_states.synsent)
        return "SYNSENT";
    else if (state == & simptcp_socket_states.synrcvd)
        return "SYNRCVD";
    else if (state == & simptcp_socket_states.established)
        return "ESTABLISHED";
    else if (state == & simptcp_socket_states.closewait)
        return "CLOSEWAIT";
    else if (state == & simptcp_socket_states.finwait1)
        return "FINWAIT1";
    else if (state == & simptcp_socket_states.finwait2)
        return "FINWAIT2";
    else if (state == & simptcp_socket_states.closing)
        return "CLOSING";
    else if (state == & simptcp_socket_states.lastack)
        return "LASTACK";
    else if (state == & simptcp_socket_states.timewait)
        return "TIMEWAIT";
    else
        assert(0);
}

/**
 * \brief called at socket creation 
 * \return the first sequence number to be used by the socket
 * \todo: randomize the choice of the sequence number to fit TCP behaviour..
 */
unsigned int get_initial_seq_num()
{
    unsigned int init_seq_num=15; 
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

    return init_seq_num;
}


/*!
 * \brief Initialise les champs de la structure #simptcp_socket
 * \param sock pointeur sur la structure simptcp_socket associee a un socket simpTCP 
 * \param lport numero de port associe au socket simptcp local 
 */
void init_simptcp_socket(struct simptcp_socket *sock, unsigned int lport)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

    assert(sock != NULL);
    lock_simptcp_socket(sock);

    /* Initialization code */

    sock->socket_type = unknown;
    sock->new_conn_req=NULL;
    sock->pending_conn_req=0;

    /* set simpctp local socket address */
    memset(&(sock->local_simptcp), 0, sizeof (struct sockaddr));
    sock->local_simptcp.sin_family = AF_INET;
    sock->local_simptcp.sin_addr.s_addr = htonl(INADDR_ANY);
    sock->local_simptcp.sin_port = htons(lport);

    memset(&(sock->remote_simptcp), 0, sizeof (struct sockaddr));


    sock->socket_state = &(simptcp_entity.simptcp_socket_states->closed);

    /* protocol entity sending side */
    sock->socket_state_sender=-1; 
    sock->next_seq_num=get_initial_seq_num();
    memset(sock->out_buffer, 0, SIMPTCP_SOCKET_MAX_BUFFER_SIZE);   
    sock->out_len=0;
    sock->nbr_retransmit=0;
    sock->timer_duration=1500;
    /* protocol entity receiving side */
    sock->socket_state_receiver=-1;
    sock->next_ack_num=0;
    memset(sock->in_buffer, 0, SIMPTCP_SOCKET_MAX_BUFFER_SIZE);   
    sock->in_len=0;

    /* MIB statistics initialisation  */
    sock->simptcp_send_count=0; 
    sock->simptcp_receive_count=0; 
    sock->simptcp_in_errors_count=0; 
    sock->simptcp_retransmit_count=0; 

    pthread_mutex_init(&(sock->mutex_socket), NULL);

    /* Add Optional field initialisations */
    unlock_simptcp_socket(sock);

}



/*! \fn int create_simptcp_socket()
 * \brief cree un nouveau socket SimpTCP et l'initialise. 
 * parcourt la table de  descripteur a la recheche d'une entree libre. S'il en trouve, cree
 * une nouvelle instance de la structure simpTCP, la rattache a la table de descrpteurs et l'initialise. 
 * \return descripteur du socket simpTCP cree ou une erreur en cas d'echec
 */
int create_simptcp_socket()
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    int fd;

    /* get a free simptcp socket descriptor */
    for (fd=0;fd< MAX_OPEN_SOCK;fd++) {
        if ((simptcp_entity.simptcp_socket_descriptors[fd]) == NULL){ 
            /* this is a free descriptor */
            /* Allocating memory for the new simptcp_socket */
            simptcp_entity.simptcp_socket_descriptors[fd] = 
                (struct simptcp_socket *) malloc(sizeof(struct simptcp_socket));
            if (!simptcp_entity.simptcp_socket_descriptors[fd]) {
                return -ENOMEM;
            }
            /* initialize the simptcp socket control block with
               local port number set to 15000+fd */
            init_simptcp_socket(simptcp_entity.simptcp_socket_descriptors[fd],15000+fd);
            simptcp_entity.open_simptcp_sockets++;

            /* return the socket descriptor */
            return fd;
        }
    } /* for */
    /* The maximum number of open simptcp
       socket reached  */
    return -ENFILE; 
}

/*! \fn void print_simptcp_socket(struct simptcp_socket *sock)
 * \brief affiche sur la sortie standard les variables d'etat associees a un socket simpTCP 
 * Les valeurs des principaux champs de la structure simptcp_socket d'un socket est affichee a l'ecran
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 */
void print_simptcp_socket(struct simptcp_socket *sock)
{
    printf("----------------------------------------\n");
    printf("local simptcp address: %s:%hu \n",inet_ntoa(sock->local_simptcp.sin_addr),ntohs(sock->local_simptcp.sin_port));
    printf("remote simptcp address: %s:%hu \n",inet_ntoa(sock->remote_simptcp.sin_addr),ntohs(sock->remote_simptcp.sin_port));   
    printf("socket type      : %d\n", sock->socket_type);
    printf("socket state: %s\n",simptcp_socket_state_get_str(sock->socket_state) );
    if (sock->socket_type == listening_server)
        printf("pending connections : %d\n", sock->pending_conn_req);
    printf("sending side \n");
    printf("sender state       : %d\n", sock->socket_state_sender);
    printf("transmit  buffer occupation : %d\n", sock->out_len);
    printf("next sequence number : %u\n", sock->next_seq_num);
    printf("retransmit number : %u\n", sock->nbr_retransmit);

    printf("Receiving side \n");
    printf("receiver state       : %d\n", sock->socket_state_receiver);
    printf("Receive  buffer occupation : %d\n", sock->in_len);
    printf("next ack number : %u\n", sock->next_ack_num);

    printf("send count       : %lu\n", sock->simptcp_send_count);
    printf("receive count       : %lu\n", sock->simptcp_receive_count);
    printf("receive error count       : %lu\n", sock->simptcp_in_errors_count);
    printf("retransmit count       : %lu\n", sock->simptcp_retransmit_count);
    printf("----------------------------------------\n");
}


/*! \fn inline int lock_simptcp_socket(struct simptcp_socket *sock)
 * \brief permet l'acces en exclusion mutuelle a la structure #simptcp_socket d'un socket
 * Les variables d'etat (#simptcp_socket) d'un socket simpTCP peuvent etre modifiees par
 * l'application (client ou serveur via les appels systeme) ou l'entite protocolaire (#simptcp_entity_handler).
 * Cette fonction repose sur l'utilisation de semaphores binaires (un semaphore par socket simpTCP). 
 * Avant tout  acces en ecriture a ces variables, l'appel a cette fonction permet 
 * 1- si le semaphore est disponible (unlocked) de placer le semaphore dans une etat indisponible 
 * 2- si le semaphore est indisponible, d'attendre jusqu'a ce qu'il devienne disponible avant de le "locker"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 */
inline int lock_simptcp_socket(struct simptcp_socket *sock)
{
    /*#if __DEBUG__
      printf("function %s called\n", __func__);
#endif   */

    if (!sock)
        return -1;

    return pthread_mutex_lock(&(sock->mutex_socket));
}

/*! \fn inline int unlock_simptcp_socket(struct simptcp_socket *sock)
 * \brief permet l'acces en exclusion mutuelle a la structure #simptcp_socket d'un socket
 * Les variables d'etat (#simptcp_socket) d'un socket simpTCP peuvent etre modifiees par
 * l'application (client ou serveur via les appels systeme) ou l'entite protocolaire (#simptcp_entity_handler).
 * Cette fonction repose sur l'utilisation de semaphores binaires (un semaphore par socket simpTCP). 
 * Après un acces "protege" en ecriture a ces variables, l'appel a cette fonction permet de liberer le semaphore 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 */
inline int unlock_simptcp_socket(struct simptcp_socket *sock)
{
    /*#if __DEBUG__
      printf("function %s called\n", __func__);
#endif   */

    if (!sock)
        return -1;

    return pthread_mutex_unlock(&(sock->mutex_socket));
}

/*! \fn void start_timer(struct simptcp_socket * sock, int duration)
 * \brief lance le timer associe au socket en fixant l'instant ou la duree a mesurer "duration" sera ecoulee (champ "timeout" de #simptcp_socket)
 * \param sock  pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 * \param duration duree a mesurer en ms
 */
void start_timer(struct simptcp_socket * sock, int duration)
{
    struct timeval t0;
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    assert(sock!=NULL);

    gettimeofday(&t0,NULL);

    sock->timeout.tv_sec=t0.tv_sec + (duration/1000);
    sock->timeout.tv_usec=t0.tv_usec + (duration %1000)*1000;  
}

/*! \fn void stop_timer(struct simptcp_socket * sock)
 * \brief stoppe le timer en reinitialisant le champ "timeout" de #simptcp_socket
 * \param sock  pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 */
void stop_timer(struct simptcp_socket * sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif  
    assert(sock!=NULL);
    sock->timeout.tv_sec=0;
    sock->timeout.tv_usec=0; 
}

/*! \fn int has_active_timer(struct simptcp_socket * sock)
 * \brief Indique si le timer associe a un socket simpTCP est actif ou pas
 * \param sock  pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 * \return 1 si timer actif, 0 sinon
 */
int has_active_timer(struct simptcp_socket * sock)
{
    return (sock->timeout.tv_sec!=0) || (sock->timeout.tv_usec!=0);
}

/*! \fn int is_timeout(struct simptcp_socket * sock)
 * \brief Indique si la duree mesuree par le timer associe a un socket simpTCP est actifs'est ecoulee ou pas
 * \param sock  pointeur sur les variables d'etat (#simptcp_socket) d'un socket simpTCP
 * \return 1 si duree ecoulee, 0 sinon
 */
int is_timeout(struct simptcp_socket * sock)
{
    struct timeval t0;

    assert(sock!=NULL);
    /* make sure that the timer is launched */
    assert(has_active_timer(sock));

    gettimeofday(&t0,NULL);
    return ((sock->timeout.tv_sec < t0.tv_sec) || 
            ( (sock->timeout.tv_sec == t0.tv_sec) && (sock->timeout.tv_usec < t0.tv_usec)));
}


int make_pdu (struct simptcp_socket * socket, char * message, size_t longueur_message, unsigned char flags) {
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    /* num port source */
    simptcp_set_sport(socket->out_buffer, ntohs(socket->local_simptcp.sin_port));
    /* num port dest */
    simptcp_set_dport(socket->out_buffer, ntohs(socket->remote_simptcp.sin_port));	
    /* sep_num */
    simptcp_set_seq_num(socket->out_buffer, (u_int16_t)(socket->next_seq_num));
    /* ack_num */
    simptcp_set_ack_num(socket->out_buffer, (u_int16_t)(socket->next_ack_num));
    /* header */
    simptcp_set_head_len(socket->out_buffer, SIMPTCP_GHEADER_SIZE) ;
    /* flags */
    simptcp_set_flags  (socket->out_buffer, flags);
    /* total_len */
    simptcp_set_total_len(socket->out_buffer, (u_int16_t)SIMPTCP_GHEADER_SIZE+longueur_message);
    socket->out_len = (u_int16_t)SIMPTCP_GHEADER_SIZE+longueur_message;
    /* window_size */
    simptcp_set_win_size   (socket->out_buffer,0 );

    memcpy( &(socket->out_buffer[sizeof(simptcp_generic_header)]), message, longueur_message) ;

    /* checksum */
    simptcp_add_checksum (socket->out_buffer, (u_int16_t)SIMPTCP_GHEADER_SIZE+longueur_message );
    /* message */
    if (sizeof(simptcp_generic_header) + longueur_message > SIMPTCP_SOCKET_MAX_BUFFER_SIZE) {
        return -1 ;
    }

    /* affichage du PDU */
    simptcp_print_packet(socket->out_buffer) ;

    return 0 ;
}




/*** socket state dependent functions ***/


/*********************************************************
 * closed_state functions *
 *********************************************************/

/*! \fn int closed_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int closed_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    /* debut modifications de sock */
    lock_simptcp_socket(sock);

    /* definition du type de socket */
    sock->socket_type = client ;

    /* mise a jour des adresses destination dans la structure simptcp_socket */
    sock->remote_simptcp =  *(struct sockaddr_in*)addr ;
    sock->remote_udp = *(struct sockaddr_in*)addr ;

    /* initialisation du next num seq et ack */
    sock->next_seq_num= 0;
    sock->next_ack_num= 0;

    /* creation du PDU */
    if ( make_pdu (sock, NULL, 0, SYN) !=  0) {
        printf("Erreur Make_PDU\n") ;
        return -1 ;
    }

    /* envoi du PDU */
    if (libc_sendto(simptcp_entity.udp_fd, (sock->out_buffer), sock->out_len, 0, addr, len) == -1)
    {
        printf("Erreur SendTo") ;
        return -1 ;
    }

    /* socket passé dans l'état synsent */
    sock->socket_state = & simptcp_socket_states.synsent ;

    /* mise au type listening_serveur pour recevoir le SYN-ACK du serveur depuis son nouveau socket */
    sock->socket_type = listening_server;

    /* incrémentation du numéro de la prochaine trame à emettre */
    sock->next_seq_num++;

    /* fin de modification de sock */
    unlock_simptcp_socket(sock);

    /* lancement du timer */
    start_timer(sock, 1000) ;

    /* 5 tentatives de connection au maximum */
    int connect_max = 5 ;

    /* attente de l'établissement de la connection ou de l'échec de connection */
    while (sock->simptcp_send_count < connect_max && strcmp(simptcp_socket_state_get_str(sock->socket_state),"ESTABLISHED")!=0) ;

    /* arret du timer */
    stop_timer(sock) ;

    /* retour d'erreur en cas d'échec */
    if (sock->simptcp_send_count >= connect_max) {
        sock->socket_state = & simptcp_socket_states.closed ;
        return -1;
    }

    /* remise à 0 du compteur d'échec */
    sock->simptcp_send_count = 0;

    return 0;
}

/*! \fn int closed_simptcp_socket_state_passive_open(struct simptcp_socket* sock, int n)
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int closed_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{ 
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    /* debut modifications du socket */
    lock_simptcp_socket(sock);

    /* On initialise la liste des sockets ayant effectue une demande de connexion */
    sock->new_conn_req = malloc(n*sizeof(struct simptcp_socket *));

    /* On modifie le type de socket en listening_server */
    sock->socket_type = listening_server;

    /* On fixe le nombre de connexions max */
    sock->max_conn_req_backlog = n;

    /* On fixe l'état de la socket */
    sock->socket_state = & simptcp_socket_states.listen ;

    /* initialisation du next num seq et ack */
    sock->next_seq_num= 0;
    sock->next_ack_num= 0;

    /* fin modifications du socket */
    unlock_simptcp_socket(sock);

    return 0;

}


/*! \fn int closed_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int closed_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    printf("ERROR : demande interdite.") ;
    return - 1;
}


/*! \fn ssize_t closed_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t closed_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    printf("ERROR : demande interdite.") ;
    return -1;
}


/*! \fn ssize_t closed_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t closed_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

    return -1;
}

/**
 * called when application calls close
 */

/*! \fn  int closed_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int closed_simptcp_socket_state_close (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;
}

/*! \fn  int closed_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "closed" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int closed_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/*! 
 * \fn void closed_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "closed"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void closed_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void closed_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "closed"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */

void closed_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

}


/*********************************************************
 * listen_state functions *
 *********************************************************/

/*! \fn int listen_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int listen_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    printf("ERROR: Demande interdite.");
    return -1;   
}

/**
 * called when application calls listen
 */
/*! \fn int listen_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int listen_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;
}

/**
 * called when application calls accept
 */
/*! \fn int listen_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int listen_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

    /* on boucle tant qu'on n'a pas de demande de connection */
    while (sock->pending_conn_req == 0);

    lock_simptcp_socket(sock);

    if (sock->new_conn_req[0] != NULL) {

        /* creation du PDU */          
        if ( make_pdu (sock->new_conn_req[0], NULL, 0, SYN+ACK) !=  0) {
            printf("Erreur Make_PDU\n") ;
            return -1 ;
        }

        if (libc_sendto(simptcp_entity.udp_fd, sock->new_conn_req[0]->out_buffer, sock->new_conn_req[0]->out_len, 0,(struct sockaddr*)(&(sock->new_conn_req[0]->remote_udp)),sock->new_conn_req[0]->out_len)   == -1) {
            printf("\nErreur libc_sendto\n");
            return -1;
        }

        /* incrementation du next num seq */
        sock->new_conn_req[0]->next_seq_num ++ ;

        /* mise a l'etat synsent */
        sock->new_conn_req[0]->socket_state = & simptcp_socket_states.synsent;

        /* 5 tentatives de connection au maximum */
        int connect_max = 5 ;

        /* lancement du timer */
        start_timer(sock->new_conn_req[0],1000);

        /* attente de la reception du ACK pour le SYN envoye */
        while (sock->new_conn_req[0]->simptcp_send_count < connect_max && strcmp(simptcp_socket_state_get_str(sock->new_conn_req[0]->socket_state),"ESTABLISHED")!=0) ;

        sock->new_conn_req[0]->simptcp_send_count = 0;

        stop_timer(sock->new_conn_req[0]);          

        if (sock->new_conn_req[0]->simptcp_send_count >= connect_max)
            return -1;

        /* suppression dans le tableau pending_con_req */
        sock->new_conn_req[0] = NULL;
        sock->pending_conn_req--;


    }
    else
        return -1;

    unlock_simptcp_socket(sock);


    return 1;
}

/**
 * called when application calls send
 */
/*! \fn ssize_t listen_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t listen_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;
}

/**
 * called when application calls recv
 */
/*! \fn ssize_t listen_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t listen_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls close
 */
/*! \fn  int listen_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int listen_simptcp_socket_state_close (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int listen_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "listen" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int listen_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

    printf("Main socket closed\n");

    return 0;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void listen_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "listen"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void listen_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    if (simptcp_get_flags(buf) == SYN) {
        if (simptcp_get_seq_num(buf) == sock->next_ack_num) {

            struct simptcp_socket* new_sock;
            int fd = create_simptcp_socket();

            new_sock = simptcp_entity. simptcp_socket_descriptors[fd];

            lock_simptcp_socket(new_sock);

            new_sock->socket_type = nonlistening_server;
            new_sock->pending_conn_req=0;

            new_sock->remote_udp = sock->remote_udp;      
            new_sock->remote_simptcp = sock->remote_simptcp; 
            new_sock->next_ack_num = simptcp_get_ack_num(buf)+1;
            new_sock->next_seq_num = simptcp_get_seq_num(buf);

            /* incrementation du nombre de demandes */
            sock->pending_conn_req++ ;

            /* reférencement de la copie dans new_conn_req */
            sock->new_conn_req[0] = new_sock;

            unlock_simptcp_socket(new_sock) ;
        }
    }
    else {
        if ( make_pdu (sock, NULL, 0, ACK) !=  0) 
            printf("Erreur Make_PDU\n") ;

        if (libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) == -1)
            printf("\nErreur libc_sento\n");

    }
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void listen_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "listen"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void listen_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}


/*********************************************************
 * synsent_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int synsent_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int synsent_simptcp_socket_state_active_open (struct  simptcp_socket* sock,struct sockaddr* addr, socklen_t len) 
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    printf("ERROR : demande de connexion deja envoye.") ;
    return -1;

}

/**
 * called when application calls listen
 */
/*! \fn int synsent_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreurprintf("+++++++++++sortie de while+++++++++");
 */
int synsent_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls accept
 */
/*! \fn int synsent_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int synsent_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t synsent_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t synsent_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    printf("ERROR : connexion pas etablie.") ;
    return -1;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t synsent_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t synsent_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls close
 */
/*! \fn  int synsent_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int synsent_simptcp_socket_state_close (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int synsent_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "synsent" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int synsent_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void synsent_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \bief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "synsent"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void synsent_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    lock_simptcp_socket(sock);

    /* verification SYN ACK */
    if (simptcp_get_flags(buf) == (SYN+ACK)) {
        /* verification du numero de sequence */
        if (simptcp_get_seq_num(buf) == sock->next_ack_num) {
            sock->socket_type = client;

            /* on passe en mode established */
            sock->socket_state = & simptcp_socket_states.established ;

            /* aquisition du nouveau port du serveur */
            sock->remote_simptcp.sin_port = htons(simptcp_get_sport(buf)); 

            /* on envoie un ACK et on prévient qu'on attend la trame suivante */
            sock->next_ack_num++;

            if ( make_pdu (sock, NULL, 0, ACK) !=  0) {
                printf("Erreur Make_PDU\n") ;
            }

            if (libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) == -1)
                printf("\nErreur libc_sento\n");


        }
        /* mauvais numero de sequence */
        else {
            if ( make_pdu (sock, NULL, 0, ACK) !=  0) {
                printf("Erreur Make_PDU\n") ;
            }

            if (libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) == -1)
                printf("\nErreur libc_sento\n");

        }
    }

    else if (simptcp_get_flags(buf) == ACK) {
        if (simptcp_get_ack_num(buf) == sock->next_seq_num) {
            sock->socket_state = & simptcp_socket_states.established ;
            stop_timer(sock);
        }
    }

    unlock_simptcp_socket(sock);

}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void synsent_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "synsent"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void synsent_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    /* arrêt du timer */
    stop_timer(sock) ;

    /* lock du socket */
    lock_simptcp_socket(sock) ;

    /* incrémentation du nombre d'envoie */
    sock->simptcp_send_count ++ ;

    /* unlock du socket */
    unlock_simptcp_socket(sock) ;

    /* ré-émission du PDU */
    libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) ;

    /* relance du timer */
    start_timer(sock, 1000) ;

}


/*********************************************************
 * synrcvd_state functions *
 *********************************************************/
/**
 * called when application calls connect
 */

/*! \fn int synrcvd_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int synrcvd_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls listen
 */
/*! \fn int synrcvd_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int synrcvd_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls accept
 */
/*! \fn int synrcvd_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int synrcvd_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t synrcvd_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre 
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t synrcvd_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t synrcvd_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t synrcvd_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls close
 */
/*! \fn  int synrcvd_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int synrcvd_simptcp_socket_state_close (struct simptcp_socket* sock)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int synrcvd_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "synrcvd" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int synrcvd_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return 0;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void synrcvd_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "synrcvd"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void synrcvd_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    /*	if (simptcp_get_flags(buf) == ACK) {
        sock->socket_state = & simptcp_socket_states.established ;
        stop_timer(sock);
        }*/

}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void synrcvd_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "synrcvd"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void synrcvd_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}


/*********************************************************
 * established_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int established_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int established_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    printf("Connexion deja etablie.\n") ;
    return -1;

}

/**
 * called when application calls listen
 */
/*! \fn int established_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int established_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    printf("Connexion deja etablie.\n") ;
    return -1;

}

/**
 * called when application calls accept
 */
/*! \fn int established_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int established_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    printf("Connexion deja etablie.\n") ;
    return 0;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t established_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t established_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif


    if (make_pdu (sock, (char*)buf, n, 0) !=  0) {
        printf("Erreur Make_PDU\n") ;
    }

    if (libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, simptcp_get_total_len(sock->out_buffer), 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) == -1)
        printf("\nErreur libc_sento\n");

    /* mise à l'etat d'attente d'un ack */
    sock->socket_state_receiver = 2;

    start_timer(sock,1000);

    /* incrémentation next_seq_num */
    sock->next_seq_num++;

    /* 5 tentatives de connection au maximum */
    int connect_max = 5 ;

    /* attente de l'établissement de la connection ou de l'échec de connection */
    while (sock->simptcp_send_count < connect_max && sock->socket_state_receiver == 2) ;


    /* arret du timer */
    stop_timer(sock) ;

    /* retour d'erreur en cas d'échec */
    if (sock->simptcp_send_count >= connect_max) {
        sock->socket_state = & simptcp_socket_states.closed ;
        return -1;
    }

    /* remise à 0 du compteur d'échec */
    sock->simptcp_send_count = 0;


    return 0;
}    
/**
 * called when application calls recv
 */
/*! \fn ssize_t established_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t established_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    sock->socket_state_sender = 1;

    /* en attente d'une trame de la part du client */
    while(sock->socket_state_sender == 1);

    return simptcp_extract_data(sock->in_buffer,buf);

}

/**
 * called when application calls close
 */
/*! \fn  int established_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int established_simptcp_socket_state_close (struct simptcp_socket* sock)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

    return 0;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int established_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "established" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int established_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    /* si le socket est un serveur, on attend une demande de déconnection de la part du client */
    if (sock->socket_type != client) {
        printf("\nWainting for closing request from client\n");
        while (sock->socket_state != & simptcp_socket_states.closewait) ;

        return closewait_simptcp_socket_state_shutdown(sock,how);

    }


    if ( make_pdu (sock, NULL, 0, FIN) !=  0) {
        printf("Erreur Make_PDU\n") ;
        return -1;
    }

    if (libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) == -1){
        printf("\nErreur libc_sento\n");
        return -1;
    }

    sock->next_seq_num ++;

    /* changement d'état du socket */
    sock->socket_state = & simptcp_socket_states.finwait1 ;

    start_timer(sock,1000);

    /* 5 tentatives de connection au maximum */
    int connect_max = 5 ;

    /* attente de l'établissement de la connection ou de l'échec de connection */
    while (sock->simptcp_send_count < connect_max && sock->socket_state != & simptcp_socket_states.closed) ;


    /* arret du timer */
    stop_timer(sock) ;

    /* retour d'erreur en cas d'échec */
    if (sock->simptcp_send_count >= connect_max) {
        sock->socket_state = & simptcp_socket_states.closed;
        return -1;
    }
    /* remise à 0 du compteur d'échec */
    sock->simptcp_send_count = 0;

    return 0;
}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void established_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "established"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void established_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

    if (simptcp_get_flags(buf) == ACK){
        /* vérification du numero d'ack */
        if (simptcp_get_ack_num(buf) == sock->next_seq_num)
        {
            sock->socket_state_receiver = -1;
        }
    }

    if (simptcp_get_flags(buf) == 0){
        if (simptcp_get_seq_num(buf) == sock->next_ack_num) {
            /* on place le pdu dans la structure sock pour pouvoir etre lu par le recv */	
            memcpy(sock->in_buffer,buf,len);
            /* on indique au recv qu'un paquet est arrivé */
            sock->socket_state_sender=-1;

            sock->next_ack_num++;

            if ( make_pdu (sock, NULL, 0, ACK) !=  0) 
                printf("Erreur Make_PDU\n") ;

            if (libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) == -1)
                printf("\nErreur libc_sento\n");
        }
        else {
            if ( make_pdu (sock, NULL, 0, ACK) !=  0) 
                printf("Erreur Make_PDU\n") ;

            if (libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) == -1)
                printf("\nErreur libc_sento\n");
        }

    }

    if (simptcp_get_flags(buf) == FIN) {
        if (simptcp_get_seq_num(buf) == sock->next_ack_num) {

            /* incrementation du next num seq */
            sock->next_ack_num ++ ;

            if ( make_pdu (sock, NULL, 0, ACK) !=  0) 
                printf("Erreur Make_PDU\n") ;

            if (libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) == -1)
                printf("\nErreur libc_sento\n");

            sock->socket_state = & simptcp_socket_states.closewait ;




        }
        else {
            if ( make_pdu (sock, NULL, 0, ACK) !=  0) 
                printf("Erreur Make_PDU\n") ;

            if (libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) == -1)
                printf("\nErreur libc_sento\n");

        }

    }

}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void established_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "established"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void established_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

    /* arrêt du timer */
    stop_timer(sock) ;

    /* lock du socket */
    lock_simptcp_socket(sock) ;

    /* incrémentation du nombre d'envoie */
    sock->simptcp_send_count ++ ;

    /* unlock du socket */
    unlock_simptcp_socket(sock) ;
    /* ré-émission du PDU */
    libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) ;

    /* relance du timer */
    start_timer(sock, 1000) ;


}


/*********************************************************
 * closewait_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int closewait_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int closewait_simptcp_socket_state_active_open (struct  simptcp_socket* sock,  struct sockaddr* addr, socklen_t len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls listen
 */
/*! \fn int closewait_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int closewait_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls accept
 */
/*! \fn int closewait_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int closewait_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t closewait_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t closewait_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t closewait_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t closewait_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls close
 */
/*! \fn  int closewait_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int closewait_simptcp_socket_state_close (struct simptcp_socket* sock)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int closewait_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "closewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int closewait_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

    sock->socket_state = & simptcp_socket_states.lastack ;
    if ( make_pdu (sock, NULL, 0, FIN) !=  0) 
        printf("Erreur Make_PDU\n") ;

    if (libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) == -1)
        printf("\nErreur libc_sento\n");

    sock->next_seq_num ++ ;

    start_timer(sock,1000);

    int connect_max = 5;
    while (sock->simptcp_send_count < connect_max && (sock->socket_state != (& simptcp_socket_states.closed)));

    /* arret du timer */
    stop_timer(sock) ;

    /* retour d'erreur en cas d'échec */
    if (sock->simptcp_send_count >= connect_max) {
        sock->socket_state = & simptcp_socket_states.closed;
        return -1;
    }
    /* remise à 0 du compteur d'échec */
    sock->simptcp_send_count = 0;



    return 0;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void closewait_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "closewait"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void closewait_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void closewait_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "closewait"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void closewait_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}


/*********************************************************
 * finwait1_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int finwait1_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int finwait1_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls listen
 */
/*! \fn int finwait1_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int finwait1_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;
}

/**
 * called when application calls accept
 */
/*! \fn int finwait1_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int finwait1_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t finwait1_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t finwait1_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t finwait1_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t finwait1_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls close
 */
/*! \fn  int finwait1_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int finwait1_simptcp_socket_state_close (struct simptcp_socket* sock)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;
}

/**
 * called when application calls shutdown
 */
/*! \fn  int finwait1_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "finwait1" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int finwait1_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void finwait1_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "finwait1"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void finwait1_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    if (simptcp_get_flags(buf) == ACK)
        /* vérification du numero de ack */
        if (simptcp_get_ack_num(buf) == sock->next_seq_num) {
            sock->socket_state = & simptcp_socket_states.finwait2 ;
            stop_timer(sock);
        }
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void finwait1_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "finwait1"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void finwait1_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

    /* arrêt du timer */
    stop_timer(sock) ;

    /* lock du socket */
    lock_simptcp_socket(sock) ;

    /* incrémentation du nombre d'envoie */
    sock->simptcp_send_count ++ ;

    /* unlock du socket */
    unlock_simptcp_socket(sock) ;
    /* ré-émission du PDU */
    libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) ;

    /* relance du timer */
    start_timer(sock, 1000) ;


}


/*********************************************************
 * finwait2_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int finwait2_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "fainwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int finwait2_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls listen
 */
/*! \fn int finwait2_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int finwait2_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls accept
 */
/*! \fn int finwait2_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int finwait2_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t finwait2_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t finwait2_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t finwait2_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t finwait2_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls close
 */
/*! \fn  int finwait2_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int finwait2_simptcp_socket_state_close (struct simptcp_socket* sock)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int finwait2_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "finwait2" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int finwait2_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void finwait2_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "finwait2"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void finwait2_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

    if (simptcp_get_flags(buf) == FIN) {
        if (simptcp_get_seq_num(buf) == sock->next_ack_num) {

            /* incrementation du next num seq */
            sock->next_ack_num ++ ;

            if ( make_pdu (sock, NULL, 0, ACK) !=  0) 
                printf("Erreur Make_PDU\n") ;

            if (libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) == -1)
                printf("\nErreur libc_sento\n");


            sock->socket_state = & simptcp_socket_states.timewait ;
            /*attente d'une seconde dans l'etat timewait */
            sleep(1);
            sock->socket_state = & simptcp_socket_states.closed ;
        }
    }
    /* mauvais numero de sequence */
    else {
        if ( make_pdu (sock, NULL, 0, ACK) !=  0) 
            printf("Erreur Make_PDU\n") ;

        if (libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) == -1)
            printf("\nErreur libc_sento\n");

    }

}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void finwait2_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "finwait2"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void finwait2_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}


/*********************************************************
 * closing_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int closing_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int closing_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls listen
 */
/*! \fn int closing_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int closing_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls accept
 */
/*! \fn int closing_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int closing_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t closing_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t closing_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t closing_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t closing_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls close
 */
/*! \fn  int closing_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int closing_simptcp_socket_state_close (struct simptcp_socket* sock)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int closing_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "closing" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int closing_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void closing_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "closing"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void closing_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void closing_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "closing"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void closing_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}


/*********************************************************
 * lastack_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */

/*! \fn int lastack_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int lastack_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls listen
 */
/*! \fn int lastack_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int lastack_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls accept
 */
/*! \fn int lastack_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int lastack_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t lastack_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf 
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t lastack_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t lastack_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t lastack_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls close
 */
/*! \fn  int lastack_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int lastack_simptcp_socket_state_close (struct simptcp_socket* sock)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int lastack_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "lastack" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int lastack_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void lastack_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "lastack"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void lastack_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    /* Verification de la reception d'un ACK */
    if (simptcp_get_flags(buf) == ACK) {
        /* Verification de la validite de la trame en regardant son num_ack */
        if (simptcp_get_ack_num(buf) == sock->next_seq_num) {
            lock_simptcp_socket(sock); 
            stop_timer(sock);
            sock->socket_state = & simptcp_socket_states.closed ;
            unlock_simptcp_socket(sock);
        }
    }

}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void lastack_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "lastack"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void lastack_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

    /* arrêt du timer */
    stop_timer(sock) ;

    /* lock du socket */
    lock_simptcp_socket(sock) ;

    /* incrémentation du nombre d'envoi */
    sock->simptcp_send_count ++ ;

    /* unlock du socket */
    unlock_simptcp_socket(sock) ;
    /* ré-émission du PDU */
    libc_sendto(simptcp_entity.udp_fd, sock->out_buffer, sock->out_len, 0,(struct sockaddr*)(&(sock->remote_udp)), sock->out_len) ;

    /* relance du timer */
    start_timer(sock, 1000) ;


}


/*********************************************************
 * timewait_state functions *
 *********************************************************/

/**
 * called when application calls connect
 */


/*! \fn int timewait_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
 * \brief lancee lorsque l'application lance l'appel "connect" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param addr adresse de niveau transport du socket simpTCP destination
 * \param len taille en octets de l'adresse de niveau transport du socket destination
 * \return  0 si succes, -1 si erreur
 */
int timewait_simptcp_socket_state_active_open (struct  simptcp_socket* sock, struct sockaddr* addr, socklen_t len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls listen
 */
/*! \fn int timewait_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n) 
 * \brief lancee lorsque l'application lance l'appel "listen" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param n  nbre max de demandes de connexion en attente (taille de la file des demandes de connexion)
 * \return  0 si succes, -1 si erreur
 */
int timewait_simptcp_socket_state_passive_open (struct simptcp_socket* sock, int n)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls accept
 */
/*! \fn int timewait_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
 * \brief lancee lorsque l'application lance l'appel "accept" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] addr pointeur sur l'adresse du socket distant de la connexion qui vient d'etre acceptee
 * \param len taille en octet de l'adresse du socket distant
 * \return 0 si succes, -1 si erreur/echec
 */
int timewait_simptcp_socket_state_accept (struct simptcp_socket* sock, struct sockaddr* addr, socklen_t* len) 
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls send
 */
/*! \fn ssize_t timewait_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "send" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf  pointeur sur le message a transmettre
 * \param n Taille du buffer (contenant le message) en octets pointe par buf  
 * \param flags options
 * \return taille en octet du message envoye ; -1 sinon
 */
ssize_t timewait_simptcp_socket_state_send (struct simptcp_socket* sock, const void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls recv
 */
/*! \fn ssize_t timewait_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
 * \brief lancee lorsque l'application lance l'appel "recv" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param [out] buf  pointeur sur le message recu
 * \param n Taille max du buffer de reception pointe par buf
 * \param flags options
 * \return  taille en octet du message recu, -1 si echec
 */
ssize_t timewait_simptcp_socket_state_recv (struct simptcp_socket* sock, void *buf, size_t n, int flags)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls close
 */
/*! \fn  int timewait_simptcp_socket_state_close (struct simptcp_socket* sock)
 * \brief lancee lorsque l'application lance l'appel "close" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \return  0 si succes, -1 si erreur
 */
int timewait_simptcp_socket_state_close (struct simptcp_socket* sock)
{

#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when application calls shutdown
 */
/*! \fn  int timewait_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
 * \brief lancee lorsque l'application lance l'appel "shutdown" alors que le socket simpTCP est dans l'etat "timewait" 
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param how sens de fermeture de le connexion (en emisison, reception, emission et reception)
 * \return  0 si succes, -1 si erreur
 */
int timewait_simptcp_socket_state_shutdown (struct simptcp_socket* sock, int how)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
    return -1;

}

/**
 * called when library demultiplexed a packet to this particular socket
 */
/*! 
 * \fn void timewait_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
 * \brief lancee lorsque l'entite protocolaire demultiplexe un PDU simpTCP pour le socket simpTCP alors qu'il est dans l'etat "timewait"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 * \param buf pointeur sur le PDU simpTCP recu
 * \param len taille en octets du PDU recu
 */
void timewait_simptcp_socket_state_process_simptcp_pdu (struct simptcp_socket* sock, void* buf, int len)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif
}

/**
 * called after a timeout has detected
 */
/*! 
 * \fn void timewait_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
 * \brief lancee lors d'un timeout du timer du socket simpTCP alors qu'il est dans l'etat "timewait"
 * \param sock pointeur sur les variables d'etat (#simptcp_socket) du socket simpTCP
 */
void timewait_simptcp_socket_state_handle_timeout (struct simptcp_socket* sock)
{
#if __DEBUG__
    printf("function %s called\n", __func__);
#endif

}

