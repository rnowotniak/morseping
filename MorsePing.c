#if 0 /*
#
#  MorsePing.c
#  Copyright (C) 2002	Robert Marcin Nowotniak <rob@submarine.ath.cx>
#  sob 26 pa¼ 2002 17:25:38 CET
#
#  Program s³u¿y do 'komunikacji' przez sieæ za pomoc± wypingowania komunikatu
#  w alfabecie Morse'a. :-)  [Oczywi¶cie to bardzo zawodna metoda]
#
#  Wymagana biblioteka libncurses oraz libpcap w wersji 0.7 (funkcja
#  pcap_findalldevs()) - dla niezale¿nego od systemu operacyjnego odnajdywania
#  interface'ów sieciowych.
#
#  Program dzia³a pod Unix'em oraz Linux'em.  _NIE_ dzia³a pod niektórymi
#  wersjami BSD, bo w tych systemach wielokana³owa obs³uga nieblokuj±cych
#  deskryptorów za pomoc± select() nie dzia³a z urz±dzeniami BPF (Berkely
#  Packet Filter).
#
#  Wpisz sh ./MorsePing.c aby skompilowaæ ten program.
#
# */
cc $0 -o MorsePing -g -O6 -pipe -Wall -lncurses -lpcap && echo "GOTOWE!"
exit 0
#endif



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <termios.h>
#include <ncurses.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <errno.h>



// #define DEBUG 0


#define	HOSTNAME_MAXLEN 70
char HOSTNAME[ HOSTNAME_MAXLEN ]={ '\0' },
	HOSTADR[16]={'\0'},
	PEERNAME [ HOSTNAME_MAXLEN ]={ '\0' },
	PEERADR[16]={ '\0' },
#define	MAX_PACKETS	10
	odbior[ MAX_PACKETS ]={ '\0' };


WINDOW *MAINWIN=NULL;
WINDOW *OK_NAD, *OK_NAD_M, *OK_ODB, *OK_ODB_M;

#define	MAX_IFACES	10
char	*IFS[ MAX_IFACES ];
pcap_t	*IFfds[ MAX_IFACES ]={'\0'};

#define	TRESC_PINGA	"1234567890ABCDEFGH1234567890ABCDEFGH"
#define	DLUGI_LENTH 36
#define	KROTKI_LENTH 18

#define	ETHERHDR_SIZE	14
#define	ICMPHDR_SIZE	8
#define	IPHDR_SIZE	20

#define	ICMP_ECHO	8
#define	BPF_PROG_TEMPLATE	"icmp and icmp[0]==8 and dst host %s"

/* Czasy w mikrosekundach */
#define	DELAY1	 500000	// Przerwa pomiêdzy pojedynczymi sygna³ami (krótki, d³ugi)
#define	DELAY2	1000000	// Przerwa pomiêdzy kodami poszczególnych liter
#define	DELAY3	2000000	// Przerwa po pe³nym s³owie

enum __pik { KROTKI=0, DLUGI=1 };
struct bpf_program prog;
struct timeval last_tv, /* czas nadej¶cia ostatniego pakietu */
	tv2;
struct timezone tz;

struct __moj_pakiet {
	struct timeval czas;
	unsigned int	len;
} PAKIETY[ MAX_PACKETS+1 ];
int	piq = 0; /* Packets in Queue */

/* Prototypy funkcji */
int Parsuj_Arg(int argc, char **argv);
int inicjalizuj_UI(void);
int inicjalizuj_Siec(void);
int MainLoop(void);
char *rozwiaz_ip(const char *hostname);
char *rozwiaz_hostname(const char *ip);
char* WezKod(char znak);
char WezZnak(const char *kod);
int WypiszMorsem(WINDOW *okno, const char *kod);
void Pingnij(const char *host, enum __pik sygnal);
int Wypinguj(const char *kod);
unsigned short IcmpSuma(const unsigned short *addr, register int len);
void PurgeFD(int fd);
unsigned long int DeltaCzasu(const struct timeval *t1, const struct timeval *t2);
void Przesun( int o_ile );
void funk_callback(u_char *u, const struct pcap_pkthdr *pkt_hdr, const u_char *pakiet);
int blad(int exitcode, const char *fmt, ...);

#define Blad1(fmt, ...) blad(EXIT_FAILURE, fmt, ##__VA_ARGS__);

char errbuf[ PCAP_ERRBUF_SIZE ];

int fd=-1, litera_zakonczona=1;
fd_set wejscie;

struct __wpis
{
	char	znak;
	char	*kod;
};

struct __wpis Morse[]=
{
	{ 'a' , ".-" },
	{ 'b' , "-..." },
	{ 'c' , "-.-." },
	{ 'd' , "-.." },
	{ 'e' , "." },
	{ 'f' , "..-." },
	{ 'g' , "--." },
	{ 'h' , "...." },
	{ 'i' , ".." },
	{ 'j' , ".---" },
	{ 'k' , "-.-" },
	{ 'l' , ".-.." },
	{ 'm' , "--" },
	{ 'n' , "-." },
	{ 'o' , "---" },
	{ 'p' , ".--." },
	{ 'r' , ".-." },
	{ 's' , "..." },
	{ 't' , "-" },
	{ 'u' , "..-" },
	{ 'v' , "...-" },
	{ 'w' , ".--" },
	{ 'x' , "-..-" },
	{ 'y' , "-.--" },
	{ 'z' , "--.." },
	{ '1' , ".----" },
	{ '2' , "..---" },
	{ '3' , "...--" },
	{ '4' , "....-" },
	{ '5' , "....." },
	{ '6' , "-...." },
	{ '7' , "--..." },
	{ '8' , "---.." },
	{ '9' , "----." },
	{ '0' , "----- "},
	{  0	, NULL }
};

#ifndef KEY_ESC
#define KEY_ESC 033
#endif

int main(argc, argv, envp)
	int	argc;
	char	**argv;
	char	**envp;
{
	Parsuj_Arg(argc, argv);

	inicjalizuj_Siec();
	inicjalizuj_UI();

	MainLoop();

	endwin();

	exit(EXIT_SUCCESS);
}


int MainLoop(void)
{
	fd_set fds1;
	char	*kod, znak;
	struct timeval timeout;
	int	key, max_fd, n, m, ilewej, shift;
	int	whitespace=1;
	int	nie_ma_spacji=0;
	unsigned int Delay2sec, Delay2uSec;
	unsigned long int D=0;

	FD_ZERO(&wejscie);
	FD_SET(0, &wejscie);
	max_fd=0;
	for( n=0; IFfds[n]; ++n )
	{
		FD_SET( pcap_fileno(IFfds[n]) , &wejscie);
		max_fd = pcap_fileno(IFfds[n])>max_fd ? pcap_fileno(IFfds[n]) : max_fd;
	}
	++max_fd;

	Delay2sec = (unsigned int) (DELAY2-50000) / 1000000;
	Delay2uSec = (unsigned int) (DELAY2-50000) % 1000000;
	last_tv.tv_sec=0;
	last_tv.tv_usec=0;
	tv2.tv_sec=0;
	tv2.tv_usec=0;

	for(;;)
	{
		fds1=wejscie;
		timeout.tv_sec= Delay2sec;
		timeout.tv_usec= Delay2uSec;

/* SELECT */
		curs_set(1);
		wrefresh(OK_NAD);
		if( (n=select(max_fd, &fds1, (fd_set*)NULL, (fd_set*)NULL, &timeout )) < 0 )
			Blad1("select()");
		curs_set(0);

#if defined(DEBUG) && DEBUG!=0
		printw("S(%d)", n);
		refresh();
#endif

		if( FD_ISSET(0, &fds1) )
		{
			--n;
			key = wgetch(OK_NAD);

			switch(key){
				case KEY_ESC:
					if( MAINWIN )
						endwin();
					close(fd);
					for( m=0; IFfds[m]; ++m )
						pcap_close( IFfds[m] );
					exit(EXIT_SUCCESS);
					break;
				case ' ' :
				case '\t':
					if( ! whitespace )
					{
						waddch(OK_NAD, ' ');
						waddch(OK_NAD_M, ' ');
						usleep( DELAY3 );
					}
					whitespace = 1;
					break;
				case '\n':
					waddch(OK_NAD, '\n');
					wrefresh(OK_NAD);
					usleep( DELAY3 );
					whitespace = 1;

					break;

				default:

					kod = WezKod(key);
					if( ! kod )
					{
						flash();
						continue;
					}

#if defined(DEBUG) && DEBUG!=0
					printw("Pingowanie ");
					refresh();
#endif

					Wypinguj(kod);
#if defined(DEBUG) && DEBUG!=0
					printw("Koniec Pingowania ");
					refresh();
#endif

					wprintw(OK_NAD, "%c", toupper(key));
					wrefresh(OK_NAD);

					whitespace = 0;

					usleep( DELAY2 );

					PurgeFD(0);
			}

			continue;
		}

		for( m=0; IFfds[m] && n ; ++m )
			if( FD_ISSET(pcap_fileno(IFfds[m]), &fds1) )
			{
				--n;
				do
				{
					if( ioctl( pcap_fileno(IFfds[m]), FIONREAD, &ilewej ) < 0 )
						Blad1("ioctl()");
					pcap_dispatch( IFfds[m], 10, funk_callback, (u_char*) NULL );
				} while ( ilewej );
			}


		if( piq )	/* KLUCZOWA CZÊ¦Æ PROGRAMU */
		{

			/* S± jakie¶ pakiety w kolejce */
			* odbior = '\0';
			shift = 0;

			for( m=0; m<=piq-1; ++m )
			{

				switch( PAKIETY[m].len )
				{
					case KROTKI_LENTH:
						strcat( odbior, "." );
						break;
					case DLUGI_LENTH:
						strcat( odbior, "-" );
						break;
				}


				if( m + 1 <= piq-1 ) /* Je¶li jest kolejny pakiet w kolejce ... */
				{
					D = DeltaCzasu( &(PAKIETY[m+1].czas), &(PAKIETY[m].czas) );

					if( D >= DELAY3 && nie_ma_spacji )
					{
						waddch(OK_ODB, ' ');
						wrefresh(OK_ODB);
						waddch(OK_ODB_M, ' ');
						wrefresh(OK_ODB_M);
						nie_ma_spacji = 0;
					}

					if( D >= DELAY2 )
					{
						/* pakiety od 0 do m tworz± literê */

						znak = WezZnak( odbior );
						waddch(OK_ODB, znak ? toupper(znak) : '?' );
						wrefresh( OK_ODB );
						* odbior = '\0';
						shift += m+1;

						litera_zakonczona = 0;
						nie_ma_spacji = 1;
					}
				}

			}

			if( shift )
				Przesun( shift );

			if( piq )
			{

				if( gettimeofday( &tv2, &tz ) < 0 )
					Blad1("gettimeofday()");

				D = DeltaCzasu( &tv2, &last_tv );

#if defined(DEBUG) && DEBUG!=0
				printw("D:%u ", D);
				refresh();
#endif

				if( D >= DELAY3 && nie_ma_spacji )
				{
					waddch(OK_ODB, ' ');
					wrefresh(OK_ODB);
					waddch(OK_ODB_M, ' ');
					wrefresh(OK_ODB_M);
					nie_ma_spacji = 0;
				}

				if( D >= DELAY2 )
				{
					* odbior = '\0';
					for( m=0; m<=piq-1; ++m )
						strcat(odbior, PAKIETY[m].len==KROTKI_LENTH ? "." : "-" );

					znak = WezZnak( odbior );
					waddch(OK_ODB, znak ? toupper(znak) : '?' );
					wrefresh( OK_ODB );
					* odbior = '\0';

					litera_zakonczona = 0;
					nie_ma_spacji = 1;
					piq=0;
				}
			}

#if defined(DEBUG) && DEBUG!=0
			printw("T");
			refresh();
#endif
			if( ! litera_zakonczona )
			{
				waddch(OK_ODB_M, ' ');
				wrefresh(OK_ODB_M);
				litera_zakonczona = 1;
			}

			continue;
		}
		else {
			if( gettimeofday( &tv2, &tz ) < 0 )
				Blad1("gettimeofday()");
			if( DeltaCzasu( &tv2, &last_tv) >= DELAY3 && nie_ma_spacji )
			{
				waddch(OK_ODB, ' ');
				wrefresh(OK_ODB);
				waddch(OK_ODB_M, ' ');
				wrefresh(OK_ODB_M);
				nie_ma_spacji = 0;
			}

		}
	}
}


int inicjalizuj_UI(void)   /* {{{ */
{

	MAINWIN=initscr();
	start_color();
	curs_set(1);

	init_pair(1, COLOR_WHITE, COLOR_BLACK);
	init_pair(2, COLOR_WHITE, COLOR_BLUE);
	init_pair(3, COLOR_WHITE, COLOR_RED);

	bkgd(' '|COLOR_PAIR(2));

	attron(A_BOLD|COLOR_PAIR(1));
	mvprintw(0, COLS-20, "---> MorsePing <---");
	mvprintw(1, 1, "  %s (%s):  ", HOSTNAME, HOSTADR);
	if( *PEERNAME )
		mvprintw((int)((LINES-9)/2)+5, 1, "  %s (%s):  ", PEERNAME, PEERADR);
	else
		mvprintw((int)((LINES-9)/2)+5, 1, "  %s:  ", PEERADR);
	attroff(A_BOLD|COLOR_PAIR(1));

	refresh();

	cbreak();
	noecho();
	ESCDELAY=200;

	OK_NAD   = newwin( (int)((LINES-9)/2), COLS-2, 2, 1 );
	wbkgd(OK_NAD, ' '|COLOR_PAIR(1));
	wrefresh(OK_NAD);
	delwin(OK_NAD);
	OK_NAD   = newwin( (int)((LINES-14)/2), COLS-4, 3, 2 );
	wrefresh(OK_NAD);

	OK_NAD_M = newwin( 2, COLS-2, (int)((LINES-9)/2)+2, 1);
	wbkgd(OK_NAD_M, ' '|COLOR_PAIR(3));
	wattron(OK_NAD_M, A_BOLD);
	wrefresh(OK_NAD_M);

	OK_ODB   = newwin( (int)((LINES-9)/2), COLS-2, (int)((LINES-9)/2)+6, 1 );
	wbkgd(OK_ODB, ' '|COLOR_PAIR(1));
	wrefresh(OK_ODB);
	delwin(OK_ODB);
	OK_ODB   = newwin( (int)((LINES-14)/2), COLS-4, (int)((LINES-9)/2)+7, 2 );
	wrefresh(OK_ODB);

	OK_ODB_M = newwin( 2, COLS-2, 2*(int)((LINES-9)/2)+6, 1 );
	wbkgd(OK_ODB_M, ' '|COLOR_PAIR(3));
	wattron(OK_ODB_M, A_BOLD);
	wrefresh(OK_ODB_M);

	keypad(MAINWIN, TRUE);
	keypad(OK_NAD, TRUE);
	keypad(OK_NAD_M, TRUE);
	keypad(OK_ODB, TRUE);
	keypad(OK_ODB_M, TRUE);

	scrollok(OK_NAD, TRUE);
	scrollok(OK_NAD_M, TRUE);
	scrollok(OK_ODB, TRUE);
	scrollok(OK_ODB_M, TRUE);


	return 0;

}  /* }}} */


int inicjalizuj_Siec(void)  /* {{{ */
{
	char *ptr;
	pcap_if_t	*iface;
	char	**ifptr=IFS;
	struct pcap_addr *p_adr;
	struct hostent *hn;
	bpf_u_int32	netp;
	bpf_u_int32	maskp;
	char	bpf_prog_txt[ strlen(BPF_PROG_TEMPLATE) + INET_ADDRSTRLEN ];
	int n, immediate;
	int jest_ether = 0;


	if( gethostname( HOSTNAME, HOSTNAME_MAXLEN ) < 0 )
		Blad1("gethostname()");

/* Próba pozyskania FQDN */
	hn=gethostbyname( HOSTNAME );
	if( ! hn )
		Blad1("gethostbyname( %s )", HOSTNAME );

	ptr=(char*)NULL;
	if( ! index(hn->h_name, '.') )
	{
		for( n=0; (ptr=hn->h_aliases[n]); ++n )
			if( index(hn->h_aliases[n], '.') )
					break;

		if( ptr )
			strncpy( HOSTNAME, ptr, HOSTNAME_MAXLEN );
	}
	else
		strncpy( HOSTNAME, hn->h_name, HOSTNAME_MAXLEN );

	endhostent();

	ptr = rozwiaz_hostname( HOSTNAME );
	if( ! ptr )
	{
		fprintf(stderr, "B³±d: Nazwa tego komputera (%s) nie wskazuje na ¿aden adres (???).\n", HOSTNAME);
		exit(EXIT_FAILURE);
	}
	strncpy( HOSTADR, ptr, 16 );
	free( ptr );



	if( pcap_findalldevs( &iface, errbuf ) < 0 )
		Blad1("pcap_findalldevs(): %s", errbuf );

	for( ifptr=IFS ; iface ; iface = iface->next )
	{
		for( p_adr=iface->addresses ; p_adr && ifptr <= IFS+MAX_IFACES-2 ; p_adr=p_adr->next )
			if ( iface->name && p_adr->addr->sa_family == AF_INET )
			{
				/* Odrzucenie Linuxowych interface'ów typu eth0:0 (aliasowanie IP) */
				if( ! index(iface->name, ':') )
				{
					*ifptr++ = iface->name;
					break;
				}
			}
	}
	*ifptr=NULL;


	sprintf(bpf_prog_txt, BPF_PROG_TEMPLATE, HOSTADR);

	for( ifptr=IFS, n=0 ; *ifptr ; ++ifptr, ++n )
	{
		if( pcap_lookupnet( *ifptr, &netp, &maskp, errbuf ) < 0 )
			Blad1("pcap_lookupnet()");

		IFfds[n] = pcap_open_live( *ifptr, ETHERHDR_SIZE+IPHDR_SIZE+ICMPHDR_SIZE+DLUGI_LENTH, 0, 0, errbuf );

		if( ! IFfds[n] )
			Blad1("pcap_open_live()");

		if( pcap_datalink( IFfds[n] ) != DLT_EN10MB )
		{
			/* Nie jest to interface Ethernetowy */
			pcap_close( IFfds[n] );
			--n;
		}
		jest_ether = 1;

		if( pcap_setnonblock( IFfds[n], 1, errbuf ) < 0 )
			Blad1("pcap_setnonblock()");

		if( pcap_compile( IFfds[n], &prog, bpf_prog_txt, 1, netp ) < 0 )
			Blad1("pcap_compile()");

		if( pcap_setfilter( IFfds[n], &prog ) < 0 )
			Blad1("pcap_setfilter()");

	}
	IFfds[n]=NULL;

	if( ! jest_ether )
	{
		fprintf(stderr, "B³±d: W systemie nie znaleziono ¿adnego interface'u Ethernetowego.\n");
		fprintf(stderr, "      (Czy na pewno uruchamiasz ten program z prawami superu¿ytkownika?).\n\n");
		exit(EXIT_FAILURE);
	}

	immediate = 1;
	for( n=0; IFfds[n]; ++n )
		if( ioctl( pcap_fileno(IFfds[n]), BIOCIMMEDIATE, (u_int*) &immediate ) < 0 )
		{
			if( errno == EOPNOTSUPP )
			{
				/*
				 *  libpcap nie pos³u¿y³ siê urz±dzeniem Berkey Packet Filter (BPF) aby rozpocz±æ
				 *  'nas³uch'. Mo¿e OS to Linux. Mo¿e dalsze dzia³anie tego programu nie ma sensu.
				 */
			}
			else
				Blad1("ioctl(..., BIOCIMMEDIATE ... )");
		}


	fd=socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if( fd < 0 )
	{
		if( errno == EPERM )
		{
			fprintf(stderr, "--->        MorsePing       <---\n--->  rob@submarine.ath.cx  <---\n");
			fprintf(stderr, "\nB³±d: Brak uprawnieñ do otwarcia surowego gniazda sieciowego (ang. raw socket)\n");
			fprintf(stderr, "Ten program, w wiêkszo¶ci przypadków, musi byæ uruchamiany z prawami superu¿ytkownika.\n");
		} else
			Blad1("socket()");
		exit(EXIT_FAILURE);
	}

	if( fcntl(fd, F_SETFL, O_NONBLOCK) < 0 )
		Blad1("fcntl()");

	FD_ZERO(&wejscie);

	return 0;
}  /* }}} */


/*  FUNKCJE IP, DNS    {{{ */
int isip(const char *cos)
{
	struct in_addr inp;

	return inet_aton(cos, &inp);
}


char *rozwiaz_ip(const char *hostname)
{
	in_addr_t tmpadr;
	struct hostent *hostent1;
	char *ptr;
	int n;


	tmpadr = inet_addr(hostname);
	hostent1 = gethostbyaddr( (const char*)&tmpadr, 4, AF_INET );

	if( ! hostent1 || ! *(hostent1->h_name) )
		return NULL;

/* Próba pozyskania FQDN */
	ptr=(char*)NULL;
	if( ! index(hostent1->h_name, '.') )
		for( n=0; (ptr=hostent1->h_aliases[n]); ++n )
			if( index(hostent1->h_aliases[n], '.') )
				break;
	ptr = ptr ? ptr : hostent1->h_name;

	return strdup( ptr );
}


char *rozwiaz_hostname(const char *ip)
{
	struct hostent *hostent1;

	hostent1 = gethostbyname( ip );

	if( ! hostent1 || ! hostent1->h_addr || ! *(hostent1->h_addr) )
		return NULL;

	return strdup( inet_ntoa( *((struct in_addr*)hostent1->h_addr) ) );
}


unsigned short IcmpSuma(const unsigned short *addr, register int len)
{
	register int nleft = len;
	unsigned short *w = (unsigned short*)addr;
	register int suma = 0;

	while(nleft > 1)
	{
		suma+=*w++;
		nleft-=2;
	}
	if (nleft==1)
		suma+=htons(*(u_char *)w << 8);

	/* Zamiana na sieciowy porz±dek bajtów */
	suma=(suma >> 16)+(suma & 0xffff);
	suma+=(suma >> 16);
	return ~suma;
}
/* }}} */


int Parsuj_Arg(int argc, char **argv)
{
	char *ptr;


	if( argc == 2 )
	{
		if( ! isip(argv[1]) )
		{
			strncpy(PEERNAME, argv[1], HOSTNAME_MAXLEN);
			ptr = rozwiaz_hostname(PEERNAME);
			if( ! ptr )
			{
				fprintf(stderr, "%s nie wskazuje na ¿aden adres.\n\n", PEERNAME);
				exit(EXIT_FAILURE);
			}
			strncpy(PEERADR, ptr, 16);
			free( ptr );
		}
		else
		{
			strncpy(PEERADR, argv[1], 16);
			ptr = rozwiaz_ip(PEERADR);
			if( ptr )
			{
				strncpy(PEERNAME, ptr, HOSTNAME_MAXLEN);
				free( ptr );
			}
			else
				strncpy(PEERNAME, "", 1);
		}
	}else
	{
		fprintf(stderr, "--->        MorsePing       <---\n--->  rob@submarine.ath.cx  <---\n\n"
				"U¿ycie:\n %s <Adres IP lub nazwa hosta>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	return 0;
}


char* WezKod(char znak)
{
	int n=-1;

	while( Morse[++n].kod )
		if( Morse[n].znak == znak )
			return Morse[n].kod;

	return NULL;

}


char WezZnak(const char *kod)
{
	int n=-1;

	while( Morse[++n].kod )
		if( ! strcmp(Morse[n].kod, kod) )
			return Morse[n].znak;

	return (char)NULL;
}


int WypiszMorsem(WINDOW *okno, const char *kod)
{
	int n=-1;

	while( kod[++n] )
		waddch(okno,
				kod[n] == '.' ? '*' : '-' );
	waddch(okno, ' ');

	return 0;
}


int Wypinguj(const char *kod)
{
	int n=-1;

	while( kod[++n] )
	{
		Pingnij(PEERADR,
				kod[n] == '.' ? KROTKI : DLUGI );
		waddch(OK_NAD_M,
				kod[n] == '.' ? '*' : '-' );
		wrefresh(OK_NAD_M);
		usleep(DELAY1);
	}

	waddch(OK_NAD_M, ' ');
	wrefresh(OK_NAD_M);

	return 0;
}


void Pingnij(const char *host, enum __pik sygnal)
{

/*
 *  Nag³ówek ICMP wygl±da tak:
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  |     Typ       |     Kod       |        Suma Kontrolna         |
 *  |        Identyfikator          |       Numer Sekwencyjny       |
 *
 */

	struct sockaddr_in adr;
	struct icmp *icmpn; /* Nag³ówek ICMP */
	int dane = ( sygnal == KROTKI ? KROTKI_LENTH : DLUGI_LENTH );
	char	pakiet[ICMPHDR_SIZE+dane];
	char	*ptr;
	int	tr_len, n;

	memset(pakiet, 'X', sizeof pakiet);
	pakiet[ sizeof(pakiet) - 1 ] = '\0';

	icmpn=(struct icmp*)pakiet;

	icmpn->icmp_type=ICMP_ECHO;
	icmpn->icmp_code=0;
	icmpn->icmp_cksum=0;
	icmpn->icmp_id= htons((int) ( 1.0 + rand()*65535.0/(RAND_MAX+1.0)) );
	icmpn->icmp_seq= htons((int) ( 1.0 + rand()*65535.0/(RAND_MAX+1.0)) );

	ptr = pakiet + ICMPHDR_SIZE;
	*ptr = '\0';
	tr_len = strlen(TRESC_PINGA);
	n = dane;

	while( n > 0 )
	{
		strncat(ptr, TRESC_PINGA, n);
		n-=tr_len;
	}

	icmpn->icmp_cksum=IcmpSuma((u_short*)&icmpn->icmp_type, ICMPHDR_SIZE+dane);

	adr.sin_family=AF_INET;
	adr.sin_addr.s_addr=inet_addr(host);
	if( sendto(fd, pakiet, sizeof pakiet, 0, (struct sockaddr*)&adr, sizeof(struct sockaddr)) < 0 )
#if defined(DEBUG) && DEBUG!=0
		perror("sendto()");
#else
		Blad1("sendto()");
#endif

}


void PurgeFD(int fd)
{
	int n, ilewej;

	if( ioctl(0, FIONREAD, &ilewej) < 0 )
	{
		if( MAINWIN )
			endwin();

		fprintf(stderr, "B³±d: ioctl(0,FIONREAD...    to nie mo¿e nie dzia³aæ (???)\n%s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	for( n=1; n<=ilewej; n++ )
		wgetch( OK_NAD );
}


unsigned long int DeltaCzasu(const struct timeval *t1, const struct timeval *t2)
{
	/* Zwraca ró¿nicê czasów w mikrosekundach */
	return 1000000*( t1->tv_sec - t2->tv_sec ) + ( t1->tv_usec - t2->tv_usec );
}


void Przesun( int o_ile )
{
	register int n=0;

	while( n < piq-o_ile )
		PAKIETY[ n++ ] = PAKIETY[ o_ile+n ];

	piq -= o_ile;
}


int blad(int exitcode, const char *fmt, ...)
{
	va_list ap;
	int err=errno;

	if( MAINWIN )
		endwin();

	fprintf(stderr, "MorsePing: ");

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, ": ");

	printf("\n%s\n", strerror(err) );

	exit( exitcode );
}


void funk_callback(u_char *u, const struct pcap_pkthdr *pkt_hdr, const u_char *pakiet)
{
	struct	ether_header*	eth_hdr;
	struct	ip	*ip_hdr;
	struct	icmp *icmp_hdr;
	int	msg_len;
	struct	timeval tv;

#if defined(DEBUG) && DEBUG!=0
	printw("CALLBACK");
	refresh();
#endif

	eth_hdr = (struct ether_header*) pakiet;
	if( ntohs(eth_hdr->ether_type) == ETHERTYPE_IP )
	{

		ip_hdr = (struct ip*) (pakiet+sizeof(struct ether_header));
		if( ! strcmp(inet_ntoa(ip_hdr->ip_dst), HOSTADR) )
		{

			if( ip_hdr->ip_p == IPPROTO_ICMP )
			{

				icmp_hdr = (struct icmp*) ((char*)(ip_hdr)+IPHDR_SIZE);
				if( icmp_hdr->icmp_type == ICMP_ECHO && icmp_hdr->icmp_code == 0 )
				{
					/* Jest zapytanie o PING */
					msg_len = pkt_hdr->len - ETHERHDR_SIZE - IPHDR_SIZE - ICMPHDR_SIZE ;

					if( gettimeofday( &tv, &tz ) < 0 )
						Blad1("gettimeofday()");

					if( piq >= MAX_PACKETS )
					{
						piq = 1;
						PAKIETY[0].czas = pkt_hdr->ts;
						PAKIETY[0].len = msg_len;
					} else {
						PAKIETY[ piq ].czas = pkt_hdr->ts;
						PAKIETY[ piq ].len = msg_len;
						++piq;
					}

					switch( msg_len )
					{
						case KROTKI_LENTH:
							waddch(OK_ODB_M, '*');
							break;
						case DLUGI_LENTH:
							waddch(OK_ODB_M, '-');
							break;
						default:
							wprintw(OK_ODB_M, "?(len:%d) ", msg_len);
					}
					wrefresh(OK_ODB_M);

					if( gettimeofday(&last_tv, &tz) < 0 )
						Blad1("gettimeofday()");

				}
			}
		}
	}
}

/* vim: set ft=c fdm=marker:*/

