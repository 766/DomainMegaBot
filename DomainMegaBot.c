#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int DomainMegaBot(char * , char *, char *, char *);
int hostname_to_ip(char * , char *);
int whois_query(char * , char * , char **);
int Str_Split(char *str, char c, char ***arr);
char* Str_Conn(const char *s1, const char *s2);

struct globalArgs_t {
    int noIndex;                /* -I option */
    float interval;               /* -s option */
    const char *outFileName;    /* -o option */
    const char *inFileName;     /* -i option */
    const char *target;         /* -t option */
    FILE *outFile;
    int verbosity;              /* -v option */
    char **inputFiles;          /* input files */
    int numInputFiles;          /* # of input files */
    int randomized;             /* --randomize option */
} globalArgs;

static const char *optString = "Ii:s:o:t:vh?";

static const struct option longOpts[] = {
    { "no-index", no_argument, NULL, 'I' },
    { "interval", required_argument, NULL, 's' },
    { "output", required_argument, NULL, 'o' },
    { "input", required_argument, NULL, 'i' },
    { "target", required_argument, NULL, 't' },
    { "verbose", no_argument, NULL, 'v' },
    { "randomize", no_argument, NULL, 0 },
    { "help", no_argument, NULL, 'h' },
    { NULL, no_argument, NULL, 0 }
};

/* Display program usage, and exit.
 */
void display_usage( void )
{
    puts( "--interval,-s            - specify query interval. unit second" );
    puts( "--output,-o              - specify the query result file " );
    puts( "--input,-i               - specify the custom domain rule file " );
    puts( "--target,-t              - specify the ccTLD " );
    /* ... */
    exit( EXIT_FAILURE );
}

/* Convert the input files to HTML, governed by globalArgs.
 */
void convert_document( void )
{
    /* ... */
    printf( "no-index: %d\n", globalArgs.noIndex );
    printf( "interval: %f\n", globalArgs.interval );
    printf( "output: %s\n", globalArgs.outFileName );
    printf( "input: %s\n", globalArgs.inFileName );
    printf( "target: %s\n", globalArgs.target );
    printf( "verbosity: %d\n", globalArgs.verbosity );
    printf( "randomized: %d\n", globalArgs.randomized );
}

int main(int argc , char *argv[]) {
    int opt = 0;
    int longIndex = 0;
    
    /* Initialize globalArgs before we get to work. */
    globalArgs.noIndex = 0;     /* false */
    globalArgs.interval = 0;
    globalArgs.outFileName = NULL;
    globalArgs.inFileName = NULL;
    globalArgs.target = NULL;
    globalArgs.outFile = NULL;
    globalArgs.verbosity = 0;
    globalArgs.inputFiles = NULL;
    globalArgs.numInputFiles = 0;
    globalArgs.randomized = 0;

    /* Process the arguments with getopt_long(), then 
     * populate globalArgs. 
     */
    opt = getopt_long( argc, argv, optString, longOpts, &longIndex );
    while( opt != -1 ) {
        switch( opt ) {
            case 'I':
                globalArgs.noIndex = 1; /* true */
            break;

            case 's':
                globalArgs.interval = atof(optarg);
            break;

            case 'i':
                globalArgs.inFileName = optarg;
            break;

            case 'o':
                globalArgs.outFileName = optarg;
            break;

            case 't':
                globalArgs.target = optarg;
            break;

            case 'v':
                globalArgs.verbosity++;
            break;

            case 'h':   /* fall-through is intentional */
            case '?':
                display_usage();
            break;

            case 0:     /* long option without a short arg */
            if( strcmp( "randomize", longOpts[longIndex].name ) == 0 ) {
                globalArgs.randomized = 1;
            }
            break;

            default:
                /* You won't actually get here. */
            break;
        }
        
        opt = getopt_long( argc, argv, optString, longOpts, &longIndex );
    }
    
    globalArgs.inputFiles = argv + optind;
    globalArgs.numInputFiles = argc - optind;

    FILE * fp = fopen("TLD_DATA","r");
    if (fp==NULL) {
        printf("TLD DATABASE NOT FOUND!\n");
        exit(1);
    }
    char *line = NULL; char Ext[10];
    size_t len = 0; ssize_t read;
    char **arr = NULL;
    char DomainExt[10]={'0'}; char NoMatchPattern[20]; char WhoisQueryServer[40];
    printf("THANK YOU FOR USING DOMAINMEGABOT POWERED BY HAR-KUUN (HTTPS://QING.SU). \n\nPLEASE NOTE THAT THIS BOT DOES NOT GUARANTEE THE AVAILABILITY. REGISTRAR'S RULES APPLY.\n\n");
    // printf("PLEASE SPECIFY TLD: ");
    // scanf("%s", Ext);
    while ((read = getline(&line, &len, fp)) != -1) {
        Str_Split(line, '=', &arr);
        // if (strcmp(arr[0],Ext)==0) {
        if (strcmp(arr[0],globalArgs.target)==0) {
           strcpy(DomainExt,arr[0]); strcpy(NoMatchPattern,arr[2]); strcpy(WhoisQueryServer,arr[1]);
           break;
       }
   }
   if (*DomainExt == '0') {
    printf("TLD NOT SUPPORTED!\n");
    exit(2);
}
fclose(fp);
// char DictFile[256];
// printf("PLEASE SPECIFY DICTIONARY FILE: ");
// scanf("%s",DictFile);
FILE * fp_Dict = fopen(globalArgs.inFileName,"r");
if (fp_Dict==NULL) {
    printf("DICTIONARY FILE NOT FOUND!\n");
    exit(3);
}
char c; size_t n=0;
char DomainPrefix[70] , domain[100], *data = NULL;
FILE * fp_Result = fopen(Str_Conn(DomainExt,"_RESULTS.DAT"),"w");
if (fp_Result==NULL) {
    printf("FAILED TO WRITE RESULTS TO FILE!\n");
    exit(4);
}
fprintf(fp_Result,"THANK YOU FOR USING DOMAINMEGABOT POWERED BY HAR-KUUN (HTTPS://QING.SU). \n\nBELOW IS THE AVAILABLE DOMAIN NAME LIST BASED ON YOUR QUERY. PLEASE NOTE THAT THIS DOES NOT GUARANTEE THE AVAILABILITY. REGISTRAR'S RULES APPLY.\n\n");
fclose(fp_Result);
while (1) {
    n=0;
    *DomainPrefix='\0';
    while ((c = fgetc(fp_Dict)) != '\n') {
        if (c==EOF) {
            printf("TASK FINISHED!\n\nTHANK YOU FOR USING DOMAINMEGABOT POWERED BY HAR-KUUN (HTTPS://QING.SU). HAVE A GREAT DAY!\n");
            fp_Result=fopen(Str_Conn(DomainExt,"_RESULTS.DAT"),"a");
            fprintf(fp_Result,"\nTHANK YOU FOR USING DOMAIN MEGABOT POWERED BY HAR-KUUN (HTTPS://QING.SU). HAVE A GREAT DAY!\n");
            fclose(fp_Result);
            fclose(fp_Dict);
            exit(0);
        }
        DomainPrefix[n++] = c;
    }
    DomainPrefix[n]='\0';
    strcpy(domain,Str_Conn(Str_Conn(DomainPrefix,"."),DomainExt));
    DomainMegaBot(domain, NoMatchPattern, WhoisQueryServer, DomainExt);
}

return EXIT_SUCCESS;
}


int DomainMegaBot(char *domain , char * NoMatchPattern, char * WhoisQueryServer, char * DomainExt) {
    char *response = NULL ; FILE * fpR;
    do {
        whois_query(WhoisQueryServer, domain, &response);
        // printf("interval :%f\n", globalArgs.interval);
        sleep(globalArgs.interval);
        if (response) break;
    }
    while(1);
    if (strstr(response,NoMatchPattern)!=NULL) {
      printf("%s AVAILABLE FOR REGISTRATION!\n", domain);
      fpR=fopen(Str_Conn(DomainExt,"_RESULTS.DAT"),"a");
      fprintf(fpR,"%s\n",domain);
      fclose(fpR);
  }
  else
      printf("%s NOT AVAILABLE.\n", domain);
  return 0;
}


int whois_query(char *server , char *query , char **response) {
    char ip[32] , message[100] , buffer[1500];
    int sock , read_size , total_size = 0;
    struct sockaddr_in dest;
    sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);
    memset( &dest , 0 , sizeof(dest) );
    dest.sin_family = AF_INET;
    if(hostname_to_ip(server , ip)) {
        printf("FAILED TO RESOLVE HOSTNAME");
        return 1;
    }
    dest.sin_addr.s_addr = inet_addr( ip );
    dest.sin_port = htons( 43 );
    if(connect( sock , (const struct sockaddr*) &dest , sizeof(dest) ) < 0) {
        perror("FAILED TO REACH WHOIS SERVER");
    }
    sprintf(message , "%s\r\n" , query);
    if( send(sock , message , strlen(message) , 0) < 0) {
        perror("FAILED TO SEND QUERY");
    }
    while( (read_size = recv(sock , buffer , sizeof(buffer) , 0) ) ) {
        *response = (char*)realloc(*response , read_size + total_size);
        if(*response == NULL) {
            printf("FAILED TO ACCESS SYSTEM MEMORY");
        }
        memcpy(*response + total_size , buffer , read_size);
        total_size += read_size;
    }
    fflush(stdout);
    *response = (char*)realloc(*response , total_size + 1);
    *(*response + total_size) = '\0';
    close(sock);
    return 0;
}


int hostname_to_ip(char * hostname , char* ip) {
    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    if ( (he = gethostbyname( hostname ) ) == NULL) {
        herror("gethostbyname");
        return 1;
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++) {
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }

    return 0;
}


int Str_Split(char *str, char c, char ***arr) {
    int count = 1;
    int token_len = 1;
    int i = 0;
    char *p;    char *t;
    p = str;
    while (*p != '\0') {
        if (*p == c)
            count++;
        p++;
    }
    *arr = (char**) malloc(sizeof(char*) * count);
    if (*arr == NULL) {
        printf("UNABLE TO ACCESS SYSTEM MEMORY.");
        exit(9);
    }
    p = str;
    while (*p != '\0') {
        if (*p == c) {
           (*arr)[i] = (char*) malloc( sizeof(char) * token_len );
           if ((*arr)[i] == NULL){
            printf("UNABLE TO ACCESS SYSTEM MEMORY.");
            exit(9);
        }
        token_len = 0;
        i++;
    }
    p++;
    token_len++;
}
(*arr)[i] = (char*) malloc( sizeof(char) * token_len );
if ((*arr)[i] == NULL) {
    printf("UNABLE TO ACCESS SYSTEM MEMORY.");
    exit(9);
}
i = 0;
p = str;
t = ((*arr)[i]);
while (*p != '\0') {
    if (*p != c && *p != '\0') {
       *t = *p;
       t++;
   }
   else {
       *t = '\0';
       i++;
       t = ((*arr)[i]);
   }
   p++;
}
return count;
}

char* Str_Conn(const char *s1, const char *s2) {
    const size_t len1 = strlen(s1);
    const size_t len2 = strlen(s2);
    char *result = (char*)malloc(len1+len2+1);
    memcpy(result, s1, len1);
    memcpy(result+len1, s2, len2+1);
    return result;
}
