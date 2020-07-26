/* --------------------------------------------- */
             /*== CONTROL FIELD ==*/

// -- Message is a response or request?
// Response            -xxxxxxx
#define RESPONSE     0b10000000
// -- What type of opcode this is?
// Opcode              x----xxx
#define QUERY        0b00000000
// -- Is the server authority of the domain?
// Authorative         xxxxx-xx
#define AA           0b00000100
// -- Is the response too big for UDP?
// Truncated           xxxxxx-x
#define TC           0b00000010
// -- Is the query we're making recursive/iterative?
// Recursion Desired   xxxxxxx-
#define RD           0b00000001
// -- Can server handle recursive or not?
// Recursion Available         -xxxxxxx
#define RA                   0b10000000
// -- Is the data authenticated?
// Authenticated data          xx-xxxxx
#define AD                   0b00100000
// -- Is checking disabled?
// Checking disabled           xxx-xxxx
#define CD                   0b00010000
// -- Status of data... Is there any error?
// Rccode                      xxxx----
#define NOERROR              0b00000000
#define FORMERR              0b00000001
#define SERVFAIL             0b00000010
#define NXDOMAIN             0b00000011


/* --------------------------------------------- */


// -- What type of address they query?
// Type
#define A     0x0001
#define CNAME 0x0005
#define AAAA  0x001c
#define OPT   0x0029
// -- What type of network they query?
// Class
#define IN    0x0001


/* --------------------------------------------- */


#define BUFSIZE          512
#define TTL              0x200
#define LOOKUP_FILENAME  "lookup.txt"
#define LOGFILE_FILENAME "logfile.txt"
